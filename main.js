const { app, BrowserWindow, ipcMain, Menu, Tray, screen, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const { spawnSync } = require('child_process');
const path = require('path');
const https = require('https');

const store = require('./src/store');
const hosts = require('./src/hostsBlocker');
const appBlocker = require('./src/appBlocker');
const lockManager = require('./src/lockManager');
const networkAgent = require('./src/networkAgent');
const crypto = require('crypto');
const networkDiscovery = require('./src/networkDiscovery');
const networkSpeedTest = require('./src/networkSpeedTest');
const windowsPermissions = require('./src/windowsPermissions');
const scheduleManager = require('./src/scheduleManager');
const { normalizeList, normalizeDuration, normalizeIpList } = require('./src/inputValidation');

const appIcon = path.join(__dirname, 'renderer', 'spacecraft.png');
const isBackgroundAgent = process.argv.includes('--background-agent');
const usesBootAgent = process.platform === 'win32' && app.isPackaged;

let mainWindow;
let speedWindow;
let tray;
let watchdogTimer;
let updateTimer;
let scheduleTimer;
let isQuitting = false;
let automaticUpdates = true;
const certificatePins = new Map();
const REMOTE_REQUEST_TIMEOUT_MS = 8000;
// The SYSTEM boot agent must not claim the interactive user's single-instance
// lock; otherwise the administrator console could be prevented from opening.
const hasSingleInstanceLock = isBackgroundAgent || app.requestSingleInstanceLock();
let updateState = {
  status: 'idle',
  currentVersion: app.getVersion(),
  availableVersion: null,
  downloaded: false,
  progress: 0,
  message: '',
  automaticUpdates
};

function configureWindowsStartup() {
  if (process.platform !== 'win32' || isBackgroundAgent || usesBootAgent) return;

  const args = app.isPackaged ? ['--hidden'] : [app.getAppPath(), '--hidden'];
  try {
    app.setLoginItemSettings({ openAtLogin: true, path: process.execPath, args, enabled: true });
  } catch (error) {
    console.warn('Current-user startup registration unavailable:', error.message);
  }

  try {
    const command = `"${process.execPath}" --hidden`;
    spawnSync('reg', [
      'add',
      'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      '/v',
      'Lockdown Blocker',
      '/t',
      'REG_SZ',
      '/d',
      command,
      '/f'
    ], { stdio: 'ignore', windowsHide: true });
  } catch (error) {
    console.warn('Machine-wide startup registration unavailable:', error.message);
  }
}

// Shared HTTPS client used for every remote agent call (legacy password
// path, signed path, and enrollment). Centralizing this means the
// certificate-pinning logic only exists once.
function createRemoteClient(host) {
  const address = host.replace(/^https?:\/\//, '').replace(/\/$/, '');
  return (method, route, body) => new Promise((resolve, reject) => {
    const request = https.request({
      hostname: address.split(':')[0],
      port: address.split(':')[1] || 47821,
      path: route,
      method,
      rejectUnauthorized: false,
      headers: body ? { 'Content-Type': 'application/json' } : {}
    }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => {
        try { resolve({ status: response.statusCode, body: JSON.parse(text) }); }
        catch (_) { reject(new Error('Invalid response from remote agent.')); }
      });
    });
    request.setTimeout(REMOTE_REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error(`Remote device timed out after ${REMOTE_REQUEST_TIMEOUT_MS / 1000} seconds.`));
    });
    request.on('socket', (socket) => socket.once('secureConnect', () => {
      const fingerprint = socket.getPeerCertificate().fingerprint256;
      const previous = certificatePins.get(address);
      if (previous && previous !== fingerprint) {
        request.destroy(new Error('Remote certificate changed. Connection rejected.'));
        return;
      }
      if (fingerprint) certificatePins.set(address, fingerprint);
    }));
    request.on('error', reject);
    if (body) request.write(JSON.stringify(body));
    request.end();
  });
}

async function remoteCommand(host, password, command, payload, role = 'operator') {
  // The password never travels over the network. It is hashed locally, and
  // that hash is used as an HMAC key to sign this specific request (see
  // networkAgent.createRequestProof). The remote agent independently
  // recomputes the same proof from its own stored password hash and
  // compares them — so a wrong password produces a proof mismatch, not a
  // transmitted secret an eavesdropper could reuse.
  const passwordHash = networkAgent.hashPassword(password);
  if (!passwordHash) {
    throw new Error('The network password must be at least 12 characters.');
  }
  const requestJson = createRemoteClient(host);

  const challengeResponse = await requestJson('GET', '/challenge');
  if (challengeResponse.status !== 200) throw new Error('Could not reach that device. Check its IP and firewall.');
  const { nonce } = challengeResponse.body;
  const request = {
    nonce,
    timestamp: Date.now(),
    requestId: crypto.randomUUID(),
    command,
    payload: payload === undefined ? null : payload,
    role
  };
  request.proof = networkAgent.createRequestProof(passwordHash, request);
  const response = await requestJson('POST', '/command', request);
  if (response.status < 200 || response.status >= 300) throw new Error(response.body.error || 'Remote command failed.');
  return response.body.data;
}

// This PC's identity when it acts as a controller. Generated once and
// reused — the private key never leaves this function's callers (main.js
// only), and is never sent over the network; only the public key is, and
// only during enrollment.
function getOrCreateControllerIdentity() {
  const data = store.load();
  if (data.controllerIdentity?.id && data.controllerIdentity?.privateKey) return data.controllerIdentity;
  const identity = networkAgent.generateControllerIdentity();
  data.controllerIdentity = identity;
  store.save(data);
  return identity;
}

// Signed path (Step 2): used once this PC has been enrolled on the target.
// No password involved at all — authentication is the Ed25519 signature,
// and the role is whatever the target's admin assigned at enrollment.
async function remoteCommandSigned(host, command, payload) {
  const identity = getOrCreateControllerIdentity();
  const requestJson = createRemoteClient(host);

  const challengeResponse = await requestJson('GET', '/challenge');
  if (challengeResponse.status !== 200) throw new Error('Could not reach that device. Check its IP and firewall.');
  const { nonce } = challengeResponse.body;
  const request = {
    nonce,
    timestamp: Date.now(),
    requestId: crypto.randomUUID(),
    command,
    payload: payload === undefined ? null : payload,
    controllerId: identity.id
  };
  request.signature = networkAgent.signRequest(identity.privateKey, request);
  const response = await requestJson('POST', '/command', request);
  if (response.status < 200 || response.status >= 300) throw new Error(response.body.error || 'Remote command failed.');
  return response.body.data;
}

// Enrolls THIS PC as a controller on the target device, using a pairing
// code an admin generated locally at the target. Role is decided by
// whoever is standing at the target PC approving the enrollment, not by
// this (the controller) side.
async function enrollWithController(host, code, label, role) {
  const identity = getOrCreateControllerIdentity();
  const requestJson = createRemoteClient(host);
  const response = await requestJson('POST', '/enroll', {
    code,
    controllerId: identity.id,
    controllerPublicKey: identity.publicKey,
    label: label || require('os').hostname(),
    role: role || 'operator'
  });
  if (response.status < 200 || response.status >= 300) throw new Error(response.body.error || 'Enrollment failed.');
  return response.body.data;
}

// Applies a patch to this PC's own network-security fields (called by the
// agent server itself when handling an incoming /enroll request).
function updateNetworkSecurity(patch) {
  const data = store.load();
  data.network = { ...data.network, ...patch };
  store.save(data);
  return data.network;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 650,
    icon: appIcon,
    skipTaskbar: true,
    show: !process.argv.includes('--hidden'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  mainWindow.on('close', (e) => {
    if (isQuitting) return;
    e.preventDefault();
    mainWindow.hide();
  });
}

function sendUpdateStatus(status, details = {}) {
  updateState = { ...updateState, status, ...details };
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('update-status', updateState);
}

async function checkForUpdates() {
  if (!app.isPackaged) {
    sendUpdateStatus('development', { message: 'Updates are available in packaged builds.' });
    return updateState;
  }
  sendUpdateStatus('checking', { message: 'Checking for updates...' });
  try {
    await autoUpdater.checkForUpdates();
  } catch (error) {
    sendUpdateStatus('error', { message: error.message });
  }
  return updateState;
}

function configureAutoUpdates() {
  if (!app.isPackaged) return;
  const savedPreference = store.load().updates?.automatic;
  automaticUpdates = savedPreference !== false;
  updateState.automaticUpdates = automaticUpdates;
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.on('update-available', (info) => {
    sendUpdateStatus('downloading', { availableVersion: info.version, downloaded: false, progress: 0, message: 'Downloading update automatically...' });
  });
  autoUpdater.on('update-not-available', () => {
    sendUpdateStatus('current', { availableVersion: null, downloaded: false, progress: 0, message: 'You are using the latest version.' });
  });
  autoUpdater.on('download-progress', (progress) => {
    sendUpdateStatus('downloading', { progress: Math.round(progress.percent), message: 'Downloading update...' });
  });
  autoUpdater.on('update-downloaded', (info) => {
    sendUpdateStatus('installing', { availableVersion: info.version, downloaded: true, progress: 100, message: 'Installing update and restarting...' });
    if (automaticUpdates) {
      isQuitting = true;
      setTimeout(() => autoUpdater.quitAndInstall(true, true), 1000);
    }
  });
  autoUpdater.on('error', (error) => {
    sendUpdateStatus('error', { message: error.message });
  });
  updateTimer = setInterval(() => {
    if (automaticUpdates) checkForUpdates();
  }, 6 * 60 * 60 * 1000);
  updateTimer.unref();
  setTimeout(() => {
    if (automaticUpdates) checkForUpdates();
  }, 5000).unref();
}

function createTray() {
  tray = new Tray(path.join(__dirname, 'renderer', 'spacecraft.png'));
  tray.setToolTip('Lockdown Blocker');
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Open', click: () => mainWindow.show() },
      { label: 'Open speed monitor', click: () => createSpeedWindow() },
      { label: 'Quit Lockdown', click: () => { isQuitting = true; app.quit(); } }
    ])
  );
}

function createSpeedWindow() {
  if (speedWindow && !speedWindow.isDestroyed()) {
    speedWindow.show();
    speedWindow.focus();
    return;
  }
  const { workArea } = screen.getPrimaryDisplay();
  speedWindow = new BrowserWindow({
    width: 310,
    height: 210,
    x: workArea.x + workArea.width - 326,
    y: workArea.y + 18,
    alwaysOnTop: true,
    frame: false,
    resizable: false,
    skipTaskbar: true,
    icon: appIcon,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  speedWindow.loadFile(path.join(__dirname, 'renderer', 'speed.html'));
  speedWindow.on('closed', () => { speedWindow = null; });
}

// Watchdog: every few seconds, re-apply the hosts block. This defeats
// someone manually editing the hosts file back while a lock is active.
function startWatchdog() {
  clearInterval(watchdogTimer);
  watchdogTimer = setInterval(() => {
    const data = store.load();
    const temporary = data.temporaryUnblock || {};
    if (temporary.until && Date.now() >= new Date(temporary.until).getTime()) {
      delete data.temporaryUnblock;
      store.save(data);
    }
    if (data.blockedSites.length > 0 || lockManager.isLocked(data.lock)) {
      const allowedSites = data.allowedSites || [];
      try {
        hosts.applyBlockedSites(effectiveBlockedSites(data));
      } catch (error) {
        console.error('Watchdog could not apply website blocks:', error.message);
      }
    }
  }, 5000);
}

function updateSites(sites) {
  sites = normalizeList(sites);
  const data = store.load();
  data.blockedSites = sites;
  store.save(data);
  hosts.applyBlockedSites(effectiveBlockedSites(data));
  recordActivity('Website block list updated', `${sites.length} site${sites.length === 1 ? '' : 's'}`);
  return data;
}

function effectiveBlockedApps(data) {
  const temporary = data.temporaryUnblock || {};
  const active = temporary.until && Date.now() < new Date(temporary.until).getTime();
  const excluded = new Set(active ? (temporary.apps || []).map((app) => app.toLowerCase()) : []);
  return (data.blockedApps || []).filter((app) => !excluded.has(app.toLowerCase()));
}

function refreshScheduledRestrictions() {
  const data = store.load();
  const active = scheduleManager.activeSchedules(data.schedules || []);
  const scheduledLock = data.lock?.source === 'schedule';
  if (active.length) {
    const endDate = active.reduce((latest, item) => item.window.endDate > latest ? item.window.endDate : latest, active[0].window.endDate);
    data.lock = { active: true, unlockAt: endDate.toISOString(), source: 'schedule' };
    store.save(data);
    return;
  }
  if (scheduledLock) {
    data.lock = { active: false, unlockAt: null };
    store.save(data);
  }
}

function startScheduleWatcher() {
  clearInterval(scheduleTimer);
  refreshScheduledRestrictions();
  scheduleTimer = setInterval(refreshScheduledRestrictions, 30000);
  scheduleTimer.unref();
}

function updateAllowedSites(sites) {
  sites = normalizeList(sites);
  const data = store.load();
  data.allowedSites = sites;
  store.save(data);
  hosts.applyBlockedSites(effectiveBlockedSites(data));
  return data;
}

function effectiveBlockedSites(data) {
  const allowed = new Set((data.allowedSites || []).map((site) => site.toLowerCase()));
  const temporary = data.temporaryUnblock || {};
  const active = temporary.until && Date.now() < new Date(temporary.until).getTime();
  const excluded = new Set(active ? (temporary.sites || []).map((site) => site.toLowerCase()) : []);
  return (data.blockedSites || []).filter((site) => !allowed.has(site.toLowerCase()) && !excluded.has(site.toLowerCase()));
}

function reportHostsPermissionError(error) {
  console.error('Website blocking requires Administrator permission:', error.message);
  if (!isBackgroundAgent && mainWindow && !mainWindow.isDestroyed()) {
    dialog.showMessageBox(mainWindow, {
      type: 'warning',
      title: 'Administrator permission required',
      message: 'Website blocking is not active.',
      detail: 'Run the terminal as Administrator and start the app again, or use the installed version which requests Administrator permission.'
    });
  }
}

function updateApps(appsList) {
  appsList = normalizeList(appsList);
  const data = store.load();
  data.blockedApps = appsList;
  store.save(data);
  recordActivity('Application block list updated', `${appsList.length} app${appsList.length === 1 ? '' : 's'}`);
  return data;
}

function startLock(minutes, password) {
  minutes = normalizeDuration(minutes);
  const data = store.load();
  data.lock = lockManager.startLock(minutes, password);
  store.save(data);
  recordActivity('Focus lock started', `${minutes} minute session`);
  return data;
}

function recordActivity(title, detail) {
  const data = store.load();
  data.activity = Array.isArray(data.activity) ? data.activity : [];
  data.activity.unshift({ id: crypto.randomUUID(), timestamp: new Date().toISOString(), title, detail });
  data.activity = data.activity.slice(0, 100);
  store.save(data);
}

function getActivity() {
  return store.load().activity || [];
}

function normalizedDeviceMac(mac) {
  const value = String(mac || '').replace(/[:-]/g, '').toLowerCase();
  return /^[\da-f]{12}$/.test(value) ? value : null;
}

function mergeNetworkGroup(group) {
  if (!group || !group.id || !group.name || !Array.isArray(group.devices)) throw new Error('Invalid network group.');
  const data = store.load();
  data.network = data.network || {};
  const groups = Array.isArray(data.network.groups) ? data.network.groups : [];
  const index = groups.findIndex((item) => item.id === group.id);
  if (index === -1) groups.push(group);
  else {
    const existing = groups[index];
    const deviceKey = (device) => normalizedDeviceMac(device.mac) || device.ip;
    const devices = new Map((existing.devices || []).map((device) => [deviceKey(device), device]));
    group.devices.forEach((device) => devices.set(deviceKey(device), { ...devices.get(deviceKey(device)), ...device }));
    groups[index] = { ...existing, name: group.name, devices: [...devices.values()] };
  }
  data.network.groups = groups;
  store.save(data);
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('network-groups-updated');
  return groups;
}

if (!hasSingleInstanceLock) {
  app.quit();
} else {
app.on('second-instance', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.show();
  mainWindow.focus();
});

app.whenReady().then(() => {
  if (process.platform === 'win32') app.setAppUserModelId('com.jimmy.lockdownblocker');
  Menu.setApplicationMenu(null);
  configureWindowsStartup();
  if (!isBackgroundAgent) {
    createWindow();
    configureAutoUpdates();
    createTray();
  }
  startWatchdog();
  startScheduleWatcher();

  const data = store.load();
  try {
    hosts.applyBlockedSites(effectiveBlockedSites(data));
  } catch (error) {
    reportHostsPermissionError(error);
  }
  appBlocker.startAppBlocking(() => effectiveBlockedApps(store.load()));
  if (data.network?.agentEnabled !== false) {
    networkAgent.startNetworkAgent({
      getData: store.load,
      getNetworkGroups: () => store.load().network?.groups || [],
      updateSites,
      updateApps,
      startLock,
      getActivity,
      mergeNetworkGroup,
      recordActivity,
      updateNetworkSecurity,
      certificateDirectory: path.join(store.DATA_DIR, 'agent-certificate'),
      port: data.network?.port || networkAgent.DEFAULT_PORT
    }).catch((error) => console.error('Network agent failed to start:', error.message));
    windowsPermissions.ensurePrivateNetworkAccess(data.network?.port || networkAgent.DEFAULT_PORT, data.network?.allowedControllerIps || [])
      .then((result) => console.log(result.created ? `Private network firewall rule created (remoteip=${result.remoteIp}).` : 'Private network firewall rule ready.'))
      .catch((error) => console.error('Private network firewall rule unavailable:', error.message));
  }
  if (!isBackgroundAgent) {
    if (usesBootAgent) {
      windowsPermissions.ensureBootAgent(process.execPath)
        .then(() => console.log('Boot-time background agent is ready.'))
        .catch((error) => console.error('Boot-time background agent unavailable:', error.message));
    }
  }
});
}

app.on('window-all-closed', () => {
  // Do nothing on Windows — keep running in tray so the block persists.
});

// ---------- IPC handlers (renderer <-> main) ----------

ipcMain.handle('get-data', () => store.load());

ipcMain.handle('get-app-version', () => app.getVersion());

ipcMain.handle('get-update-status', () => updateState);

ipcMain.handle('set-automatic-updates', (_evt, enabled) => {
  automaticUpdates = Boolean(enabled);
  const data = store.load();
  data.updates = { ...(data.updates || {}), automatic: automaticUpdates };
  store.save(data);
  updateState.automaticUpdates = automaticUpdates;
  return updateState;
});

ipcMain.handle('check-for-updates', () => checkForUpdates());

ipcMain.handle('download-update', async () => {
  if (!app.isPackaged) return updateState;
  try {
    sendUpdateStatus('downloading', { progress: 0, message: 'Downloading update...' });
    await autoUpdater.downloadUpdate();
  } catch (error) {
    sendUpdateStatus('error', { message: error.message });
  }
  return updateState;
});

ipcMain.handle('install-update', () => {
  if (!app.isPackaged || !updateState.downloaded) return false;
  isQuitting = true;
  autoUpdater.quitAndInstall(false, true);
  return true;
});

ipcMain.handle('update-sites', (_evt, sites) => {
  return updateSites(sites);
});

ipcMain.handle('update-apps', (_evt, appsList) => {
  return updateApps(appsList);
});

ipcMain.handle('update-allowed-sites', (_evt, sites) => updateAllowedSites(sites));

ipcMain.handle('start-lock', (_evt, { minutes, password }) => {
  return startLock(minutes, password);
});

ipcMain.handle('get-lock-status', () => {
  const data = store.load();
  return {
    locked: lockManager.isLocked(data.lock),
    remainingMs: lockManager.timeRemainingMs(data.lock)
  };
});

ipcMain.handle('get-schedules', () => store.load().schedules || []);

ipcMain.handle('save-schedule', (_evt, schedule) => {
  const start = scheduleManager.parseTime(schedule?.start);
  const end = scheduleManager.parseTime(schedule?.end);
  const days = Array.isArray(schedule?.days) ? [...new Set(schedule.days.map(Number).filter((day) => day >= 0 && day <= 6))] : [];
  if (!schedule?.name || start === null || end === null || start === end || !days.length) {
    throw new Error('Schedule needs a name, different start/end times, and at least one day.');
  }
  const data = store.load();
  const schedules = Array.isArray(data.schedules) ? data.schedules : [];
  const cleaned = { id: schedule.id || crypto.randomUUID(), name: String(schedule.name).trim().slice(0, 50), start: schedule.start, end: schedule.end, days, enabled: schedule.enabled !== false };
  const index = schedules.findIndex((item) => item.id === cleaned.id);
  if (index >= 0) schedules[index] = cleaned;
  else schedules.push(cleaned);
  data.schedules = schedules;
  store.save(data);
  refreshScheduledRestrictions();
  return schedules;
});

ipcMain.handle('delete-schedule', (_evt, id) => {
  const data = store.load();
  data.schedules = (data.schedules || []).filter((schedule) => schedule.id !== id);
  store.save(data);
  refreshScheduledRestrictions();
  return data.schedules;
});

ipcMain.handle('temporary-unblock', (_evt, { minutes, sites, apps }) => {
  const duration = normalizeDuration(minutes);
  const data = store.load();
  data.temporaryUnblock = { until: new Date(Date.now() + duration * 60000).toISOString(), sites: normalizeList(sites || []), apps: normalizeList(apps || []).map((app) => app.toLowerCase()) };
  store.save(data);
  hosts.applyBlockedSites(effectiveBlockedSites(data));
  return data.temporaryUnblock;
});

ipcMain.handle('clear-temporary-unblock', () => {
  const data = store.load();
  delete data.temporaryUnblock;
  store.save(data);
  hosts.applyBlockedSites(effectiveBlockedSites(data));
  return true;
});

ipcMain.handle('remote-command', (_evt, { host, password, command, payload, role }) =>
  remoteCommand(host, password || 'no-password', command, payload, role)
);

ipcMain.handle('discover-network', () => networkDiscovery.discoverNetwork({ port: store.load().network?.port || networkAgent.DEFAULT_PORT }));

ipcMain.handle('network-speed-test', (event) => networkSpeedTest.measureNetworkSpeed({
  onStage: (stage) => event.sender.send('network-speed-stage', stage)
}));

ipcMain.handle('get-network-groups', () => store.load().network?.groups || []);

// This sets the password THIS PC's agent expects from a controller. The
// same password must be set on every PC in the lab for the shared-password
// model to work; it is stored only as a scrypt hash, never in plain text.
ipcMain.handle('set-agent-password', (_evt, password) => {
  const hash = networkAgent.hashPassword(password);
  if (!hash) throw new Error('Network password must be at least 12 characters.');
  const data = store.load();
  data.network = data.network || {};
  data.network.passwordHash = hash;
  store.save(data);
  recordActivity('Agent password changed', 'Local device');
  return { configured: true };
});

ipcMain.handle('get-agent-security-status', () => {
  const data = store.load();
  return {
    passwordConfigured: Boolean(data.network?.passwordHash),
    allowedControllerIps: data.network?.allowedControllerIps || [],
    allowLegacyPassword: data.network?.allowLegacyPassword !== false,
    enrolledControllerCount: (data.network?.enrolledControllers || []).length
  };
});

// This PC's own identity when it acts as a controller. Only the id and
// public key ever go to the renderer or over the network — the private
// key stays in the store file and this process.
ipcMain.handle('get-controller-identity', () => {
  const identity = getOrCreateControllerIdentity();
  return { id: identity.id, publicKey: identity.publicKey };
});

// Generates a pairing code on THIS PC (the target being enrolled onto).
// Must be triggered by someone at this machine's own app — it is never
// reachable as a network command.
ipcMain.handle('generate-pairing-code', () => networkAgent.startPairing());

ipcMain.handle('get-pairing-status', () => networkAgent.pairingStatus());

ipcMain.handle('cancel-pairing', () => {
  networkAgent.clearPairing();
  return { active: false };
});

// Controller-side: enroll THIS PC onto a target device using a code shown
// on that target's own screen.
ipcMain.handle('enroll-controller', (_evt, { host, code, label, role }) =>
  enrollWithController(host, code, label, role)
);

// The signed-request path for a PC that has already been enrolled
// elsewhere. Renderer call sites can switch to this once enrollment is
// confirmed working; the legacy remote-command path keeps working
// alongside it during migration.
ipcMain.handle('remote-command-signed', (_evt, { host, command, payload }) =>
  remoteCommandSigned(host, command, payload)
);

ipcMain.handle('get-enrolled-controllers', () => {
  const data = store.load();
  // publicKey is not secret, but there's no reason to ship it to the
  // renderer for a list view — trim it down to what the UI needs.
  return (data.network?.enrolledControllers || []).map(({ id, label, role, enrolledAt }) => ({ id, label, role, enrolledAt }));
});

ipcMain.handle('remove-enrolled-controller', (_evt, id) => {
  const data = store.load();
  const before = (data.network?.enrolledControllers || []).length;
  data.network = data.network || {};
  data.network.enrolledControllers = (data.network.enrolledControllers || []).filter((c) => c.id !== id);
  store.save(data);
  if (data.network.enrolledControllers.length < before) recordActivity('Enrolled controller removed', id);
  return data.network.enrolledControllers.map(({ id: cid, label, role, enrolledAt }) => ({ id: cid, label, role, enrolledAt }));
});

// Once every controller that needs access to this PC is enrolled, the
// shared password can be retired here so a leaked password alone stops
// being enough to reach this specific device.
ipcMain.handle('set-allow-legacy-password', (_evt, allowed) => {
  const data = store.load();
  data.network = data.network || {};
  data.network.allowLegacyPassword = Boolean(allowed);
  store.save(data);
  recordActivity(allowed ? 'Legacy shared password re-enabled' : 'Legacy shared password disabled', 'Local device');
  return { allowLegacyPassword: data.network.allowLegacyPassword };
});

// Controls which IPs the Windows firewall lets reach this PC's agent port
// at all. An empty list means loopback-only (see windowsPermissions.js) —
// nothing on the LAN can reach it until at least one controller IP is added.
ipcMain.handle('update-allowed-controllers', async (_evt, ips) => {
  const cleaned = normalizeIpList(ips || []);
  const data = store.load();
  data.network = data.network || {};
  data.network.allowedControllerIps = cleaned;
  store.save(data);
  recordActivity('Allowed controller list updated', `${cleaned.length} IP${cleaned.length === 1 ? '' : 's'}`);
  try {
    const result = await windowsPermissions.ensurePrivateNetworkAccess(data.network?.port || networkAgent.DEFAULT_PORT, cleaned);
    return { allowedControllerIps: cleaned, firewall: result };
  } catch (error) {
    return { allowedControllerIps: cleaned, firewall: { supported: false, error: error.message } };
  }
});

ipcMain.handle('delete-network-group', (_evt, groupId) => {
  const data = store.load();
  data.network = data.network || { groups: [] };
  data.network.groups = (data.network.groups || []).filter((group) => group.id !== groupId);
  store.save(data);
  return data.network.groups;
});

ipcMain.handle('save-network-group', (_evt, group) => {
  const data = store.load();
  data.network = data.network || { groups: [] };
  const groups = data.network?.groups || [];
  const cleaned = {
    id: group.id || crypto.randomUUID(),
    name: String(group.name || '').trim().slice(0, 50),
    devices: Array.isArray(group.devices) ? group.devices : []
  };
  if (!cleaned.name) throw new Error('Group name is required.');
  const existing = groups.findIndex((item) => item.id === cleaned.id);
  if (existing >= 0) groups[existing] = cleaned;
  else groups.push(cleaned);
  data.network.groups = groups;
  store.save(data);
  return groups;
});
