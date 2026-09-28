const https = require('https');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');
const selfsigned = require('selfsigned');
const { execFile } = require('child_process');

const DEFAULT_PORT = 47821;
const SHUTDOWN_RESPONSE_DELAY_MS = 1500;
const REQUEST_CLOCK_SKEW_MS = 2 * 60 * 1000;
const REQUEST_ID_TTL_MS = 2 * 60 * 1000;
let server;
const pendingNonces = new Set();
const usedRequestIds = new Map();

// Every command must declare the minimum role allowed to run it. Read-only
// commands need only 'viewer'; commands that change state need 'operator';
// destructive commands (shutdown) need 'admin'. Unlisted commands are
// rejected outright rather than defaulting to open access.
const ROLE_LEVELS = { viewer: 1, operator: 2, admin: 3 };
const COMMAND_MIN_ROLE = {
  'get-data': 'viewer',
  'get-status': 'viewer',
  'get-activity': 'viewer',
  'get-network-groups': 'viewer',
  'update-sites': 'operator',
  'update-apps': 'operator',
  'start-lock': 'operator',
  'merge-network-group': 'operator',
  'shutdown': 'admin'
};

function roleIsSufficient(role, command) {
  const required = COMMAND_MIN_ROLE[command];
  const level = ROLE_LEVELS[role];
  return Boolean(required) && Boolean(level) && level >= ROLE_LEVELS[required];
}

// Constant-time comparison so a mismatched proof can't be distinguished by
// how quickly the server rejects it (timing side-channel).
function proofsMatch(expectedHex, providedHex) {
  if (typeof providedHex !== 'string') return false;
  const expected = Buffer.from(expectedHex, 'hex');
  const provided = Buffer.from(providedHex, 'hex');
  if (expected.length === 0 || expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
}

// ---------- Controller enrollment (Step 2) ----------
//
// The shared password (Step 1) proves "this request came from someone who
// knows the password" — but the password is the same on every PC, so it
// can't say *which* controller, and the role is whatever the client claims.
// Enrollment replaces that with per-device identity: each controller has
// its own Ed25519 key pair, an admin approves it once (via a short-lived
// pairing code entered at the target PC), and the role is then fixed by
// what the admin assigned at enrollment time — not self-declared per
// request. The shared password remains available as a fallback during
// migration (see allowLegacyPassword) but enrolled controllers never need
// it, and their role can't be spoofed by a stolen password alone.

const PAIRING_TTL_MS = 10 * 60 * 1000;
const PAIRING_MAX_ATTEMPTS = 8;
const PAIRING_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // no 0/O/1/I — read aloud without ambiguity
const VALID_ROLES = new Set(['viewer', 'operator', 'admin']);
let pendingPairing = null; // { code, expiresAt, attempts } — in memory only, never persisted

function generateControllerIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { id: fingerprintPublicKey(publicKey), publicKey, privateKey };
}

function fingerprintPublicKey(publicKeyPem) {
  return crypto.createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 16);
}

// Deliberately does NOT include role: for an enrolled controller, role comes
// from the agent's own stored enrollment record, never from the request.
function canonicalSignedRequest({ nonce, timestamp, requestId, command, payload, controllerId }) {
  return JSON.stringify([nonce, timestamp, requestId, command, payload, controllerId]);
}

function signRequest(privateKeyPem, request) {
  return crypto.sign(null, Buffer.from(canonicalSignedRequest(request)), privateKeyPem).toString('hex');
}

function verifyRequestSignature(publicKeyPem, request, signatureHex) {
  if (typeof signatureHex !== 'string') return false;
  try {
    return crypto.verify(null, Buffer.from(canonicalSignedRequest(request)), publicKeyPem, Buffer.from(signatureHex, 'hex'));
  } catch (_) {
    return false; // malformed key or signature — never throw into the request handler
  }
}

function generatePairingCode() {
  const bytes = crypto.randomBytes(10);
  let code = '';
  for (let i = 0; i < 10; i += 1) code += PAIRING_ALPHABET[bytes[i] % PAIRING_ALPHABET.length];
  return code;
}

// Called locally, by the admin standing at the target PC (or its own admin
// UI) — never over the network. Starting a new pairing invalidates any
// previous one, so only one enrollment can be in progress at a time.
function startPairing() {
  pendingPairing = { code: generatePairingCode(), expiresAt: Date.now() + PAIRING_TTL_MS, attempts: 0 };
  return { code: pendingPairing.code, expiresAt: pendingPairing.expiresAt };
}

function clearPairing() {
  pendingPairing = null;
}

function pairingStatus() {
  if (!pendingPairing || Date.now() >= pendingPairing.expiresAt) return { active: false };
  return { active: true, code: pendingPairing.code, expiresAt: pendingPairing.expiresAt };
}

// Verifies a code against the in-progress pairing, consuming an attempt.
// Too many wrong attempts invalidates the code outright, so a script can't
// grind through the ~50-bit code space by brute force within its 10-minute
// window.
function consumePairingAttempt(code) {
  if (!pendingPairing || Date.now() >= pendingPairing.expiresAt) return false;
  pendingPairing.attempts += 1;
  if (pendingPairing.attempts > PAIRING_MAX_ATTEMPTS) {
    clearPairing();
    return false;
  }
  return typeof code === 'string' && code.toUpperCase() === pendingPairing.code;
}

async function loadCertificate(certificateDirectory) {
  const directory = certificateDirectory || path.join(process.cwd(), '.lockdown-cert');
  const keyPath = path.join(directory, 'agent.key');
  const certPath = path.join(directory, 'agent.crt');
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    return { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  }
  fs.mkdirSync(directory, { recursive: true });
  const generated = await selfsigned.generate([{ name: 'commonName', value: 'Lockdown Blocker Agent' }], {
    keySize: 2048,
    days: 3650,
    algorithm: 'sha256'
  });
  fs.writeFileSync(keyPath, generated.private);
  fs.writeFileSync(certPath, generated.cert);
  return { key: generated.private, cert: generated.cert };
}

function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 12) return null;
  return `scrypt:${crypto.scryptSync(password, 'lockdown-agent-v1', 32).toString('hex')}`;
}

function canonicalRequest({ nonce, timestamp, requestId, command, payload, role }) {
  return JSON.stringify([nonce, timestamp, requestId, command, payload, role]);
}

function createRequestProof(passwordHash, request) {
  return crypto.createHmac('sha256', passwordHash || 'no-password').update(canonicalRequest(request)).digest('hex');
}

function remoteAddress(request) {
  return String(request.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '');
}

function rememberRequestId(requestId) {
  const now = Date.now();
  for (const [id, expiresAt] of usedRequestIds) {
    if (expiresAt <= now) usedRequestIds.delete(id);
  }
  if (usedRequestIds.has(requestId)) return false;
  usedRequestIds.set(requestId, now + REQUEST_ID_TTL_MS);
  return true;
}

function sendJson(response, statusCode, body) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(body));
}

function publicLock(lock) {
  if (!lock) return null;
  return { active: Boolean(lock.active), unlockAt: lock.unlockAt || null };
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) request.destroy();
    });
    request.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); } catch (error) { reject(error); }
    });
    request.on('error', reject);
  });
}

function runShutdown() {
  return new Promise((resolve, reject) => {
    const systemRoot = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
    const shutdownPath = path.join(systemRoot, 'System32', 'shutdown.exe');
    execFile(shutdownPath, ['/s', '/f', '/t', '5'], { windowsHide: true }, (error, stdout, stderr) => {
      if (!error) {
        resolve({ scheduled: true, delaySeconds: 5 });
        return;
      }
      const detail = String(stderr || stdout || error.message || '').trim();
      reject(new Error(detail || `Windows shutdown failed with code ${error.code || 'unknown'}.`));
    });
  });
}

async function startNetworkAgent({ getData, getNetworkGroups, updateSites, updateApps, startLock, getActivity, mergeNetworkGroup, recordActivity, updateNetworkSecurity, certificateDirectory, port = DEFAULT_PORT } = {}) {
  stopNetworkAgent();
  const certificate = await loadCertificate(certificateDirectory);
  server = https.createServer(certificate, async (request, response) => {
    if (request.method === 'GET' && request.url === '/health') {
      sendJson(response, 200, { ok: true, name: 'Lockdown Blocker Agent', hostname: os.hostname() });
      return;
    }

    if (request.method === 'GET' && request.url === '/challenge') {
      const nonce = crypto.randomBytes(32).toString('hex');
      pendingNonces.add(nonce);
      setTimeout(() => pendingNonces.delete(nonce), 30000);
      sendJson(response, 200, { nonce });
      return;
    }

    // Enrollment: bootstraps trust for a new controller WITHOUT the shared
    // password, using a one-time code the admin generated locally at this
    // PC. Someone has to be physically able to click "Generate pairing
    // code" in this PC's own app for enrollment to succeed at all.
    if (request.method === 'POST' && request.url === '/enroll') {
      try {
        const body = await readBody(request);
        const address = remoteAddress(request);
        if (!consumePairingAttempt(body.code)) {
          if (recordActivity) recordActivity('Controller enrollment rejected (bad or expired code)', address);
          sendJson(response, 401, { error: 'Invalid or expired pairing code.' });
          return;
        }
        const publicKey = String(body.controllerPublicKey || '');
        const claimedId = String(body.controllerId || '');
        if (!publicKey.includes('BEGIN PUBLIC KEY') || fingerprintPublicKey(publicKey) !== claimedId) {
          sendJson(response, 400, { error: 'Malformed controller identity.' });
          return;
        }
        const role = VALID_ROLES.has(body.role) ? body.role : 'viewer';
        const label = String(body.label || 'Unnamed controller').trim().slice(0, 80) || 'Unnamed controller';
        const existing = ((getData().network || {}).enrolledControllers || []).filter((c) => c.id !== claimedId);
        const entry = { id: claimedId, publicKey, label, role, enrolledAt: new Date().toISOString() };
        if (updateNetworkSecurity) updateNetworkSecurity({ enrolledControllers: [...existing, entry] });
        clearPairing();
        if (recordActivity) recordActivity(`Controller enrolled: ${label} (${role})`, address);
        sendJson(response, 200, { ok: true, data: { id: claimedId, role, label } });
      } catch (error) {
        sendJson(response, 500, { error: error.message });
      }
      return;
    }

    if (request.method !== 'POST' || request.url !== '/command') {
      sendJson(response, 404, { error: 'Not found' });
      return;
    }

    try {
      const body = await readBody(request);
      const address = remoteAddress(request);

      const timestamp = Number(body.timestamp);
      const validTimestamp = Number.isSafeInteger(timestamp) && Math.abs(Date.now() - timestamp) <= REQUEST_CLOCK_SKEW_MS;
      const validRequestId = typeof body.requestId === 'string' && body.requestId.length >= 16 && body.requestId.length <= 100;
      const validNonce = pendingNonces.has(body.nonce);
      const validRequest = validTimestamp && validRequestId && rememberRequestId(body.requestId);
      if (!validNonce || !validRequest) {
        if (recordActivity) recordActivity('Agent request rejected (malformed request)', address);
        sendJson(response, 401, { error: 'Request validation failed' });
        return;
      }
      pendingNonces.delete(body.nonce);

      const network = getData().network || {};
      let role;

      if (body.controllerId) {
        // Enrolled-controller path: role comes from the stored enrollment
        // record for this specific controller id, never from the request.
        const controller = (network.enrolledControllers || []).find((c) => c.id === body.controllerId);
        if (!controller) {
          if (recordActivity) recordActivity('Agent request rejected (unknown controller)', address);
          sendJson(response, 401, { error: 'This controller is not enrolled on this device.' });
          return;
        }
        const signedRequest = {
          nonce: body.nonce,
          timestamp: body.timestamp,
          requestId: body.requestId,
          command: body.command,
          payload: body.payload === undefined ? null : body.payload,
          controllerId: body.controllerId
        };
        if (!verifyRequestSignature(controller.publicKey, signedRequest, body.signature)) {
          if (recordActivity) recordActivity(`Agent request rejected (bad signature for ${controller.label})`, address);
          sendJson(response, 401, { error: 'Authentication failed.' });
          return;
        }
        role = controller.role;
      } else {
        // Legacy shared-password path (Step 1). Kept for gradual migration;
        // can be switched off per device once every controller that talks
        // to it is enrolled (see allowLegacyPassword).
        if (network.allowLegacyPassword === false) {
          if (recordActivity) recordActivity('Agent request rejected (legacy password disabled)', address);
          sendJson(response, 403, { error: 'This device only accepts enrolled controllers now.' });
          return;
        }
        const passwordHash = network.passwordHash || null;
        if (!passwordHash) {
          if (recordActivity) recordActivity('Agent request rejected (no agent password configured)', address);
          sendJson(response, 403, { error: 'This device has no agent password configured yet. Set one before sending commands.' });
          return;
        }
        const expectedProof = createRequestProof(passwordHash, {
          nonce: body.nonce,
          timestamp: body.timestamp,
          requestId: body.requestId,
          command: body.command,
          payload: body.payload === undefined ? null : body.payload,
          role: body.role
        });
        if (!proofsMatch(expectedProof, body.proof)) {
          if (recordActivity) recordActivity('Agent request rejected (invalid password)', address);
          sendJson(response, 401, { error: 'Authentication failed.' });
          return;
        }
        role = body.role;
      }

      // Role check applies identically to both paths above; only where the
      // role itself came from differs.
      if (!Object.prototype.hasOwnProperty.call(COMMAND_MIN_ROLE, body.command)) {
        sendJson(response, 400, { error: 'Unknown command' });
        return;
      }
      if (!roleIsSufficient(role, body.command)) {
        if (recordActivity) recordActivity(`Agent request rejected (role '${role}' cannot run '${body.command}')`, address);
        sendJson(response, 403, { error: `The '${role}' role is not allowed to run '${body.command}'.` });
        return;
      }

      if (body.command === 'shutdown') {
        sendJson(response, 202, { ok: true, data: { scheduled: true, delaySeconds: 5 } });
        response.once('finish', () => {
          setTimeout(() => {
            runShutdown().catch((error) => {
              if (recordActivity) recordActivity(`Shutdown failed: ${error.message}`);
            });
          }, SHUTDOWN_RESPONSE_DELAY_MS).unref();
        });
        return;
      }

      let result;
      if (body.command === 'get-data') {
        const data = getData();
        result = { blockedSites: data.blockedSites, blockedApps: data.blockedApps, lock: publicLock(data.lock) };
      }
      else if (body.command === 'get-network-groups') result = getNetworkGroups ? getNetworkGroups() : [];
      else if (body.command === 'update-sites') result = updateSites(body.payload || []);
      else if (body.command === 'update-apps') result = updateApps(body.payload || []);
      else if (body.command === 'start-lock') {
        const payload = body.payload || {};
        result = startLock(payload.minutes, payload.password);
      }
      else if (body.command === 'merge-network-group') result = mergeNetworkGroup(body.payload || {});
      else if (body.command === 'get-status') result = { online: true, hostname: os.hostname(), platform: process.platform, lock: publicLock(getData().lock) };
      else if (body.command === 'get-activity') result = { hostname: os.hostname(), entries: getActivity ? getActivity() : [] };
      else {
        sendJson(response, 400, { error: 'Unknown command' });
        return;
      }
      sendJson(response, 200, { ok: true, data: result });
    } catch (error) {
      sendJson(response, 500, { error: error.message });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
    server.listen(port, '0.0.0.0');
  }).catch((error) => {
    server = null;
    throw new Error(`Network agent could not listen on port ${port}: ${error.message}`);
  });
  return port;
}

function stopNetworkAgent() {
  if (server) server.close();
  server = null;
}

module.exports = {
  startNetworkAgent,
  stopNetworkAgent,
  hashPassword,
  canonicalRequest,
  createRequestProof,
  loadCertificate,
  DEFAULT_PORT,
  ROLE_LEVELS,
  COMMAND_MIN_ROLE,
  roleIsSufficient,
  proofsMatch,
  generateControllerIdentity,
  fingerprintPublicKey,
  canonicalSignedRequest,
  signRequest,
  verifyRequestSignature,
  generatePairingCode,
  startPairing,
  clearPairing,
  pairingStatus,
  consumePairingAttempt,
  VALID_ROLES
};