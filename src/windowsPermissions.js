const { execFile } = require('child_process');

const FIREWALL_RULE_NAME = 'Lockdown Blocker Agent';
const BOOT_TASK_NAME = 'Lockdown Blocker Background Agent';

function run(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { windowsHide: true }, (error, stdout, stderr) => {
      if (error) reject(new Error(stderr || error.message));
      else resolve(stdout);
    });
  });
}

// allowedIps: list of controller IPs approved to reach the agent port.
// Deliberately does NOT default to 'localsubnet' — on a flat lab network,
// that would let any student PC on the same subnet reach every other PC's
// agent port. With no controller IPs configured yet, the rule restricts to
// loopback only, so the agent is reachable locally but not over the LAN
// until at least one controller is explicitly allowed.
async function ensurePrivateNetworkAccess(port, allowedIps = []) {
  if (process.platform !== 'win32') return { supported: false };
  const remoteIp = Array.isArray(allowedIps) && allowedIps.length ? allowedIps.join(',') : '127.0.0.1';
  await run('netsh', ['advfirewall', 'firewall', 'delete', 'rule', `name=${FIREWALL_RULE_NAME}`]).catch(() => {});
  await run('netsh', [
    'advfirewall', 'firewall', 'add', 'rule',
    `name=${FIREWALL_RULE_NAME}`,
    'dir=in', 'action=allow', 'protocol=TCP', `localport=${port}`,
    'profile=any', `remoteip=${remoteIp}`, 'enable=yes'
  ]);
  return { supported: true, created: true, remoteIp };
}

async function ensureBootAgent(executablePath) {
  if (process.platform !== 'win32') return { supported: false };
  if (!executablePath) throw new Error('Lockdown executable path is required for the boot agent.');

  // Run at machine boot as SYSTEM before any Windows account signs in. /F refreshes
  // the executable path after an application update.
  const taskCommand = `"${executablePath}" --background-agent`;
  await run('schtasks', [
    '/Create', '/TN', BOOT_TASK_NAME, '/TR', taskCommand,
    '/SC', 'ONSTART', '/RU', 'SYSTEM', '/RL', 'HIGHEST', '/F'
  ]);
  await run('schtasks', ['/Run', '/TN', BOOT_TASK_NAME]);
  return { supported: true, created: true };
}

module.exports = { ensurePrivateNetworkAccess, ensureBootAgent, FIREWALL_RULE_NAME, BOOT_TASK_NAME };