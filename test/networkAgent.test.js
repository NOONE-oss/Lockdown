const assert = require('node:assert/strict');
const test = require('node:test');
const { createRequestProof, hashPassword, roleIsSufficient, proofsMatch, COMMAND_MIN_ROLE,
  generateControllerIdentity, fingerprintPublicKey, signRequest, verifyRequestSignature,
  generatePairingCode, startPairing, clearPairing, pairingStatus, consumePairingAttempt } = require('../src/networkAgent');

test('request proof covers command, payload, role, and request metadata', () => {
  const base = {
    nonce: 'nonce',
    timestamp: 1700000000000,
    requestId: 'request-id-12345678',
    command: 'update-sites',
    payload: ['example.com'],
    role: 'operator'
  };
  const proof = createRequestProof(hashPassword('test-password'), base);
  assert.notEqual(proof, createRequestProof(hashPassword('test-password'), { ...base, command: 'shutdown', role: 'admin' }));
  assert.notEqual(proof, createRequestProof(hashPassword('test-password'), { ...base, payload: ['other.example'] }));
  assert.notEqual(proof, createRequestProof(hashPassword('test-password'), { ...base, requestId: 'different-request-123' }));
});

test('a request with the wrong password produces a non-matching proof', () => {
  const base = {
    nonce: 'nonce', timestamp: 1700000000000, requestId: 'request-id-12345678',
    command: 'update-sites', payload: ['example.com'], role: 'operator'
  };
  const correctProof = createRequestProof(hashPassword('correct-password-123'), base);
  const wrongProof = createRequestProof(hashPassword('totally-wrong-pw-99'), base);
  assert.equal(proofsMatch(correctProof, correctProof), true);
  assert.equal(proofsMatch(correctProof, wrongProof), false);
});

test('proofsMatch rejects malformed or missing proofs rather than throwing', () => {
  const expected = createRequestProof(hashPassword('a-password-that-is-long-enough'), { nonce: 'n', timestamp: 1, requestId: 'r', command: 'get-data', payload: null, role: 'viewer' });
  assert.equal(proofsMatch(expected, undefined), false);
  assert.equal(proofsMatch(expected, ''), false);
  assert.equal(proofsMatch(expected, 'not-hex-and-wrong-length'), false);
  assert.equal(proofsMatch(expected, expected.slice(0, -2)), false); // truncated
});

test('hashPassword rejects short passwords so a weak password can never produce a usable hash', () => {
  assert.equal(hashPassword('short'), null);
  assert.equal(hashPassword(''), null);
  assert.equal(hashPassword(undefined), null);
  assert.notEqual(hashPassword('a-password-that-is-long-enough'), null);
});

test('roleIsSufficient enforces the minimum role per command', () => {
  assert.equal(roleIsSufficient('viewer', 'get-data'), true);
  assert.equal(roleIsSufficient('viewer', 'update-sites'), false);
  assert.equal(roleIsSufficient('operator', 'update-sites'), true);
  assert.equal(roleIsSufficient('operator', 'shutdown'), false);
  assert.equal(roleIsSufficient('admin', 'shutdown'), true);
  assert.equal(roleIsSufficient('admin', 'anything-unlisted'), false);
  assert.equal(roleIsSufficient(undefined, 'get-data'), false);
});

test('every command handled by the agent has a declared minimum role', () => {
  const handledCommands = ['get-data', 'get-status', 'get-activity', 'get-network-groups', 'update-sites', 'update-apps', 'start-lock', 'merge-network-group', 'shutdown'];
  for (const command of handledCommands) {
    assert.ok(COMMAND_MIN_ROLE[command], `${command} is missing from COMMAND_MIN_ROLE`);
  }
});

// ---------- Step 2: controller enrollment ----------

test('a controller identity fingerprints consistently from its own public key', () => {
  const identity = generateControllerIdentity();
  assert.equal(identity.id, fingerprintPublicKey(identity.publicKey));
  assert.equal(identity.id.length, 16);
  const other = generateControllerIdentity();
  assert.notEqual(identity.id, other.id);
});

test('a signed request verifies against the signer\'s public key and detects tampering', () => {
  const identity = generateControllerIdentity();
  const request = { nonce: 'n', timestamp: Date.now(), requestId: 'request-id-12345678', command: 'update-sites', payload: ['example.com'], controllerId: identity.id };
  const signature = signRequest(identity.privateKey, request);

  assert.equal(verifyRequestSignature(identity.publicKey, request, signature), true);
  assert.equal(verifyRequestSignature(identity.publicKey, { ...request, payload: ['evil.example'] }, signature), false);
  assert.equal(verifyRequestSignature(identity.publicKey, { ...request, command: 'shutdown' }, signature), false);
  assert.equal(verifyRequestSignature(generateControllerIdentity().publicKey, request, signature), false);
});

test('verifyRequestSignature fails safely on malformed or missing signatures rather than throwing', () => {
  const identity = generateControllerIdentity();
  const request = { nonce: 'n', timestamp: 1, requestId: 'r', command: 'get-data', payload: null, controllerId: identity.id };
  assert.doesNotThrow(() => verifyRequestSignature(identity.publicKey, request, 'not-a-real-signature'));
  assert.equal(verifyRequestSignature(identity.publicKey, request, 'not-a-real-signature'), false);
  assert.equal(verifyRequestSignature(identity.publicKey, request, undefined), false);
});

test('generatePairingCode produces fixed-length codes from an unambiguous alphabet', () => {
  const code = generatePairingCode();
  assert.equal(code.length, 10);
  assert.match(code, /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{10}$/);
});

test('pairing accepts the correct code while active and rejects a wrong one', () => {
  clearPairing();
  const { code } = startPairing();
  assert.equal(pairingStatus().active, true);
  assert.equal(consumePairingAttempt('WRONG-CODE'), false);
  assert.equal(consumePairingAttempt(code), true);
  clearPairing();
});

test('too many wrong attempts invalidates the pairing code entirely', () => {
  clearPairing();
  const { code } = startPairing();
  for (let i = 0; i < 9; i += 1) consumePairingAttempt('WRONG-CODE');
  // Even the correct code no longer works once the attempt budget is spent.
  assert.equal(consumePairingAttempt(code), false);
  assert.equal(pairingStatus().active, false);
});

test('pairingStatus reports inactive when nothing has been started', () => {
  clearPairing();
  assert.deepEqual(pairingStatus(), { active: false });
});