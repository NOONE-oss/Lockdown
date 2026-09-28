const assert = require('node:assert/strict');
const test = require('node:test');

const { normalizeList, normalizeDuration, normalizeIpList } = require('../src/inputValidation');

test('normalizeList removes blank, non-text, and duplicate entries', () => {
  assert.deepEqual(normalizeList([' https://www.youtube.com/shorts ', '', 'youtube.com', null, 'reddit.com']), [
    'youtube.com',
    'reddit.com'
  ]);
});

test('normalizeList rejects non-lists', () => {
  assert.throws(() => normalizeList('youtube.com'), /Expected a list/);
});

test('normalizeDuration accepts whole minutes in the MVP range', () => {
  assert.equal(normalizeDuration('15.9'), 15);
});

test('normalizeDuration rejects invalid or excessive values', () => {
  assert.throws(() => normalizeDuration(0), /between 1 and 1440/);
  assert.throws(() => normalizeDuration(1441), /between 1 and 1440/);
});

test('normalizeIpList dedupes and trims valid IPv4 addresses', () => {
  assert.deepEqual(normalizeIpList([' 192.168.1.10 ', '192.168.1.10', '192.168.1.11']), ['192.168.1.10', '192.168.1.11']);
});

test('normalizeIpList rejects anything that is not a valid IPv4 address', () => {
  assert.throws(() => normalizeIpList(['192.168.1.999']), /Not a valid IPv4/);
  assert.throws(() => normalizeIpList(['not-an-ip']), /Not a valid IPv4/);
  assert.throws(() => normalizeIpList(['localsubnet']), /Not a valid IPv4/);
});

test('normalizeIpList rejects non-lists', () => {
  assert.throws(() => normalizeIpList('192.168.1.10'), /Expected a list/);
});