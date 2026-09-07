import assert from 'node:assert/strict';
import { test } from 'node:test';
import { watchVncQuality } from '../lib/vnc-quality.mjs';

const freshClient = () => ({ qualityLevel: 6, compressionLevel: 2 });
const high = { qualityLevel: 9, compressionLevel: 2 };
const constrained = { qualityLevel: 6, compressionLevel: 6 };

test('missing Network Information API favors quality, including Safari', () => {
  const client = freshClient();
  const stop = watchVncQuality(client);
  assert.deepEqual(client, high);
  stop();
});

test('Data Saver, slow connection classes, or positive downlink below 2 Mbps reduce quality', () => {
  for (const hints of [
    { saveData: true },
    ...['slow-2g', '2g', '3g'].map(effectiveType => ({ effectiveType })),
    { downlink: 0.025 }, { downlink: 1.999 },
    { effectiveType: '4g', downlink: 1 },
  ]) {
    const client = freshClient();
    const stop = watchVncQuality(client, hints);
    assert.deepEqual(client, constrained, JSON.stringify(hints));
    stop();
  }
});

test('unknown or invalid hints do not needlessly downgrade quality; 2 Mbps is sufficient', () => {
  for (const hints of [
    {}, { effectiveType: 'unknown' }, { effectiveType: '4g', saveData: false },
    ...[2, 10, 0, -1, NaN, Infinity, '1', undefined].map(downlink => ({ downlink })),
  ]) {
    const client = freshClient();
    const stop = watchVncQuality(client, hints);
    assert.deepEqual(client, high, String(hints.downlink ?? hints.effectiveType));
    stop();
  }
});

test('connection change events lower and restore settings on the same client', () => {
  const connection = Object.assign(new EventTarget(), { effectiveType: '4g', downlink: 10, saveData: false });
  const client = freshClient();
  const stop = watchVncQuality(client, connection);
  assert.deepEqual(client, high);
  connection.saveData = true;
  connection.dispatchEvent(new Event('change'));
  assert.deepEqual(client, constrained);
  connection.saveData = false;
  connection.dispatchEvent(new Event('change'));
  assert.deepEqual(client, high);
  connection.downlink = 1;
  connection.dispatchEvent(new Event('change'));
  assert.deepEqual(client, constrained);
  connection.downlink = 10;
  connection.dispatchEvent(new Event('change'));
  assert.deepEqual(client, high);
  stop();
});

test('cleanup detaches the old client before reconnect installs a new listener', () => {
  const connection = Object.assign(new EventTarget(), { saveData: true });
  const oldClient = freshClient();
  const stopOld = watchVncQuality(oldClient, connection);
  assert.deepEqual(oldClient, constrained);
  stopOld(); stopOld();
  connection.saveData = false;
  const newClient = freshClient();
  const stopNew = watchVncQuality(newClient, connection);
  connection.dispatchEvent(new Event('change'));
  assert.deepEqual(oldClient, constrained);
  assert.deepEqual(newClient, high);
  stopNew();
  connection.saveData = true;
  connection.dispatchEvent(new Event('change'));
  assert.deepEqual(newClient, high);
});
