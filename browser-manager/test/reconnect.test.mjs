import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createReconnectLoop } from '../lib/reconnect.mjs';

function fixture(t, active = true) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const delays = [];
  let retries = 0;
  const loop = createReconnectLoop(() => retries++, value => delays.push(value), active);
  t.after(() => loop.dispose());
  return { loop, delays, retries: () => retries, tick: ms => t.mock.timers.tick(ms) };
}

test('failed connections retry after 1, 2, 4, 8, 10, 10 seconds', t => {
  const { loop, delays, retries, tick } = fixture(t);
  let expected = 0;
  for (const seconds of [1, 2, 4, 8, 10, 10]) {
    loop.disconnected();
    assert.equal(delays.at(-1), seconds);
    tick(seconds * 1000 - 1);
    assert.equal(retries(), expected);
    tick(1);
    assert.equal(retries(), ++expected);
    assert.equal(delays.at(-1), null);
  }
});

test('repeated disconnect events do not duplicate or postpone a pending retry', t => {
  const { loop, retries, tick } = fixture(t);
  loop.disconnected(); tick(500); loop.disconnected();
  tick(499); assert.equal(retries(), 0);
  tick(1); assert.equal(retries(), 1);
  tick(5000); assert.equal(retries(), 1);
});

test('a successful connection cancels pending work and resets the backoff', t => {
  const { loop, delays, retries, tick } = fixture(t);
  loop.disconnected(); tick(1000);
  loop.disconnected(); assert.equal(delays.at(-1), 2);
  loop.connected(); assert.equal(delays.at(-1), null);
  tick(10_000); assert.equal(retries(), 1);
  loop.disconnected(); assert.equal(delays.at(-1), 1);
  tick(1000); assert.equal(retries(), 2);
});

test('inactive pages do no work; resuming reconnects even a previously healthy socket', t => {
  const { loop, delays, retries, tick } = fixture(t, false);
  loop.disconnected(); loop.retry(); tick(60_000);
  assert.equal(retries(), 0);
  assert(delays.every(value => value === null));
  loop.setActive(true); assert.equal(retries(), 1);
  loop.setActive(true); assert.equal(retries(), 1);
  loop.connected(); loop.setActive(false); tick(60_000);
  assert.equal(retries(), 1);
  loop.setActive(true); assert.equal(retries(), 2);
  loop.setActive(true); assert.equal(retries(), 2);
  loop.disconnected(); loop.setActive(false);
  assert.equal(delays.at(-1), null);
  tick(60_000); assert.equal(retries(), 2);
  loop.disconnected(); tick(60_000); assert.equal(retries(), 2);
});

test('manual retry is immediate, cancels its timer, and preserves backoff until connected', t => {
  const { loop, delays, retries, tick } = fixture(t);
  loop.disconnected(); tick(1000);
  loop.disconnected(); assert.equal(delays.at(-1), 2);
  tick(500); loop.retry();
  assert.equal(retries(), 2);
  assert.equal(delays.at(-1), null);
  tick(5000); assert.equal(retries(), 2);
  loop.disconnected(); assert.equal(delays.at(-1), 4);
  loop.connected(); loop.disconnected();
  assert.equal(delays.at(-1), 1);
});

test('dispose cancels retries and makes all later calls inert', t => {
  const { loop, delays, retries, tick } = fixture(t);
  loop.disconnected(); loop.dispose();
  assert.equal(delays.at(-1), null);
  const disposedDelays = [...delays];
  loop.retry(); loop.connected(); loop.disconnected();
  loop.setActive(false); loop.setActive(true); loop.dispose();
  tick(60_000);
  assert.equal(retries(), 0);
  assert.deepEqual(delays, disposedDelays);
});
