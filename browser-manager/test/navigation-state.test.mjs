import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNavigationState } from '../lib/navigation-state.mjs';

function fixture(t) {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const reads = [], values = [];
  const loop = createNavigationState(signal => {
    const pending = { ...Promise.withResolvers(), signal };
    reads.push(pending);
    return pending.promise;
  }, value => values.push(value));
  t.after(() => loop.dispose());
  return { loop, reads, values, tick: ms => t.mock.timers.tick(ms) };
}

test('active polling publishes booleans sequentially, 500ms after each settlement', async t => {
  const { loop, reads, values, tick } = fixture(t);
  tick(10_000); loop.setActive(false);
  assert.equal(reads.length, 0);
  loop.setActive(true); loop.setActive(true);
  assert.equal(reads.length, 1);
  tick(10_000);
  assert.equal(reads.length, 1, 'A pending read must never overlap a second poll');
  reads[0].resolve(true); await Promise.resolve();
  assert.deepEqual(values, [true]);
  tick(499); assert.equal(reads.length, 1);
  tick(1); assert.equal(reads.length, 2);
  reads[1].resolve(false); await Promise.resolve();
  assert.deepEqual(values, [true, false]);
});

test('read errors and invalid results publish unknown without breaking later polling', async t => {
  const { loop, reads, values, tick } = fixture(t);
  loop.setActive(true);
  for (const value of [new Error('network unavailable'), undefined, 'true', 1, {}, null]) {
    const pending = reads.at(-1);
    if (value instanceof Error) pending.reject(value); else pending.resolve(value);
    await Promise.resolve();
    assert.equal(values.at(-1), null);
    tick(500);
  }
  reads.at(-1).resolve(true); await Promise.resolve();
  assert.deepEqual(values, [null, null, null, null, null, null, true]);
});

test('pausing aborts, dims Back, cancels timers, and resumes immediately without stale results', async t => {
  const { loop, reads, values, tick } = fixture(t);
  loop.setActive(true);
  loop.setActive(false); loop.setActive(false);
  assert.equal(reads[0].signal.aborted, true);
  assert.deepEqual(values, [null]);
  tick(10_000); assert.equal(reads.length, 1);
  loop.setActive(true); loop.setActive(true);
  assert.equal(reads.length, 2, 'Resume must not wait for an aborted producer to settle');
  reads[1].resolve(false); await Promise.resolve();
  reads[0].resolve(true); await Promise.resolve();
  assert.deepEqual(values, [null, false], 'An old response cannot re-enable Back');
  loop.setActive(false);
  tick(10_000); assert.equal(reads.length, 2, 'Pausing cancels a scheduled poll');
  loop.setActive(true); assert.equal(reads.length, 3);
});

test('dispose aborts an active read and makes late completions and future calls inert', async t => {
  const { loop, reads, values, tick } = fixture(t);
  loop.setActive(true); loop.dispose();
  assert.equal(reads[0].signal.aborted, true);
  assert.deepEqual(values, [null]);
  reads[0].resolve(true); await Promise.resolve();
  loop.setActive(false); loop.setActive(true); loop.dispose();
  tick(10_000);
  assert.equal(reads.length, 1);
  assert.deepEqual(values, [null]);
});

test('dispose also cancels a poll scheduled after a completed read', async t => {
  const { loop, reads, values, tick } = fixture(t);
  loop.setActive(true);
  reads[0].resolve(true); await Promise.resolve();
  loop.dispose(); tick(10_000);
  assert.equal(reads.length, 1);
  assert.deepEqual(values, [true, null]);
});
