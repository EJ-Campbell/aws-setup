import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canFitViewport } from '../lib/fit-viewport.mjs';

test('Fit is unnecessary at exact fit or when either limiting dimension already fits 1:1', () => {
  for (const size of [[390, 680, 390, 680], [390, 680, 390, 900], [390, 680, 800, 680]]) {
    assert.equal(canFitViewport(...size), false, JSON.stringify(size));
  }
});

test('Fit is useful when the available rectangle scales the frame up or down', () => {
  for (const size of [[390, 680, 780, 1360], [1440, 900, 390, 680],
    [390, 680, 390, 480], [390, 680, 320, 680]]) {
    assert.equal(canFitViewport(...size), true, JSON.stringify(size));
  }
});

test('fractional changes below one CSS pixel in both dimensions are not useful', () => {
  assert.equal(canFitViewport(128, 256, 128.25, 512), false);
  assert.equal(canFitViewport(128, 256, 127.75, 512), false);
  assert.equal(canFitViewport(256, 128, 512, 128.25), false);
});

test('exactly one CSS pixel of change in either dimension makes Fit useful', () => {
  assert.equal(canFitViewport(128, 256, 128.5, 512), true);
  assert.equal(canFitViewport(128, 256, 127.5, 512), true);
  assert.equal(canFitViewport(256, 128, 512, 128.5), true);
});

test('invalid, nonnumeric, nonfinite, or nonpositive dimensions fail closed', () => {
  for (let index = 0; index < 4; index++) {
    for (const value of [0, -1, NaN, Infinity, -Infinity, undefined, null, '390']) {
      const size = [390, 680, 780, 1360];
      size[index] = value;
      assert.equal(canFitViewport(...size), false, `dimension ${index}: ${String(value)}`);
    }
  }
});
