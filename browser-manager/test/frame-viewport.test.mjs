import assert from 'node:assert/strict';
import { test } from 'node:test';
import { frameViewport } from '../lib/frame-viewport.mjs';

test('recognizes only the canonical Desktop framebuffer', () => {
  assert.deepEqual(frameViewport(1440, 900), { mode: 'desktop', width: 1440, height: 900 });
  for (const [width, height] of [[1439, 900], [1441, 900], [1440, 899], [1440, 901], [1280, 720]]) {
    assert.equal(frameViewport(width, height), null);
  }
});

test('Phone bounds are inclusive and preserve the actual framebuffer dimensions', () => {
  for (const width of [320, 390, 500]) {
    for (const height of [480, 844, 900]) {
      assert.deepEqual(frameViewport(width, height), { mode: 'phone', width, height });
    }
  }
  for (const [width, height] of [[319, 844], [501, 844], [390, 479], [390, 901]]) {
    assert.equal(frameViewport(width, height), null);
  }
});

test('missing, malformed, fractional, and non-finite dimensions remain unknown', () => {
  assert.equal(frameViewport(), null);
  for (const value of [undefined, null, '', '390', false, {}, [], NaN, Infinity, -Infinity, 0, -1, 390.5]) {
    assert.equal(frameViewport(value, 844), null);
    assert.equal(frameViewport(390, value), null);
  }
});

test('an unrecognized partial resize is not guessed from width or height alone', () => {
  for (const [width, height] of [[1440, 844], [390, 0], [0, 844], [390, undefined], [undefined, 844]]) {
    assert.equal(frameViewport(width, height), null);
  }
});

test('local CSS scaling does not change classification of intrinsic canvas dimensions', () => {
  const scaledDesktop = { width: 1440, height: 900, clientWidth: 390, clientHeight: 244 };
  assert.deepEqual(frameViewport(scaledDesktop.width, scaledDesktop.height),
    { mode: 'desktop', width: 1440, height: 900 });
  const expandedPhone = { width: 390, height: 844, clientWidth: 1440, clientHeight: 900 };
  assert.deepEqual(frameViewport(expandedPhone.width, expandedPhone.height),
    { mode: 'phone', width: 390, height: 844 });
});
