import assert from 'node:assert/strict';
import { test } from 'node:test';
import { frameViewport, VNC_PIXEL_RATIO } from '../lib/frame-viewport.mjs';

test('recognizes only the canonical Desktop framebuffer', () => {
  assert.equal(VNC_PIXEL_RATIO, 2);
  assert.deepEqual(frameViewport(2880, 1800), { mode: 'desktop', width: 1440, height: 900 });
  assert.deepEqual(frameViewport(1440, 900), { mode: 'desktop', width: 1440, height: 900 });
  for (const [width, height] of [[1439, 900], [1441, 900], [1440, 899], [1440, 901], [1280, 720],
    [2879, 1800], [2881, 1800], [2880, 1799], [2880, 1801]]) {
    assert.equal(frameViewport(width, height), null);
  }
});

test('Phone bounds are inclusive and return logical dimensions for 2x and legacy frames', () => {
  for (const width of [320, 390, 500]) {
    for (const height of [480, 844, 900]) {
      assert.deepEqual(frameViewport(width * 2, height * 2), { mode: 'phone', width, height });
      assert.deepEqual(frameViewport(width, height), { mode: 'phone', width, height });
    }
  }
  for (const [width, height] of [[319, 844], [501, 844], [390, 479], [390, 901],
    [638, 1688], [1002, 1688], [780, 958], [780, 1802], [781, 1688], [780, 1689]]) {
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
  for (const [width, height] of [[1440, 844], [390, 0], [0, 844], [390, undefined], [undefined, 844],
    [2880, 1688], [780, 844], [390, 1688], [780, 0]]) {
    assert.equal(frameViewport(width, height), null);
  }
});

test('local CSS scaling does not change classification of intrinsic canvas dimensions', () => {
  const scaledDesktop = { width: 2880, height: 1800, clientWidth: 390, clientHeight: 244 };
  assert.deepEqual(frameViewport(scaledDesktop.width, scaledDesktop.height),
    { mode: 'desktop', width: 1440, height: 900 });
  const expandedPhone = { width: 780, height: 1688, clientWidth: 1440, clientHeight: 900 };
  assert.deepEqual(frameViewport(expandedPhone.width, expandedPhone.height),
    { mode: 'phone', width: 390, height: 844 });
});
