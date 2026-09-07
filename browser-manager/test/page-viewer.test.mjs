import assert from 'node:assert/strict';
import { test } from 'node:test';
import { navigationUrl, framePoint, fittedSize, modifiersFor, isPasteShortcut, physicalKey, wheelPixels, pageMessage } from '../lib/page-viewer.mjs';

test('navigation normalizes websites but never executes local/script/data addresses', () => {
  assert.equal(navigationUrl(' example.com/path?q=yes '), 'https://example.com/path?q=yes');
  assert.equal(navigationUrl('http://localhost:3000'), 'http://localhost:3000/');
  assert.equal(navigationUrl('about:blank'), 'about:blank');
  for (const input of ['', 'javascript:alert(1)', 'data:text/html,test', 'file:///etc/passwd', 'chrome://settings',
    'https://username:password@example.com', 'https://exam\nple.com', 'not a url', 'https://', 'https://example.com/' + 'x'.repeat(2048)]) {
    assert.throws(() => navigationUrl(input));
  }
});

test('fit and Retina-independent pointer mapping use the actual canvas rectangle', () => {
  const frame = { width: 1440, height: 900 };
  const fit = fittedSize({ width: 390, height: 600 }, frame);
  assert.equal(fit.width, 390);
  const bounds = { left: 12, top: 80, ...fit };
  assert.deepEqual(framePoint(207, 80 + fit.height / 2, bounds, frame), { x: 720, y: 450 });
  assert.deepEqual(framePoint(12, 80, bounds, frame), { x: 0, y: 0 });
  assert.equal(framePoint(11, 80, bounds, frame), null);
  assert.equal(framePoint(402, 80, bounds, frame), null);
  assert.deepEqual(framePoint(1000, -20, bounds, frame, true), { x: 1439, y: 0 });
  assert.equal(framePoint(10, 20, { ...bounds, width: 0 }, frame), null);
  assert.equal(framePoint(NaN, 20, bounds, frame), null);
  assert.deepEqual(fittedSize({ width: 390, height: 600 }, frame, false), frame);
  assert.deepEqual(fittedSize({ width: 1000, height: 500 }, { width: 390, height: 844 }), { width: 390 * 500 / 844, height: 500 });
});

test('physical text is inserted once; special keys preserve modifier bits', () => {
  assert.equal(modifiersFor({ altKey: true, ctrlKey: true, metaKey: true, shiftKey: true }), 15);
  const event = { key: 'A', code: 'KeyA', shiftKey: true };
  assert.deepEqual(physicalKey(event, 'down'), { type: 'text', text: 'A' });
  assert.equal(physicalKey(event, 'up'), null);
  assert.deepEqual(physicalKey({ key: '😀', code: 'KeyA' }, 'down'), { type: 'text', text: '😀' });
  assert.deepEqual(physicalKey({ key: 'ArrowLeft', code: 'ArrowLeft', altKey: true }, 'down'),
    { type: 'key', action: 'down', key: 'ArrowLeft', code: 'ArrowLeft', modifiers: 1 });
  assert.equal(physicalKey({ key: 'Dead', code: 'Quote' }, 'down'), null);
  assert.equal(physicalKey({ key: 'a', code: 'KeyA', isComposing: true }, 'down'), null);
});

test('every supported paste accelerator is redirected to explicit text entry', () => {
  for (const event of [{ key: 'v', metaKey: true }, { key: 'V', ctrlKey: true, shiftKey: true }, { key: 'Insert', shiftKey: true }]) {
    assert.equal(isPasteShortcut(event), true);
  }
  for (const event of [{ key: 'v' }, { key: 'Insert' }, { key: 'x', metaKey: true }]) assert.equal(isPasteShortcut(event), false);
});

test('wheel modes are bounded and expressed in CSS pixels', () => {
  assert.equal(wheelPixels(3, 1, 900), 48);
  assert.equal(wheelPixels(-1, 2, 900), -900);
  assert.equal(wheelPixels(0.5, 0, 900), 0.5);
  assert.equal(wheelPixels(1e10, 0, 900), 2000);
  assert.equal(wheelPixels(NaN, 0, 900), 0);
});

test('only bounded typed server messages are accepted', () => {
  assert.deepEqual(pageMessage(JSON.stringify({ type: 'frame', data: '/9j/AA==', width: 390, height: 844 })),
    { type: 'frame', data: '/9j/AA==', width: 390, height: 844 });
  const tabs = { type: 'tabs', tabs: [{ id: 'a', title: '<script>text only</script>', url: 'https://example.com' }], activeId: 'a', canGoBack: true };
  assert.deepEqual(pageMessage(JSON.stringify(tabs)), tabs);
  assert.deepEqual(pageMessage('{"type":"tabs","tabs":[],"activeId":null,"canGoBack":false}'),
    { type: 'tabs', tabs: [], activeId: '', canGoBack: false });
  for (const value of ['null', 'bad json', '{}', JSON.stringify({ type: 'frame', data: '<svg>', width: 390, height: 844 }),
    JSON.stringify({ type: 'frame', data: 'AA==', width: 1e9, height: 1 }), JSON.stringify({ type: 'tabs', tabs: [null], activeId: 'a' })]) {
    assert.equal(pageMessage(value), null);
  }
  assert.equal(pageMessage(JSON.stringify({ type: 'error', message: 'x'.repeat(2000) })).message.length, 500);
});
