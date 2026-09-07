import assert from 'node:assert/strict';
import { test } from 'node:test';
import { attachTouchScroll } from '../lib/touch-scroll.mjs';

function fixture(t, reducedMotion = false) {
  let now = 100, nextFrame = 0, vendorActive = false;
  const frames = new Map(), wheels = [], vendor = [];
  class InputEvent {
    constructor(type, options = {}) { Object.assign(this, { type, isTrusted: false }, options); }
    preventDefault() { this.defaultPrevented = true; }
    stopImmediatePropagation() { this.stopped = true; }
  }
  const emitter = () => {
    const listeners = new Map();
    return {
      addEventListener(type, callback) {
        const set = listeners.get(type) ?? new Set();
        set.add(callback); listeners.set(type, set);
      },
      removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
      dispatchEvent(event) {
        for (const callback of listeners.get(event.type) ?? []) {
          callback(event);
          if (event.stopped) break;
        }
        return !event.defaultPrevented;
      },
      listenerCount: () => [...listeners.values()].reduce((count, set) => count + set.size, 0),
    };
  };
  const win = Object.assign(emitter(), {
    Event: InputEvent, WheelEvent: InputEvent,
    performance: { now: () => now },
    matchMedia: () => ({ matches: reducedMotion }),
    requestAnimationFrame(callback) { frames.set(++nextFrame, callback); return nextFrame; },
    cancelAnimationFrame(id) { frames.delete(id); },
  });
  const doc = Object.assign(emitter(), { defaultView: win });
  const target = Object.assign(emitter(), { ownerDocument: doc });
  // Model the ancestor capture listeners, then only the relevant noVNC behavior:
  // touchcancel resets its recognizer but can emit a tap before doing so.
  const canvas = {
    tagName: 'CANVAS',
    dispatchEvent(event) {
      event.target = canvas;
      target.dispatchEvent(event);
      if (event.stopped) return false;
      if (event.type === 'wheel') wheels.push({ time: now, ...event });
      if (event.type === 'touchstart') vendorActive = true;
      if (event.type.startsWith('touch')) vendor.push(event.type);
      if (['touchend', 'touchcancel'].includes(event.type) && vendorActive) {
        canvas.dispatchEvent(new InputEvent('gesturestart', { detail: { type: 'onetap' } }));
        canvas.dispatchEvent(new InputEvent('gestureend', { detail: { type: 'onetap' } }));
        vendorActive = false;
      }
      if (event.type === 'gesturestart') vendor.push(event.detail.type);
      return true;
    },
  };
  const dispose = attachTouchScroll(target);
  t.after(dispose);
  const point = (x = 100, y = 200, identifier = 1) => ({ clientX: x, clientY: y, identifier });
  const touch = (type, changed = point(), touches = type === 'touchend' || type === 'touchcancel' ? [] : [changed]) => {
    const event = new InputEvent(type, { changedTouches: [changed], touches });
    canvas.dispatchEvent(event);
    return event;
  };
  const step = (ms = 16) => {
    now += ms;
    const queued = [...frames.values()]; frames.clear();
    for (const callback of queued) callback(now);
  };
  const swipe = () => {
    touch('touchstart'); step(); touch('touchmove', point(100, 170)); step();
  };
  return { canvas, win, doc, target, wheels, vendor, touch, point, step, swipe, dispose,
    event: (type, values = {}) => new InputEvent(type, values),
    now: () => now, queued: () => frames.size };
}

test('a tap or movement below eight pixels remains available to noVNC', t => {
  const f = fixture(t);
  assert.ok(!f.touch('touchstart').defaultPrevented);
  assert.ok(!f.touch('touchmove', f.point(100, 193)).defaultPrevented);
  assert.ok(!f.touch('touchend', f.point(100, 193)).defaultPrevented);
  f.step(1000);
  assert.deepEqual(f.wheels, []);
  assert.equal(f.vendor.filter(value => value === 'onetap').length, 1);
});

test('eight-pixel swipe takeover resets noVNC without leaking a cancel-generated tap', t => {
  const f = fixture(t);
  f.touch('touchstart');
  assert.equal(f.touch('touchmove', f.point(100, 192)).defaultPrevented, true);
  f.step();
  assert.equal(f.vendor.filter(value => value === 'touchcancel').length, 1);
  assert.ok(!f.vendor.includes('onetap'));
  assert.equal(f.wheels.length, 1);
  assert.equal(f.wheels[0].deltaY, 50);
  assert.equal(f.wheels[0].deltaX, 0);
  assert.equal(f.wheels[0].clientX, 100);
  assert.equal(f.wheels[0].clientY, 200);
  assert.equal(f.touch('touchend', f.point(100, 192)).defaultPrevented, true);
  assert.ok(!f.vendor.includes('onetap'));
});

test('horizontal swipes use horizontal notches at the original target', t => {
  const f = fixture(t);
  f.touch('touchstart'); f.touch('touchmove', f.point(120, 201)); f.step();
  assert.equal(f.wheels[0].deltaX, -50);
  assert.equal(f.wheels[0].deltaY, 0);
});

test('held swipes cap queued notches and pace dispatch instead of bursting', t => {
  const f = fixture(t);
  f.swipe();
  f.touch('touchmove', f.point(100, -10000));
  for (let i = 0; i < 30; i++) f.step(16);
  assert.equal(f.wheels.length, 4, 'initial notch plus at most three queued notches');
  assert.equal(f.queued(), 0);
  for (let i = 1; i < f.wheels.length; i++) {
    assert.ok(f.wheels[i].time - f.wheels[i - 1].time >= 45);
  }
});

test('release glide is paced and ends within five hundred milliseconds', t => {
  const f = fixture(t);
  f.swipe(); f.touch('touchmove', f.point(100, 80));
  f.touch('touchend', f.point(100, 80));
  const released = f.now();
  for (let i = 0; i < 80; i++) f.step(16);
  assert.ok(f.wheels.length > 1);
  assert.ok(f.wheels.at(-1).time <= released + 500);
  assert.equal(f.queued(), 0);
  for (let i = 1; i < f.wheels.length; i++) assert.ok(f.wheels[i].time - f.wheels[i - 1].time >= 45);
});

test('reduced-motion preference disables release glide', t => {
  const f = fixture(t, true);
  f.swipe(); f.touch('touchend', f.point(100, 170));
  const count = f.wheels.length;
  for (let i = 0; i < 40; i++) f.step();
  assert.equal(f.wheels.length, count);
  assert.equal(f.queued(), 0);
});

test('reduced motion keeps an accepted quick swipe even when release precedes the first frame', t => {
  const f = fixture(t, true);
  f.touch('touchstart');
  f.touch('touchmove', f.point(100, 170));
  f.touch('touchend', f.point(100, 170));
  f.step();
  assert.equal(f.wheels.length, 1, 'disable inertia, not the accepted swipe');
  assert.equal(f.wheels[0].deltaY, 50);
  for (let i = 0; i < 40; i++) f.step();
  assert.equal(f.wheels.length, 1);
  assert.equal(f.queued(), 0);
});

test('cancellation before swipe takeover cannot accidentally tap the remote page', t => {
  const f = fixture(t);
  f.touch('touchstart');
  assert.equal(f.touch('touchcancel').defaultPrevented, true);
  assert.ok(!f.vendor.includes('onetap'));
  assert.deepEqual(f.wheels, []);
});

test('new touch and lifecycle interruption cancel queued glide without a late burst', t => {
  for (const interrupt of [
    f => f.touch('touchstart', f.point(150, 250)),
    f => f.touch('touchcancel'),
    f => f.win.dispatchEvent(f.event('blur')),
    f => f.win.dispatchEvent(f.event('pagehide')),
    f => f.doc.dispatchEvent(f.event('visibilitychange')),
    f => f.target.dispatchEvent(f.event('keydown')),
    f => f.canvas.dispatchEvent(f.event('wheel', { isTrusted: true })),
    f => f.dispose(),
  ]) {
    const f = fixture(t);
    f.swipe(); f.touch('touchend', f.point(100, 170)); interrupt(f);
    const count = f.wheels.length;
    for (let i = 0; i < 50; i++) f.step();
    assert.equal(f.wheels.length, count);
    assert.equal(f.queued(), 0);
  }
});

test('a contact stopping glide does not click, but the next normal tap still does', t => {
  const f = fixture(t);
  f.swipe(); f.touch('touchend', f.point(100, 170));
  assert.equal(f.queued(), 1);
  f.touch('touchstart', f.point(150, 250));
  assert.equal(f.touch('touchend', f.point(150, 250)).defaultPrevented, true);
  assert.ok(!f.vendor.includes('onetap'));
  const count = f.wheels.length;
  f.step(1000);
  assert.equal(f.wheels.length, count);
  assert.equal(f.queued(), 0);
  f.touch('touchstart', f.point(150, 250));
  assert.ok(!f.touch('touchend', f.point(150, 250)).defaultPrevented);
  assert.equal(f.vendor.filter(value => value === 'onetap').length, 1);
});

test('multitouch, recognized long press, and double-tap dragging stay delegated to noVNC', t => {
  for (const delegate of [
    f => { const second = f.point(140, 200, 2); f.touch('touchstart', second, [f.point(), second]); },
    f => f.canvas.dispatchEvent(f.event('gesturestart', { detail: { type: 'longpress' } })),
    f => { f.touch('touchend'); f.step(100); f.touch('touchstart'); },
  ]) {
    const f = fixture(t);
    f.touch('touchstart'); delegate(f);
    assert.ok(!f.touch('touchmove', f.point(100, 80)).defaultPrevented);
    f.step(100);
    assert.deepEqual(f.wheels, []);
    assert.ok(!f.vendor.includes('touchcancel'));
  }
});

test('adding another finger during a swipe blocks until release and does not trap the next tap', t => {
  const f = fixture(t);
  f.swipe();
  const second = f.point(150, 170, 2);
  assert.equal(f.touch('touchstart', second, [f.point(100, 170), second]).defaultPrevented, true);
  assert.equal(f.touch('touchmove', f.point(100, 100)).defaultPrevented, true);
  f.touch('touchend', second, [f.point(100, 100)]);
  f.touch('touchend', f.point(100, 100));
  const count = f.wheels.length;
  f.step(1000);
  assert.equal(f.wheels.length, count);
  f.touch('touchstart'); f.touch('touchend');
  assert.equal(f.vendor.filter(value => value === 'onetap').length, 1);
});

test('dispose removes listeners and cancels a pending tap without producing one', t => {
  const f = fixture(t);
  f.touch('touchstart'); f.dispose();
  assert.ok(!f.vendor.includes('onetap'));
  assert.equal(f.target.listenerCount(), 0);
  assert.equal(f.win.listenerCount(), 0);
  assert.equal(f.doc.listenerCount(), 0);
});
