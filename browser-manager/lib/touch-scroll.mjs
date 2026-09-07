/** One-finger scrolling over noVNC's public DOM input, without changing mouse input.
 * RFB wheels are discrete notches, not pixel deltas: pace them and bound the glide.
 * @param {HTMLElement} target
 */
export function attachTouchScroll(target) {
  const doc = target.ownerDocument;
  const win = doc.defaultView;
  let gesture = null;
  let lastTap = null;
  let cancelling = false;
  let animation = 0;
  let motion = null;
  const stop = (event) => { event.preventDefault(); event.stopImmediatePropagation(); };
  const stopMotion = () => { win.cancelAnimationFrame(animation); animation = 0; motion = null; };

  function tick(now) {
    animation = 0;
    if (!motion) return;
    if (motion.released) {
      const elapsed = Math.min(32, now - motion.time);
      motion.pending += motion.velocity * elapsed;
      motion.velocity *= Math.exp(-elapsed / 180);
      if (now - motion.released > 500 || Math.abs(motion.velocity) < 0.03) {
        stopMotion();
        return;
      }
    }
    motion.time = now;
    // A bounded queue avoids a delayed burst when a phone stalls or resumes.
    motion.pending = Math.max(-180, Math.min(180, motion.pending));
    if (Math.abs(motion.pending) >= 60 && now - motion.sent >= 45) {
      const direction = Math.sign(motion.pending);
      motion.pending -= direction * 60;
      motion.sent = now;
      motion.canvas.dispatchEvent(new win.WheelEvent('wheel', {
        bubbles: true, cancelable: true, clientX: motion.x, clientY: motion.y,
        deltaX: motion.axis === 'x' ? direction * 50 : 0,
        deltaY: motion.axis === 'y' ? direction * 50 : 0,
      }));
    }
    if (motion && (motion.released || Math.abs(motion.pending) >= 60)) schedule();
  }
  function schedule() { if (!animation) animation = win.requestAnimationFrame(tick); }

  function cancelVendor(current) {
    // noVNC treats touchcancel as touchend, which can synthesize a tap. Filter
    // those gesture events while resetting its recognizer; never send that click.
    cancelling = true;
    try {
      const event = new win.Event('touchcancel', { bubbles: true, cancelable: true });
      Object.defineProperty(event, 'changedTouches', { value: [current.touch] });
      current.canvas.dispatchEvent(event);
    } finally { cancelling = false; }
  }
  function touchStart(event) {
    const stoppedGlide = Boolean(motion?.released);
    stopMotion();
    if (gesture?.scrolling || gesture?.blocked) {
      gesture.blocked = true;
      stop(event);
      return;
    }
    if (event.touches.length !== 1) { gesture = null; lastTap = null; return; }
    const touch = event.changedTouches[0];
    const canvas = event.target;
    if (canvas.tagName !== 'CANVAS') return;
    const now = win.performance.now();
    const drag = lastTap && now - lastTap.time < 300 &&
      Math.hypot(touch.clientX - lastTap.x, touch.clientY - lastTap.y) < 24;
    gesture = { canvas, touch, x: touch.clientX, y: touch.clientY,
      lastX: touch.clientX, lastY: touch.clientY, time: now, start: now,
      velocity: 0, delegated: Boolean(drag), scrolling: false, blocked: false, stoppedGlide };
    lastTap = null;
  }
  function touchMove(event) {
    const current = gesture;
    if (!current || current.delegated) return;
    if (current.blocked) { stop(event); return; }
    const touch = Array.from(event.changedTouches).find((item) => item.identifier === current.touch.identifier);
    if (!touch) return;
    const dx = current.x - touch.clientX;
    const dy = current.y - touch.clientY;
    const now = win.performance.now();
    if (!current.scrolling) {
      if (Math.hypot(dx, dy) < 8) return;
      current.scrolling = true;
      current.axis = Math.abs(dy) >= Math.abs(dx) ? 'y' : 'x';
      cancelVendor(current);
      motion = { canvas: current.canvas, x: current.x, y: current.y, axis: current.axis,
        pending: Math.sign(current.axis === 'y' ? dy : dx) * 60,
        velocity: 0, time: now, sent: -Infinity, released: 0 };
    } else if (motion) {
      motion.pending += current.axis === 'y' ? current.lastY - touch.clientY : current.lastX - touch.clientX;
    }
    const delta = current.axis === 'y' ? current.lastY - touch.clientY : current.lastX - touch.clientX;
    const velocity = Math.max(-2, Math.min(2, delta / Math.max(8, now - current.time)));
    current.velocity = current.velocity * 0.4 + velocity * 0.6;
    current.lastX = touch.clientX; current.lastY = touch.clientY; current.time = now;
    schedule();
    stop(event);
  }
  function touchEnd(event) {
    const current = gesture;
    if (!current) return;
    if (current.scrolling || current.blocked) {
      stop(event);
      if (event.touches.length) return;
      const now = win.performance.now();
      if (motion && !current.blocked && now - current.time < 80 && Math.abs(current.velocity) >= 0.1 &&
          !win.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        motion.velocity = current.velocity;
        motion.released = now;
        motion.time = now;
        schedule();
      } else if (motion && !current.blocked) {
        // Reduced motion disables the glide, not movement already accepted
        // between the last animation frame and finger release.
        motion.velocity = 0;
        schedule();
      } else stopMotion();
    } else if (!current.delegated && current.stoppedGlide) {
      // A touch used to stop coasting must not also activate the link beneath it.
      cancelVendor(current);
      stop(event);
    } else if (!current.delegated && win.performance.now() - current.start < 250) {
      lastTap = { x: current.x, y: current.y, time: win.performance.now() };
    }
    if (!event.touches.length) gesture = null;
  }
  function touchCancel(event) {
    if (cancelling) return;
    stopMotion();
    if (gesture && !gesture.delegated) {
      if (!gesture.scrolling && !gesture.blocked) cancelVendor(gesture);
      stop(event);
    }
    gesture = null; lastTap = null;
  }
  function vendorGesture(event) {
    if (cancelling) { stop(event); return; }
    // Long press and multitouch keep noVNC's established behavior.
    if (gesture) gesture.delegated = true;
  }
  const options = { capture: true, passive: false };
  const listeners = { touchstart: touchStart, touchmove: touchMove, touchend: touchEnd,
    touchcancel: touchCancel, gesturestart: vendorGesture, gestureend: vendorGesture };
  for (const [type, listener] of Object.entries(listeners)) target.addEventListener(type, listener, options);
  const interrupt = () => { stopMotion(); lastTap = null; };
  win.addEventListener('blur', interrupt);
  win.addEventListener('pagehide', interrupt);
  doc.addEventListener('visibilitychange', interrupt);
  target.addEventListener('keydown', stopMotion, true);
  // Only physical wheel input interrupts the synthetic touch glide.
  const wheel = (event) => { if (event.isTrusted) stopMotion(); };
  target.addEventListener('wheel', wheel, true);
  return () => {
    stopMotion();
    if (gesture && !gesture.delegated && !gesture.scrolling && !gesture.blocked) cancelVendor(gesture);
    for (const [type, listener] of Object.entries(listeners)) target.removeEventListener(type, listener, true);
    win.removeEventListener('blur', interrupt);
    win.removeEventListener('pagehide', interrupt);
    doc.removeEventListener('visibilitychange', interrupt);
    target.removeEventListener('keydown', stopMotion, true);
    target.removeEventListener('wheel', wheel, true);
  };
}
