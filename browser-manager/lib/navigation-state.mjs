/**
 * Poll only an active viewer; an aborted read can never publish into a later connection.
 * @param {(signal: AbortSignal) => Promise<boolean | null>} read
 * @param {(value: boolean | null) => void} publish
 */
export function createNavigationState(read, publish) {
  let active = false, disposed = false, timer, controller;
  const cancel = () => {
    clearTimeout(timer);
    timer = undefined;
    controller?.abort();
    controller = undefined;
  };
  const poll = async () => {
    if (!active || disposed || controller) return;
    const pending = new AbortController();
    controller = pending;
    let value = null;
    try { value = await read(pending.signal); } catch { /* Unknown state keeps Back disabled. */ }
    if (controller !== pending || !active || disposed) return;
    controller = undefined;
    publish(typeof value === 'boolean' ? value : null);
    if (active && !disposed) timer = setTimeout(() => { timer = undefined; void poll(); }, 500);
  };
  return {
    setActive(value) {
      if (disposed || value === active) return;
      active = value;
      cancel();
      if (active) void poll();
      else publish(null);
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      active = false;
      cancel();
      publish(null);
    },
  };
}
