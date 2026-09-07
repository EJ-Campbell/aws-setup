/**
 * One retry timer per viewer. Only a successful connection resets the backoff.
 * @param {() => void} retry
 * @param {(seconds: number | null) => void} onDelay
 * @param {boolean} active
 */
export function createReconnectLoop(retry, onDelay, active) {
  let nextDelay = 1000;
  let timer;
  let disposed = false;
  const cancel = () => {
    clearTimeout(timer);
    timer = undefined;
    onDelay(null);
  };
  const request = () => {
    if (disposed) return;
    cancel();
    if (active) retry();
  };
  return {
    retry: request,
    connected() {
      if (disposed) return;
      nextDelay = 1000;
      cancel();
    },
    disconnected() {
      if (disposed || !active || timer !== undefined) return;
      const delay = nextDelay;
      nextDelay = Math.min(nextDelay * 2, 10_000);
      onDelay(delay / 1000);
      timer = setTimeout(request, delay);
    },
    setActive(value) {
      if (disposed || value === active) return;
      active = value;
      // Refresh even an apparently connected socket after phone suspension.
      // Visibility and focus often fire together; only the state transition retries.
      if (active) request();
      else cancel();
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      cancel();
    },
  };
}
