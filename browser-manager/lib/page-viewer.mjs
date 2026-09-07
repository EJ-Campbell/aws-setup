// Pure viewer geometry/input helpers. The server independently validates commands.
export function navigationUrl(value) {
  const input = String(value ?? '').trim();
  if (input === 'about:blank') return input;
  if (!input || input.length > 2048 || /[\s\u0000-\u001f\u007f]/u.test(input)) throw new Error('Enter an http:// or https:// address (up to 2048 characters).');
  const candidate = /^[a-z][a-z\d+.-]*:/i.test(input) ? input : `https://${input}`;
  let url;
  try { url = new URL(candidate); } catch { throw new Error('Enter a valid website address.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.href.length > 2048) {
    throw new Error('Only HTTP and HTTPS websites are supported; do not put passwords in the address.');
  }
  return url.href;
}

export function modifiersFor(event) {
  return (event.altKey ? 1 : 0) | (event.ctrlKey ? 2 : 0) | (event.metaKey ? 4 : 0) | (event.shiftKey ? 8 : 0);
}

export function isPasteShortcut(event) {
  return Boolean(((event.ctrlKey || event.metaKey) && event.key?.toLowerCase() === 'v')
    || (event.shiftKey && event.key === 'Insert'));
}

/** Map the exact rendered image rectangle to CDP CSS coordinates, not device pixels. */
export function framePoint(clientX, clientY, bounds, frame, clamp = false) {
  const values = [clientX, clientY, bounds.left, bounds.top, bounds.width, bounds.height, frame.width, frame.height];
  if (!values.every(Number.isFinite) || bounds.width <= 0 || bounds.height <= 0 || frame.width <= 0 || frame.height <= 0) return null;
  const x = (clientX - bounds.left) / bounds.width;
  const y = (clientY - bounds.top) / bounds.height;
  if (!clamp && (x < 0 || x >= 1 || y < 0 || y >= 1)) return null;
  return {
    x: Math.max(0, Math.min(frame.width - 1, Math.floor(x * frame.width))),
    y: Math.max(0, Math.min(frame.height - 1, Math.floor(y * frame.height))),
  };
}

export function fittedSize(available, frame, fit = true) {
  const ratio = fit ? Math.min(1, Math.max(1, available.width) / frame.width, Math.max(1, available.height) / frame.height) : 1;
  return { width: Math.max(1, frame.width * ratio), height: Math.max(1, frame.height * ratio) };
}

export function wheelPixels(delta, mode, height) {
  if (!Number.isFinite(delta)) return 0;
  return Math.max(-2000, Math.min(2000, delta * (mode === 1 ? 16 : mode === 2 ? height : 1)));
}

/** Text is explicit; raw key events never need the host or viewer clipboard. */
export function physicalKey(event, action) {
  if (event.isComposing || ['Dead', 'Process', 'Unidentified'].includes(event.key) || !event.key || !event.code) return null;
  const modifiers = modifiersFor(event);
  if (!(modifiers & 7) && [...event.key].length === 1) return action === 'down' ? { type: 'text', text: event.key } : null;
  return { type: 'key', action, key: event.key, code: event.code, modifiers };
}

/** Treat JSON as data only: never inject a remote title, URL, error, or frame as HTML. */
export function pageMessage(raw) {
  if (typeof raw !== 'string' || raw.length > 12 * 1024 * 1024) return null;
  let message;
  try { message = JSON.parse(raw); } catch { return null; }
  if (!message || typeof message !== 'object') return null;
  if (message.type === 'frame') {
    if (!Number.isInteger(message.width) || !Number.isInteger(message.height) || message.width < 1 || message.height < 1
        || message.width > 8192 || message.height > 8192 || typeof message.data !== 'string'
        || !message.data || !/^[A-Za-z0-9+/]+={0,2}$/.test(message.data)) return null;
    return { type: 'frame', data: message.data, width: message.width, height: message.height };
  }
  if (message.type === 'tabs') {
    if (!Array.isArray(message.tabs) || message.tabs.length > 128 || !(typeof message.activeId === 'string' || message.activeId === null)
        || !message.tabs.every(tab => tab && typeof tab.id === 'string' && tab.id.length <= 256
          && typeof tab.title === 'string' && tab.title.length <= 8192 && typeof tab.url === 'string' && tab.url.length <= 32768)) return null;
    return { type: 'tabs', tabs: message.tabs.map(({ id, title, url }) => ({ id, title, url })),
      activeId: message.activeId ?? '', canGoBack: message.canGoBack === true };
  }
  if (message.type === 'error' && typeof message.message === 'string') return { type: 'error', message: message.message.slice(0, 500) };
  return null;
}
