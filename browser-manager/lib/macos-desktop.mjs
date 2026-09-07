import { spawn } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const MAX_PACKET = 12 * 1024 * 1024;
const MAX_TABS = 32;
const DEFAULT_VIEWPORT = { mode: 'desktop', width: 1440, height: 900 };
const safeError = (response) => Object.assign(new Error('Browser command failed'), {
  // Chrome briefly rejects page-domain calls while a history/navigation commit swaps documents.
  // This exact response means the command did not execute; do not retry arbitrary errors/actions.
  pageTransition: response?.code === -32000 && response?.message === 'Not attached to an active page',
});

function navigationUrl(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error('Invalid browser URL');
  }
  if (value === 'about:blank') return value;
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error('Invalid browser URL'); }
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new Error('Invalid browser URL');
  }
  return parsed.href;
}

function viewportValue(value) {
  const { mode, width, height } = value ?? {};
  if (!Number.isInteger(width) || !Number.isInteger(height) ||
      (mode === 'desktop' ? width !== 1440 || height !== 900
        : mode !== 'phone' || width < 320 || width > 500 || height < 480 || height > 900)) {
    throw new Error('Invalid browser viewport');
  }
  return { mode, width, height };
}

// Private inherited pipes are the only CDP transport. No debugging TCP listener, arbitrary CDP
// method, browser-global cookie API, JavaScript evaluation, or filesystem API is exposed to viewers.
class ChromePipe {
  constructor(child, onEvent, onFailure, timeoutMs) {
    this.writer = child.stdio[3];
    this.pending = new Map();
    this.nextId = 1;
    this.buffer = Buffer.alloc(0);
    this.stopped = false;
    this.timeoutMs = timeoutMs;
    const failed = () => { if (!this.stopped) onFailure(); };
    this.writer.on('error', failed);
    child.stdio[4].on('error', failed);
    child.stdio[4].on('end', failed);
    child.stdio[4].on('close', failed);
    child.stdio[4].on('data', (part) => {
      if (this.stopped) return;
      this.buffer = Buffer.concat([this.buffer, part]);
      if (this.buffer.length > MAX_PACKET) return failed();
      let end;
      while ((end = this.buffer.indexOf(0)) !== -1) {
        const packet = this.buffer.subarray(0, end);
        this.buffer = this.buffer.subarray(end + 1);
        let message;
        try { message = JSON.parse(packet.toString('utf8')); } catch { return failed(); }
        if (!message || typeof message !== 'object') return failed();
        if (Object.hasOwn(message, 'id')) {
          const entry = this.pending.get(message.id);
          if (!entry) continue;
          this.pending.delete(message.id);
          clearTimeout(entry.timer);
          if (message.error) entry.reject(safeError(message.error));
          else entry.resolve(message.result ?? {});
        } else if (typeof message.method === 'string') {
          try { onEvent(message); } catch { return failed(); }
        }
      }
    });
  }

  send(method, params = {}, sessionId) {
    if (this.stopped || this.pending.size >= 64 || this.writer.writableLength > 256 * 1024) {
      return Promise.reject(new Error('Browser is busy or unavailable'));
    }
    const id = this.nextId++;
    const packet = JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) });
    if (Buffer.byteLength(packet) > 64 * 1024) return Promise.reject(new Error('Browser command too large'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('Browser command timed out'));
      }, this.timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
      this.writer.write(`${packet}\0`, (error) => {
        if (error && this.pending.has(id)) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(safeError());
        }
      });
    });
  }

  stop() {
    this.stopped = true;
    for (const { reject, timer } of this.pending.values()) {
      clearTimeout(timer);
      reject(new Error('Browser is closed'));
    }
    this.pending.clear();
    this.buffer = Buffer.alloc(0);
  }
}

/** Actual headed macOS Chrome; pixels and input are page-only, never the Mac desktop.
 * The second argument is a process seam for offline tests, not an HTTP/client option.
 */
export async function launchMacDesktop({ runtimeDir, profile, browserBin, url, signal }, {
  spawnProcess = spawn,
  killGroup = (pid, name) => { try { process.kill(-pid, name); } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  } },
  timeoutMs = 10_000,
  shutdownMs = 5_000,
  captureIntervalMs = 100,
} = {}) {
  url = navigationUrl(url);
  if (!isAbsolute(profile) || !isAbsolute(runtimeDir) || !isAbsolute(browserBin)) {
    throw new Error('Browser requires absolute managed paths');
  }
  for (const directory of [profile, runtimeDir]) {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 ||
        info.uid !== process.getuid()) throw new Error('Browser directories must be private and owned');
  }
  const resolvedProfile = await realpath(profile);
  const personalProfile = join(homedir(), 'Library/Application Support/Google/Chrome');
  const personalRelative = relative(personalProfile, resolvedProfile);
  if (personalRelative === '' || (!personalRelative.startsWith('..') && !isAbsolute(personalRelative))) {
    throw new Error('The personal Chrome profile cannot be used');
  }
  if (signal?.aborted) throw new Error('Browser start cancelled');

  let closing;
  let pipe;
  let ready = false;
  let activeId;
  let viewport = { ...DEFAULT_VIEWPORT };
  let lastFrame;
  let navigation = { canGoBack: false, canGoForward: false };
  let historyRead;
  let tail = Promise.resolve();
  let queued = 0;
  let streamRevision = 0;
  let captureTimer;
  let pointerButtons = 0;
  const tabs = new Map();
  const listeners = new Set();
  const exited = Promise.withResolvers();
  const finished = Promise.withResolvers();
  const startFailed = Promise.withResolvers();
  void startFailed.promise.catch(() => {});

  const child = spawnProcess(browserBin, [
    `--user-data-dir=${resolvedProfile}`, '--remote-debugging-pipe',
    '--no-first-run', '--no-default-browser-check', '--disable-session-crashed-bubble',
    '--window-size=1440,1000', 'about:blank',
  ], { detached: true, shell: false, stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });

  function emit(message) {
    for (const listener of listeners) {
      try { listener(structuredClone(message)); } catch { /* One closed viewer cannot kill Chrome. */ }
    }
  }
  const snapshot = () => ({ type: 'tabs', tabs: [...tabs.values()].map(({ id, title, url }) => ({ id, title, url })),
    activeId: activeId ?? null, canGoBack: navigation.canGoBack });
  const tabsChanged = () => emit(snapshot());
  function fail() {
    if (closing) return;
    const error = new Error('Managed Chrome disconnected');
    startFailed.reject(error);
    if (ready) emit({ type: 'error', message: error.message });
    void close();
  }
  const aborted = () => fail();
  signal?.addEventListener('abort', aborted, { once: true });
  child.once('error', () => { exited.resolve(); fail(); });
  child.once('exit', () => { exited.resolve(); fail(); });

  function close() {
    if (closing) return closing;
    // Set closing before signal delivery, and reject outstanding CDP commands immediately. Never
    // discover processes by name/profile or read a disk PID: only this spawn's owned group is killed.
    closing = Promise.resolve().then(async () => {
      signal?.removeEventListener('abort', aborted);
      clearTimeout(captureTimer);
      streamRevision += 1;
      emit({ type: 'closed' });
      listeners.clear();
      // Chrome's Browser.close performs its normal profile/cookie flush on macOS. SIGINT alone can
      // terminate before that flush; signals are only bounded fallback for an unresponsive browser.
      if (pipe && child.pid && child.exitCode === null && child.signalCode === null) {
        let timer;
        await Promise.race([pipe.send('Browser.close').catch(() => {}), exited.promise,
          new Promise(resolve => { timer = setTimeout(resolve, Math.min(shutdownMs, 2000)); })]);
        clearTimeout(timer);
      }
      pipe?.stop();
      if (child.pid && child.exitCode === null && child.signalCode === null) {
        let timer;
        await Promise.race([exited.promise, new Promise((resolve) => {
          timer = setTimeout(resolve, shutdownMs);
        })]);
        clearTimeout(timer);
        if (child.exitCode === null && child.signalCode === null) {
          try { child.kill('SIGINT'); } catch { /* Already gone. */ }
        }
      }
      if (child.pid) {
        try { killGroup(child.pid, 'SIGKILL'); } catch { /* Parent has already reaped the group. */ }
      }
      await exited.promise;
      finished.resolve();
    });
    return closing;
  }

  const enqueue = (operation) => {
    if (closing || queued >= 64) return Promise.reject(new Error('Browser is busy or unavailable'));
    queued += 1;
    const result = tail.then(() => {
      if (closing) throw new Error('Browser is closed');
      return operation();
    });
    tail = result.catch(() => {}).finally(() => { queued -= 1; });
    return result;
  };
  const background = (operation) => { void enqueue(operation).catch(() => {
    if (!closing) emit({ type: 'error', message: 'Browser operation could not complete' });
  }); };

  async function pageCommand(method, params, sessionId, isAuthorized = () => true) {
    const deadline = Date.now() + 2000;
    for (;;) {
      if (closing || !isAuthorized()) throw new Error('Browser is closed or authorization expired');
      try { return await pipe.send(method, params, sessionId); } catch (error) {
        if (!error.pageTransition || Date.now() >= deadline) throw error;
        await delay(50);
      }
    }
  }

  async function readHistory() {
    const tab = tabs.get(activeId);
    if (!tab?.sessionId || closing) return { canGoBack: null };
    if (!historyRead) {
      historyRead = pageCommand('Page.getNavigationHistory', {}, tab.sessionId).then((result) => {
        if (tab.id === activeId && !closing) {
          navigation = { canGoBack: result.currentIndex > 0,
            canGoForward: result.currentIndex < result.entries.length - 1 };
          tabsChanged();
        }
        return { ...navigation };
      }).catch(() => ({ canGoBack: null })).finally(() => { historyRead = undefined; });
    }
    return historyRead;
  }

  function onEvent({ method, params = {}, sessionId }) {
    if (closing) return;
    if (method === 'Target.targetCreated' || method === 'Target.targetInfoChanged') {
      const info = params.targetInfo;
      if (info?.type !== 'page' || typeof info.targetId !== 'string') return;
      let safeUrl;
      try { safeUrl = navigationUrl(info.url || 'about:blank'); } catch {
        // Internal/file pages must never be streamed, even if navigated via page content or a local
        // keyboard. Disable the owned target before any later frame can leave the process.
        const unsafe = tabs.get(info.targetId);
        if (unsafe) unsafe.blocked = true;
        if (activeId === info.targetId) lastFrame = undefined;
        background(async () => {
          await pipe.send('Target.closeTarget', { targetId: info.targetId });
        });
        return;
      }
      const previous = tabs.get(info.targetId);
      if (!previous && tabs.size >= MAX_TABS) {
        background(() => pipe.send('Target.closeTarget', { targetId: info.targetId }));
        return;
      }
      tabs.set(info.targetId, Object.assign(previous ?? {}, { id: info.targetId,
        title: String(info.title ?? '').slice(0, 512), url: safeUrl, blocked: false }));
      tabsChanged();
      if (!previous && ready && info.openerId && tabs.has(info.openerId)) {
        background(() => activate(info.targetId));
      }
    } else if (method === 'Target.targetDestroyed') {
      const wasActive = activeId === params.targetId;
      tabs.delete(params.targetId);
      if (wasActive) {
        activeId = undefined;
        lastFrame = undefined;
        navigation = { canGoBack: false, canGoForward: false };
        background(async () => {
          const next = tabs.keys().next().value ?? await createTab('about:blank');
          await activate(next);
        });
      }
      tabsChanged();
    } else if (method === 'Inspector.detached' && tabs.get(activeId)?.sessionId === sessionId) {
      if (!tabs.get(activeId).closing && params.reason !== 'target_closed') fail();
    } else if (['Page.frameNavigated', 'Page.navigatedWithinDocument', 'Page.loadEventFired'].includes(method) &&
        tabs.get(activeId)?.sessionId === sessionId) {
      const destination = method === 'Page.frameNavigated' && !params.frame?.parentId ? params.frame?.url
        : method === 'Page.navigatedWithinDocument' ? params.url : undefined;
      if (destination) {
        try { navigationUrl(destination); } catch {
          tabs.get(activeId).blocked = true;
          lastFrame = undefined;
          const id = activeId;
          background(() => pipe.send('Target.closeTarget', { targetId: id }));
          return;
        }
      }
      void readHistory();
    }
  }

  pipe = new ChromePipe(child, onEvent, fail, timeoutMs);

  async function streaming(tab, enabled) {
    if (!tab?.sessionId || tab.streaming === enabled) return;
    tab.streaming = enabled;
    clearTimeout(captureTimer);
    const revision = ++streamRevision;
    if (!enabled) return;
    let failures = 0;
    const current = () => !closing && tab.streaming && !tab.blocked && tab.id === activeId &&
      revision === streamRevision && listeners.size > 0;
    const capture = async () => {
      if (!current()) return;
      const size = viewport;
      try {
        await enqueue(async () => {
          if (!current()) return;
          // Native macOS window bounds can clip startScreencast to the physical display (observed
          // 1440x718 on this Retina Mac despite a 1440x900 CSS viewport). Capture the renderer surface
          // directly instead: one in-flight capture, at most 10 fps, and only while viewers subscribe.
          const layout = await pipe.send('Page.getLayoutMetrics', {}, tab.sessionId);
          const visual = layout.cssVisualViewport;
          if (!visual || !Number.isFinite(visual.pageX) || !Number.isFinite(visual.pageY) ||
              visual.pageX < 0 || visual.pageY < 0 || visual.pageX > 1e8 || visual.pageY > 1e8 ||
              visual.clientWidth !== size.width || visual.clientHeight !== size.height) {
            throw new Error('Browser viewport unavailable');
          }
          const { data } = await pipe.send('Page.captureScreenshot', {
            format: 'jpeg', quality: 80, fromSurface: true, captureBeyondViewport: true,
            clip: { x: visual.pageX, y: visual.pageY, width: size.width, height: size.height, scale: 1 },
          }, tab.sessionId);
          if (!current() || size !== viewport) return;
          if (typeof data !== 'string' || data.length > 8 * 1024 * 1024 || !/^[A-Za-z0-9+/]+={0,2}$/.test(data)) {
            throw new Error('Browser frame unavailable');
          }
          lastFrame = { type: 'frame', data, width: size.width, height: size.height };
          failures = 0;
          emit(lastFrame);
        });
      } catch {
        failures += 1;
        if (current() && failures >= 3) return fail();
      } finally {
        if (current()) {
          captureTimer = setTimeout(capture, failures ? 1000 : captureIntervalMs);
          captureTimer.unref?.();
        }
      }
    };
    void capture();
  }

  async function attach(tab) {
    if (tab.sessionId) return;
    const attached = await pipe.send('Target.attachToTarget', { targetId: tab.id, flatten: true });
    tab.sessionId = attached.sessionId;
    await pageCommand('Page.enable', {}, tab.sessionId);
    // No file chooser events or uploads are exposed; a page cannot drive the Mac's native picker.
    await pageCommand('Page.setInterceptFileChooserDialog', { enabled: true }, tab.sessionId);
    await pageCommand('Emulation.setDeviceMetricsOverride', {
      width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false,
    }, tab.sessionId);
  }

  async function activate(id) {
    const tab = tabs.get(id);
    if (!tab || tab.blocked) throw new Error('Unknown browser tab');
    if (activeId !== id) {
      await streaming(tabs.get(activeId), false);
      lastFrame = undefined;
      pointerButtons = 0;
      navigation = { canGoBack: false, canGoForward: false };
    }
    await attach(tab);
    await pageCommand('Emulation.setDeviceMetricsOverride', {
      width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false,
    }, tab.sessionId);
    await pipe.send('Target.activateTarget', { targetId: id });
    activeId = id;
    tabsChanged();
    await streaming(tab, listeners.size > 0);
    await readHistory();
  }

  async function createTab(targetUrl) {
    if (tabs.size >= MAX_TABS) throw new Error('Browser tab limit reached');
    const result = await pipe.send('Target.createTarget', { url: targetUrl });
    if (!tabs.has(result.targetId)) tabs.set(result.targetId, {
      id: result.targetId, title: '', url: targetUrl, blocked: false,
    });
    return result.targetId;
  }

  function validateCommand(message) {
    if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Invalid browser command');
    const value = { ...message };
    const types = ['navigate', 'back', 'forward', 'reload', 'newTab', 'selectTab', 'closeTab', 'mouse', 'key', 'text'];
    if (!types.includes(value.type)) throw new Error('Invalid browser command');
    const fields = { navigate: ['url'], newTab: ['url'], back: [], forward: [], reload: [],
      selectTab: ['id'], closeTab: ['id'], text: ['text'],
      mouse: ['action', 'x', 'y', 'button', 'deltaX', 'deltaY', 'modifiers'],
      key: ['action', 'key', 'code', 'modifiers'] };
    if (Object.keys(value).some(key => key !== 'type' && !fields[value.type].includes(key))) {
      throw new Error('Invalid browser command fields');
    }
    if (['navigate', 'newTab'].includes(value.type)) value.url = navigationUrl(value.url ?? (value.type === 'newTab' ? 'about:blank' : undefined));
    if (['selectTab', 'closeTab'].includes(value.type) &&
        (typeof value.id !== 'string' || value.id.length > 128 || !tabs.has(value.id))) throw new Error('Unknown browser tab');
    if (value.type === 'text' && (typeof value.text !== 'string' || value.text.length > 4096 || value.text.includes('\0'))) {
      throw new Error('Invalid browser text');
    }
    if (['mouse', 'key'].includes(value.type)) {
      value.modifiers ??= 0;
      if (!Number.isInteger(value.modifiers) || value.modifiers < 0 || value.modifiers > 15) throw new Error('Invalid key modifiers');
    }
    if (value.type === 'mouse') {
      if (!['move', 'down', 'up', 'wheel'].includes(value.action) ||
          !Number.isFinite(value.x) || !Number.isFinite(value.y) || value.x < 0 || value.y < 0 ||
          value.x >= viewport.width || value.y >= viewport.height) throw new Error('Invalid pointer command');
      value.button ??= 'left';
      if (!['left', 'middle', 'right'].includes(value.button)) throw new Error('Invalid pointer button');
      if (value.action === 'wheel' && (!Number.isFinite(value.deltaX) || !Number.isFinite(value.deltaY) ||
          Math.abs(value.deltaX) > 2000 || Math.abs(value.deltaY) > 2000)) throw new Error('Invalid wheel command');
    }
    if (value.type === 'key' && (!['down', 'up'].includes(value.action) ||
        typeof value.key !== 'string' || value.key.length < 1 || value.key.length > 64 ||
        typeof value.code !== 'string' || !/^[A-Za-z0-9]{1,64}$/.test(value.code) ||
        /[\u0000-\u001f\u007f]/.test(value.key))) throw new Error('Invalid keyboard command');
    if (value.type === 'key' && (((value.modifiers & 6) && value.code === 'KeyV') ||
        ((value.modifiers & 8) && value.code === 'Insert'))) {
      throw new Error('Use explicit browser text input instead of the Mac clipboard');
    }
    return value;
  }

  async function perform(value, isAuthorized = () => true) {
    const { type } = value;
    if (type === 'newTab') return activate(await createTab(value.url));
    if (type === 'selectTab') return activate(value.id);
    if (type === 'closeTab') {
      const closingTab = tabs.get(value.id);
      if (!closingTab) throw new Error('Unknown browser tab');
      // Closing Chrome's final native window can quit the entire process. Keep one owned blank page
      // first, then close the requested tab; expected Inspector.detached may precede targetDestroyed.
      if (tabs.size === 1) await activate(await createTab('about:blank'));
      closingTab.closing = true;
      try { return await pipe.send('Target.closeTarget', { targetId: value.id }); } catch (error) {
        closingTab.closing = false;
        throw error;
      }
    }
    const tab = tabs.get(activeId);
    if (!tab?.sessionId || tab.blocked) throw new Error('Browser tab is unavailable');
    const send = (method, params) => pageCommand(method, params, tab.sessionId, isAuthorized);
    if (type === 'navigate') {
      const result = await send('Page.navigate', { url: value.url });
      if (result.errorText) throw new Error('Page could not be loaded');
    } else if (type === 'reload') await send('Page.reload', {});
    else if (type === 'back' || type === 'forward') {
      const history = await send('Page.getNavigationHistory', {});
      const entry = history.entries[history.currentIndex + (type === 'back' ? -1 : 1)];
      if (entry) await send('Page.navigateToHistoryEntry', { entryId: entry.id });
    } else if (type === 'text') await send('Input.insertText', { text: value.text });
    else if (type === 'key') await send('Input.dispatchKeyEvent', {
      type: value.action === 'down' ? (value.key === 'Enter' && !(value.modifiers & 7) ? 'keyDown' : 'rawKeyDown') : 'keyUp',
      key: value.key, code: value.code,
      modifiers: value.modifiers,
      windowsVirtualKeyCode: virtualKey(value.code),
      ...(value.action === 'down' && value.key === 'Enter' && !(value.modifiers & 7) ? { text: '\r' } : {}),
    });
    else if (type === 'mouse') {
      // Check again after queueing: another viewer may have resized the shared viewport.
      if (value.x >= viewport.width || value.y >= viewport.height) throw new Error('Pointer is outside browser viewport');
      const flag = { left: 1, right: 2, middle: 4 }[value.button];
      const nextButtons = value.action === 'down' ? pointerButtons | flag
        : value.action === 'up' ? pointerButtons & ~flag : pointerButtons;
      await send('Input.dispatchMouseEvent', {
        type: { move: 'mouseMoved', down: 'mousePressed', up: 'mouseReleased', wheel: 'mouseWheel' }[value.action],
        x: value.x, y: value.y, button: value.action === 'move'
          ? (nextButtons & 1 ? 'left' : nextButtons & 2 ? 'right' : nextButtons & 4 ? 'middle' : 'none')
          : value.action === 'wheel' ? 'none' : value.button,
        buttons: nextButtons,
        modifiers: value.modifiers, ...(['down', 'up'].includes(value.action) ? { clickCount: 1 } : {}),
        ...(value.action === 'wheel' ? { deltaX: value.deltaX, deltaY: value.deltaY } : {}),
      });
      pointerButtons = nextButtons;
    }
    if (['navigate', 'reload', 'back', 'forward'].includes(type)) await readHistory();
  }

  try {
    await Promise.race([startFailed.promise, (async () => {
      await pipe.send('Browser.getVersion');
      // Fail closed if this Chrome cannot enforce download denial. No files leave the browser sandbox
      // via a public control API; downloads can be added later only with an explicit managed boundary.
      await pipe.send('Browser.setDownloadBehavior', { behavior: 'deny' });
      await pipe.send('Target.setDiscoverTargets', { discover: true });
      const found = await pipe.send('Target.getTargets');
      for (const targetInfo of found.targetInfos ?? []) onEvent({ method: 'Target.targetCreated', params: { targetInfo } });
      const initial = tabs.keys().next().value ?? await createTab('about:blank');
      await activate(initial);
      await perform({ type: 'navigate', url });
    })()]);
    ready = true;
    return {
      transport: 'page', close, closed: finished.promise,
      getNavigation: readHistory,
      subscribe(listener) {
        if (closing || typeof listener !== 'function') throw new Error('Browser is unavailable');
        listeners.add(listener);
        try { listener(snapshot()); if (lastFrame) listener({ ...lastFrame }); } catch { /* Closed viewer. */ }
        background(() => streaming(tabs.get(activeId), listeners.size > 0));
        return () => {
          listeners.delete(listener);
          if (!closing) background(() => streaming(tabs.get(activeId), listeners.size > 0));
        };
      },
      command(message, { isAuthorized = () => true } = {}) {
        let value;
        try { value = validateCommand(message); } catch (error) { return Promise.reject(error); }
        return enqueue(() => {
          if (typeof isAuthorized !== 'function' || !isAuthorized()) throw new Error('Browser authorization expired');
          return perform(value, isAuthorized);
        });
      },
      resize(value) {
        let next;
        try { next = viewportValue(value); } catch (error) { return Promise.reject(error); }
        return enqueue(async () => {
          const tab = tabs.get(activeId);
          if (!tab?.sessionId) throw new Error('Browser tab is unavailable');
          await streaming(tab, false);
          try {
            await pageCommand('Emulation.setDeviceMetricsOverride', {
              width: next.width, height: next.height, deviceScaleFactor: 1, mobile: false,
            }, tab.sessionId);
          } catch (error) {
            // A failed resize must not strand subscribers with a stopped stream. Reassert the old
            // viewport before resuming; fail closed if Chrome cannot restore a trustworthy mapping.
            try {
              await pageCommand('Emulation.setDeviceMetricsOverride', {
                width: viewport.width, height: viewport.height, deviceScaleFactor: 1, mobile: false,
              }, tab.sessionId);
              await streaming(tab, listeners.size > 0);
            } catch { fail(); }
            throw error;
          }
          viewport = next;
          lastFrame = undefined;
          await streaming(tab, listeners.size > 0);
          return { ...viewport };
        });
      },
    };
  } catch (error) {
    await close();
    throw error;
  }
}

// Only key identifiers are accepted from clients; native editor commands and text are not forwarded.
function virtualKey(code) {
  if (/^Key[A-Z]$/.test(code)) return code.charCodeAt(3);
  if (/^Digit[0-9]$/.test(code)) return code.charCodeAt(5);
  return { Backspace: 8, Tab: 9, Enter: 13, NumpadEnter: 13, ShiftLeft: 16, ShiftRight: 16,
    ControlLeft: 17, ControlRight: 17, AltLeft: 18, AltRight: 18, Escape: 27, Space: 32,
    PageUp: 33, PageDown: 34, End: 35, Home: 36, ArrowLeft: 37, ArrowUp: 38,
    ArrowRight: 39, ArrowDown: 40, Delete: 46, MetaLeft: 91, MetaRight: 92 }[code] ?? 0;
}
