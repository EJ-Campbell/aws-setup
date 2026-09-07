import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import { mkdtemp, mkdir, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { launchMacDesktop } from '../lib/macos-desktop.mjs';

async function fixture(t, overrides = {}) {
  const directory = await realpath(await mkdtemp(join(tmpdir(), 'bm-mac-unit-')));
  const profile = join(directory, 'profile');
  const runtimeDir = join(directory, 'run');
  await mkdir(profile, { mode: 0o700 });
  await mkdir(runtimeDir, { mode: 0o700 });
  t.after(() => rm(directory, { recursive: true, force: true }));
  const child = new EventEmitter();
  Object.assign(child, { pid: 12345678, exitCode: null, signalCode: null });
  const kills = [];
  const commands = [];
  const output = new PassThrough();
  let launch;
  let bytes = '';
  const targets = new Map([['tab1', { targetId: 'tab1', type: 'page', title: 'Blank', url: 'about:blank' }]]);
  let counter = 1;
  const sizes = new Map();
  const event = (method, params = {}, sessionId) => output.write(`${JSON.stringify({ method, params, sessionId })}\0`);
  const input = new Writable({ write(part, _encoding, callback) {
    bytes += part.toString();
    let index;
    while ((index = bytes.indexOf('\0')) !== -1) {
      const command = JSON.parse(bytes.slice(0, index));
      bytes = bytes.slice(index + 1);
      commands.push(command);
      if (overrides.ignore === command.method) continue;
      let result = {};
      if (command.method === 'Target.getTargets') result = { targetInfos: [...targets.values()] };
      if (command.method === 'Target.attachToTarget') result = { sessionId: `session-${command.params.targetId}` };
      if (command.method === 'Page.getNavigationHistory') result = {
        currentIndex: 1, entries: [{ id: 10 }, { id: 11 }, { id: 12 }],
      };
      if (command.method === 'Emulation.setDeviceMetricsOverride') sizes.set(command.sessionId, command.params);
      if (command.method === 'Page.getLayoutMetrics') {
        const size = sizes.get(command.sessionId) ?? { width: 1440, height: 900 };
        result = { cssVisualViewport: { pageX: 0, pageY: 0, clientWidth: size.width, clientHeight: size.height } };
      }
      if (command.method === 'Page.captureScreenshot') result = { data: '/9j/2Q==' };
      if (command.method === 'Target.createTarget') {
        const targetId = `tab${++counter}`;
        const targetInfo = { targetId, type: 'page', title: '', url: command.params.url };
        targets.set(targetId, targetInfo);
        event('Target.targetCreated', { targetInfo });
        result = { targetId };
      }
      if (command.method === 'Target.closeTarget') {
        event('Inspector.detached', { reason: 'target_closed' }, `session-${command.params.targetId}`);
        targets.delete(command.params.targetId);
        event('Target.targetDestroyed', { targetId: command.params.targetId });
      }
      output.write(`${JSON.stringify({ id: command.id, result,
        ...(overrides.error === command.method || (overrides.failPhone && command.method === 'Emulation.setDeviceMetricsOverride' && command.params.width === 390)
          ? { error: { message: 'secret private browser error' } } : {}),
      })}\0`);
    }
    callback();
  } });
  child.stdio = [null, null, null, input, output];
  child.kill = (name) => {
    kills.push(['child', name]);
    child.signalCode = name;
    queueMicrotask(() => child.emit('exit', null, name));
  };
  const controller = new AbortController();
  const options = { runtimeDir, profile, browserBin: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    url: 'https://example.test/', signal: controller.signal };
  const deps = { spawnProcess: (bin, args, options) => {
    launch = { bin, args, options };
    return child;
  }, killGroup: (pid, name) => kills.push([pid, name]), timeoutMs: 40, shutdownMs: 40, captureIntervalMs: 5 };
  let desktop;
  if (!overrides.noLaunch) {
    desktop = await launchMacDesktop(options, deps);
    t.after(() => desktop.close());
  }
  return { desktop, child, commands, kills, event, output, options, deps, controller,
    launch: () => launch, targets };
}

test('headed Chrome has a dedicated profile, no listening debug port and the renderer sandbox enabled', async (t) => {
  const f = await fixture(t);
  const launch = f.launch();
  assert.equal(f.desktop.transport, 'page');
  assert.equal(launch.options.shell, false);
  assert.equal(launch.options.detached, true);
  assert.deepEqual(launch.options.stdio, ['ignore', 'ignore', 'ignore', 'pipe', 'pipe']);
  assert(launch.args.includes(`--user-data-dir=${f.options.profile}`));
  assert(launch.args.includes('--remote-debugging-pipe'));
  assert(!launch.args.some(value => /--headless|--no-sandbox|--remote-debugging-port|--disable-web-security/.test(value)));
  assert.deepEqual(f.commands.find(c => c.method === 'Browser.setDownloadBehavior').params, { behavior: 'deny' });
  assert(f.commands.some(c => c.method === 'Page.setInterceptFileChooserDialog'));
});

test('URL, path and private-directory validation runs before Chrome spawn', async (t) => {
  const f = await fixture(t, { noLaunch: true });
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,test', 'chrome://settings',
    'http://user:pass@example.test', 'https://example.test/\n', 'about:config']) {
    await assert.rejects(launchMacDesktop({ ...f.options, url }, f.deps), /Invalid browser URL/);
  }
  await assert.rejects(launchMacDesktop({ ...f.options, profile: 'relative' }, f.deps), /absolute/);
  assert.equal(f.launch(), undefined);
});

test('only bounded fixed commands reach CDP', async (t) => {
  const f = await fixture(t);
  const before = f.commands.length;
  for (const message of [null, [], { type: 'Runtime.evaluate', expression: '1+1' },
    { type: 'navigate', url: 'file:///private' }, { type: 'selectTab', id: 'other-process' },
    { type: 'text', text: 'x'.repeat(4097) }, { type: 'text', text: '\0' },
    { type: 'mouse', action: 'move', x: Infinity, y: 1 },
    { type: 'mouse', action: 'down', x: 1440, y: 1 },
    { type: 'mouse', action: 'up', x: 1, y: 1, button: 'back' },
    { type: 'mouse', action: 'wheel', x: 1, y: 1, deltaX: 0, deltaY: 2001 },
    { type: 'key', action: 'down', key: 'a', code: 'KeyA', modifiers: 16 },
    { type: 'key', action: 'press', key: 'a', code: 'KeyA' },
    { type: 'key', action: 'down', key: 'v', code: 'KeyV', modifiers: 4 },
    { type: 'key', action: 'down', key: 'Insert', code: 'Insert', modifiers: 8 },
    { type: 'reload', method: 'Runtime.evaluate' }, { type: 'text', text: 'x', path: '/private' }]) {
    await assert.rejects(f.desktop.command(message));
  }
  assert.equal(f.commands.length, before);
  await f.desktop.command({ type: 'text', text: 'Hello 😀' });
  assert.deepEqual(f.commands.at(-1).params, { text: 'Hello 😀' });
  await f.desktop.command({ type: 'key', action: 'down', key: 'Enter', code: 'Enter' });
  assert.deepEqual(f.commands.at(-1).params, {
    type: 'keyDown', key: 'Enter', code: 'Enter', modifiers: 0, windowsVirtualKeyCode: 13, text: '\r',
  });
  assert(!f.commands.some(c => /Runtime\.|Network\.|Storage\.|DOM\./.test(c.method)));
});

test('navigation, mouse and shared tabs use only owned sessions', async (t) => {
  const f = await fixture(t);
  const received = [];
  const unsubscribe = f.desktop.subscribe(m => received.push(m));
  await f.desktop.command({ type: 'back' });
  assert(f.commands.some(c => c.method === 'Page.navigateToHistoryEntry' && c.params.entryId === 10));
  await f.desktop.command({ type: 'forward' });
  assert(f.commands.some(c => c.method === 'Page.navigateToHistoryEntry' && c.params.entryId === 12));
  await f.desktop.command({ type: 'newTab', url: 'https://example.test/second' });
  assert.equal(received.filter(m => m.type === 'tabs').at(-1).activeId, 'tab2');
  await f.desktop.command({ type: 'mouse', action: 'down', button: 'left', x: 50, y: 60 });
  assert.equal(f.commands.findLast(c => c.method === 'Input.dispatchMouseEvent').sessionId, 'session-tab2');
  assert.equal(f.commands.findLast(c => c.method === 'Input.dispatchMouseEvent').params.clickCount, 1);
  await f.desktop.command({ type: 'selectTab', id: 'tab1' });
  assert.equal(received.filter(m => m.type === 'tabs').at(-1).activeId, 'tab1');
  unsubscribe();
});

test('page surface frames are viewport bounded and snapshots are isolated between viewers', async (t) => {
  const f = await fixture(t);
  const received = [];
  f.desktop.subscribe(m => received.push(m));
  await delay(5);
  assert.equal(received.at(-1).type, 'frame');
  assert.equal(received.at(-1).width, 1440);
  assert(f.commands.some(c => c.method === 'Page.captureScreenshot' && c.params.captureBeyondViewport === true));
  const replay = [];
  f.desktop.subscribe(m => { replay.push(m); if (m.type === 'tabs') m.tabs[0].title = 'tampered'; });
  assert.deepEqual(replay.map(m => m.type), ['tabs', 'frame']);
  const third = [];
  f.desktop.subscribe(m => third.push(m));
  assert.equal(third[0].tabs[0].title, 'Blank');
  await f.desktop.resize({ mode: 'phone', width: 390, height: 844 });
  await delay(10);
  assert.equal(received.at(-1).width, 390);
  await assert.rejects(f.desktop.resize({ mode: 'phone', width: 1600, height: 900 }));
  await assert.rejects(f.desktop.command({ type: 'mouse', action: 'move', x: 500, y: 1 }));
});

test('popup discovery is confined to the owned pipe and unsafe pages are not streamed', async (t) => {
  const f = await fixture(t);
  const received = [];
  f.desktop.subscribe(m => received.push(m));
  f.event('Target.targetCreated', { targetInfo: { targetId: 'popup', type: 'page',
    title: 'Sign in', url: 'https://login.example.test/', openerId: 'tab1' } });
  await delay(5);
  assert.equal(received.filter(m => m.type === 'tabs').at(-1).activeId, 'popup');
  const before = received.filter(m => m.type === 'frame').length;
  f.event('Target.targetInfoChanged', { targetInfo: { targetId: 'popup', type: 'page', url: 'file:///private' } });
  f.event('Page.screencastFrame', { sessionId: 1, data: '/9j/2Q==',
    metadata: { deviceWidth: 1440, deviceHeight: 900 } }, 'session-popup');
  assert.equal(received.filter(m => m.type === 'frame').length, before);
  await delay(5);
  assert(f.commands.some(c => c.method === 'Target.closeTarget' && c.params.targetId === 'popup'));
});

test('closing and pipe loss terminate only this owned process group', async (t) => {
  const f = await fixture(t);
  const received = [];
  f.desktop.subscribe(m => received.push(m));
  f.output.end();
  await f.desktop.closed;
  assert(received.some(m => m.type === 'error' && m.message === 'Managed Chrome disconnected'));
  assert.deepEqual(f.kills, [['child', 'SIGINT'], [12345678, 'SIGKILL']]);
  await f.desktop.close();
  assert.equal(f.kills.length, 2);
  await assert.rejects(f.desktop.command({ type: 'reload' }));
});

test('CDP errors are safe and startup download-denial failure closes Chrome', async (t) => {
  const f = await fixture(t, { noLaunch: true, error: 'Browser.setDownloadBehavior' });
  await assert.rejects(launchMacDesktop(f.options, f.deps), { message: 'Browser command failed' });
  assert.deepEqual(f.kills, [['child', 'SIGINT'], [12345678, 'SIGKILL']]);
});

test('command queue is bounded and timeouts do not reveal browser data', async (t) => {
  const f = await fixture(t, { ignore: 'Input.insertText' });
  const keepAlive = setInterval(() => {}, 1000);
  t.after(() => clearInterval(keepAlive));
  const first = f.desktop.command({ type: 'text', text: 'secret content' });
  await assert.rejects(first, { message: 'Browser command timed out' });
  const results = Array.from({ length: 70 }, () => f.desktop.command({ type: 'text', text: 'x' }).catch(e => e.message));
  await delay(1);
  await f.desktop.close();
  assert((await Promise.all(results)).some(value => value === 'Browser is busy or unavailable'));
});

test('authorization is rechecked after a command waits behind another viewer', async (t) => {
  const f = await fixture(t, { ignore: 'Input.insertText' });
  const keepAlive = setInterval(() => {}, 1000);
  t.after(() => clearInterval(keepAlive));
  let authorized = true;
  const held = f.desktop.command({ type: 'text', text: 'held' }).catch(e => e.message);
  const queued = f.desktop.command({ type: 'reload' }, { isAuthorized: () => authorized }).catch(e => e.message);
  authorized = false;
  assert.equal(await held, 'Browser command timed out');
  assert.equal(await queued, 'Browser authorization expired');
  assert(!f.commands.some(c => c.method === 'Page.reload'));
});

test('malformed pipe messages fail closed and emit a subscriber cleanup event', async (t) => {
  const f = await fixture(t);
  const received = [];
  f.desktop.subscribe(m => received.push(m));
  f.output.write('not-json\0');
  await f.desktop.closed;
  assert.equal(received.at(-1).type, 'closed');
  assert.equal(f.kills.at(-1)[0], f.child.pid);
});

test('aborting a live desktop closes its owned Chrome', async (t) => {
  const f = await fixture(t);
  f.controller.abort();
  await f.desktop.closed;
  assert.equal(f.kills.at(-1)[0], f.child.pid);
});

test('two viewers keep shared frames alive and the last unsubscribe stops capture', async (t) => {
  const f = await fixture(t);
  const first = [], second = [];
  await delay(10);
  assert(!f.commands.some(c => c.method === 'Page.captureScreenshot'));
  const stopFirst = f.desktop.subscribe(m => first.push(m));
  await delay(15);
  const stopSecond = f.desktop.subscribe(m => second.push(m));
  await delay(15);
  stopFirst();
  const count = second.filter(m => m.type === 'frame').length;
  await delay(15);
  assert(second.filter(m => m.type === 'frame').length > count);
  stopSecond();
  await delay(10);
  const stoppedCount = f.commands.filter(c => c.method === 'Page.captureScreenshot').length;
  await delay(15);
  assert.equal(f.commands.filter(c => c.method === 'Page.captureScreenshot').length, stoppedCount);
  f.desktop.subscribe(() => {});
  await delay(15);
  assert(f.commands.filter(c => c.method === 'Page.captureScreenshot').length > stoppedCount);
});

test('expected active-tab detach does not close Chrome, including the final tab', async (t) => {
  const f = await fixture(t);
  const messages = [];
  f.desktop.subscribe(message => messages.push(message));
  await f.desktop.command({ type: 'newTab', url: 'https://example.test/second' });
  await f.desktop.command({ type: 'closeTab', id: 'tab2' });
  await delay(5);
  assert.equal(messages.filter(m => m.type === 'tabs').at(-1).activeId, 'tab1');
  assert.equal(f.kills.length, 0);
  await f.desktop.command({ type: 'closeTab', id: 'tab1' });
  await delay(5);
  const latest = messages.filter(m => m.type === 'tabs').at(-1);
  assert.equal(latest.tabs.length, 1);
  assert.equal(latest.tabs[0].url, 'about:blank');
  assert.equal(f.kills.length, 0);
  assert(!messages.some(m => m.type === 'closed'));
});

test('mouse moves preserve shared held-button state for drag controls', async (t) => {
  const f = await fixture(t);
  await f.desktop.command({ type: 'mouse', action: 'down', x: 10, y: 10, button: 'left' });
  await f.desktop.command({ type: 'mouse', action: 'move', x: 30, y: 30, button: 'left' });
  let move = f.commands.findLast(c => c.method === 'Input.dispatchMouseEvent');
  assert.equal(move.params.buttons, 1);
  assert.equal(move.params.button, 'left');
  await f.desktop.command({ type: 'mouse', action: 'up', x: 30, y: 30, button: 'left' });
  await f.desktop.command({ type: 'mouse', action: 'move', x: 40, y: 40 });
  move = f.commands.findLast(c => c.method === 'Input.dispatchMouseEvent');
  assert.equal(move.params.buttons, 0);
  assert.equal(move.params.button, 'none');
});

test('failed resize restores the prior viewport and resumes its stream', async (t) => {
  const overrides = {};
  const f = await fixture(t, overrides);
  const messages = [];
  f.desktop.subscribe(message => messages.push(message));
  await delay(10);
  // The fake fails only the new phone metrics; reasserting the old desktop size can succeed.
  overrides.failPhone = true;
  await assert.rejects(f.desktop.resize({ mode: 'phone', width: 390, height: 844 }));
  const count = messages.filter(m => m.type === 'frame').length;
  await delay(15);
  assert(messages.filter(m => m.type === 'frame').length > count);
  assert.equal(messages.filter(m => m.type === 'frame').at(-1).width, 1440);
});
