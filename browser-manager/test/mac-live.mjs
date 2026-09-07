// Opt-in native smoke only: node test/mac-live.mjs. Creates a private temporary profile and closes
// only its own Chrome child. No personal profiles, services, screenshots, or authentication are read.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { launchMacDesktop } from '../lib/macos-desktop.mjs';

if (process.platform !== 'darwin') throw new Error('This opt-in test requires native macOS');
const directory = await realpath(await mkdtemp(join(tmpdir(), 'bm-native-smoke-')));
const profile = join(directory, 'profile');
const runtimeDir = join(directory, 'run');
await mkdir(profile, { mode: 0o700 });
await mkdir(runtimeDir, { mode: 0o700 });
const requests = [];
const server = createServer((request, response) => {
  requests.push({ url: request.url, cookie: request.headers.cookie });
  response.setHeader('Content-Type', 'text/html');
  response.setHeader('Cache-Control', 'no-store');
  if (request.url === '/set-cookie') response.setHeader('Set-Cookie', 'smoke=persisted; Max-Age=3600; SameSite=Lax; Path=/');
  response.end(`<!doctype html><title>Managed native smoke</title><body style="margin:0;background:#eff8ff">
    <button style="position:absolute;left:20px;top:20px;width:180px;height:40px" onclick="fetch('/clicked')">Click</button>
    <form action="/typed"><input name="text" style="position:absolute;left:20px;top:90px;width:260px;height:35px"></form>
    <button style="position:absolute;left:20px;top:150px;width:180px;height:40px" onclick="window.open('/popup','_blank')">Popup</button>
    <p style="position:absolute;top:240px">Actual headed Chrome on macOS</p></body>`);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const options = { runtimeDir, profile,
  browserBin: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  url: `${base}/set-cookie`, signal: new AbortController().signal };
let desktop;
const frames = [];
const tabs = [];
const errors = [];
let keychainDenied = false;
const testDependencies = { spawnProcess: (...args) => {
  args[2] = { ...args[2], stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] };
  const child = spawn(...args);
  child.stderr.on('data', bytes => {
    if (/errSecInteractionNotAllowed|Code=-25308/.test(bytes.toString())) keychainDenied = true;
  });
  return child;
} };
async function waitFor(check, description) {
  const deadline = Date.now() + 15_000;
  while (!await check()) {
    if (Date.now() > deadline) throw new Error(`Native smoke timed out: ${description}`);
    await delay(50);
  }
}
async function click(x, y) {
  await desktop.command({ type: 'mouse', action: 'down', x, y, button: 'left' });
  await desktop.command({ type: 'mouse', action: 'up', x, y, button: 'left' });
}
function jpegSize(data) {
  const bytes = Buffer.from(data, 'base64');
  assert.equal(bytes.readUInt16BE(0), 0xffd8);
  for (let i = 2; i + 9 < bytes.length;) {
    if ([0xffc0, 0xffc1, 0xffc2].includes(bytes.readUInt16BE(i))) {
      return { width: bytes.readUInt16BE(i + 7), height: bytes.readUInt16BE(i + 5) };
    }
    const length = bytes.readUInt16BE(i + 2);
    assert(length >= 2);
    i += 2 + length;
  }
  throw new Error('Native Chrome returned an invalid JPEG');
}
try {
  desktop = await launchMacDesktop(options, testDependencies);
  const record = message => {
    if (message.type === 'frame') frames.push(message);
    if (message.type === 'tabs') tabs.push(message);
    if (message.type === 'error') errors.push(message.message);
  };
  const stopFirst = desktop.subscribe(record);
  await waitFor(() => frames.length, 'first headed frame');
  assert.equal(frames[0].width, 1440);
  assert.equal(frames[0].height, 900);
  assert.deepEqual(jpegSize(frames[0].data), { width: 1440, height: 900 });
  const secondFrames = [];
  const stopSecond = desktop.subscribe(message => { if (message.type === 'frame') secondFrames.push(message); });
  await waitFor(() => secondFrames.length >= 2, 'second viewer capture');
  stopFirst();
  const count = secondFrames.length;
  await waitFor(() => secondFrames.length > count, 'remaining viewer capture');
  stopSecond();
  desktop.subscribe(record);
  await click(70, 40);
  await waitFor(() => requests.some(r => r.url === '/clicked'), 'page-only pointer click');
  await click(80, 105);
  await desktop.command({ type: 'text', text: 'native mac smoke' });
  await desktop.command({ type: 'key', action: 'down', key: 'Enter', code: 'Enter' });
  await desktop.command({ type: 'key', action: 'up', key: 'Enter', code: 'Enter' });
  await waitFor(() => requests.some(r => r.url === '/typed?text=native+mac+smoke'), 'text and Enter input');
  await desktop.command({ type: 'navigate', url: `${base}/second` });
  await waitFor(() => requests.some(r => r.url === '/second'), 'navigation');
  assert(requests.find(r => r.url === '/second').cookie?.includes('smoke=persisted'), 'fixture cookie exists before restart');
  await waitFor(async () => (await desktop.getNavigation()).canGoBack === true, 'navigation history after commit');
  await desktop.command({ type: 'back' });
  await desktop.command({ type: 'forward' });
  await desktop.resize({ mode: 'phone', width: 390, height: 844 });
  await waitFor(() => frames.some(f => f.width === 390 && f.height === 844), 'phone viewport');
  assert.deepEqual(jpegSize(frames.find(f => f.width === 390).data), { width: 390, height: 844 });
  await desktop.command({ type: 'navigate', url: `${base}/popup-launch` });
  await delay(300);
  const beforePopup = tabs.at(-1).tabs.length;
  await click(60, 165);
  await waitFor(() => tabs.at(-1).tabs.length > beforePopup, 'owned OAuth-style popup');
  await waitFor(() => tabs.at(-1).tabs.find(t => t.id === tabs.at(-1).activeId)?.url.endsWith('/popup'), 'popup activation');
  await desktop.command({ type: 'newTab', url: `${base}/new-tab` });
  await waitFor(() => tabs.at(-1).tabs.find(t => t.id === tabs.at(-1).activeId)?.url.endsWith('/new-tab'), 'new tab');
  await desktop.command({ type: 'closeTab', id: tabs.at(-1).activeId });
  await delay(200);
  await assert.rejects(desktop.command({ type: 'navigate', url: 'file:///etc/passwd' }));
  await desktop.close();
  await desktop.closed;
  console.log('Native Mac page/input/tabs/phone smoke passed; checking encrypted cookie persistence.');
  desktop = await launchMacDesktop({ ...options, url: `${base}/after-restart` }, testDependencies);
  await waitFor(() => requests.some(r => r.url === '/after-restart'), 'restart navigation');
  assert(requests.find(r => r.url === '/after-restart').cookie?.includes('smoke=persisted'), keychainDenied
    ? 'macOS Keychain denied Chrome encryption (-25308); run in the signed-in GUI session and approve any macOS Keychain prompt. No insecure bypass was used.'
    : 'Synthetic persistent cookie did not survive a normal Chrome restart');
  assert.deepEqual(errors, []);
  console.log('Native Mac smoke passed: headed JPEG page stream, CSS dimensions, click, text+Enter, history, phone resize, popup, tabs, URL guard, profile persistence, owned cleanup.');
} finally {
  await desktop?.close();
  await new Promise(resolve => server.close(resolve));
  await rm(directory, { recursive: true, force: true });
}
