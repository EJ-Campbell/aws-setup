// Optional host acceptance: real sandboxed desktops, production UI, and signed test identity.
// No production auth bypass, browser debugging port, or existing profile is used.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chromium, expect } from '@playwright/test';
import { generateKeyPair, SignJWT } from 'jose';
import next from 'next';
import { createAuthorizer } from '../lib/auth.mjs';
import { createHttpServer } from '../lib/http.mjs';
import { createInstanceManager } from '../lib/instances.mjs';

process.umask(0o077);
const browserBin = process.env.BM_BROWSER_BIN;
assert.ok(browserBin?.startsWith('/'), 'Set BM_BROWSER_BIN to an installed, sandbox-capable Chromium binary');
const project = dirname(dirname(fileURLToPath(import.meta.url)));
const stateDir = await mkdtemp(join(tmpdir(), 'bm-acceptance-'));
const shots = join(homedir(), 'browser-manager-ui-artifacts', new Date().toISOString().replaceAll(':', '-'));
await mkdir(shots, { recursive: true, mode: 0o700 });
const listen = (server, address) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(address, () => { server.off('error', reject); resolve(server.address()); });
});
const closeServer = server => new Promise(resolve => {
  server?.closeVnc?.(); server?.closeAllConnections();
  if (server) server.close(resolve); else resolve();
});
const events = [];
const remoteViewport = name => {
  const event = events.findLast(event => event.name === name && event.kind === 'viewport');
  return event ? JSON.parse(event.value) : null;
};
const fixture = createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/event') {
    events.push(Object.fromEntries(url.searchParams)); res.end('ok'); return;
  }
  const name = url.pathname === '/beta' ? 'beta' : 'alpha';
  res.setHeader('Content-Type', 'text/html');
  res.end(`<!doctype html><html><head><title>${name} isolated browser</title><style>
    body{margin:48px;background:#f1f5f9;color:#172033;font:24px system-ui}h1{font-size:52px}
    input{padding:20px;width:80%;font:28px system-ui}button{margin-top:32px;padding:32px;font:24px system-ui}
    .mode-paint{position:fixed;right:8px;bottom:8px;width:16px;height:16px;background:#3b82f6;pointer-events:none}
    @media(max-width:500px){body{margin:20px;font-size:18px}h1{font-size:30px}input{box-sizing:border-box;width:100%;padding:14px;font-size:18px}.mode-paint{background:#8b5cf6}}
    </style></head><body><h1>${name}: private desktop</h1><p>This browser has its own persistent profile.</p>
    <input autofocus placeholder="Type here from your phone"><p>Pointer and keyboard acceptance fixture.</p><span class="mode-paint" aria-hidden="true"></span>
    <script>const name=${JSON.stringify(name)};const report=(kind,value)=>fetch('/event?'+new URLSearchParams({name,kind,value}));
    report('profile',localStorage.getItem('owner')||'fresh');localStorage.setItem('owner',name);
    const reportViewport=()=>report('viewport',JSON.stringify({width:innerWidth,height:innerHeight,
      phone:matchMedia('(max-width:500px)').matches,font:getComputedStyle(document.querySelector('h1')).fontSize,
      value:document.querySelector('input').value,url:location.pathname+location.search,
      profile:localStorage.getItem('owner'),overflow:document.documentElement.scrollWidth>innerWidth}));
    addEventListener('resize',reportViewport);
    addEventListener('pageshow',()=>{report('location',location.pathname+location.search);
      report('history-length',String(history.length));reportViewport();});
    document.querySelector('input').addEventListener('input',e=>{
      document.body.style.background='#d5f4e6';report('input',e.target.value);
    });
    document.addEventListener('pointerdown',()=>report('pointer','received'));</script></body></html>`);
});
const fixtureAddress = await listen(fixture, { host: '127.0.0.1', port: 0 });
const fixtureOrigin = `http://127.0.0.1:${fixtureAddress.port}`;
const config = { baseUrl: 'http://127.0.0.1', issuer: 'https://test.cloudflareaccess.com',
  audience: 'local-acceptance', owner: 'owner@example.test' };
const keys = await generateKeyPair('RS256');
const token = await new SignJWT({ email: config.owner }).setProtectedHeader({ alg: 'RS256' })
  .setSubject('local-owner').setIssuer(config.issuer).setAudience(config.audience)
  .setIssuedAt().setExpirationTime('15m').sign(keys.privateKey);
let manager, app, server, control, browser, peerBrowser, activePage;
try {
  app = next({ dev: false, dir: project, hostname: '127.0.0.1' });
  await app.prepare();
  server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: app.getRequestHandler() });
  const address = await listen(server, { host: '127.0.0.1', port: 0 });
  config.baseUrl = `http://127.0.0.1:${address.port}`;
  // Create API after the ephemeral listening port is known, so exact-Origin checks use it.
  await closeServer(server);
  manager = createInstanceManager({ stateDir, browserBin, baseUrl: config.baseUrl });
  await manager.initialize();
  server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: app.getRequestHandler() });
  await listen(server, { host: '127.0.0.1', port: address.port });
  control = createHttpServer({ manager, config, local: true });
  await listen(control, join(stateDir, 'control.sock'));
  const cli = (...args) => promisify(execFile)(process.execPath, [join(project, 'bin/browserctl.mjs'), ...args], {
    env: { ...process.env, BM_STATE_DIR: stateDir }, timeout: 45000,
  });
  assert.equal((await fetch(config.baseUrl)).status, 401);
  await cli('start', 'alpha', '--url', `${fixtureOrigin}/alpha`);
  await cli('start', 'beta', '--url', `${fixtureOrigin}/beta`);
  await expect.poll(() => events.filter(e => e.kind === 'profile').length).toBe(2);
  assert.deepEqual(events.filter(e => e.kind === 'profile').map(e => e.value), ['fresh', 'fresh']);
  assert.equal(manager.list().filter(row => row.state === 'running').length, 2);
  console.log('Two real sandboxed browsers started with isolated profiles and private sockets.');

  browser = await chromium.launch({ executablePath: browserBin, chromiumSandbox: true });
  const errors = [];
  for (const [label, viewport] of [['desktop', { width: 1440, height: 1000 }], ['phone', { width: 390, height: 844 }]]) {
    const context = await browser.newContext({ viewport, extraHTTPHeaders: { 'Cf-Access-Jwt-Assertion': token },
      isMobile: label === 'phone', hasTouch: label === 'phone' });
    await context.addInitScript(supported => {
      Object.defineProperty(document, 'fullscreenEnabled', { get: () => supported });
    }, label === 'desktop');
    const page = await context.newPage();
    activePage = page;
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(config.baseUrl);
    await expect(page.getByRole('heading', { name: 'alpha', exact: true })).toBeVisible();
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label} dashboard overflow`);
    await page.screenshot({ path: join(shots, `${label}-dashboard.png`), fullPage: true });
    const selected = label === 'phone' ? 'beta' : 'alpha';
    await page.getByRole('listitem').filter({ has: page.getByRole('heading', { name: selected, exact: true }) })
      .getByRole('link', { name: 'Open desktop', exact: true }).click();
    await expect(page).toHaveURL(`${config.baseUrl}/browsers/${selected}`);
    await expect(page.getByRole('status').filter({ hasText: /^Connected$/ })).toBeVisible({ timeout: 15000 });
    const back = page.getByRole('button', { name: 'Back in remote browser', exact: true });
    await expect(back).toHaveText('Back');
    await expect(back).toBeDisabled();
    if (label === 'desktop') await expect(page.getByRole('button', { name: 'Enter fullscreen', exact: true })).toBeVisible();
    else await expect(page.getByRole('button', { name: /^(Enter|Exit) fullscreen$/ })).toHaveCount(0);
    const canvas = page.locator('.vnc-screen canvas');
    await expect(canvas).toBeVisible();
    await page.getByRole('button', { name: 'Keyboard', exact: true }).click();
    await page.getByRole('textbox', { name: 'Text for the remote desktop' }).fill(`typed-from-${label}`);
    await page.getByRole('button', { name: 'Type text', exact: true }).click();
    await expect.poll(() => events.some(e => e.name === (label === 'phone' ? 'beta' : 'alpha') &&
      e.kind === 'input' && e.value === `typed-from-${label}`)).toBe(true);
    // Input reaching Chrome is insufficient: its resulting paint must return through VNC.
    await expect.poll(() => canvas.evaluate(node => [...node.getContext('2d').getImageData(100, node.height - 40, 1, 1).data]))
      .toEqual([213, 244, 230, 255]);
    await page.screenshot({ path: join(shots, `${label}-keyboard.png`), fullPage: true });
    await page.bringToFront();
    // Require a fresh transport after the drop; a stale Connected label cannot satisfy this.
    const automaticSocket = page.waitForEvent('websocket', {
      predicate: socket => new URL(socket.url()).pathname === `/browsers/${selected}/vnc`, timeout: 15000,
    });
    server.closeVnc();
    await automaticSocket;
    await expect(page.getByRole('status').filter({ hasText: /^Connected$/ })).toBeVisible({ timeout: 15000 });
    await expect.poll(() => canvas.evaluate(node => [...node.getContext('2d').getImageData(100, node.height - 40, 1, 1).data]))
      .toEqual([213, 244, 230, 255]);
    await expect(page).toHaveURL(`${config.baseUrl}/browsers/${selected}`);
    await page.screenshot({ path: join(shots, `${label}-auto-reconnected.png`), fullPage: true });
    // Navigate the actual remote Chrome, then use the viewer toolbar to go back. pageshow
    // reports both a network reload and a back/forward-cache restore without using CDP.
    const nextLocation = `/${selected}?history=next-${label}`;
    await page.getByRole('button', { name: 'Address bar', exact: true }).click();
    await page.getByRole('textbox', { name: 'Text for the remote desktop' }).fill(`${fixtureOrigin}${nextLocation}`);
    await page.getByRole('button', { name: 'Type text', exact: true }).click();
    await page.getByRole('button', { name: 'Enter ↵', exact: true }).click();
    await expect.poll(() => events.some(e => e.name === selected && e.kind === 'location' && e.value === nextLocation)).toBe(true);
    await page.getByRole('button', { name: 'Close keyboard controls' }).click();
    const beforeBack = events.length;
    await expect(back).toBeEnabled();
    await back.click();
    await expect.poll(() => events.slice(beforeBack).some(e => e.name === selected && e.kind === 'location' && e.value === `/${selected}`)).toBe(true);
    await expect(back).toBeDisabled();
    await expect.poll(() => events.slice(beforeBack).some(e => e.name === selected &&
      e.kind === 'history-length' && Number(e.value) > 1)).toBe(true);
    await expect(page).toHaveURL(`${config.baseUrl}/browsers/${selected}`);
    await expect.poll(() => remoteViewport(selected)?.value).toBe(`typed-from-${label}`);
    const baseline = remoteViewport(selected);
    const otherName = selected === 'alpha' ? 'beta' : 'alpha';
    const otherBrowser = manager.list().find(row => row.name === otherName);
    const originalSocket = manager.getSocket(selected), otherSocket = manager.getSocket(otherName);
    const persistedState = await readFile(join(stateDir, 'instances.json'), 'utf8');
    const untouchedEvents = () => events.filter(event => event.name === selected &&
      ['profile', 'location', 'input'].includes(event.kind)).length;
    const beforeResize = untouchedEvents();
    const phoneMode = page.getByRole('button', { name: 'Phone mode', exact: true });
    await expect(phoneMode).toHaveAttribute('aria-pressed', 'false');
    let peerPage, peerConnections = 0, primaryReconnects = 0;
    const trackPrimary = () => primaryReconnects++;
    if (label === 'desktop') {
      // Separate processes keep both viewers foregrounded; tab focus/reconnect must not refresh away the bug.
      peerBrowser = await chromium.launch({ executablePath: browserBin, chromiumSandbox: true });
      peerPage = await peerBrowser.newPage({ viewport, extraHTTPHeaders: { 'Cf-Access-Jwt-Assertion': token } });
      peerPage.on('pageerror', error => errors.push(error.message));
      peerPage.on('websocket', () => peerConnections++);
      await peerPage.goto(`${config.baseUrl}/browsers/${selected}`);
      await expect(peerPage.getByRole('status').filter({ hasText: /^Connected$/ })).toBeVisible({ timeout: 15000 });
      await expect(peerPage.getByRole('button', { name: 'Phone mode', exact: true })).toHaveAttribute('aria-pressed', 'false');
      assert.ok(await peerPage.evaluate(() => document.hasFocus()));
      assert.ok(await page.evaluate(() => document.hasFocus()));
      page.on('websocket', trackPrimary);
    }
    await phoneMode.click();
    await expect(phoneMode).toHaveAttribute('aria-pressed', 'true');
    const phoneViewport = manager.list().find(row => row.name === selected).viewport;
    assert.equal(phoneViewport.mode, 'phone');
    assert.equal(phoneViewport.width, 390);
    if (label === 'desktop') assert.equal(phoneViewport.height, 844);
    else assert.ok(phoneViewport.height >= 480 && phoneViewport.height <= 900);
    await expect.poll(() => canvas.evaluate(node => [node.width, node.height]))
      .toEqual([phoneViewport.width, phoneViewport.height]);
    await expect.poll(() => {
      const { height, ...content } = remoteViewport(selected) ?? {};
      return content;
    }).toEqual({
      width: 390, phone: true, font: '30px',
      value: baseline.value, url: baseline.url, profile: baseline.profile, overflow: false,
    });
    const phoneContent = remoteViewport(selected);
    assert.ok(phoneContent.height > 0 && phoneContent.height <= phoneViewport.height);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label} Phone mode overflow`);
    // Geometry and DOM reflow can arrive before their new VNC pixels; capture the painted mode.
    await expect.poll(() => canvas.evaluate(node => [...node.getContext('2d').getImageData(node.width - 16, node.height - 16, 1, 1).data]))
      .toEqual([139, 92, 246, 255]);
    await page.screenshot({ path: join(shots, `${label}-phone-mode.png`), fullPage: true });
    if (peerPage) {
      activePage = peerPage;
      const peerMode = peerPage.getByRole('button', { name: 'Phone mode', exact: true });
      const peerCanvas = peerPage.locator('.vnc-screen canvas');
      await expect.poll(() => peerCanvas.evaluate(node => [node.width, node.height])).toEqual([390, phoneViewport.height]);
      await expect(peerMode).toHaveAttribute('aria-pressed', 'true');
      await peerPage.screenshot({ path: join(shots, 'second-viewer-phone-mode.png'), fullPage: true });
      const restore = peerPage.waitForRequest(request => request.method() === 'POST' &&
        new URL(request.url()).pathname === `/api/browsers/${selected}/viewport`);
      await peerMode.click();
      assert.deepEqual((await restore).postDataJSON(), { mode: 'desktop' }, 'An existing second viewer must request the opposite shared mode');
      await expect.poll(() => canvas.evaluate(node => [node.width, node.height])).toEqual([1440, 900]);
      await expect(phoneMode).toHaveAttribute('aria-pressed', 'false');
      await expect(peerMode).toHaveAttribute('aria-pressed', 'false');
      await phoneMode.click();
      await expect(phoneMode).toHaveAttribute('aria-pressed', 'true');
      await expect(peerMode).toHaveAttribute('aria-pressed', 'true');
      await expect.poll(() => remoteViewport(selected)).toEqual(phoneContent);
      await expect.poll(() => canvas.evaluate(node => [...node.getContext('2d').getImageData(node.width - 16, node.height - 16, 1, 1).data]))
        .toEqual([139, 92, 246, 255]);
      assert.equal(primaryReconnects, 0, 'Shared mode must synchronize without reconnecting the first viewer');
      assert.equal(peerConnections, 1, 'Shared mode must synchronize without reconnecting the second viewer');
      await expect(peerPage).toHaveURL(`${config.baseUrl}/browsers/${selected}`);
      page.off('websocket', trackPrimary);
      await peerBrowser.close(); peerBrowser = undefined;
      activePage = page;
    }
    // A new VNC connection must retain the native viewport, not merely redraw a scaled desktop.
    const phoneSocket = page.waitForEvent('websocket', {
      predicate: socket => new URL(socket.url()).pathname === `/browsers/${selected}/vnc`, timeout: 15000,
    });
    await page.getByRole('button', { name: 'Reconnect desktop' }).click();
    await phoneSocket;
    await expect(page.getByRole('status').filter({ hasText: /^Connected$/ })).toBeVisible({ timeout: 15000 });
    await expect(phoneMode).toHaveAttribute('aria-pressed', 'true');
    assert.deepEqual(manager.list().find(row => row.name === selected).viewport, phoneViewport);
    await expect.poll(() => canvas.evaluate(node => [node.width, node.height]))
      .toEqual([390, phoneViewport.height]);
    assert.equal(remoteViewport(selected).value, baseline.value);
    assert.equal(untouchedEvents(), beforeResize, 'Resize/reconnect must not reload, navigate, or replay input');
    // Phone mode must leave Chrome's real address bar and navigation usable.
    const phoneLocation = `/${selected}?phone-navigation=${label}`;
    await page.getByRole('button', { name: 'Keyboard', exact: true }).click();
    await page.getByRole('button', { name: 'Address bar', exact: true }).click();
    await page.getByRole('textbox', { name: 'Text for the remote desktop' }).fill(`${fixtureOrigin}${phoneLocation}`);
    await page.getByRole('button', { name: 'Type text', exact: true }).click();
    await page.getByRole('button', { name: 'Enter ↵', exact: true }).click();
    await expect.poll(() => remoteViewport(selected)?.url).toBe(phoneLocation);
    assert.equal(remoteViewport(selected).width, 390);
    await page.getByRole('button', { name: 'Close keyboard controls' }).click();
    await expect(back).toBeEnabled();
    await back.click();
    await expect.poll(() => remoteViewport(selected)).toEqual(phoneContent);
    await expect(back).toBeDisabled();
    await expect.poll(() => canvas.evaluate(node => [node.width, node.height]))
      .toEqual([390, phoneViewport.height]);
    const afterPhoneNavigation = untouchedEvents();
    await phoneMode.click();
    await expect(phoneMode).toHaveAttribute('aria-pressed', 'false');
    await expect.poll(() => canvas.evaluate(node => [node.width, node.height])).toEqual([1440, 900]);
    await expect.poll(() => {
      const { height, ...content } = remoteViewport(selected) ?? {};
      return content;
    }).toEqual({ width: 1440, phone: false, font: '52px', value: baseline.value,
      url: baseline.url, profile: baseline.profile, overflow: false });
    assert.ok(remoteViewport(selected).height > 0 && remoteViewport(selected).height < 900,
      'Desktop restores browser chrome outside fullscreen');
    await expect.poll(() => canvas.evaluate(node => [...node.getContext('2d').getImageData(node.width - 16, node.height - 16, 1, 1).data]))
      .toEqual([59, 130, 246, 255]);
    assert.equal(untouchedEvents(), afterPhoneNavigation, 'Restoring Desktop must not reload, navigate, or replay input');
    assert.equal(manager.getSocket(selected), originalSocket);
    assert.equal(manager.getSocket(otherName), otherSocket);
    assert.deepEqual(manager.list().find(row => row.name === otherName), otherBrowser);
    assert.equal(await readFile(join(stateDir, 'instances.json'), 'utf8'), persistedState);
    await expect(page).toHaveURL(`${config.baseUrl}/browsers/${selected}`);
    const rect = await canvas.boundingBox();
    await page.mouse.click(rect.x + rect.width * 0.5, rect.y + rect.height * 0.65);
    await expect.poll(() => events.some(e => e.name === (label === 'phone' ? 'beta' : 'alpha') && e.kind === 'pointer')).toBe(true);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${label} desktop overflow`);
    await page.screenshot({ path: join(shots, `${label}-desktop.png`), fullPage: true });
    await page.getByRole('button', { name: 'Reconnect desktop' }).click();
    await expect(page.getByRole('status').filter({ hasText: /^Connected$/ })).toBeVisible();
    await context.close();
  }
  assert.deepEqual(errors, []);
  await manager.setViewport('alpha', { mode: 'phone', width: 390, height: 844 });
  assert.equal(manager.list().find(row => row.name === 'alpha').viewport.mode, 'phone');
  const beforeRestart = events.filter(e => e.name === 'alpha' && e.kind === 'profile').length;
  await cli('stop', 'alpha');
  assert.equal(manager.list().find(row => row.name === 'beta').state, 'running');
  await cli('start', 'alpha');
  assert.deepEqual(manager.list().find(row => row.name === 'alpha').viewport, { mode: 'desktop', width: 1440, height: 900 });
  await expect.poll(() => events.filter(e => e.name === 'alpha' && e.kind === 'profile').length).toBeGreaterThan(beforeRestart);
  // Chrome may restore a saved tab as well as opening the requested start URL.
  assert.ok(events.filter(e => e.name === 'alpha' && e.kind === 'profile').slice(1).every(e => e.value === 'alpha'));
  await writeFile(join(shots, 'acceptance.json'), JSON.stringify({ passed: true, browserBin,
    checks: ['signed-auth', 'two-isolated-desktops', 'CLI-start-stop', 'real-VNC-keyboard-pointer',
      'desktop-and-phone-layout', 'automatic-reconnect-desktop-and-phone', 'remote-browser-back-desktop-and-phone',
      'native-back-availability', 'fullscreen-supported-and-unsupported',
      'native-phone-reflow-desktop-and-phone', 'shared-phone-toggle-without-reconnect',
      'phone-viewport-reconnect-and-restart', 'reconnect', 'profile-retention'], events }, null, 2), { mode: 0o600 });
  console.log(`PASS: desktop + phone VNC, input, reconnect, Back, native Phone mode, and retained profile data. Screenshots: ${shots}`);
} catch (error) {
  // Next installs an uncaught-exception listener; preserve a failing exit status explicitly.
  console.error(error);
  await activePage?.screenshot({ path: join(shots, 'failure.png'), fullPage: true }).catch(() => {});
  await writeFile(join(shots, 'acceptance.json'), JSON.stringify({ passed: false, events }, null, 2), { mode: 0o600 });
  console.error(`Failure artifacts: ${shots}`);
  process.exitCode = 1;
} finally {
  await peerBrowser?.close();
  await browser?.close();
  await closeServer(server); await closeServer(control);
  await manager?.close(); await app?.close(); await closeServer(fixture);
  console.log(`Acceptance-only profiles retained at ${stateDir}; all test desktops stopped.`);
}
