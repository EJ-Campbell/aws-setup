// Opt-in Mac UI acceptance: build first, then node test/page-viewer-live.mjs.
// Uses real headed Chrome, a separate headless test viewer, temporary profiles and a
// signed ephemeral Access identity. Never captures the Mac desktop or personal sessions.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir, homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium, expect } from '@playwright/test';
import { generateKeyPair, SignJWT } from 'jose';
import next from 'next';
import { createAuthorizer } from '../lib/auth.mjs';
import { createHttpServer } from '../lib/http.mjs';
import { createInstanceManager } from '../lib/instances.mjs';

if (process.platform !== 'darwin') throw new Error('This opt-in acceptance test requires macOS.');
process.umask(0o077);
const browserBin = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const project = dirname(dirname(fileURLToPath(import.meta.url)));
const stateDir = await realpath(await mkdtemp(join(tmpdir(), 'bm-page-ui-')));
const screenshots = join(homedir(), 'browser-manager-ui-artifacts', 'mac-page-' + new Date().toISOString().replaceAll(':', '-'));
await mkdir(screenshots, { recursive: true, mode: 0o700 });
const check = expect.configure({ timeout: 15000 });
const events = [];
const errors = [];
const listen = (server, address) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(address, () => { server.off('error', reject); resolve(server.address()); });
});
const closeServer = server => new Promise(resolve => {
  server?.closeVnc?.(); server?.closeAllConnections();
  if (server) server.close(resolve); else resolve();
});
const fixture = createServer((request, response) => {
  const url = new URL(request.url, 'http://localhost');
  if (url.pathname === '/event') { events.push(Object.fromEntries(url.searchParams)); response.end('ok'); return; }
  const name = url.searchParams.get('name') === 'phone' ? 'phone' : 'desktop';
  response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
  response.end(`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>${name} fixture</title>
    <style>body{margin:0;min-height:2500px;background:#eff8ff;color:#20354b;font:18px system-ui}
    button{position:absolute;left:20px;top:20px;width:180px;height:40px;font:16px system-ui}
    input{position:absolute;left:20px;top:90px;width:300px;height:42px;box-sizing:border-box;font:18px system-ui}
    main{position:absolute;top:190px;left:24px;right:24px}h1{font-size:38px;letter-spacing:-1px;margin:0 0 12px}p{max-width:590px;line-height:1.6}
    .cards{display:flex;gap:14px;margin-top:28px}.cards div{background:white;border:1px solid #c8daeb;border-radius:12px;padding:22px;flex:1}
    @media(max-width:500px){h1{font-size:30px}.cards{flex-direction:column}.cards div{padding:16px}}</style></head><body>
    <button id="tap">Test page click</button><input aria-label="Remote fixture input" placeholder="Remote page input">
    <main><h1>Your Mac, one page at a time.</h1><p>This acceptance fixture runs inside native Chrome. The page viewer does not capture the desktop or other Mac apps.</p>
    <div class="cards"><div>Separate browser profile</div><div>Phone-friendly controls</div></div><p style="margin-top:950px">Scrolling stays inside the remote page.</p></main>
    <script>const name=${JSON.stringify(name)};const report=(kind,value)=>fetch('/event?'+new URLSearchParams({name,kind,value}));
    const input=document.querySelector('input');document.querySelector('#tap').onclick=()=>report('click','yes');
    input.oninput=()=>{document.body.style.background='#d5f4e6';report('input',input.value)};
    addEventListener('pageshow',()=>report('location',location.pathname+location.search));
    addEventListener('scroll',()=>report('scroll',String(scrollY)));
    addEventListener('resize',()=>report('viewport',JSON.stringify({width:innerWidth,height:innerHeight})));
    report('viewport',JSON.stringify({width:innerWidth,height:innerHeight}));</script></body></html>`);
});
const fixtureAddress = await listen(fixture, { host: '127.0.0.1', port: 0 });
const fixtureOrigin = `http://127.0.0.1:${fixtureAddress.port}`;
const config = { baseUrl: 'http://127.0.0.1', transport: 'page', issuer: 'https://test.cloudflareaccess.com',
  audience: 'mac-page-ui-test', owner: 'owner@example.test' };
const keys = await generateKeyPair('RS256');
const token = await new SignJWT({ email: config.owner }).setProtectedHeader({ alg: 'RS256' }).setSubject('ui-test-owner')
  .setIssuer(config.issuer).setAudience(config.audience).setIssuedAt().setExpirationTime('15m').sign(keys.privateKey);
let app, server, manager, viewer, activePage;
try {
  app = next({ dev: false, dir: project, hostname: '127.0.0.1' });
  await app.prepare();
  const reservation = createServer();
  const address = await listen(reservation, { host: '127.0.0.1', port: 0 });
  await closeServer(reservation);
  config.baseUrl = `http://127.0.0.1:${address.port}`;
  manager = createInstanceManager({ stateDir, browserBin, baseUrl: config.baseUrl });
  await manager.initialize();
  server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: app.getRequestHandler() });
  await listen(server, { host: '127.0.0.1', port: address.port });
  assert.equal((await fetch(config.baseUrl + '/api/config')).status, 401);
  viewer = await chromium.launch({ executablePath: browserBin, headless: true, chromiumSandbox: true });

  for (const [name, viewport] of [['desktop', { width: 1440, height: 1050 }], ['phone', { width: 390, height: 844 }]]) {
    const initialUrl = `${fixtureOrigin}/fixture?name=${name}`;
    await manager.start(name, { url: initialUrl });
    assert.equal(manager.list().find(row => row.name === name).state, 'running');
    const context = await viewer.newContext({ viewport, isMobile: name === 'phone', hasTouch: name === 'phone',
      extraHTTPHeaders: { 'Cf-Access-Jwt-Assertion': token } });
    const page = await context.newPage();
    activePage = page;
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${config.baseUrl}/browsers/${name}`);
    await page.bringToFront();
    const canvas = page.locator('.mac-page-canvas');
    await check(page.locator('[data-transport="page"]')).toBeVisible();
    await check(page.getByRole('status').filter({ hasText: /^Connected · Mac Chrome$/ })).toBeVisible();
    await check(page.getByRole('heading', { name: 'Waiting for the page' })).toHaveCount(0);
    await check(canvas).toHaveAttribute('tabindex', '0');
    await check(page.getByRole('textbox', { name: 'Remote page address' })).toHaveValue(initialUrl);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${name}: no page overflow`);
    await page.screenshot({ path: join(screenshots, `${name}-initial.png`), fullPage: true });

    async function point(x, y) {
      const bounds = await canvas.boundingBox();
      const size = await canvas.evaluate(node => ({ width: node.width, height: node.height }));
      return { x: bounds.x + x * bounds.width / size.width, y: bounds.y + y * bounds.height / size.height };
    }
    async function click(x, y) {
      const position = await point(x, y);
      if (name === 'phone') await page.touchscreen.tap(position.x, position.y);
      else await page.mouse.click(position.x, position.y);
    }
    await click(100, 40);
    await check.poll(() => events.some(event => event.name === name && event.kind === 'click')).toBe(true);
    await click(100, 110);
    if (name === 'desktop') {
      await page.keyboard.type('physical');
      await check.poll(() => events.findLast(event => event.name === name && event.kind === 'input')?.value).toBe('physical');
    }
    await page.getByRole('button', { name: 'Keyboard', exact: true }).click();
    await page.getByRole('textbox', { name: 'Text for the remote page' }).fill(`typed-from-${name}`);
    // Filling the explicit entry field must not send anything by itself.
    assert(!events.some(event => event.name === name && event.kind === 'input' && event.value.includes('typed-from-')));
    await page.getByRole('button', { name: 'Send text', exact: true }).click();
    await check.poll(() => events.findLast(event => event.name === name && event.kind === 'input')?.value)
      .toBe((name === 'desktop' ? 'physical' : '') + `typed-from-${name}`);
    // JPEG may round a flat color by a channel or two; require the returned input paint.
    await check.poll(() => canvas.evaluate(node => [...node.getContext('2d').getImageData(5, 5, 1, 1).data]
      .every((value, index) => Math.abs(value - [213, 244, 230, 255][index]) <= 3))).toBe(true);
    await check.poll(() => canvas.evaluate(node => {
      const pixels = node.getContext('2d').getImageData(110, 98, 180, 28).data;
      let ink = 0;
      for (let index = 0; index < pixels.length; index += 4) if (pixels[index] < 100 && pixels[index + 1] < 100 && pixels[index + 2] < 100) ink++;
      return ink;
    })).toBeGreaterThan(30);
    await page.screenshot({ path: join(screenshots, `${name}-keyboard.png`), fullPage: true });
    await page.getByRole('button', { name: 'Close keyboard controls' }).click();

    const remoteAddress = page.getByRole('textbox', { name: 'Remote page address' });
    await remoteAddress.fill(`${fixtureOrigin}/second?name=${name}`);
    await page.getByRole('button', { name: 'Go to address' }).click();
    await check.poll(() => events.some(event => event.name === name && event.kind === 'location' && event.value.startsWith('/second'))).toBe(true);
    const back = page.getByRole('button', { name: 'Back in remote browser' });
    await check(back).toBeEnabled();
    await back.click();
    await check(remoteAddress).toHaveValue(initialUrl);
    await page.getByRole('button', { name: 'Forward in remote browser' }).click();
    await check(remoteAddress).toHaveValue(`${fixtureOrigin}/second?name=${name}`);
    await back.click();
    await check(remoteAddress).toHaveValue(initialUrl);

    const originalCount = await page.getByRole('tab').count();
    await page.getByRole('button', { name: 'New tab', exact: true }).click();
    await check(page.getByRole('tab')).toHaveCount(originalCount + 1);
    await check(remoteAddress).toHaveValue('about:blank');
    await remoteAddress.fill(`${fixtureOrigin}/new-tab?name=${name}`);
    await page.getByRole('button', { name: 'Go to address' }).click();
    await check.poll(() => events.some(event => event.name === name && event.kind === 'location' && event.value.startsWith('/new-tab'))).toBe(true);
    await page.locator('.mac-tab[data-active="true"]').getByRole('button', { name: /^Close tab / }).click();
    await check(page.getByRole('tab')).toHaveCount(originalCount);
    await check(remoteAddress).toHaveValue(initialUrl);

    const phoneButton = page.getByRole('button', { name: 'Phone mode' });
    await check(phoneButton).toBeEnabled();
    await phoneButton.click();
    await check(phoneButton).toHaveAttribute('aria-pressed', 'true');
    await check.poll(() => canvas.evaluate(node => node.width)).toBe(390);
    await check(canvas).toHaveAttribute('tabindex', '0');
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `${name}: no phone mode overflow`);
    await page.screenshot({ path: join(screenshots, `${name}-phone-mode.png`), fullPage: true });
    if (name === 'phone') {
      const cdp = await context.newCDPSession(page);
      const bounds = await canvas.boundingBox();
      const touch = { x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height * 0.8 };
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [touch] });
      for (let step = 1; step <= 5; step++) {
        await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ ...touch, y: touch.y - step * bounds.height * 0.07 }] });
        await new Promise(resolve => setTimeout(resolve, 55));
      }
      await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
      await check.poll(() => events.some(event => event.name === name && event.kind === 'scroll' && Number(event.value) > 50)).toBe(true);
      await cdp.detach();
    } else {
      const center = await point(250, 350);
      await page.mouse.move(center.x, center.y);
      await page.mouse.wheel(0, 400);
      await check.poll(() => events.some(event => event.name === name && event.kind === 'scroll' && Number(event.value) > 50)).toBe(true);
    }

    const newSocket = page.waitForEvent('websocket', { predicate: socket => new URL(socket.url()).pathname === `/browsers/${name}/page` });
    server.closeVnc();
    await newSocket;
    await check(canvas).toHaveAttribute('tabindex', '0');
    await check.poll(() => canvas.evaluate(node => node.width)).toBe(390);
    await check(page.getByRole('status').filter({ hasText: /^Connected · Mac Chrome$/ })).toBeVisible();
    await page.screenshot({ path: join(screenshots, `${name}-reconnected.png`), fullPage: true });
    await phoneButton.click();
    await check.poll(() => canvas.evaluate(node => node.width)).toBe(1440);
    await context.close();
    activePage = null;
    await manager.stop(name);
    console.log(`${name}: native-page UI input, paint, history, tabs, Phone mode, scroll and automatic reconnect passed.`);
  }
  assert.deepEqual(errors, []);
  await writeFile(join(screenshots, 'acceptance.json'), JSON.stringify({ passed: true, errors, checks: [
    'signed-auth', 'page-transport', 'desktop-phone-layout', 'scaled-mouse-touch-coordinates', 'physical-keyboard',
    'explicit-text-only', 'returned-paint', 'back-forward-address', 'create-close-tabs', 'phone-resize',
    'touch-scroll', 'mouse-wheel', 'automatic-reconnect', 'no-personal-profile-or-desktop-capture',
  ] }, null, 2), { mode: 0o600 });
  console.log(`PASS. Test-only page screenshots: ${screenshots}`);
} catch (error) {
  console.error(error);
  await activePage?.screenshot({ path: join(screenshots, 'failure.png'), fullPage: true }).catch(() => {});
  await writeFile(join(screenshots, 'acceptance.json'), JSON.stringify({ passed: false, errors, events }, null, 2), { mode: 0o600 });
  console.error(`Test-only failure artifacts: ${screenshots}`);
  process.exitCode = 1;
} finally {
  await viewer?.close();
  await closeServer(server);
  await manager?.close();
  await app?.close();
  await closeServer(fixture);
  await rm(stateDir, { recursive: true, force: true });
  console.log('Only test-created browser processes and temporary profiles were closed/removed.');
}
