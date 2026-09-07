// Optional host acceptance: real sandboxed desktops, production UI, and signed test identity.
// No production auth bypass, browser debugging port, or existing profile is used.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
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
    </style></head><body><h1>${name}: private desktop</h1><p>This browser has its own persistent profile.</p>
    <input autofocus placeholder="Type here from your phone"><p>Pointer and keyboard acceptance fixture.</p>
    <script>const name=${JSON.stringify(name)};const report=(kind,value)=>fetch('/event?'+new URLSearchParams({name,kind,value}));
    report('profile',localStorage.getItem('owner')||'fresh');localStorage.setItem('owner',name);
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
let manager, app, server, control, browser;
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
    const page = await context.newPage();
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
    await page.getByRole('button', { name: 'Close keyboard controls' }).click();
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
  await cli('stop', 'alpha');
  assert.equal(manager.list().find(row => row.name === 'beta').state, 'running');
  await cli('start', 'alpha');
  await expect.poll(() => events.filter(e => e.name === 'alpha' && e.kind === 'profile').length).toBeGreaterThanOrEqual(2);
  // Chrome may restore a saved tab as well as opening the requested start URL.
  assert.ok(events.filter(e => e.name === 'alpha' && e.kind === 'profile').slice(1).every(e => e.value === 'alpha'));
  await writeFile(join(shots, 'acceptance.json'), JSON.stringify({ passed: true, browserBin,
    checks: ['signed-auth', 'two-isolated-desktops', 'CLI-start-stop', 'real-VNC-keyboard-pointer',
      'desktop-and-phone-layout', 'reconnect', 'profile-retention'], events }, null, 2), { mode: 0o600 });
  console.log(`PASS: desktop + phone VNC, input, reconnect, and retained profile data. Screenshots: ${shots}`);
} catch (error) {
  // Next installs an uncaught-exception listener; preserve a failing exit status explicitly.
  console.error(error);
  process.exitCode = 1;
} finally {
  await browser?.close();
  await closeServer(server); await closeServer(control);
  await manager?.close(); await app?.close(); await closeServer(fixture);
  console.log(`Acceptance-only profiles retained at ${stateDir}; all test desktops stopped.`);
}
