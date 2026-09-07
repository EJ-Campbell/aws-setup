import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer as createSocketServer } from 'node:net';
import { WebSocket } from 'ws';
import { generateKeyPair, SignJWT } from 'jose';
import { browserViewport, createAuthorizer } from '../lib/auth.mjs';
import { createHttpServer } from '../lib/http.mjs';

const keys = await generateKeyPair('RS256');
const config = { baseUrl: 'https://browsers.example.test', issuer: 'https://team.cloudflareaccess.com', audience: 'browser-audience', serviceTokenId: '', owner: 'owner@example.test' };
const token = await new SignJWT({ email: config.owner }).setProtectedHeader({ alg: 'RS256' })
  .setIssuedAt().setSubject('owner').setIssuer(config.issuer).setAudience(config.audience)
  .setExpirationTime('5m').sign(keys.privateKey);
const headers = { 'cf-access-jwt-assertion': token, Origin: config.baseUrl, 'Content-Type': 'application/json' };
const bind = async server => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return `http://127.0.0.1:${server.address().port}`; };
const close = async server => { server.closeVnc?.(); server.closeAllConnections?.(); await new Promise(done => server.close(done)); };

test('navigation is an owner-authenticated read on the exact registered route', async () => {
  const calls = [];
  const manager = { getNavigation: async name => { calls.push(name); return { canGoBack: name === 'alpha' }; } };
  const server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: (_req, res) => res.end() });
  const base = await bind(server);
  const wrongOwner = await new SignJWT({ email: 'other@example.test' }).setProtectedHeader({ alg: 'RS256' })
    .setIssuedAt().setSubject('other').setIssuer(config.issuer).setAudience(config.audience)
    .setExpirationTime('5m').sign(keys.privateKey);
  try {
    for (const [sentHeaders, status] of [[{}, 401],
      [{ 'cf-access-authenticated-user-email': config.owner }, 401],
      [{ 'cf-access-jwt-assertion': wrongOwner }, 403]]) {
      assert.equal((await fetch(`${base}/api/browsers/alpha/navigation`, { headers: sentHeaders })).status, status);
    }
    for (const path of ['/api/browsers/alpha/navigation/extra', '/api/browsers/alpha%2fbeta/navigation']) {
      assert.equal((await fetch(base + path, { headers })).status, 404);
    }
    assert.equal((await fetch(`${base}/api/browsers/alpha/navigation`, { method: 'POST', headers, body: '{}' })).status, 404);
    assert.deepEqual(calls, []);
    for (const name of ['alpha', 'beta']) {
      const response = await fetch(`${base}/api/browsers/${name}/navigation?pid=123&name=other`, {
        headers: { 'cf-access-jwt-assertion': token },
      });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.deepEqual(await response.json(), { canGoBack: name === 'alpha' });
    }
    assert.deepEqual(calls, ['alpha', 'beta']);
  } finally { await close(server); }
});

test('viewport mutations require owner + exact Origin and bounded dimensions without command fields', async () => {
  const calls = [];
  const row = { name: 'stable', state: 'running' };
  const manager = { setViewport: async (name, value) => {
    calls.push([name, value]); return { ...row, viewport: browserViewport(value) };
  } };
  const server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: () => {} });
  const base = await bind(server);
  const phone = { mode: 'phone', width: 390, height: 680 };
  try {
    for (const [body, sentHeaders, status] of [
      [phone, { 'Content-Type': 'application/json' }, 401],
      [phone, { ...headers, Origin: 'https://evil.test' }, 403],
      [phone, { ...headers, Origin: '' }, 403],
      [{ ...phone, width: 10000 }, headers, 400],
      [{ ...phone, height: '680' }, headers, 400],
      [{ ...phone, command: 'arbitrary' }, headers, 400],
      [{ ...phone, display: ':0' }, headers, 400],
      [{ ...phone, profile: '/private' }, headers, 400],
      [{ mode: 'desktop', width: 10000 }, headers, 400],
    ]) {
      const response = await fetch(`${base}/api/browsers/stable/viewport`, {
        method: 'POST', headers: sentHeaders, body: JSON.stringify(body),
      });
      assert.equal(response.status, status);
    }
    assert.deepEqual(calls, []);
    for (const value of [phone, { mode: 'desktop' }]) {
      const response = await fetch(`${base}/api/browsers/stable/viewport`, { method: 'POST', headers, body: JSON.stringify(value) });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { browser: { ...row, viewport: browserViewport(value) } });
    }
    assert.deepEqual(calls, [['stable', phone], ['stable', { mode: 'desktop' }]]);
  } finally { await close(server); }
});

test('HTTP denies unauthenticated/forged identity, cross-origin mutations, unknown paths, and profile injection', async () => {
  const calls = [];
  const manager = { list: () => [], start: async (...args) => { calls.push(args); return { name: args[0] }; }, stop: async () => ({}), getSocket: () => null };
  const server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: (_req, res) => res.end('page') });
  const base = await bind(server);
  try {
    assert.equal((await fetch(base)).status, 401);
    assert.equal((await fetch(base, { headers: { 'cf-access-authenticated-user-email': config.owner } })).status, 401);
    assert.equal(await (await fetch(`${base}/?navigation=1`, { headers })).text(), 'page');
    for (const [path, body, overrides, status] of [
      ['/api/browsers', { name: 'one' }, { Origin: 'https://evil.test' }, 403],
      ['/api/browsers', { name: '../other' }, {}, 400],
      ['/api/browsers', { name: 'one', profile: '/home/ubuntu/.config' }, {}, 400],
      ['/api/browsers', { name: 'one', url: 'file:///etc/passwd' }, {}, 400],
      ['/api/arbitrary', { name: 'one' }, {}, 404],
    ]) {
      assert.equal((await fetch(base + path, { method: 'POST', headers: { ...headers, ...overrides }, body: JSON.stringify(body) })).status, status);
    }
    assert.deepEqual(calls, []);
    const result = await fetch(`${base}/api/browsers`, { method: 'POST', headers, body: JSON.stringify({ name: 'one', url: 'https://example.test' }) });
    assert.equal(result.status, 200);
    assert.deepEqual(calls, [['one', { url: 'https://example.test/' }]]);
  } finally { await close(server); }
});

test('VNC upgrades require auth+Origin and route only to the selected registered Unix socket', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'browser-route-test-'));
  const sockets = [];
  const desktops = [];
  for (const name of ['one', 'two']) {
    const server = createSocketServer(socket => { sockets.push(socket); socket.write(name); socket.on('data', data => socket.write(data)); });
    server.listen(join(scratch, name)); await once(server, 'listening'); desktops.push(server);
  }
  const manager = { getSocket: name => ['one', 'two'].includes(name) ? join(scratch, name) : null };
  const server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: (_req, res) => res.end() });
  const base = (await bind(server)).replace('http:', 'ws:');
  const clients = [];
  try {
    for (const [path, sentHeaders, expected] of [
      ['/browsers/one/vnc', {}, 401], ['/browsers/one/vnc', { ...headers, Origin: 'https://evil.test' }, 403],
      ['/browsers/missing/vnc', headers, 404], ['/browsers/one/not-vnc', headers, 404],
    ]) {
      const ws = new WebSocket(base + path, { headers: sentHeaders });
      ws.on('error', () => {});
      const status = await new Promise(resolve => ws.once('unexpected-response', (_req, res) => { resolve(res.statusCode); res.destroy(); ws.terminate(); }));
      assert.equal(status, expected);
    }
    for (const name of ['one', 'two']) {
      const ws = new WebSocket(`${base}/browsers/${name}/vnc`, { headers }); clients.push(ws);
      assert.equal((await once(ws, 'message'))[0].toString(), name);
      ws.send(`only-${name}`);
      assert.equal((await once(ws, 'message'))[0].toString(), `only-${name}`);
    }
    assert.equal(sockets.length, 2);
  } finally {
    for (const ws of clients) ws.terminate();
    for (const socket of sockets) socket.destroy();
    await close(server);
    await Promise.all(desktops.map(close));
    await rm(scratch, { recursive: true });
  }
});

test('an open VNC connection expires with its verified Access session', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'browser-expiry-test-'));
  let upstream;
  const desktop = createSocketServer(socket => { upstream = socket; });
  desktop.listen(join(scratch, 'vnc')); await once(desktop, 'listening');
  const server = createHttpServer({ manager: { getSocket: () => join(scratch, 'vnc') }, config,
    authorize: async () => ({ expiresAt: Date.now() + 30 }), nextHandler: () => {} });
  const base = (await bind(server)).replace('http:', 'ws:');
  try {
    const ws = new WebSocket(`${base}/browsers/one/vnc`, { headers: { Origin: config.baseUrl } });
    const [code] = await once(ws, 'close'); assert.equal(code, 1008);
  } finally { upstream?.destroy(); await close(server); await close(desktop); await rm(scratch, { recursive: true }); }
});

test('Access expiry severs desktop input even when the client ignores the WebSocket close handshake', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'browser-expiry-input-test-'));
  const received = [];
  let upstream;
  const desktop = createSocketServer(socket => {
    upstream = socket;
    socket.on('data', data => received.push(data.toString()));
  });
  desktop.listen(join(scratch, 'vnc')); await once(desktop, 'listening');
  const server = createHttpServer({ manager: { getSocket: () => join(scratch, 'vnc') }, config,
    authorize: async () => ({ expiresAt: Date.now() + 200 }), nextHandler: () => {} });
  const base = (await bind(server)).replace('http:', 'ws:');
  let ws;
  try {
    const connected = once(desktop, 'connection');
    ws = new WebSocket(`${base}/browsers/one/vnc`, { headers: { Origin: config.baseUrl } });
    await once(ws, 'open');
    await connected;
    // Simulate an uncooperative peer: receive the close frame, but do not acknowledge it
    // or mark the client closed. This keeps sending possible during the close timeout.
    ws._receiver.removeAllListeners('conclude');
    const closeFrame = once(ws._receiver, 'conclude');
    const before = once(upstream, 'data');
    ws.send('before-expiry'); await before;
    const [code] = await closeFrame; assert.equal(code, 1008);
    assert.equal(ws.readyState, WebSocket.OPEN);
    ws.send('after-expiry');
    await new Promise(done => setTimeout(done, 30));
    assert.deepEqual(received, ['before-expiry']);
    assert.equal(upstream.destroyed, true, 'desktop socket closes without waiting for the peer');
  } finally {
    ws?.terminate(); upstream?.destroy(); await close(server); await close(desktop);
    await rm(scratch, { recursive: true });
  }
});

test('requests during startup or teardown cannot reach the manager', async () => {
  const server = createHttpServer({ manager: { list: () => assert.fail('not ready') }, config, local: true, isReady: () => false });
  const base = await bind(server);
  try { assert.equal((await fetch(`${base}/api/browsers`)).status, 503); }
  finally { await close(server); }
});

test('rename requires owner auth and exact Origin, accepts only a valid label, and preserves the stable route', async () => {
  const calls = [];
  const row = { name: 'stable', label: 'stable', url: `${config.baseUrl}/browsers/stable`, state: 'running' };
  const manager = { list: () => [row], rename: async (name, label) => { calls.push([name, label]); return { ...row, label }; } };
  const server = createHttpServer({ manager, config, authorize: createAuthorizer(config, keys.publicKey), nextHandler: () => {} });
  const base = await bind(server);
  try {
    for (const [path, body, sentHeaders, status] of [
      ['/api/browsers/stable/rename', { label: 'New label' }, { 'Content-Type': 'application/json' }, 401],
      ['/api/browsers/stable/rename', { label: 'New label' }, { ...headers, Origin: 'https://evil.test' }, 403],
      ['/api/browsers/stable/rename', { label: 'New label' }, { ...headers, Origin: '' }, 403],
      ['/api/browsers/stable/rename', { label: 'New label', name: 'different' }, headers, 400],
      ['/api/browsers/stable/rename', { label: 'New label', profile: '/private' }, headers, 400],
      ['/api/browsers/stable/rename', {}, headers, 400],
      ['/api/browsers/stable/rename', { label: 'bad\nlabel' }, headers, 400],
      ['/api/browsers/stable/rename', { label: 'x'.repeat(81) }, headers, 400],
      ['/api/browsers/missing/rename', { label: 'New label' }, headers, 404],
    ]) {
      const response = await fetch(base + path, { method: 'POST', headers: sentHeaders, body: JSON.stringify(body) });
      assert.equal(response.status, status);
    }
    assert.deepEqual(calls, []);
    const response = await fetch(`${base}/api/browsers/stable/rename`, { method: 'POST', headers, body: JSON.stringify({ label: '  Personal browser  ' }) });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { browser: { ...row, label: 'Personal browser' } });
    assert.deepEqual(calls, [['stable', 'Personal browser']]);
  } finally { await close(server); }
});
