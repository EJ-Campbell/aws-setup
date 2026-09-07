import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { WebSocket } from 'ws';
import { generateKeyPair, SignJWT } from 'jose';
import { createAuthorizer } from '../lib/auth.mjs';
import { createHttpServer } from '../lib/http.mjs';

const keys = await generateKeyPair('RS256');
const config = { baseUrl: 'https://mac-browsers.example.test', issuer: 'https://team.cloudflareaccess.com',
  audience: 'mac-only-audience', owner: 'owner@example.test', transport: 'page' };
const sign = (overrides = {}) => new SignJWT({ email: config.owner, ...overrides }).setProtectedHeader({ alg: 'RS256' })
  .setIssuedAt().setSubject('owner').setIssuer(config.issuer).setAudience(config.audience)
  .setExpirationTime('5m').sign(keys.privateKey);
const token = await sign();
const headers = { Origin: config.baseUrl, 'cf-access-jwt-assertion': token };
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fixture(authorize = createAuthorizer(config, keys.publicKey)) {
  const calls = [];
  const subscribers = new Set();
  const closed = Promise.withResolvers();
  const desktop = {
    closed: closed.promise,
    subscribe(fn) { subscribers.add(fn); fn({ type: 'tabs', tabs: [], activeId: '', canGoBack: false }); return () => subscribers.delete(fn); },
    async command(message) { calls.push(message); },
  };
  const manager = { getPage: name => name === 'mac' ? desktop : null, getSocket: () => null };
  const server = createHttpServer({ manager, config, authorize, nextHandler: (_req, res) => res.end('app') });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  const clients = [];
  return { desktop, calls, subscribers, manager, base, closed: { resolve() {
    for (const send of [...subscribers]) send({ type: 'closed' });
    closed.resolve();
  } },
    connect(path = '/browsers/mac/page', sentHeaders = headers) {
      const client = new WebSocket(base.replace('http:', 'ws:') + path, { headers: sentHeaders });
      client.on('error', () => {}); clients.push(client); return client;
    },
    async cleanup() {
      for (const client of clients) client.terminate();
      server.closeVnc(); server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    },
  };
}

test('Mac config identifies page transport only after owner authorization', async () => {
  const f = await fixture();
  try {
    assert.equal((await fetch(f.base + '/api/config')).status, 401);
    assert.deepEqual(await (await fetch(f.base + '/api/config', { headers })).json(),
      { baseUrl: config.baseUrl, transport: 'page' });
  } finally { await f.cleanup(); }
});

test('page upgrades verify JWT, exact Origin and registered browser; never expose CDP routes', async () => {
  const f = await fixture();
  try {
    const wrongOwner = await sign({ email: 'other@example.test' });
    for (const [path, sentHeaders, expected] of [
      ['/browsers/mac/page', {}, 401],
      ['/browsers/mac/page', { Origin: config.baseUrl, 'cf-access-authenticated-user-email': config.owner }, 401],
      ['/browsers/mac/page', { ...headers, Origin: 'https://other.test' }, 403],
      ['/browsers/mac/page', { ...headers, 'cf-access-jwt-assertion': wrongOwner }, 403],
      ['/browsers/unknown/page', headers, 404], ['/browsers/mac/vnc', headers, 404],
      ['/devtools/browser/mac', headers, 404], ['/browsers/mac/page/extra', headers, 404],
    ]) {
      const client = f.connect(path, sentHeaders);
      const status = await new Promise(resolve => client.once('unexpected-response', (_req, res) => {
        resolve(res.statusCode); res.destroy(); client.terminate();
      }));
      assert.equal(status, expected);
    }
    assert.equal(f.subscribers.size, 0);
    assert.deepEqual(f.calls, []);
  } finally { await f.cleanup(); }
});

test('page socket sends only its selected desktop frames and removes subscriptions on disconnect', async () => {
  const f = await fixture();
  try {
    const client = f.connect();
    assert.equal(JSON.parse((await once(client, 'message'))[0]).type, 'tabs');
    const frame = once(client, 'message');
    for (const send of f.subscribers) send({ type: 'frame', data: 'fake-jpeg', width: 640, height: 480 });
    assert.equal(JSON.parse((await frame)[0]).type, 'frame');
    client.send(JSON.stringify({ type: 'text', text: 'explicit user text' }));
    await delay(20);
    assert.deepEqual(f.calls, [{ type: 'text', text: 'explicit user text' }]);
    const ended = once(client, 'close'); client.close(); await ended; await delay(10);
    assert.equal(f.subscribers.size, 0);
  } finally { await f.cleanup(); }
});

test('page expiry stops queued input even when the client ignores the close handshake', async () => {
  const f = await fixture(async () => ({ expiresAt: Date.now() + 180 }));
  const unblock = Promise.withResolvers();
  try {
    f.desktop.command = async message => { f.calls.push(message); await unblock.promise; };
    const client = f.connect(); await once(client, 'message');
    client._receiver.removeAllListeners('conclude');
    const expired = once(client._receiver, 'conclude');
    client.send(JSON.stringify({ type: 'reload' }));
    client.send(JSON.stringify({ type: 'back' }));
    assert.equal((await expired)[0], 1008);
    assert.equal(f.subscribers.size, 0);
    unblock.resolve();
    client.send(JSON.stringify({ type: 'forward' }));
    await delay(20);
    assert.deepEqual(f.calls, [{ type: 'reload' }]);
  } finally { unblock.resolve(); await f.cleanup(); }
});

test('slow viewers may drop frames but must reconnect before losing tab identity', async (t) => {
  const f = await fixture();
  try {
    const client = f.connect(); await once(client, 'message');
    const backlog = t.mock.getter(WebSocket.prototype, 'bufferedAmount', () => 3 * 1024 * 1024);
    for (const send of f.subscribers) send({ type: 'frame', data: 'discard', width: 640, height: 480 });
    assert.equal(f.subscribers.size, 1, 'dropping a frame alone does not revoke the viewer');
    const closed = once(client, 'close');
    for (const send of [...f.subscribers]) send({ type: 'tabs', tabs: [{ id: 'new', title: 'New page', url: 'https://new.test' }], activeId: 'new' });
    backlog.mock.restore();
    assert.equal(f.subscribers.size, 0, 'control backpressure revokes input immediately');
    assert.equal((await closed)[0], 1013);
    assert.deepEqual(f.calls, []);
  } finally { await f.cleanup(); }
});

test('binary, malformed and oversized page input closes without reaching the browser', async () => {
  for (const value of [Buffer.from('binary'), '[1,2]', '{broken', 'x'.repeat(16385)]) {
    const f = await fixture();
    try {
      const client = f.connect(); await once(client, 'message');
      const closed = once(client, 'close'); client.send(value);
      assert([1008, 1009].includes((await closed)[0]));
      assert.deepEqual(f.calls, []);
    } finally { await f.cleanup(); }
  }
});

test('Mac viewer count is bounded and replacing/stopping a browser revokes the old socket', async () => {
  const f = await fixture();
  try {
    const clients = [];
    for (let i = 0; i < 8; i++) { const client = f.connect(); await once(client, 'message'); clients.push(client); }
    const ninth = f.connect();
    const status = await new Promise(resolve => ninth.once('unexpected-response', (_req, res) => {
      resolve(res.statusCode); res.destroy(); ninth.terminate();
    }));
    assert.equal(status, 429);
    f.manager.getPage = () => null;
    const closed = once(clients[0], 'close'); clients[0].send('{"type":"reload"}');
    assert.equal((await closed)[0], 1008);
    assert.deepEqual(f.calls, []);
    f.closed.resolve();
    await delay(20);
    assert.equal(f.subscribers.size, 0);
  } finally { await f.cleanup(); }
});
