import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { configureViewer, readViewerInput, readViewerSecret } from '../scripts/configure-openclaw-viewer.mjs';

const keys = await generateKeyPair('RS256');
const secret = {
  client_id: '0123456789abcdef0123456789abcdef.access',
  client_secret: `cfast_${'a'.repeat(48)}`,
  base_url: 'https://browsers.cc-games.dev',
  issuer: 'https://ejc3.cloudflareaccess.com', audience: 'a'.repeat(64),
};
const raw = JSON.stringify(secret);
const signed = (claims = {}, options = {}) => new SignJWT({
  type: 'app', common_name: secret.client_id, ...claims,
}).setProtectedHeader({ alg: 'RS256' }).setIssuedAt(options.iat)
  .setSubject(options.sub ?? '').setIssuer(options.issuer || secret.issuer)
  .setAudience(options.audience || secret.audience).setExpirationTime(options.exp || '5m')
  .sign(options.key || keys.privateKey);

function harness(token, options = {}) {
  const events = [];
  const cookies = options.cookies || [`CF_Authorization=${token}; Domain=browsers.cc-games.dev; Path=/; Secure; HttpOnly`];
  return {
    events,
    dependencies: {
      key: keys.publicKey,
      callBrowserRequest: async (parent, request) => {
        events.push({ kind: 'browser', parent, ...request });
        if (request.path === options.failPath) throw new Error(`unsafe dependency body ${token} ${secret.client_secret}`);
        return { ok: true };
      },
      fetchImpl: async (url, request) => {
        events.push({ kind: 'fetch', url, ...request });
        if (options.fetchError) throw new Error(`unsafe fetch error ${secret.client_secret}`);
        return {
          status: options.status ?? 200,
          redirected: options.redirected || false,
          url: options.responseUrl || `${secret.base_url}/`,
          headers: { getSetCookie: () => cookies },
          body: { cancel: async () => events.push({ kind: 'cancel-body' }) },
        };
      },
    },
  };
}

test('viewer exchanges secret once at exact HTTPS origin and installs only a verified host-only cookie', async () => {
  const token = await signed();
  const { events, dependencies } = harness(token);
  const result = await configureViewer({ raw }, dependencies);
  assert.deepEqual(events.map(event => event.path || event.kind), [
    '/set/headers', 'fetch', 'cancel-body', '/cookies/set', '/navigate',
  ]);
  assert.deepEqual(events[0].body, { headers: {} });
  assert.equal(events[1].url, `${secret.base_url}/`);
  assert.equal(events[1].redirect, 'error');
  assert.ok(events[1].signal instanceof AbortSignal);
  assert.deepEqual(events[1].headers, {
    'CF-Access-Client-Id': secret.client_id, 'CF-Access-Client-Secret': secret.client_secret,
  });
  const browserCalls = events.filter(event => event.kind === 'browser');
  assert.ok(!JSON.stringify(browserCalls).includes(secret.client_secret));
  const cookie = events[3].body.cookie;
  assert.deepEqual(cookie, {
    name: 'CF_Authorization', value: token, url: `${secret.base_url}/`,
    httpOnly: true, secure: true, sameSite: 'Lax', expires: result.expiresAt / 1000,
  });
  assert.ok(!('domain' in cookie));
  assert.equal(events[4].body.url, secret.base_url);
  for (const request of browserCalls) assert.equal(request.query.profile, 'secure-browser-viewer');
});

test('viewer accepts both supported service-secret formats and rejects missing or unsafe public metadata', () => {
  assert.equal(readViewerSecret(raw).client_id, secret.client_id);
  assert.equal(readViewerSecret(JSON.stringify({ ...secret, client_secret: 'b'.repeat(64) })).audience, secret.audience);
  for (const change of [
    { base_url: 'https://evil.test' }, { base_url: `${secret.base_url}.evil.test` },
    { base_url: 'http://browsers.cc-games.dev' }, { base_url: `${secret.base_url}/path` },
    { issuer: 'https://evil.cloudflareaccess.com' }, { audience: undefined },
    { audience: [secret.audience] }, { client_id: [secret.client_id] },
    { audience: 'wrong' }, { client_id: 'wrong' }, { client_secret: 'wrong' },
  ]) assert.throws(() => readViewerSecret(JSON.stringify({ ...secret, ...change })));
  for (const invalid of ['null', '[]', '{}', 'not json', ' '.repeat(16385)]) {
    assert.throws(() => readViewerSecret(invalid));
  }
});

test('viewer reads stdin with a strict byte bound', async () => {
  assert.equal(await readViewerInput([Buffer.from(raw.slice(0, 20)), Buffer.from(raw.slice(20))]), raw);
  await assert.rejects(readViewerInput(['x'.repeat(16384), 'x']));
  await assert.rejects(readViewerInput(['é'.repeat(8193)]));
});

test('viewer refuses invalid profile names before any request', async () => {
  for (const profile of ['default/other', '-bad', '', 'A', 'a'.repeat(49)]) {
    const { events, dependencies } = harness(await signed());
    await assert.rejects(configureViewer({ raw, profile }, dependencies));
    assert.equal(events.length, 0);
  }
});

for (const [description, options] of [
  ['missing cookie', { cookies: [] }],
  ['duplicate cookie', { cookies: ['CF_Authorization=x', 'CF_Authorization=y'] }],
  ['malformed cookie', { cookies: ['CF_Authorization=not-a-jwt'] }],
  ['oversized cookie', { cookies: [`CF_Authorization=${'a'.repeat(16385)}.b.c`] }],
  ['redirect response', { status: 302 }],
  ['redirected response', { redirected: true }],
  ['off-origin response', { responseUrl: 'https://evil.test/' }],
  ['denied response', { status: 403 }],
  ['fetch failure', { fetchError: true }],
]) {
  test(`viewer fails closed on ${description} without installing a cookie or navigating`, async () => {
    const { events, dependencies } = harness(await signed(), options);
    await assert.rejects(configureViewer({ raw }, dependencies));
    assert.deepEqual(events.filter(event => event.kind === 'browser').map(event => event.path), ['/set/headers']);
  });
}

test('viewer verifies cookie signature, app audience, issuer, identity, timestamps, and exact service claims', async () => {
  const other = await generateKeyPair('RS256');
  const invalidTokens = [
    await signed({}, { key: other.privateKey }),
    await signed({}, { audience: 'b'.repeat(64) }),
    await signed({}, { issuer: 'https://other.cloudflareaccess.com' }),
    await signed({}, { exp: '1 second ago' }), await signed({}, { exp: '30s' }),
    await signed({}, { exp: '24h' }), await signed({}, { iat: Math.floor(Date.now() / 1000) + 120 }),
    await signed({ common_name: 'f'.repeat(32) + '.access' }),
    await signed({ common_name: undefined }), await signed({ type: 'org' }),
    await signed({}, { sub: 'owner' }),
  ];
  for (const token of invalidTokens) {
    const { events, dependencies } = harness(token);
    await assert.rejects(configureViewer({ raw }, dependencies));
    assert.deepEqual(events.filter(event => event.kind === 'browser').map(event => event.path), ['/set/headers']);
  }
});

test('viewer aborts when legacy header clearing fails and never echoes dependency credentials', async () => {
  const token = await signed();
  for (const failPath of ['/set/headers', '/cookies/set', '/navigate']) {
    const { events, dependencies } = harness(token, { failPath });
    await assert.rejects(configureViewer({ raw }, dependencies), error => {
      assert.ok(!error.message.includes(token));
      assert.ok(!error.message.includes(secret.client_secret));
      assert.equal(error.cause, undefined);
      return true;
    });
    if (failPath === '/set/headers') assert.equal(events.length, 1);
    if (failPath === '/cookies/set') assert.ok(!events.some(event => event.path === '/navigate'));
  }
});
