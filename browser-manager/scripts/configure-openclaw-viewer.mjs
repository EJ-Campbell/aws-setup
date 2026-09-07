#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readdir, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const BASE_URL = 'https://browsers.cc-games.dev';
const ISSUER = 'https://ejc3.cloudflareaccess.com';
const fail = message => { throw new Error(`browser-manager viewer: ${message}`); };

export function readViewerSecret(raw) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 16384) fail('secret input is too large');
  let secret;
  try { secret = JSON.parse(raw); } catch { fail('secret input is not valid JSON'); }
  if (!secret || typeof secret !== 'object' || Array.isArray(secret) ||
      ['client_id', 'client_secret', 'base_url', 'issuer', 'audience'].some(name => typeof secret[name] !== 'string') ||
      !/^[a-f0-9]{32}\.access$/.test(secret.client_id || '') ||
      !/^(?:[a-f0-9]{64}|cfast_[A-Za-z0-9]{48})$/.test(secret.client_secret || '') ||
      secret.base_url !== BASE_URL || secret.issuer !== ISSUER ||
      !/^[a-f0-9]{64}$/.test(secret.audience || '')) {
    fail('secret input is not the configured browser-manager Access credential');
  }
  return secret;
}

export async function readViewerInput(input) {
  const chunks = [];
  let size = 0;
  for await (const chunk of input) {
    size += Buffer.byteLength(chunk);
    if (size > 16384) fail('secret input is too large');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString('utf8');
}

// Keep the long-lived service secret out of Chromium entirely. A named profile does
// not restrict extra HTTP headers to one origin: redirects, subresources, and later
// navigations would otherwise disclose them. Only a host-only short-lived cookie
// enters the viewer; remote desktops retain their own, separate website sessions.
export async function configureViewer({ raw, profile = 'secure-browser-viewer' }, {
  callBrowserRequest, fetchImpl = globalThis.fetch, key,
}) {
  if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(profile)) fail('invalid OpenClaw browser profile name');
  const secret = readViewerSecret(raw);
  const parent = { browserProfile: profile, timeout: '30000' };
  const request = (path, body) => callBrowserRequest(parent, {
    method: 'POST', path, query: { profile }, body,
  });

  try {
    // Remove credentials installed by older versions before any navigation. Failure
    // to clear them aborts; never silently continue with profile-wide secret headers.
    await request('/set/headers', { headers: {} });
    const response = await fetchImpl(`${BASE_URL}/`, {
      method: 'GET', redirect: 'error', signal: AbortSignal.timeout(15000),
      headers: {
        'CF-Access-Client-Id': secret.client_id,
        'CF-Access-Client-Secret': secret.client_secret,
      },
    });
    await response.body?.cancel();
    if (response.status !== 200 || response.redirected || response.url !== `${BASE_URL}/`) {
      fail('Access did not return a successful direct response');
    }
    const cookies = response.headers.getSetCookie().filter(value => value.startsWith('CF_Authorization='));
    if (cookies.length !== 1) fail('Access did not return exactly one authorization cookie');
    const token = cookies[0].split(';', 1)[0].slice('CF_Authorization='.length);
    if (token.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
      fail('Access returned an invalid authorization cookie');
    }
    const { payload } = await jwtVerify(token, key || createRemoteJWKSet(
      new URL(`${ISSUER}/cdn-cgi/access/certs`), { timeoutDuration: 5000 },
    ), {
      issuer: ISSUER, audience: secret.audience, algorithms: ['RS256'],
      requiredClaims: ['exp', 'iat', 'sub', 'type', 'common_name'],
    });
    const now = Math.floor(Date.now() / 1000);
    if (payload.type !== 'app' || payload.sub !== '' || payload.common_name !== secret.client_id ||
        !Number.isSafeInteger(payload.exp) || !Number.isSafeInteger(payload.iat) ||
        payload.exp <= now + 60 || payload.exp > now + 13 * 3600 || payload.iat > now + 30) {
      fail('Access cookie does not identify the expected short-lived service session');
    }
    await request('/cookies/set', { cookie: {
      name: 'CF_Authorization', value: token, url: `${BASE_URL}/`,
      httpOnly: true, secure: true, sameSite: 'Lax', expires: payload.exp,
    } });
    await request('/navigate', { url: BASE_URL });
    return { profile, expiresAt: payload.exp * 1000 };
  } catch {
    // Dependency errors may include HTTP bodies or cookie values. Never print their
    // message/cause/stack, even when the gateway or Access response is malformed.
    fail('setup failed; check the viewer profile, current secret, and Access configuration');
  }
}

async function loadOpenClawClient() {
  // Import OpenClaw's own authenticated request helper: cookies travel in its Gateway
  // request body, never argv or a temporary file. Hashed chunk names vary by release.
  const launcher = await realpath(execFileSync('/usr/bin/which', ['openclaw'], { encoding: 'utf8' }).trim());
  const dist = join(dirname(launcher), 'dist');
  const matches = (await readdir(dist)).filter(name => /^browser-cli-shared-.*\.js$/.test(name));
  if (matches.length !== 1) fail('could not resolve the installed OpenClaw browser client');
  const { n: callBrowserRequest } = await import(pathToFileURL(join(dist, matches[0])));
  if (typeof callBrowserRequest !== 'function') fail('installed OpenClaw browser client is incompatible');
  return callBrowserRequest;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const raw = await readViewerInput(process.stdin);
    const result = await configureViewer({ raw, profile: process.argv[2] }, {
      callBrowserRequest: await loadOpenClawClient(),
    });
    process.stdout.write(`Configured OpenClaw profile ${result.profile} for the private browser manager.\n`);
  } catch {
    process.stderr.write('browser-manager viewer: setup failed; check the profile, current secret, and installed dependencies.\n');
    process.exitCode = 1;
  }
}
