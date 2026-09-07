#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { readdir, realpath } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const fail = message => { throw new Error(`browser-manager viewer: ${message}`); };
const profile = process.argv[2] || 'secure-browser-viewer';
if (!/^[a-z0-9][a-z0-9-]{0,47}$/.test(profile)) fail('invalid OpenClaw browser profile name');

let raw = '';
for await (const chunk of process.stdin) {
  raw += chunk;
  if (raw.length > 16384) fail('secret input is too large');
}

let secret;
try { secret = JSON.parse(raw); } catch { fail('secret input is not valid JSON'); }
if (!secret || typeof secret !== 'object' || Array.isArray(secret) ||
    !/^[a-f0-9]{32}\.access$/.test(secret.client_id || '') ||
    !/^(?:[a-f0-9]{64}|cfast_[A-Za-z0-9]{48})$/.test(secret.client_secret || '')) {
  fail('secret input is not a Cloudflare Access service-token pair');
}

// Import OpenClaw's own request helper so the credential travels in the Gateway request
// body, never argv, a temporary file, or this process's output. The chunk name is hashed
// per OpenClaw release, so resolve the one installed beside the launcher at runtime.
const launcher = await realpath(execFileSync('/usr/bin/which', ['openclaw'], { encoding: 'utf8' }).trim());
const dist = join(dirname(launcher), 'dist');
const matches = (await readdir(dist)).filter(name => /^browser-cli-shared-.*\.js$/.test(name));
if (matches.length !== 1) fail('could not resolve the installed OpenClaw browser client');
const { n: callBrowserRequest } = await import(pathToFileURL(join(dist, matches[0])));
if (typeof callBrowserRequest !== 'function') fail('installed OpenClaw browser client is incompatible');

const parent = { browserProfile: profile, timeout: '30000' };
await callBrowserRequest(parent, {
  method: 'POST',
  path: '/set/headers',
  query: { profile },
  body: {
    headers: {
      'CF-Access-Client-Id': secret.client_id,
      'CF-Access-Client-Secret': secret.client_secret,
    },
  },
});
await callBrowserRequest(parent, {
  method: 'POST',
  path: '/navigate',
  query: { profile },
  body: { url: 'https://browsers.cc-games.dev' },
});

// Do not include target URLs, token metadata, or response bodies in normal output.
process.stdout.write(`Configured OpenClaw profile ${profile} for the private browser manager.\n`);
