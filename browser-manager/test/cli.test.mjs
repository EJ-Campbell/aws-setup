import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHttpServer } from '../lib/http.mjs';

test('CLI rename and list show the label while url keeps the stable name', async () => {
  const stateDir = await mkdtemp(join(tmpdir(), 'browser-cli-rename-'));
  const row = { name: 'stable', label: 'stable', state: 'running', url: 'https://browsers.example/browsers/stable' };
  const calls = [];
  const server = createHttpServer({ local: true, config: { baseUrl: 'https://browsers.example' }, manager: {
    list: () => [row], rename: async (name, label) => { calls.push([name, label]); row.label = label; return row; },
  } });
  server.listen(join(stateDir, 'control.sock'));
  await once(server, 'listening');
  const cli = (...args) => promisify(execFile)(process.execPath, ['bin/browserctl.mjs', ...args], {
    env: { ...process.env, BM_STATE_DIR: stateDir }, timeout: 5000,
  });
  try {
    assert.equal((await cli('rename', 'stable', '  Personal browser  ')).stdout.trim(), `Personal browser: ${row.url}`);
    assert.deepEqual(calls, [['stable', 'Personal browser']]);
    assert.equal((await cli('url', 'stable')).stdout.trim(), row.url);
    assert.match((await cli('list')).stdout, /stable\tPersonal browser\trunning/);
    await assert.rejects(cli('rename', 'stable', 'bad\nlabel'), /label/);
    await assert.rejects(cli('rename', 'stable', 'one', 'two'), /browserctl/);
    assert.equal(calls.length, 1);
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(stateDir, { recursive: true, force: true });
  }
});
