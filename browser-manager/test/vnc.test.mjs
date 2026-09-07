import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readdir, readFile, readlink, rm } from 'node:fs/promises';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { vncArguments } from '../lib/desktop.mjs';

async function tcpListeners(pid) {
  const sockets = new Set();
  for (const fd of await readdir(`/proc/${pid}/fd`)) {
    try {
      const target = await readlink(`/proc/${pid}/fd/${fd}`);
      const match = /^socket:\[(\d+)\]$/.exec(target);
      if (match) sockets.add(match[1]);
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const listeners = [];
  for (const family of ['tcp', 'tcp6']) {
    const table = await readFile(`/proc/net/${family}`, 'utf8');
    for (const row of table.trim().split('\n').slice(1)) {
      const fields = row.trim().split(/\s+/);
      if (fields[3] === '0A' && sockets.has(fields[9])) listeners.push(`${family}:${fields[1]}`);
    }
  }
  return listeners;
}

function hasBanner(socketPath) {
  return new Promise(resolve => {
    const socket = connect(socketPath);
    let banner = '';
    const finish = value => { socket.destroy(); resolve(value); };
    socket.setTimeout(2000, () => finish(false));
    socket.once('error', () => finish(false));
    socket.once('close', () => resolve(false));
    socket.on('data', bytes => {
      banner += bytes.toString('ascii');
      if (banner.length >= 12) finish(/^RFB \d{3}\.\d{3}\n/.test(banner));
    });
  });
}

test('production x11vnc accepts Unix RFB without owning a TCP4 or TCP6 listener', { timeout: 10_000 }, async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'browser-vnc-test-'));
  const socketPath = join(scratch, 'vnc.sock');
  const args = vncArguments({ display: '0', authFile: join(scratch, 'Xauthority'), socketPath });
  let child;
  let done;
  try {
    // Prevent a regressed argument set from opening a public listener even during this test.
    for (const flag of ['-rfbport', '-rfbportv6']) {
      assert(args.includes(flag), `production arguments must include ${flag}`);
      assert.equal(args[args.indexOf(flag) + 1], '0');
    }
    // An explicit display overrides rawfb's no-X behavior. Clear only the fixture display;
    // all production transport flags stay intact. No browser, desktop, or profile is involved.
    child = spawn('/usr/bin/x11vnc', [...args, '-display', '', '-rawfb', 'file:/dev/zero@64x64x32'],
      { stdio: ['ignore', 'ignore', 'pipe'] });
    let failure;
    let stderr = '';
    child.once('error', error => { failure = error; });
    child.stderr.on('data', bytes => { stderr = (stderr + bytes.toString()).slice(-4096); });
    done = new Promise(resolve => child.once('close', resolve));
    const deadline = Date.now() + 5000;
    while (!(await hasBanner(socketPath))) {
      if (failure) throw failure;
      assert.equal(child.exitCode, null, `x11vnc exited: ${stderr}`);
      assert.equal(child.signalCode, null, `x11vnc was terminated: ${stderr}`);
      assert(Date.now() < deadline, `Unix RFB did not become ready: ${stderr}`);
      await delay(25);
    }
    assert.equal(child.exitCode, null);
    assert.equal(child.signalCode, null);
    assert.deepEqual(await tcpListeners(child.pid), [], 'x11vnc must expose only its private Unix socket');
    assert.equal(child.exitCode, null);
    assert.equal(child.signalCode, null);
  } finally {
    if (child) {
      child.kill('SIGTERM');
      await Promise.race([done, delay(1000, undefined, { ref: false })]);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await done;
    }
    await rm(scratch, { recursive: true, force: true });
  }
});
