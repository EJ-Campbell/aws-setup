import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, readlink, writeFile, rm, stat, symlink, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { createInstanceManager } from '../lib/instances.mjs';

async function fixture(t, launch) {
  const stateDir = await mkdtemp(join(tmpdir(), 'browser-manager-'));
  const launches = [];
  const manager = createInstanceManager({ stateDir, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' }, {
    launch: launch ?? (async (options) => {
      const ended = Promise.withResolvers();
      const handle = { socketPath: join(options.runtimeDir, 'vnc.sock'), closed: ended.promise,
        close: async () => { handle.stopped = true; ended.resolve(); } };
      launches.push({ ...options, handle });
      return handle;
    }),
  });
  t.after(async () => { await manager.close(); await rm(stateDir, { recursive: true, force: true }); });
  await manager.initialize();
  return { manager, stateDir, launches };
}

test('named desktops have isolated profiles and sockets; stopping preserves only the chosen profile', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  const [a, b] = await Promise.all([manager.start('alpha', { url: 'https://example.com' }), manager.start('beta')]);
  assert.equal(a.url, 'https://browsers.example/browsers/alpha');
  assert.equal(b.state, 'running');
  assert.notEqual(launches[0].profile, launches[1].profile);
  assert.notEqual(manager.getSocket('alpha'), manager.getSocket('beta'));
  assert.equal((await stat(launches[0].profile)).mode & 0o777, 0o700);
  assert.equal((await stat(launches[0].runtimeDir)).mode & 0o777, 0o700);
  await writeFile(join(launches[0].profile, 'session-cookie'), 'private-alpha');
  await manager.stop('alpha');
  assert.equal(manager.getSocket('alpha'), null);
  assert.equal(launches[1].handle.stopped, undefined);
  await manager.start('alpha');
  assert.equal(await readFile(join(launches[2].profile, 'session-cookie'), 'utf8'), 'private-alpha');
  assert.equal(launches[2].url, 'https://example.com/');
  assert.equal(launches[2].profile, launches[0].profile);
  assert.equal(JSON.stringify(manager.list()).includes(stateDir), false);
  assert.equal((await stat(join(stateDir, 'instances.json'))).mode & 0o777, 0o600);
  await manager.close();
  assert.equal(launches.every(({ handle }) => handle.stopped), true);
});

test('rejects route escapes, unsafe URLs, linked state/profiles, and overbroad state permissions', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  for (const name of ['', '../other', '/tmp/other', 'UPPER', 'a/b', 'a%2fb', 'x'.repeat(49)]) {
    assert.throws(() => manager.start(name), /Invalid browser name/);
    assert.throws(() => manager.getSocket(name), /Invalid browser name/);
  }
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'https://user:pass@example.com', '--no-sandbox']) {
    assert.throws(() => manager.start('invalid', { url }), /URL/);
  }
  await symlink(join(stateDir, 'profiles'), join(stateDir, 'linked'));
  await assert.rejects(manager.start('linked', { profile: join(stateDir, 'linked') }), /directory/);
  const unsafe = join(stateDir, 'unsafe');
  await mkdir(unsafe);
  await chmod(unsafe, 0o755);
  const other = createInstanceManager({ stateDir: unsafe, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' });
  await assert.rejects(other.initialize(), /directory/);
  assert.equal(launches.length, 0);
});

test('explicit profile reuse is private, refuses existing Chrome locks, and never clears them', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  const profile = join(stateDir, 'existing-profile');
  await mkdir(profile, { mode: 0o700 });
  await symlink('host-12345', join(profile, 'SingletonLock'));
  await assert.rejects(manager.start('imported', { profile }), /already in use/);
  assert.equal((await readFile(join(stateDir, 'instances.json')).catch(() => null)), null);
  await rm(join(profile, 'SingletonLock'));
  await manager.start('imported', { profile });
  await assert.rejects(manager.start('same-profile', { profile }), /could not start/);
  assert.equal(launches.length, 1);
  assert.equal(launches[0].profile, profile);
  assert.equal(JSON.stringify(manager.list()).includes(profile), false);
});

test('managed profiles delegate stale-lock recovery to Chromium without deleting locks', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  await manager.start('owned');
  await manager.stop('owned');
  const profile = join(stateDir, 'profiles', 'owned');
  await symlink('old-host-12345', join(profile, 'SingletonLock'));
  await symlink('/stale/chromium/socket', join(profile, 'SingletonSocket'));
  await manager.start('owned');
  assert.equal(launches.length, 2);
  assert.equal(manager.list()[0].state, 'running');
  assert.equal(await readlink(join(profile, 'SingletonLock')), 'old-host-12345');
  assert.equal(await readlink(join(profile, 'SingletonSocket')), '/stale/chromium/socket');
});

test('reload restores desired desktops but ignores stored process identifiers', async (t) => {
  const { manager, stateDir } = await fixture(t);
  await manager.start('restart');
  await manager.start('stopped');
  await manager.stop('stopped');
  await manager.close();
  const saved = JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'));
  saved[0].pid = process.pid;
  await writeFile(join(stateDir, 'instances.json'), JSON.stringify(saved), { mode: 0o600 });
  const started = [];
  const restored = createInstanceManager({ stateDir, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' }, {
    launch: async (options) => {
      started.push(options);
      return { socketPath: join(options.runtimeDir, 'vnc.sock'), close: async () => {}, closed: new Promise(() => {}) };
    },
  });
  t.after(() => restored.close());
  await restored.initialize();
  assert.equal(started.length, 1);
  assert.deepEqual(restored.list().map(({ name, state }) => [name, state]), [['restart', 'running'], ['stopped', 'stopped']]);
});

test('partial startup failure is not advertised and retains the browser profile', async (t) => {
  const { manager, stateDir } = await fixture(t, async ({ profile }) => {
    await writeFile(join(profile, 'retained'), 'not deleted');
    throw new Error('private process diagnostic');
  });
  await assert.rejects(manager.start('failed'), /could not start/);
  assert.equal(manager.getSocket('failed'), null);
  assert.equal(manager.list()[0].state, 'error');
  assert.equal(JSON.stringify(manager.list()).includes('private process diagnostic'), false);
  assert.equal(await readFile(join(stateDir, 'profiles', 'failed', 'retained'), 'utf8'), 'not deleted');
  assert.equal(JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'))[0].desired, false);
});

test('close wins over an in-flight start and cannot leave a newly started desktop running', async (t) => {
  const started = Promise.withResolvers();
  const release = Promise.withResolvers();
  let stopped = false;
  const { manager, stateDir } = await fixture(t, async () => {
    started.resolve();
    await release.promise;
    return { socketPath: '/never-published', close: async () => { stopped = true; }, closed: new Promise(() => {}) };
  });
  const start = manager.start('closing');
  const rejected = assert.rejects(start, /closed/);
  await started.promise;
  const closing = manager.close();
  release.resolve();
  await Promise.all([rejected, closing]);
  assert.equal(stopped, true);
  assert.equal(manager.getSocket('closing'), null);
  assert.equal(JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'))[0].desired, false);
  await assert.rejects(manager.start('late'), /closed/);
});

test('close awaits initialization and does not restore saved desktops afterward', async (t) => {
  const { manager, stateDir } = await fixture(t);
  await manager.start('restore');
  await manager.close();
  let launches = 0;
  const restored = createInstanceManager({ stateDir, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' }, {
    launch: async () => { launches++; throw new Error('Must not launch'); },
  });
  const initializing = restored.initialize();
  await restored.close();
  assert.deepEqual(restored.list().map(({ name, state }) => [name, state]), [['restore', 'stopped']]);
  await initializing;
  assert.equal(launches, 0);
  assert.equal(restored.getSocket('restore'), null);
});

test('state-save failures do not expose private paths or leave temporary metadata', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  await mkdir(join(stateDir, 'instances.json'));
  await assert.rejects(manager.start('save-failed'), { message: 'Could not save private browser state' });
  assert.equal(launches.length, 0);
  assert.equal((await readdir(stateDir)).some((name) => name.startsWith('.instances-')), false);
});

test('limits accidental process fanout to 32 named desktops', async (t) => {
  const { manager, launches } = await fixture(t);
  for (let index = 0; index < 32; index++) await manager.start(`browser-${index}`);
  await assert.rejects(manager.start('too-many'), /limit reached/);
  assert.equal(launches.length, 32);
});
