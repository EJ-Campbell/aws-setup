import assert from 'node:assert/strict';
import { mkdtemp, mkdir, open, readFile, readdir, readlink, realpath, writeFile, rm, stat, symlink, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { createInstanceManager } from '../lib/instances.mjs';

// macOS /var is a symlink and its per-user tmp path can exceed the Unix socket limit.
// Use a short canonical temporary root, without weakening production path validation.
const testTmp = await realpath(process.platform === 'darwin' ? '/tmp' : tmpdir());

async function fixture(t, launch) {
  const stateDir = await mkdtemp(join(testTmp, 'browser-manager-'));
  const launches = [];
  const manager = createInstanceManager({ stateDir, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' }, {
    launch: launch ?? (async (options) => {
      const ended = Promise.withResolvers();
      const handle = { socketPath: join(options.runtimeDir, 'vnc.sock'), closed: ended.promise,
        resizes: [], resize: async viewport => { handle.resizes.push(viewport); },
        close: async () => { handle.stopped = true; ended.resolve(); } };
      launches.push({ ...options, handle });
      return handle;
    }),
  });
  t.after(async () => { await manager.close(); await rm(stateDir, { recursive: true, force: true }); });
  await manager.initialize();
  return { manager, stateDir, launches };
}

async function failStateSync(t, stateDir, directory = false) {
  const file = await open(stateDir);
  const prototype = Object.getPrototypeOf(file);
  await file.close();
  const sync = prototype.sync;
  return t.mock.method(prototype, 'sync', async function () {
    if ((await this.stat()).isDirectory() === directory) throw new Error('Injected sync failure');
    return sync.call(this);
  });
}

test('navigation reads only the selected live desktop and never saves or exposes history', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  await manager.start('alpha'); await manager.start('beta');
  const saved = await readFile(join(stateDir, 'instances.json'), 'utf8');
  const socket = manager.getSocket('alpha');
  launches[0].handle.getNavigation = async () => ({ canGoBack: true, history: 'private' });
  launches[1].handle.getNavigation = async () => ({ canGoBack: false });
  assert.deepEqual(await manager.getNavigation('alpha'), { canGoBack: true });
  assert.deepEqual(await manager.getNavigation('beta'), { canGoBack: false });
  assert.equal(await readFile(join(stateDir, 'instances.json'), 'utf8'), saved);
  assert.equal(manager.getSocket('alpha'), socket);
  for (const result of [null, {}, { canGoBack: 'yes' }]) {
    launches[0].handle.getNavigation = async () => result;
    assert.deepEqual(await manager.getNavigation('alpha'), { canGoBack: null });
  }
  launches[0].handle.getNavigation = async () => { throw new Error('private native diagnostic'); };
  assert.deepEqual(await manager.getNavigation('alpha'), { canGoBack: null });
  await assert.rejects(manager.getNavigation('missing'), error => error.status === 404);
  await assert.rejects(manager.getNavigation('../alpha'), /Invalid browser name/);
  await manager.stop('alpha');
  assert.deepEqual(await manager.getNavigation('alpha'), { canGoBack: null });
  assert.equal(launches.length, 2);
});

test('navigation cannot enable Back from a late snapshot after stop, replacement, or close', async (t) => {
  const { manager, launches } = await fixture(t);
  await manager.start('alpha');
  for (const boundary of ['stop', 'replace', 'close']) {
    const result = Promise.withResolvers();
    launches.at(-1).handle.getNavigation = () => result.promise;
    const reading = manager.getNavigation('alpha');
    if (boundary === 'close') await manager.close();
    else await manager.stop('alpha');
    if (boundary === 'replace') await manager.start('alpha');
    result.resolve({ canGoBack: true });
    assert.deepEqual(await reading, { canGoBack: null });
    if (boundary === 'stop') await manager.start('alpha');
  }
});

test('Phone mode resizes only the selected live desktop, without saving state or restarting its browser', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  const desktop = { mode: 'desktop', width: 1440, height: 900 };
  const phone = { mode: 'phone', width: 390, height: 680 };
  await manager.start('alpha'); await manager.start('beta');
  const socket = manager.getSocket('alpha');
  const saved = await readFile(join(stateDir, 'instances.json'), 'utf8');
  const resized = await manager.setViewport('alpha', phone);
  assert.deepEqual(resized.viewport, phone);
  assert.deepEqual(manager.list()[1].viewport, desktop);
  assert.deepEqual(launches[0].handle.resizes, [phone]);
  assert.deepEqual(launches[1].handle.resizes, []);
  assert.equal(manager.getSocket('alpha'), socket);
  assert.equal(launches.length, 2);
  assert.equal(await readFile(join(stateDir, 'instances.json'), 'utf8'), saved);
  // Public results cannot mutate geometry; explicit requests can recover uncertain native state.
  resized.viewport.width = 500;
  assert.deepEqual((await manager.setViewport('alpha', phone)).viewport, phone);
  assert.equal(launches[0].handle.resizes.length, 2);
  assert.deepEqual((await manager.setViewport('alpha', { mode: 'desktop' })).viewport, desktop);
  assert.deepEqual(launches[0].handle.resizes, [phone, phone, desktop]);
  await manager.setViewport('alpha', phone);
  await manager.stop('alpha'); await manager.start('alpha');
  assert.deepEqual(manager.list()[0].viewport, desktop);
});

test('resize validation and native failures cannot claim a mode change or restart the browser', async (t) => {
  const { manager, launches } = await fixture(t);
  const phone = { mode: 'phone', width: 390, height: 680 };
  for (const input of [null, {}, [], { ...phone, width: '390' }, { ...phone, width: 319 },
    { ...phone, width: 501 }, { ...phone, height: 479 }, { ...phone, height: 901 },
    { ...phone, height: 500.5 }, { ...phone, display: ':0' }, { mode: 'desktop', width: 500 },
    { mode: 'phone', width: 390 }, { ...phone, mode: 'arbitrary' }]) {
    assert.throws(() => manager.setViewport('alpha', input), error => error.status === 400);
  }
  await assert.rejects(manager.setViewport('missing', phone), error => error.status === 404);
  await manager.start('alpha');
  const before = manager.list()[0];
  launches[0].handle.resize = async () => { throw new Error('Native resize failed'); };
  await assert.rejects(manager.setViewport('alpha', phone), /Native resize failed/);
  assert.deepEqual(manager.list()[0], before);
  assert.equal(launches.length, 1);
  await manager.stop('alpha');
  await assert.rejects(manager.setViewport('alpha', phone), error => error.status === 409);
});

test('queued resize completes before stop closes its exact desktop', async (t) => {
  const { manager, launches } = await fixture(t);
  await manager.start('alpha');
  const started = Promise.withResolvers();
  const finish = Promise.withResolvers();
  launches[0].handle.resize = async () => { started.resolve(); await finish.promise; };
  const resizing = manager.setViewport('alpha', { mode: 'phone', width: 390, height: 680 });
  await started.promise;
  const stopping = manager.stop('alpha');
  assert.equal(launches[0].handle.stopped, undefined);
  finish.resolve();
  assert.equal((await resizing).viewport.mode, 'phone');
  await stopping;
  assert.equal(launches[0].handle.stopped, true);
});

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

test('Mac page handles are scoped to the selected running desktop and revoked on stop or replacement', async (t) => {
  const { manager, launches } = await fixture(t);
  await manager.start('mac'); await manager.start('other');
  assert.equal(manager.getPage('mac'), null, 'Linux desktops are not page transports');
  launches[0].handle.transport = 'page';
  assert.equal(manager.getPage('mac'), launches[0].handle);
  assert.equal(manager.getPage('other'), null);
  assert.equal(manager.getPage('missing'), null);
  assert.throws(() => manager.getPage('../mac'), /Invalid browser name/);
  await manager.stop('mac');
  assert.equal(manager.getPage('mac'), null);
  await manager.start('mac');
  launches[2].handle.transport = 'page';
  assert.equal(manager.getPage('mac'), launches[2].handle);
  await manager.close();
  assert.equal(manager.getPage('mac'), null);
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
  assert.deepEqual(manager.list(), []);
  await rm(join(stateDir, 'instances.json'), { recursive: true });
  for (let index = 0; index < 32; index++) await manager.start(`browser-${index}`);
  assert.equal(launches.length, 32);
});

test('failed start restores the existing profile and URL configuration', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  await manager.start('alpha', { url: 'https://original.example' });
  await manager.stop('alpha');
  const before = manager.list();
  const profile = join(stateDir, 'other-profile');
  await mkdir(profile, { mode: 0o700 });
  const failure = await failStateSync(t, stateDir);
  await assert.rejects(manager.start('alpha', { profile, url: 'https://changed.example' }), /Could not save/);
  failure.mock.restore();
  assert.deepEqual(manager.list(), before);
  await manager.start('alpha');
  assert.equal(launches[1].profile, launches[0].profile);
  assert.equal(launches[1].url, 'https://original.example/');
});

test('failed stop retains desired running state through a later save and reload', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  await manager.start('alpha');
  const failure = await failStateSync(t, stateDir);
  await assert.rejects(manager.stop('alpha'), /Could not save/);
  failure.mock.restore();
  assert.equal(manager.list()[0].state, 'running');
  assert.equal(launches[0].handle.stopped, undefined);
  await manager.start('beta');
  const saved = JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'));
  assert.equal(saved.find(({ name }) => name === 'alpha').desired, true);
  await launches[0].handle.close();
  await manager.stop('beta'); // Wait behind alpha's exit callback in the manager's queue.
  assert.equal(manager.list().find(({ name }) => name === 'alpha').state, 'error');
  await manager.close();
  const restored = createInstanceManager({ stateDir, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' }, {
    launch: async () => ({ socketPath: '/test/socket', close: async () => {}, closed: new Promise(() => {}) }),
  });
  t.after(() => restored.close());
  await restored.initialize();
  assert.equal(restored.list().find(({ name }) => name === 'alpha').state, 'running');
});

test('directory sync failure after rename retains the replaced state without claiming rollback', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  const failure = await failStateSync(t, stateDir, true);
  await assert.rejects(manager.start('alpha'), /durability could not be confirmed/);
  failure.mock.restore();
  assert.equal(manager.list()[0].name, 'alpha');
  assert.equal(launches.length, 0);
  const saved = JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'));
  assert.equal(saved[0].desired, true);
  await manager.start('beta');
  assert.equal(JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'))[0].desired, true);
  const stopFailure = await failStateSync(t, stateDir, true);
  await assert.rejects(manager.stop('beta'), /durability could not be confirmed/);
  stopFailure.mock.restore();
  assert.equal(manager.list().find(({ name }) => name === 'beta').state, 'running');
  await manager.start('gamma');
  assert.equal(JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'))
    .find(({ name }) => name === 'beta').desired, false);
});

test('limits accidental process fanout to 32 named desktops', async (t) => {
  const { manager, launches } = await fixture(t);
  for (let index = 0; index < 32; index++) await manager.start(`browser-${index}`);
  await assert.rejects(manager.start('too-many'), /limit reached/);
  assert.equal(launches.length, 32);
});

test('rename persists only a display label while a running desktop keeps its identity and profile', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  const before = await manager.start('stable-name');
  assert.equal(before.label, 'stable-name');
  const stateFile = join(stateDir, 'instances.json');
  const original = JSON.parse(await readFile(stateFile, 'utf8'))[0];
  assert.equal(Object.hasOwn(original, 'label'), false, 'old metadata does not need a label');
  const socket = manager.getSocket('stable-name');
  const renamed = await manager.rename('stable-name', '  Claude · Personal  ');
  assert.deepEqual(renamed, { ...before, label: 'Claude · Personal' });
  assert.equal(manager.getSocket('stable-name'), socket);
  assert.equal(launches.length, 1);
  assert.equal(launches[0].handle.stopped, undefined);
  assert.deepEqual(JSON.parse(await readFile(stateFile, 'utf8'))[0], { ...original, label: 'Claude · Personal' });
  await manager.close();
  const restored = createInstanceManager({ stateDir, browserBin: '/test/chrome', baseUrl: 'https://browsers.example' }, {
    launch: async ({ profile }) => {
      assert.equal(profile, original.profile);
      return { socketPath: '/restored/socket', close: async () => {}, closed: new Promise(() => {}) };
    },
  });
  t.after(() => restored.close());
  await restored.initialize();
  assert.deepEqual(restored.list(), [{ ...before, label: 'Claude · Personal' }]);
});

test('rename rejects invalid labels and rolls back failed saves without replacing the desktop record', async (t) => {
  const { manager, stateDir, launches } = await fixture(t);
  await manager.start('alpha');
  for (const label of [undefined, null, 1, '', '   ', 'x'.repeat(81), 'line\nbreak', '\ttrim', 'nul\0', 'delete\x7f', 'control\x85']) {
    assert.throws(() => manager.rename('alpha', label), /label/);
  }
  await assert.rejects(manager.rename('missing', 'Good label'), /Unknown browser/);
  for (const label of ['alpha', 'Kept label']) {
    if (label !== 'alpha') await manager.rename('alpha', label);
    const before = manager.list();
    const disk = await readFile(join(stateDir, 'instances.json'), 'utf8');
    const failure = await failStateSync(t, stateDir);
    await assert.rejects(manager.rename('alpha', 'Lost label'), /Could not save/);
    failure.mock.restore();
    assert.deepEqual(manager.list(), before);
    assert.equal(await readFile(join(stateDir, 'instances.json'), 'utf8'), disk);
  }
  await launches[0].handle.close();
  await manager.start('beta');
  assert.equal(manager.list().find(({ name }) => name === 'alpha').state, 'error');
});

test('rename preserves the replaced label when directory sync fails after rename', async (t) => {
  const { manager, stateDir } = await fixture(t);
  await manager.start('alpha');
  const failure = await failStateSync(t, stateDir, true);
  await assert.rejects(manager.rename('alpha', 'Replaced label'), /durability could not be confirmed/);
  failure.mock.restore();
  assert.equal(manager.list()[0].label, 'Replaced label');
  assert.equal(JSON.parse(await readFile(join(stateDir, 'instances.json'), 'utf8'))[0].label, 'Replaced label');
});
