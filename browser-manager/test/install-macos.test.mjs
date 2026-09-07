import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify, parseEnv } from 'node:util';
import { installMacOS, requireNode, stableExecutable, readPrivate, parseConfiguration, renderLaunchAgent,
  renderWrapper, redactLogLine, LABELS, MARKER, LOG_LIMIT } from '../scripts/install-macos.mjs';

const execute = promisify(execFile);
const uid = process.getuid();
const validateConfig = env => {
  if (!env.BM_ACCESS_AUD || !env.BM_BASE_URL?.startsWith('https://') ||
      !env.BM_ACCESS_ISSUER?.endsWith('.cloudflareaccess.com') || !env.BM_OWNER_EMAIL?.includes('@')) throw new Error('auth rejected');
  return { port: Number(env.BM_PORT || 3210), baseUrl: env.BM_BASE_URL };
};

async function fixture(t) {
  // macOS TMPDIR is too long to stand in for a real short /Users/<owner> home.
  const root = await fs.realpath(await fs.mkdtemp(join(process.platform === 'darwin' ? '/private/tmp' : tmpdir(), 'bm-mac-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const home = join(root, 'home');
  const project = join(home, 'aws/browser-manager');
  const executable = join(root, 'bin/node');
  const browser = join(root, 'Google Chrome.app/Contents/MacOS/Google Chrome');
  const cloudflared = join(root, 'bin/cloudflared');
  for (const directory of [home, join(project, '.next'), join(project, 'bin'), join(root, 'bin'), join(root, 'Google Chrome.app/Contents/MacOS')]) await fs.mkdir(directory, { recursive: true });
  for (const [target, content, mode] of [
    [join(project, 'server.mjs'), 'export {};\n', 0o644],
    [join(project, '.next/BUILD_ID'), 'test-build\n', 0o644],
    [join(project, 'bin/browserctl.mjs'), '#!/usr/bin/env node\n', 0o755],
    [executable, '#!/bin/false\n', 0o755], [browser, '#!/bin/false\n', 0o755], [cloudflared, '#!/bin/false\n', 0o755],
  ]) { await fs.writeFile(target, content, { mode }); await fs.chmod(target, mode); }
  const configFile = join(root, 'config.env');
  const config = `BM_BASE_URL=https://mac-browsers.example.test\nBM_ACCESS_AUD=audience\nBM_ACCESS_ISSUER=https://team.cloudflareaccess.com\nBM_OWNER_EMAIL=owner@example.test\nBM_BROWSER_BIN="${browser}"\n`;
  await fs.writeFile(configFile, config, { mode: 0o600 });
  const tokenFile = join(root, 'token');
  await fs.writeFile(tokenFile, 'private-tunnel-token-123456\n', { mode: 0o600 });
  const calls = [];
  const loaded = new Map();
  let gui = true;
  let lint = true;
  const run = async (command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === '--version') return { stdout: 'v22.22.0\n', stderr: '' };
    if (command === cloudflared) return { stdout: 'usage: --token-file PATH', stderr: '' };
    if (command === '/usr/bin/plutil' && !lint) throw new Error('invalid plist');
    if (command === '/bin/launchctl') {
      if (args[0] === 'print' && args[1] === `gui/${uid}`) {
        if (!gui) throw Object.assign(new Error('no session'), { code: 113 });
        return { stdout: 'gui domain', stderr: '' };
      }
      if (args[0] === 'print') {
        if (!loaded.has(args[1])) throw Object.assign(new Error('no service'), { code: 113, stderr: 'Could not find service' });
        return { stdout: `service {\n\tpath = ${loaded.get(args[1])}\n}\n`, stderr: '' };
      }
      if (args[0] === 'bootstrap') {
        const label = args[2].split('/').at(-1).slice(0, -'.plist'.length);
        loaded.set(`${args[1]}/${label}`, args[2]);
      }
      if (args[0] === 'bootout') loaded.delete(args[1]);
    }
    return { stdout: '', stderr: '' };
  };
  return { root, home, project, browser, configFile, tokenFile, config, calls, loaded,
    setGUI: value => { gui = value; }, setLint: value => { lint = value; },
    dependencies: { platform: 'darwin', uid, home, project, node: executable, version: '22.22.0',
      cloudflared, run, validateConfig } };
}

function mutations(calls) { return calls.filter(call => call.command === '/bin/launchctl' && ['bootstrap', 'bootout'].includes(call.args[0])); }

test('macOS/user/Node gates happen before installation', async t => {
  const f = await fixture(t);
  for (const change of [{ platform: 'linux' }, { uid: 0 }, { version: '22.12.0' }]) {
    await assert.rejects(installMacOS({ configFile: f.configFile }, { ...f.dependencies, ...change }));
  }
  assert.equal(f.calls.length, 0);
  assert.throws(() => requireNode('20.20.0'));
  assert.throws(() => requireNode('invalid'));
  requireNode('22.13.0'); requireNode('v24.0.0');
});

test('private input requires exact0600, owner, a regular file, and no links', async t => {
  const f = await fixture(t);
  await fs.chmod(f.configFile, 0o644);
  await assert.rejects(readPrivate(f.configFile));
  await fs.chmod(f.configFile, 0o600);
  const symlink = join(f.root, 'config-link');
  await fs.symlink(f.configFile, symlink);
  await assert.rejects(readPrivate(symlink));
  const hardlink = join(f.root, 'config-hardlink');
  await fs.link(f.configFile, hardlink);
  await assert.rejects(readPrivate(f.configFile));
  await fs.unlink(hardlink);
  await assert.rejects(readPrivate(f.configFile, { uid: uid + 1 }));
  assert.equal(await readPrivate(f.configFile), f.config);
});

test('stable Homebrew executable aliases are retained only for the verified same executable', async t => {
  const f = await fixture(t);
  const current = f.dependencies.node;
  const alias = join(f.root, 'node-stable');
  const other = join(f.root, 'node-other');
  await fs.symlink(current, alias);
  await fs.symlink(f.browser, other);
  assert.equal(await stableExecutable(current, [other, alias]), alias);
  assert.equal(await stableExecutable(current, [other]), current);
  assert.equal(await stableExecutable(alias), alias);
  await fs.chmod(current, 0o777);
  await assert.rejects(stableExecutable(alias), /not writable/);
});

test('dotenv is parsed as data and delegates authentication validation', async () => {
  let delegated;
  const text = 'BM_ACCESS_AUD="$(touch /tmp/not-a-command)"\nBM_ACCESS_SERVICE_TOKEN_ID=client.access\n';
  const result = await parseConfiguration(text, env => { delegated = env; return { port: 3210 }; });
  assert.equal(delegated.BM_ACCESS_AUD, '$(touch /tmp/not-a-command)');
  assert.equal(result.env.BM_ACCESS_SERVICE_TOKEN_ID, 'client.access');
  for (const content of ['NODE_OPTIONS=--inspect\n', 'BM_STATE_DIR=/elsewhere\n',
    'TUNNEL_TOKEN=secret\n', 'BM_OWNER_EMAIL="first\nsecond"\n']) {
    await assert.rejects(parseConfiguration(content, () => ({ port: 3210 })));
  }
  await assert.rejects(parseConfiguration('BM_ACCESS_AUD=aud\n', () => { throw new Error('auth rejected'); }));
  await assert.rejects(parseConfiguration('BM_ACCESS_AUD=aud\n', () => ({ port: 9000 })));
});

test('installation writes native scoped LaunchAgents with a clean environment and no token value', async t => {
  const f = await fixture(t);
  const result = await installMacOS({ configFile: f.configFile, tokenFile: f.tokenFile }, f.dependencies);
  assert.deepEqual(result.labels, [LABELS.manager, LABELS.tunnel]);
  assert.equal(result.state, join(f.home, '.local/state/browser-manager'));
  assert.equal(await fs.readlink(result.command), join(f.project, 'bin/browserctl.mjs'));
  const env = parseEnv(await fs.readFile(result.config, 'utf8'));
  assert.equal(env.BM_BROWSER_BIN, f.browser);
  for (const kind of ['manager', 'tunnel']) {
    const plist = await fs.readFile(join(f.home, 'Library/LaunchAgents', `${LABELS[kind]}.plist`), 'utf8');
    assert.ok(plist.includes(MARKER));
    assert.ok(plist.includes('<string>/usr/bin/env</string><string>-i</string>'));
    assert.ok(plist.includes(`<key>WorkingDirectory</key><string>${f.project}</string>`));
    assert.ok(plist.includes('<string>NODE_ENV=production</string>'));
    assert.ok(plist.includes('<key>LimitLoadToSessionType</key><string>Aqua</string>'));
    assert.ok(plist.includes('<key>Umask</key><integer>63</integer>'));
    assert.ok(!plist.includes('private-tunnel-token-123456'));
    assert.equal(plist.includes('--env-file='), kind === 'manager');
  }
  const wrapper = await fs.readFile(join(f.home, '.config/browser-manager/launch-macos.mjs'), 'utf8');
  assert.ok(wrapper.includes("'--token-file', settings.token"));
  assert.ok(!wrapper.includes('private-tunnel-token-123456'));
  assert.ok(!wrapper.includes('shell: true'));
  for (const path of [result.config, join(f.home, '.config/browser-manager/tunnel-token'),
    join(f.home, '.config/browser-manager/launch-macos.mjs'), join(result.logs, 'manager.stdout.log')]) {
    assert.equal((await fs.stat(path)).mode & 0o777, 0o600);
  }
  for (const path of [result.state, result.logs, join(f.home, '.config/browser-manager')]) assert.equal((await fs.stat(path)).mode & 0o777, 0o700);
  assert.equal(mutations(f.calls).length, 2);
  assert.ok(mutations(f.calls).every(call => call.args[0] === 'bootstrap' && call.args[1] === `gui/${uid}`));
});

test('SSH requires an existing GUI login and does not bootstrap a GUI or root domain', async t => {
  const f = await fixture(t);
  f.setGUI(false);
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /GUI login/);
  assert.equal(mutations(f.calls).length, 0);
  await assert.rejects(fs.stat(join(f.home, '.config/browser-manager')));
});

test('manager-only reinstall preserves tunnel and all profiles while restarting only its exact label', async t => {
  const f = await fixture(t);
  const first = await installMacOS({ configFile: f.configFile, tokenFile: f.tokenFile }, f.dependencies);
  const profile = join(first.state, 'normal-existing-profile');
  await fs.mkdir(profile, { mode: 0o700 });
  await fs.writeFile(join(profile, 'Cookies'), 'keep my login', { mode: 0o600 });
  const tokenPath = join(f.home, '.config/browser-manager/tunnel-token');
  const tokenBefore = await fs.readFile(tokenPath, 'utf8');
  const tunnelPlist = join(f.home, 'Library/LaunchAgents', `${LABELS.tunnel}.plist`);
  const tunnelBefore = await fs.readFile(tunnelPlist, 'utf8');
  f.calls.length = 0;
  await installMacOS({ configFile: first.config }, f.dependencies);
  assert.equal(await fs.readFile(tokenPath, 'utf8'), tokenBefore);
  assert.equal(await fs.readFile(tunnelPlist, 'utf8'), tunnelBefore);
  assert.equal(await fs.readFile(join(profile, 'Cookies'), 'utf8'), 'keep my login');
  assert.deepEqual(mutations(f.calls).map(call => call.args), [
    ['bootout', `gui/${uid}/${LABELS.manager}`], ['bootstrap', `gui/${uid}`, join(f.home, 'Library/LaunchAgents', `${LABELS.manager}.plist`)],
  ]);
});

test('existing unmanaged plist is never overwritten or unloaded', async t => {
  const f = await fixture(t);
  const agents = join(f.home, 'Library/LaunchAgents');
  await fs.mkdir(agents, { recursive: true });
  const plist = join(agents, `${LABELS.manager}.plist`);
  await fs.writeFile(plist, 'someone else owns this job\n', { mode: 0o600 });
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /unmanaged/);
  assert.equal(await fs.readFile(plist, 'utf8'), 'someone else owns this job\n');
  assert.equal(mutations(f.calls).length, 0);
});

test('a loaded label without our managed file is not treated as ours', async t => {
  const f = await fixture(t);
  f.loaded.set(`gui/${uid}/${LABELS.manager}`, '/different/job.plist');
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /unmanaged job/);
  assert.equal(mutations(f.calls).length, 0);
});

test('launchctl permission and I/O failures are not mistaken for missing jobs', async t => {
  const f = await fixture(t);
  const normal = f.dependencies.run;
  f.dependencies.run = async (command, args, options) => {
    if (command === '/bin/launchctl' && args[0] === 'print' && args[1].includes(LABELS.manager)) {
      throw Object.assign(new Error('permission denied'), { code: 5, stderr: 'Input/output error' });
    }
    return normal(command, args, options);
  };
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /permission denied/);
  assert.equal(mutations(f.calls).length, 0);
});

test('socket guard covers per-desktop runtime sockets, not only control.sock', async t => {
  const f = await fixture(t);
  const suffix = '/.local/state/browser-manager/run/d-XXXXXX/vnc.sock';
  const home = '/' + 'a'.repeat(103 - Buffer.byteLength(suffix));
  assert.ok(Buffer.byteLength(join(home, '.local/state/browser-manager/control.sock')) < 104);
  await assert.rejects(installMacOS({ configFile: f.configFile }, { ...f.dependencies, home }), /Unix socket/);
});

test('symlink installation directories and an unrelated browserctl command are refused', async t => {
  const f = await fixture(t);
  await fs.mkdir(join(f.home, 'Library'));
  await fs.symlink(f.root, join(f.home, 'Library/LaunchAgents'));
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /symlinks/);
  await fs.unlink(join(f.home, 'Library/LaunchAgents'));
  await fs.mkdir(join(f.home, '.local/bin'), { recursive: true });
  await fs.writeFile(join(f.home, '.local/bin/browserctl'), 'unrelated executable', { mode: 0o755 });
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /browserctl/);
  assert.equal(mutations(f.calls).length, 0);
});

test('another checkout cannot take ownership of an existing managed installation', async t => {
  const f = await fixture(t);
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  const manifest = join(f.home, '.config/browser-manager/macos-install.json');
  const value = JSON.parse(await fs.readFile(manifest, 'utf8'));
  await fs.writeFile(manifest, JSON.stringify({ ...value, project: '/somewhere/else' }), { mode: 0o600 });
  f.calls.length = 0;
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /Another checkout/);
  assert.equal(mutations(f.calls).length, 0);
});

test('a prepared destination0600env can be adopted but an unrelated file cannot be overwritten', async t => {
  const f = await fixture(t);
  const directory = join(f.home, '.config/browser-manager');
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const target = join(directory, 'browser-manager.env');
  await fs.writeFile(target, f.config, { mode: 0o600 });
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /unmanaged configuration/);
  await installMacOS({ configFile: target }, f.dependencies);
  assert.ok(await fs.stat(join(directory, 'macos-install.json')));
});

test('missing build or non-executable Chrome cannot change running services', async t => {
  const f = await fixture(t);
  await fs.chmod(f.browser, 0o600);
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /Install Chrome/);
  await fs.chmod(f.browser, 0o755);
  await fs.unlink(join(f.project, '.next/BUILD_ID'));
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /Build this owned checkout/);
  assert.equal(mutations(f.calls).length, 0);
});

test('Chrome accepts standard admin-group app permissions without changing the app', async t => {
  for (const owner of [uid, 0]) {
    const f = await fixture(t);
    await fs.chmod(f.browser, 0o775);
    f.dependencies.io = { ...fs, stat: async target => {
      const info = await fs.stat(target);
      if (target === f.browser) { info.uid = owner; info.gid = 80; }
      return info;
    } };
    await installMacOS({ configFile: f.configFile }, f.dependencies);
    assert.equal((await fs.stat(f.browser)).mode & 0o777, 0o775);
    assert.equal(mutations(f.calls).length, 1);
  }
});

test('Chrome refuses writable staff/other groups, world write, and an unrelated owner', async t => {
  for (const { mode, gid, owner } of [
    { mode: 0o775, gid: 20, owner: uid },
    { mode: 0o775, gid: 81, owner: uid },
    { mode: 0o777, gid: 80, owner: uid },
    { mode: 0o757, gid: 80, owner: uid },
    { mode: 0o755, gid: 80, owner: uid + 1 },
  ]) {
    const f = await fixture(t);
    await fs.chmod(f.browser, mode);
    f.dependencies.io = { ...fs, stat: async target => {
      const info = await fs.stat(target);
      if (target === f.browser) { info.uid = owner; info.gid = gid; }
      return info;
    } };
    await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /owner\/root regular executable/);
    assert.equal(mutations(f.calls).length, 0);
    assert.equal((await fs.stat(f.browser)).mode & 0o777, mode);
  }
});

test('configuration/plist checks complete before owned jobs are stopped', async t => {
  const f = await fixture(t);
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  f.setLint(false);
  f.calls.length = 0;
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /invalid plist/);
  assert.equal(mutations(f.calls).length, 0);
});

const bootstrapIOError = () => Object.assign(new Error('bootstrap I/O error'), {
  code: 5, stderr: 'Bootstrap failed: 5: Input/output error\nTry re-running the command as root for richer errors.\n',
});

test('verified owned restart retries transient bootstrap5 without touching other labels', async t => {
  const f = await fixture(t);
  await installMacOS({ configFile: f.configFile, tokenFile: f.tokenFile }, f.dependencies);
  f.calls.length = 0;
  const normal = f.dependencies.run;
  const waits = [];
  let failures = 1;
  f.dependencies.sleep = async ms => { waits.push(ms); };
  f.dependencies.run = async (command, args, options) => {
    if (command === '/bin/launchctl' && args[0] === 'bootstrap' && failures-- > 0) {
      f.calls.push({ command, args, options }); throw bootstrapIOError();
    }
    return normal(command, args, options);
  };
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  assert.deepEqual(waits, [500]);
  assert.deepEqual(mutations(f.calls).map(call => call.args[0]), ['bootout', 'bootstrap', 'bootstrap']);
  assert.ok(mutations(f.calls).every(call => !call.args.some(arg => arg.includes(LABELS.tunnel))));
  assert.ok(f.loaded.has(`gui/${uid}/${LABELS.tunnel}`));
});

test('permanent post-bootout bootstrap5 is explicit and bounded to six attempts', async t => {
  const f = await fixture(t);
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  f.calls.length = 0;
  const normal = f.dependencies.run;
  const waits = [];
  f.dependencies.sleep = async ms => { waits.push(ms); };
  f.dependencies.run = async (command, args, options) => {
    if (command === '/bin/launchctl' && args[0] === 'bootstrap') {
      f.calls.push({ command, args, options }); throw bootstrapIOError();
    }
    return normal(command, args, options);
  };
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /six bounded attempts/);
  assert.deepEqual(waits, [500, 1000, 2000, 4000, 5000]);
  const attempts = mutations(f.calls).filter(call => call.args[0] === 'bootstrap');
  assert.equal(attempts.length, 6);
  assert.ok(attempts.every(call => call.options.timeout === 5000));
});

test('first-install bootstrap5 and restart permission/non5 errors are never retried', async t => {
  for (const [existing, error] of [
    [false, bootstrapIOError()],
    [true, Object.assign(new Error('permission denied'), { code: 1, stderr: 'Operation not permitted' })],
    [true, Object.assign(new Error('permission denied'), { code: 5, stderr: 'Bootstrap failed: 5: Permission denied' })],
  ]) {
    const f = await fixture(t);
    if (existing) await installMacOS({ configFile: f.configFile }, f.dependencies);
    f.calls.length = 0;
    const normal = f.dependencies.run;
    const waits = [];
    f.dependencies.sleep = async ms => { waits.push(ms); };
    f.dependencies.run = async (command, args, options) => {
      if (command === '/bin/launchctl' && args[0] === 'bootstrap') {
        f.calls.push({ command, args, options }); throw error;
      }
      return normal(command, args, options);
    };
    await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), actual => actual === error);
    assert.deepEqual(waits, []);
    assert.equal(mutations(f.calls).filter(call => call.args[0] === 'bootstrap').length, 1);
  }
});

test('a still-visible owned job must unload before a fresh successful bootstrap', async t => {
  const f = await fixture(t);
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  f.calls.length = 0;
  const normal = f.dependencies.run;
  const waits = [];
  let bootedOut = false;
  f.dependencies.sleep = async ms => { waits.push(ms); };
  f.dependencies.run = async (command, args, options) => {
    const result = await normal(command, args, options).catch(error => {
      if (bootedOut && args[0] === 'print' && waits.length === 0 && error.code === 113) {
        return { stdout: `path = ${join(f.home, 'Library/LaunchAgents', LABELS.manager + '.plist')}\n` };
      }
      throw error;
    });
    if (args[0] === 'bootout') bootedOut = true;
    return result;
  };
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  assert.deepEqual(waits, [500]);
  assert.equal(mutations(f.calls).filter(call => call.args[0] === 'bootstrap').length, 1);
});

test('an owned job that never finishes unloading is not mistaken for success', async t => {
  const f = await fixture(t);
  await installMacOS({ configFile: f.configFile }, f.dependencies);
  f.calls.length = 0;
  const normal = f.dependencies.run;
  const waits = [];
  f.dependencies.sleep = async ms => { waits.push(ms); };
  f.dependencies.run = async (command, args, options) => {
    if (args[0] === 'bootout') { f.calls.push({ command, args, options }); return {}; }
    return normal(command, args, options);
  };
  await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), /still unloading/);
  assert.equal(waits.length, 5);
  assert.equal(mutations(f.calls).filter(call => call.args[0] === 'bootstrap').length, 0);
});

test('restart probes reject a different loaded path and permission failures without retries', async t => {
  for (const deny of [false, true]) {
    const f = await fixture(t);
    await installMacOS({ configFile: f.configFile }, f.dependencies);
    f.calls.length = 0;
    const normal = f.dependencies.run;
    const waits = [];
    let bootedOut = false;
    f.dependencies.sleep = async ms => { waits.push(ms); };
    f.dependencies.run = async (command, args, options) => {
      if (bootedOut && args[0] === 'print') {
        f.calls.push({ command, args, options });
        if (deny) throw Object.assign(new Error('probe permission denied'), { code: 5, stderr: 'Input/output error' });
        return { stdout: 'path = /unmanaged/job.plist\n' };
      }
      const result = await normal(command, args, options);
      if (args[0] === 'bootout') bootedOut = true;
      return result;
    };
    await assert.rejects(installMacOS({ configFile: f.configFile }, f.dependencies), deny ? /probe permission denied/ : /unmanaged job appeared/);
    assert.deepEqual(waits, []);
    assert.equal(mutations(f.calls).filter(call => call.args[0] === 'bootstrap').length, 0);
  }
});

test('generated wrapper is valid Node code with bounded redacted logging and scoped child termination', async t => {
  const f = await fixture(t);
  const text = renderWrapper({ project: f.project, home: f.home, node: process.execPath,
    config: f.configFile, token: f.tokenFile, state: join(f.home, '.local/state/browser-manager'),
    logs: join(f.root, 'logs'), cloudflared: '/opt/homebrew/bin/cloudflared', path: '/usr/bin:/bin' });
  const file = join(f.root, 'wrapper.mjs');
  await fs.writeFile(file, text, { mode: 0o600 });
  await execute(process.execPath, ['--check', file]);
  assert.ok(text.includes(`const maximum = ${LOG_LIMIT}`));
  assert.ok(text.includes('ftruncateSync(descriptor, 0)'));
  assert.ok(text.includes('O_NOFOLLOW'));
  assert.ok(text.includes("child.kill('SIGKILL')"));
  assert.ok(!text.includes('process.kill(-'));
  assert.equal(redactLogLine('value secret-token tail', 'secret-token'), 'value [redacted] tail');
  assert.equal(redactLogLine('Authorization: Bearer sensitive'), 'Authorization: Bearer [redacted]');
  assert.ok(!redactLogLine('CF-Access-Client-Secret: sensitive').includes('sensitive'));
});

test('XML encoding preserves spaces while escaping markup in user-owned paths', () => {
  const plist = renderLaunchAgent({ kind: 'manager', project: '/Users/a/A & B', home: '/Users/a',
    node: '/node', wrapper: '/wrapper', config: '/config', state: '/state', logs: '/logs', path: '/bin' });
  assert.ok(plist.includes('/Users/a/A &amp; B'));
  assert.ok(!plist.includes('/bin/sh'));
  assert.ok(!plist.includes('setenv'));
});
