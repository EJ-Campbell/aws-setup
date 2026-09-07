#!/usr/bin/env node
// Install only the browser owner's native GUI LaunchAgents. No sudo or shell sourcing.
import * as fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve, relative, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv, promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export const MARKER = 'Managed by browser-manager/scripts/install-macos.mjs';
export const LABELS = Object.freeze({ manager: 'com.ejc3.browser-manager', tunnel: 'com.ejc3.browser-manager-tunnel' });
export const LOG_LIMIT = 1024 * 1024;
const DEFAULT_CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const ALLOWED = new Set(['BM_BASE_URL', 'BM_ACCESS_AUD', 'BM_ACCESS_ISSUER', 'BM_OWNER_EMAIL',
  'BM_PORT', 'BM_BROWSER_BIN', 'BM_ACCESS_SERVICE_TOKEN_ID']);
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const execute = promisify(execFile);
const fail = message => { throw new Error(`browser-manager: ${message}`); };
const safeText = value => typeof value === 'string' && !/[\u0000-\u001f\u007f]/u.test(value);

export function requireNode(version) {
  const match = /^(?:v)?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version);
  if (!match || Number(match[1]) < 22 || (Number(match[1]) === 22 && Number(match[2]) < 13)) {
    fail('Node.js 22.13 or newer is required.');
  }
}

export async function stableExecutable(current, aliases = [], { io = fs, uid = process.getuid() } = {}) {
  async function verified(candidate) {
    if (!isAbsolute(candidate) || !safeText(candidate)) fail('Executable paths must be absolute and contain no control characters.');
    const link = await io.lstat(candidate);
    const canonical = await io.realpath(candidate);
    const target = await io.stat(canonical);
    if (![0, uid].includes(link.uid) || ![0, uid].includes(target.uid) ||
        !target.isFile() || (target.mode & 0o022) !== 0) fail('Executables must be trusted owner/root files, not writable by other users.');
    await io.access(candidate, constants.X_OK);
    return canonical;
  }
  const canonical = await verified(current);
  for (const alias of aliases) {
    try { if (await verified(alias) === canonical) return alias; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return current;
}

export async function readPrivate(path, { io = fs, uid = process.getuid() } = {}) {
  const initial = await io.lstat(path);
  if (!initial.isFile() || initial.isSymbolicLink() || initial.uid !== uid ||
      (initial.mode & 0o777) !== 0o600 || initial.nlink !== 1 || initial.size < 1 || initial.size > 65536) {
    fail('Inputs must be nonempty, owned regular files with mode 0600; no symlinks or hard links.');
  }
  const handle = await io.open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.ino !== initial.ino || opened.dev !== initial.dev || opened.uid !== uid ||
        !opened.isFile() || (opened.mode & 0o777) !== 0o600 || opened.nlink !== 1) fail('Input changed while opening.');
    const text = await handle.readFile('utf8');
    if (!text || Buffer.byteLength(text) > 65536) fail('Input is empty or too large.');
    return text;
  } finally { await handle.close(); }
}

export async function parseConfiguration(text, validate = async env => {
  const { readConfig } = await import('../lib/auth.mjs');
  return readConfig(env);
}) {
  const env = parseEnv(text);
  if (Object.keys(env).some(key => !ALLOWED.has(key)) ||
      Object.values(env).some(value => !safeText(value) || /["\\]/u.test(value))) {
    fail('Configuration may contain only documented BM_* values, without multiline values, quotes, or escapes.');
  }
  const config = await validate(env);
  if (config.port !== 3210) fail('The Terraform tunnel requires BM_PORT=3210.');
  if (env.BM_ACCESS_SERVICE_TOKEN_ID && !/^[A-Za-z0-9._-]{1,256}$/.test(env.BM_ACCESS_SERVICE_TOKEN_ID)) {
    fail('BM_ACCESS_SERVICE_TOKEN_ID must be a service client ID, not a token secret.');
  }
  return { env, config };
}

const xml = text => String(text).replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' })[character]);
function plistValue(value) {
  if (typeof value === 'string') return `<string>${xml(value)}</string>`;
  if (typeof value === 'boolean') return value ? '<true/>' : '<false/>';
  if (typeof value === 'number') return `<integer>${value}</integer>`;
  if (Array.isArray(value)) return `<array>${value.map(plistValue).join('')}</array>`;
  return `<dict>${Object.entries(value).map(([key, item]) => `<key>${xml(key)}</key>${plistValue(item)}`).join('')}</dict>`;
}

export function renderLaunchAgent({ kind, project, home, node, wrapper, config, state, logs, path }) {
  const args = ['/usr/bin/env', '-i', `HOME=${home}`, `PATH=${path}`, 'NODE_ENV=production',
    `BM_STATE_DIR=${state}`, node];
  if (kind === 'manager') args.push(`--env-file=${config}`);
  args.push(wrapper, kind);
  const contents = {
    Label: LABELS[kind], ProgramArguments: args, WorkingDirectory: project,
    RunAtLoad: true, KeepAlive: { SuccessfulExit: false }, ThrottleInterval: 5, ExitTimeOut: 25,
    ProcessType: 'Interactive', LimitLoadToSessionType: 'Aqua', Umask: 0o077,
    StandardOutPath: join(logs, `${kind}.stdout.log`), StandardErrorPath: join(logs, `${kind}.stderr.log`),
  };
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!-- ${MARKER} -->\n` +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    `<plist version="1.0">${plistValue(contents)}</plist>\n`;
}

export function redactLogLine(line, token = '') {
  if (token) line = line.split(token).join('[redacted]');
  return line.replace(/\beyJ[A-Za-z0-9_+/=-]{24,}(?:\.[A-Za-z0-9_-]+){0,2}/g, '[redacted-token]')
    .replace(/(Bearer\s+|CF-Access-Client-Secret\s*[:=]\s*)\S+/gi, '$1[redacted]');
}

export function renderWrapper(settings) {
  // All settings are installer-validated paths serialized as data, never shell text.
  return `// ${MARKER}
import { spawn } from 'node:child_process';
import { openSync, closeSync, fstatSync, ftruncateSync, writeSync, readFileSync, constants } from 'node:fs';
import { StringDecoder } from 'node:string_decoder';
const settings = ${JSON.stringify(settings)};
const kind = process.argv[2];
if (!['manager', 'tunnel'].includes(kind)) process.exit(1);
process.umask(0o077);
const maximum = ${LOG_LIMIT};
${redactLogLine.toString()}
function append(stream, line, token) {
  const path = settings.logs + '/' + kind + '.' + stream + '.log';
  const descriptor = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1) throw new Error('unsafe log');
    const value = Buffer.from(redactLogLine(line, token) + '\\n');
    if (stat.size + value.length > maximum) ftruncateSync(descriptor, 0);
    writeSync(descriptor, value);
  } finally { closeSync(descriptor); }
}
let child;
try {
  // The connector token is passed only by file path, never argv/environment/logs.
  const token = kind === 'tunnel' ? readFileSync(settings.token, 'utf8').trim() : '';
  const command = kind === 'manager' ? settings.node : settings.cloudflared;
  const args = kind === 'manager'
    ? ['--env-file=' + settings.config, settings.project + '/server.mjs']
    : ['tunnel', '--no-autoupdate', 'run', '--token-file', settings.token];
  const env = { HOME: settings.home, PATH: settings.path, NODE_ENV: 'production', BM_STATE_DIR: settings.state };
  child = spawn(command, args, { cwd: settings.project, env, stdio: ['ignore', 'pipe', 'pipe'] });
  for (const [name, readable] of [['stdout', child.stdout], ['stderr', child.stderr]]) {
    const decoder = new StringDecoder('utf8');
    let pending = '', dropping = false;
    const consume = text => {
      pending += text;
      let newline;
      while ((newline = pending.indexOf('\\n')) >= 0) {
        const line = pending.slice(0, newline);
        pending = pending.slice(newline + 1);
        append(name, dropping || line.length > 65536 ? '[oversized log line omitted]' : line, token);
        dropping = false;
      }
      if (pending.length > 65536) { pending = ''; dropping = true; }
    };
    readable.on('data', data => { try { consume(decoder.write(data)); } catch { child.kill('SIGTERM'); } });
    readable.on('end', () => { try { consume(decoder.end()); if (pending || dropping) append(name, dropping ? '[oversized log line omitted]' : pending, token); } catch {} });
  }
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
    child.kill(signal);
    setTimeout(() => child.kill('SIGKILL'), 20000).unref();
  });
  child.once('error', () => { try { append('stderr', 'Browser Manager child could not start; check installed executable paths.', ''); } catch {} process.exitCode = 1; });
  child.once('close', code => { process.exitCode = Number.isInteger(code) ? code : 1; });
} catch {
  try { append('stderr', 'Browser Manager launcher failed; check private configuration files.', ''); } catch {}
  process.exitCode = 1;
}
`;
}

export async function installMacOS({ configFile, tokenFile } = {}, dependencies = {}) {
  const io = dependencies.io || fs;
  const platform = dependencies.platform || process.platform;
  const uid = dependencies.uid ?? process.getuid?.() ?? -1;
  const home = resolve(dependencies.home || homedir());
  const project = resolve(dependencies.project || projectRoot);
  let node = dependencies.node || process.execPath;
  const version = dependencies.version || process.versions.node;
  const run = dependencies.run || execute;
  const validator = dependencies.validateConfig;
  if (platform !== 'darwin') fail('Use install.sh on Linux; this installer requires macOS.');
  if (uid === 0) fail('Run as the browser owner, never root.');
  requireNode(version);
  // Keep Homebrew's stable formula link, not a Cellar version removed by cleanup.
  node = await stableExecutable(node, dependencies.node ? [] :
    ['/opt/homebrew/opt/node@22/bin/node', '/usr/local/opt/node@22/bin/node'], { io, uid });
  if (!configFile || !safeText(configFile) || (tokenFile && !safeText(tokenFile))) fail('Usage: node scripts/install-macos.mjs CONFIG_ENV [TUNNEL_TOKEN_FILE]');
  for (const path of [home, project, node]) if (!isAbsolute(path) || !safeText(path)) fail('Installation paths must be absolute and contain no control characters.');
  const path = [dirname(node), '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(delimiter);
  const base = join(home, '.config/browser-manager');
  const state = join(home, '.local/state/browser-manager');
  const logs = join(state, 'macos-logs');
  const agents = join(home, 'Library/LaunchAgents');
  const bin = join(home, '.local/bin');
  const config = join(base, 'browser-manager.env');
  const token = join(base, 'tunnel-token');
  const wrapper = join(base, 'launch-macos.mjs');
  const manifestPath = join(base, 'macos-install.json');
  if ([join(state, 'control.sock'), join(state, 'run/d-XXXXXX/vnc.sock')]
    .some(socket => Buffer.byteLength(socket) >= 104)) fail('The fixed state path is too long for a macOS Unix socket.');

  const exists = async target => { try { return await io.lstat(target); } catch (error) { if (error.code === 'ENOENT') return null; throw error; } };
  async function safeDirectory(target, privateDirectory = false, create = false) {
    if (target !== home && (relative(home, target).startsWith('..') || isAbsolute(relative(home, target)))) fail('Installation directory escaped the user home.');
    if (target !== home) await safeDirectory(dirname(target), false, create);
    let stat = await exists(target);
    if (!stat && create) { await io.mkdir(target, { mode: privateDirectory ? 0o700 : 0o755 }); stat = await io.lstat(target); }
    if (stat && (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o022) !== 0)) fail('Installation directories must be owned directories, not symlinks or writable by other users.');
    if (stat && privateDirectory && (stat.mode & 0o077) !== 0) fail('Existing private configuration/state directories must already have mode 0700.');
  }
  await safeDirectory(home);
  if (await io.realpath(home) !== home || await io.realpath(project) !== project) fail('The home and fixed checkout must not use symlink paths.');
  const projectInfo = await io.lstat(project);
  if (!projectInfo.isDirectory() || projectInfo.uid !== uid || (projectInfo.mode & 0o022) !== 0) fail('The fixed checkout must belong to the browser owner and not be writable by other users.');
  for (const target of [base, state, logs, agents, bin]) await safeDirectory(target, [base, state, logs].includes(target));
  for (const target of [join(project, 'server.mjs'), join(project, '.next/BUILD_ID'), join(project, 'bin/browserctl.mjs')]) {
    const stat = await io.lstat(target).catch(() => null);
    if (!stat?.isFile() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o022) !== 0 || stat.size === 0 ||
        await io.realpath(target) !== target) fail('Build this owned checkout first: npm ci && npm run build.');
  }
  await io.access(join(project, 'bin/browserctl.mjs'), constants.X_OK);
  await io.access(node, constants.X_OK);
  requireNode((await run(node, ['--version'], { env: { PATH: path }, maxBuffer: 65536 })).stdout.trim());
  const parsed = await parseConfiguration(await readPrivate(resolve(configFile), { io, uid }), validator);
  const browser = parsed.env.BM_BROWSER_BIN || DEFAULT_CHROME;
  if (!isAbsolute(browser) || !safeText(browser) || /["\\]/u.test(browser)) fail('BM_BROWSER_BIN must be an absolute executable Chrome path.');
  await io.access(browser, constants.X_OK).catch(() => fail('Install Chrome or set BM_BROWSER_BIN to its executable; no browser is downloaded or replaced.'));
  const browserInfo = await io.stat(browser);
  // Native macOS app bundles commonly permit the trusted admin group (GID 80) to
  // update them. Do not chmod the owner's Chrome; this exception is browser-only.
  if (!browserInfo.isFile() || ![0, uid].includes(browserInfo.uid) ||
      (browserInfo.mode & 0o002) !== 0 || ((browserInfo.mode & 0o020) !== 0 && browserInfo.gid !== 80)) {
    fail('Chrome must be an owner/root regular executable, writable only by its owner or the macOS admin group.');
  }
  parsed.env.BM_BROWSER_BIN = browser;
  const content = Object.entries(parsed.env).sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key}="${value}"`).join('\n') + '\n';
  let cloudflared = null;
  let tokenContent;
  if (tokenFile) {
    tokenContent = (await readPrivate(resolve(tokenFile), { io, uid })).trim();
    if (!tokenContent || tokenContent.length > 16384 || /\s|[\u0000-\u001f\u007f]/u.test(tokenContent)) fail('The connector token must be one nonempty token, not JSON or shell code.');
    const candidates = dependencies.cloudflared ? [dependencies.cloudflared] : path.split(delimiter).map(directory => join(directory, 'cloudflared'));
    for (const candidate of candidates) {
      try { cloudflared = await stableExecutable(candidate, [], { io, uid }); break; }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    if (!cloudflared || !safeText(cloudflared)) fail('Install cloudflared before supplying a tunnel token.');
    const help = await run(cloudflared, ['tunnel', 'run', '--help'], { env: { HOME: home, PATH: path }, maxBuffer: 1024 * 1024 });
    if (!help.stdout.includes('--token-file')) fail('Update cloudflared: --token-file support is required.');
  }

  let manifest = null;
  if (await exists(manifestPath)) {
    try { manifest = JSON.parse(await readPrivate(manifestPath, { io, uid })); } catch { fail('Refusing an unsafe or unrecognized installation manifest.'); }
    if (manifest.managedBy !== MARKER || manifest.schema !== 1 || manifest.project !== project) fail('Another checkout owns this installation; keep its fixed path.');
  }
  const kinds = tokenFile ? ['manager', 'tunnel'] : ['manager'];
  const plists = Object.fromEntries(kinds.map(kind => [kind, join(agents, `${LABELS[kind]}.plist`)]));
  for (const [target, supplied] of [[config, configFile], [token, tokenFile]]) {
    if (!(await exists(target))) continue;
    await readPrivate(target, { io, uid });
    if (supplied && resolve(supplied) !== target && !manifest) fail('Refusing to replace an unmanaged configuration or token file.');
  }
  for (const target of [wrapper, ...Object.values(plists)]) {
    if (!(await exists(target))) continue;
    const original = await readPrivate(target, { io, uid });
    if (!manifest || !original.split('\n').slice(0, 3).some(line => line.includes(MARKER))) fail('Refusing to replace an unmanaged launcher or LaunchAgent.');
  }
  const command = join(bin, 'browserctl');
  const commandInfo = await exists(command);
  if (commandInfo && (!commandInfo.isSymbolicLink() || commandInfo.uid !== uid || await io.readlink(command) !== join(project, 'bin/browserctl.mjs'))) fail('Refusing to replace an existing browserctl command.');
  const logPaths = kinds.flatMap(kind => ['stdout', 'stderr'].map(stream => join(logs, `${kind}.${stream}.log`)));
  for (const target of logPaths) {
    const stat = await exists(target);
    if (stat && (!manifest || !stat.isFile() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o777) !== 0o600 || stat.nlink !== 1)) fail('Refusing an unmanaged or unsafe launcher log.');
  }
  const domain = `gui/${uid}`;
  await run('/bin/launchctl', ['print', domain], { maxBuffer: 1024 * 1024 }).catch(() => fail('No GUI login session exists for this user. Sign in on the Mac; SSH alone cannot create an Aqua session.'));
  const loaded = {};
  for (const kind of kinds) {
    try {
      const result = await run('/bin/launchctl', ['print', `${domain}/${LABELS[kind]}`], { maxBuffer: 1024 * 1024 });
      if (!manifest || !(await exists(plists[kind])) || !result.stdout.split('\n').some(line => line.trim() === `path = ${plists[kind]}`)) fail('The LaunchAgent label is already loaded by an unmanaged job.');
      loaded[kind] = true;
    } catch (error) {
      // An unreadable/denied GUI service is not evidence that its label is unused.
      if (!Number.isInteger(error.code) || !/Could not find service|No such process|service.*not found/i.test(error.stderr || '')) throw error;
      loaded[kind] = false;
    }
  }

  // Finish every collision/ownership/GUI check before writing or restarting anything.
  for (const target of [base, state, logs, agents, bin]) await safeDirectory(target, [base, state, logs].includes(target), true);
  async function atomic(target, data, mode = 0o600) {
    const temporary = join(dirname(target), `.browser-manager-${randomUUID()}`);
    const handle = await io.open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, mode);
    try { await handle.writeFile(data); await handle.sync(); } finally { await handle.close(); }
    try { await io.rename(temporary, target); } catch (error) { await io.unlink(temporary); throw error; }
  }
  const settings = { project, home, node, cloudflared: cloudflared || manifest?.cloudflared || null, config, token, state, logs, path };
  const generated = renderWrapper(settings);
  const staged = await io.mkdtemp(join(base, '.macos-install-'));
  await io.chmod(staged, 0o700);
  try {
    const stagedWrapper = join(staged, 'launch.mjs');
    await io.writeFile(stagedWrapper, generated, { mode: 0o600, flag: 'wx' });
    await run(node, ['--check', stagedWrapper], { env: { PATH: path }, maxBuffer: 65536 });
    const rendered = {};
    for (const kind of kinds) {
      rendered[kind] = renderLaunchAgent({ kind, ...settings, wrapper });
      const stagedPlist = join(staged, `${kind}.plist`);
      await io.writeFile(stagedPlist, rendered[kind], { mode: 0o600, flag: 'wx' });
      await run('/usr/bin/plutil', ['-lint', '--', stagedPlist], { maxBuffer: 65536 });
    }
    // Stop only our verified loaded labels. No global environment or GUI bootout.
    for (const kind of kinds) if (loaded[kind]) await run('/bin/launchctl', ['bootout', `${domain}/${LABELS[kind]}`], { maxBuffer: 65536 });
    await atomic(manifestPath, JSON.stringify({ managedBy: MARKER, schema: 1, project, cloudflared: settings.cloudflared }) + '\n');
    await atomic(config, content);
    if (tokenFile) await atomic(token, tokenContent + '\n');
    await atomic(wrapper, generated);
    for (const target of logPaths) {
      if (!(await exists(target))) await io.writeFile(target, '', { flag: 'wx', mode: 0o600 });
    }
    for (const kind of kinds) await atomic(plists[kind], rendered[kind]);
    if (!commandInfo) await io.symlink(join(project, 'bin/browserctl.mjs'), command);
    for (const kind of kinds) await run('/bin/launchctl', ['bootstrap', domain, plists[kind]], { maxBuffer: 65536 });
  } finally {
    // This directory is newly created here, private, and contains only our staged text.
    await io.rm(staged, { recursive: true, force: true });
  }
  return { project, state, config, logs, command, domain, labels: kinds.map(kind => LABELS[kind]),
    message: 'Installed user LaunchAgents for this GUI login. Profiles are retained; logout stops them. Logs are private, redacted, and bounded to 1 MiB per stream.' };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length < 1 || args.length > 2 || args[0] === '--help') {
    console.error('Usage: node scripts/install-macos.mjs CONFIG_ENV [TUNNEL_TOKEN_FILE]');
    process.exitCode = 1;
  } else {
    try { console.log((await installMacOS({ configFile: args[0], tokenFile: args[1] })).message); }
    catch (error) {
      // Child errors can carry argv/environment/output; never print those payloads.
      console.error(error.message?.startsWith('browser-manager:') ? error.message : 'browser-manager: Installation failed; check private inputs, the GUI session, and installed executable paths.');
      process.exitCode = 1;
    }
  }
}
