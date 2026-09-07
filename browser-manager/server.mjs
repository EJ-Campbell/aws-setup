import next from 'next';
import { mkdir, lstat, unlink, chmod } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { connect } from 'node:net';
import { createAuthorizer, readConfig } from './lib/auth.mjs';
import { createHttpServer } from './lib/http.mjs';
import { createInstanceManager } from './lib/instances.mjs';

process.umask(0o077);
const config = readConfig();
config.transport = process.platform === 'darwin' ? 'page' : 'vnc';
const stateDir = resolve(process.env.BM_STATE_DIR || join(homedir(), '.local/state/browser-manager'));
await mkdir(stateDir, { recursive: true, mode: 0o700 });
const info = await lstat(stateDir);
if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o077) !== 0) {
  throw new Error('BM_STATE_DIR must be an owner-only directory (mode 0700), not a symlink');
}
const socketPath = join(stateDir, 'control.sock');
try {
  const socketInfo = await lstat(socketPath);
  if (!socketInfo.isSocket() || socketInfo.uid !== process.getuid()) throw new Error('Unsafe control socket path');
  const active = await new Promise((resolveProbe, reject) => {
    const probe = connect(socketPath);
    probe.once('connect', () => { probe.destroy(); resolveProbe(true); });
    probe.once('error', error => error.code === 'ECONNREFUSED' ? resolveProbe(false) : reject(error));
    probe.setTimeout(1000, () => { probe.destroy(); reject(new Error('Control socket did not respond')); });
  });
  if (active) throw new Error('Browser manager is already running');
  const current = await lstat(socketPath);
  if (current.ino !== socketInfo.ino || current.dev !== socketInfo.dev) throw new Error('Control socket changed during startup');
  await unlink(socketPath);
} catch (error) { if (error.code !== 'ENOENT') throw error; }

if (!process.env.BM_BROWSER_BIN?.startsWith('/')) {
  throw new Error('Set BM_BROWSER_BIN to the absolute path of your installed Chromium or Chrome binary');
}
const manager = createInstanceManager({ stateDir, browserBin: process.env.BM_BROWSER_BIN, baseUrl: config.baseUrl });
const app = next({ dev: process.env.NODE_ENV === 'development', dir: dirname(fileURLToPath(import.meta.url)), hostname: '127.0.0.1', port: config.port });
const authorize = createAuthorizer(config);
let ready = false;
let stopping = false;
const publicServer = createHttpServer({ manager, config, authorize, nextHandler: app.getRequestHandler(), isReady: () => ready });
const localServer = createHttpServer({ manager, config, local: true, isReady: () => ready });
const listen = (server, target) => new Promise((done, reject) => {
  server.once('error', reject);
  server.listen(target, () => { server.off('error', reject); done(); });
});
let closing;
const close = () => closing ||= (async () => {
  ready = false;
  stopping = true;
  publicServer.closeVnc();
  publicServer.closeAllConnections();
  localServer.closeAllConnections();
  await Promise.all([publicServer, localServer].map(server => new Promise(done => server.close(done))));
  await manager.close();
  await app.close();
})();
process.once('SIGTERM', () => void close());
process.once('SIGINT', () => void close());
try {
  // Binding the private control socket first prevents two supervisors from owning the same profiles.
  await listen(localServer, socketPath);
  await chmod(socketPath, 0o600);
  await app.prepare();
  if (stopping) throw new Error('Startup cancelled');
  await manager.initialize();
  if (stopping) throw new Error('Startup cancelled');
  await listen(publicServer, { host: '127.0.0.1', port: config.port });
  ready = true;
  console.log(`Browser manager ready on loopback port ${config.port}; public origin ${config.baseUrl}`);
} catch (error) {
  await close();
  throw error;
}
