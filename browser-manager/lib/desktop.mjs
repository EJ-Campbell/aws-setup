import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { writeFile, chmod } from 'node:fs/promises';
import { connect } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

// Xauthority wire record: FamilyWild selects this private cookie regardless of hostname. The server
// loads the cookie before display allocation; clients receive the same cookie with the chosen number.
function authority(display, cookie) {
  const fields = ['', display, 'MIT-MAGIC-COOKIE-1', cookie].map((value) => {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const size = Buffer.alloc(2);
    size.writeUInt16BE(bytes.length);
    return Buffer.concat([size, bytes]);
  });
  return Buffer.concat([Buffer.from([255, 255]), ...fields]);
}

export function vncArguments({ display, authFile, socketPath }) {
  return [
    '-norc', '-display', `:${display}`, '-auth', authFile,
    // LibVNCServer has its own IPv6 port; x11vnc's -no6 does not disable it.
    '-unixsock', socketPath, '-rfbport', '0', '-rfbportv6', '0', '-no6', '-forever', '-shared',
    '-nopw', '-noremote', '-nocmds', '-novncconnect', '-input', 'KMBC', '-quiet',
  ];
}

/** Only these fixed programs are launched. Native subprocesses never inherit a shell or CDP port. */
export async function launchDesktop({ runtimeDir, profile, browserBin, url, signal }) {
  const children = [];
  const failed = Promise.withResolvers();
  // A rejection can precede the readiness race (for example, spawn ENOENT).
  void failed.promise.catch(() => {});
  let closing;
  const close = () => {
    if (closing) return closing;
    closing = (async () => {
      signal.removeEventListener('abort', aborted);
      const browser = children.find(({ label }) => label === 'Browser');
      if (browser) {
        // Chromium handles SIGINT as normal AttemptExit; SIGTERM takes the shorter SessionEnding
        // path. Keep X and renderer children alive until profile data and singleton locks are flushed.
        if (browser.child.exitCode === null && browser.child.signalCode === null) browser.child.kill('SIGINT');
        await Promise.race([browser.done, delay(5_000, undefined, { ref: false })]);
        kill(browser.child, 'SIGKILL');
        await browser.done;
      }
      const desktop = children.filter((entry) => entry !== browser).toReversed();
      for (const { child } of desktop) kill(child, 'SIGTERM');
      await Promise.race([Promise.all(desktop.map(({ done }) => done)), delay(2_000, undefined, { ref: false })]);
      for (const { child } of desktop) kill(child, 'SIGKILL');
      await Promise.all(children.map(({ done }) => done));
    })();
    return closing;
  };
  const aborted = () => failed.reject(new Error('Desktop start cancelled'));
  signal.addEventListener('abort', aborted, { once: true });
  if (signal.aborted) aborted();
  function launch(label, bin, args, env, extraPipe = false) {
    if (signal.aborted) throw new Error('Desktop start cancelled');
    const child = spawn(bin, args, {
      env,
      detached: true,
      stdio: extraPipe ? ['ignore', 'ignore', 'ignore', 'pipe'] : 'ignore',
    });
    const done = new Promise((resolve) => {
      child.once('error', () => {
        failed.reject(new Error(`${label} could not start`));
        resolve();
      });
      child.once('exit', (code) => {
        failed.reject(new Error(`${label} exited${code === null ? '' : ` (status ${code})`}`));
        resolve();
      });
    });
    children.push({ label, child, done });
    return child;
  }

  const authFile = join(runtimeDir, 'Xauthority');
  const socketPath = join(runtimeDir, 'vnc.sock');
  const cookie = randomBytes(16);
  try {
    await writeFile(authFile, authority('0', cookie), { mode: 0o600, flag: 'wx' });
    const x = launch('Xvfb', '/usr/bin/Xvfb', [
      '-displayfd', '3', '-screen', '0', '1440x900x24', '-nolisten', 'tcp',
      '-auth', authFile, '-noreset',
    ], process.env, true);
    const display = await Promise.race([
      failed.promise,
      delay(15_000, undefined, { ref: false }).then(() => { throw new Error('Desktop display timed out'); }),
      new Promise((resolve, reject) => {
        let text = '';
        x.stdio[3].on('data', (part) => {
          text += part;
          if (/^\d{1,5}\n$/.test(text)) resolve(text.trim());
          else if (text.length > 8 || text.includes('\n')) reject(new Error('Invalid display allocation'));
        });
      }),
    ]);
    await writeFile(authFile, authority(display, cookie), { mode: 0o600 });
    const env = { ...process.env, DISPLAY: `:${display}`, XAUTHORITY: authFile };
    delete env.WAYLAND_DISPLAY;
    launch('Window manager', '/usr/bin/openbox', ['--sm-disable'], env);
    launch('VNC server', '/usr/bin/x11vnc', vncArguments({ display, authFile, socketPath }), env);
    launch('Browser', browserBin, [
      `--user-data-dir=${profile}`, '--ozone-platform=x11', '--no-first-run',
      '--no-default-browser-check', '--start-maximized', '--window-size=1440,900', url,
    ], env);
    await Promise.race([
      failed.promise,
      (async () => {
        const deadline = Date.now() + 15_000;
        while (Date.now() < deadline) {
          if (signal.aborted || closing) throw new Error('Desktop start cancelled');
          if (await readySocket(socketPath)) {
            await chmod(socketPath, 0o600);
            // Catch Chrome's immediate profile-lock/sandbox startup failures before advertising it.
            await delay(300);
            return;
          }
          await delay(50);
        }
        throw new Error('Desktop connection timed out');
      })(),
    ]);
    if (signal.aborted) throw new Error('Desktop start cancelled');
    return { socketPath, close, closed: failed.promise.catch(close) };
  } catch (error) {
    await close();
    throw error;
  }
}

function kill(child, signal) {
  if (!child.pid) return;
  // Every group was created by this process. No PID or process group is ever recovered from disk.
  // Signal the group even after its leader exits: Chrome renderer children can otherwise survive it.
  try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}

function readySocket(path) {
  return new Promise((resolve) => {
    const socket = connect(path);
    const finish = (ready) => { socket.destroy(); resolve(ready); };
    socket.setTimeout(300, () => finish(false));
    socket.once('error', () => finish(false));
    socket.once('data', (bytes) => finish(bytes.toString('ascii').startsWith('RFB ')));
  });
}
