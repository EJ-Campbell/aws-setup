import { execFile, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { writeFile, chmod } from 'node:fs/promises';
import { connect } from 'node:net';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';

const execute = promisify(execFile);
// xprop can read these numeric hints, but writes them as CARDINAL instead of WM_SIZE_HINTS.
// This fixed native call preserves the original type and every field; no script comes from callers.
const WRITE_HINTS = `import ctypes as c,sys
x=c.CDLL('libX11.so.6');x.XOpenDisplay.restype=c.c_void_p
d=c.c_void_p(x.XOpenDisplay(None))
if not d.value: raise RuntimeError('Private display unavailable')
p=x.XInternAtom(d,b'WM_NORMAL_HINTS',0);t=x.XInternAtom(d,b'WM_SIZE_HINTS',0)
v=[int(s) for s in sys.argv[2].split(',')];a=(c.c_long*len(v))(*v)
x.XChangeProperty(d,int(sys.argv[1],16),p,t,32,0,c.byref(a),len(v))
x.XSync(d,0);x.XCloseDisplay(d)`;

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
    '-xrandr', 'resize',
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
  const resizeAbort = new AbortController();
  let resizeTail = Promise.resolve();
  const close = () => {
    if (closing) return closing;
    closing = (async () => {
      signal.removeEventListener('abort', aborted);
      resizeAbort.abort();
      await resizeTail;
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
    const browser = launch('Browser', browserBin, [
      `--user-data-dir=${profile}`, '--ozone-platform=x11', '--no-first-run',
      '--no-default-browser-check', '--start-maximized', '--window-size=1440,900', url,
    ], env);
    let activeMode = '1440x900';
    const modes = new Map();
    const originalHints = new Map();
    async function resizeDesktop(viewport) {
      const { mode, width, height } = viewport;
      if (!Number.isInteger(width) || !Number.isInteger(height) ||
          (mode === 'desktop' ? width !== 1440 || height !== 900
            : mode !== 'phone' || width < 320 || width > 500 || height < 480 || height > 900)) {
        throw new Error('Invalid browser viewport');
      }
      let deadline = Date.now() + 15_000;
      const command = async (bin, args) => {
        if (closing || signal.aborted || resizeAbort.signal.aborted || Date.now() >= deadline) {
          throw new Error('Browser resize cancelled or timed out');
        }
        return (await execute(bin, args, { env, signal: resizeAbort.signal,
          timeout: Math.min(2_000, deadline - Date.now()), maxBuffer: 65_536 })).stdout;
      };
      const hints = async (id) => {
        const raw = await command('/usr/bin/xprop', ['-id', id, '-f', 'WM_NORMAL_HINTS', '32c', ' = $0+\\n', 'WM_NORMAL_HINTS']);
        const match = /^WM_NORMAL_HINTS\(WM_SIZE_HINTS\) = ([\d, ]+)\s*$/.exec(raw);
        const values = match?.[1].split(',').map(Number);
        if (values?.length !== 18 || values.some(v => !Number.isInteger(v) || v < 0 || v > 0xffffffff)) {
          throw new Error('Browser window size hints are unavailable');
        }
        return values;
      };
      const writeHints = (id, values) => command('/usr/bin/python3', ['-c', WRITE_HINTS, id, values.join(',')]);
      // Match only windows belonging to this exact live child on its private authenticated display.
      const listing = await command('/usr/bin/wmctrl', ['-lp']);
      const windows = listing.split('\n').flatMap(line => {
        const match = /^(0x[\da-f]+)\s+-?\d+\s+(\d+)\s/i.exec(line);
        return match && Number(match[2]) === browser.pid ? [match[1]] : [];
      });
      if (!windows.length || windows.length > 32) throw new Error('Browser windows are not ready for resizing');
      const before = new Map();
      for (const id of windows) before.set(id, await hints(id));
      const previousMode = activeMode;
      const savedBefore = new Map(originalHints);
      try {
        let nextMode = '1440x900';
        if (mode === 'phone') {
          // At most two custom modes exist. Prepare the inactive slot so rollback retains the old one.
          nextMode = [...modes].find(([, entry]) => entry.size === `${width}x${height}`)?.[0]
            ?? (activeMode === 'bm-phone-0' ? 'bm-phone-1' : 'bm-phone-0');
          if (modes.get(nextMode)?.size !== `${width}x${height}`) {
            if (modes.has(nextMode)) {
              if (modes.get(nextMode).attached) {
                await command('/usr/bin/xrandr', ['--delmode', 'screen', nextMode]);
                modes.get(nextMode).attached = false;
              }
              await command('/usr/bin/xrandr', ['--rmmode', nextMode]);
              modes.delete(nextMode);
            }
            await command('/usr/bin/xrandr', ['--newmode', nextMode, '30',
              ...[width, width + 10, width + 50, width + 90, height, height + 6, height + 16, height + 56].map(String)]);
            modes.set(nextMode, { size: `${width}x${height}`, attached: false });
          }
          if (!modes.get(nextMode).attached) {
            await command('/usr/bin/xrandr', ['--addmode', 'screen', nextMode]);
            modes.get(nextMode).attached = true;
          }
          for (const id of windows) {
            if (!originalHints.has(id)) originalHints.set(id, before.get(id));
            await command('/usr/bin/wmctrl', ['-ir', id, '-b', 'add,maximized_vert,maximized_horz']);
            // EWMH requests are asynchronous; let Chrome publish its maximized-window hints first.
            await delay(100);
            // Chromium's 500px minimum otherwise crops a 390px desktop. Keep browser chrome and
            // every other ICCCM hint; removing only PMinSize gives a genuinely narrow page layout.
            const narrow = await hints(id);
            narrow[0] &= ~16;
            await writeHints(id, narrow);
          }
        }
        await command('/usr/bin/xrandr', ['--output', 'screen', '--mode', nextMode]);
        if (mode === 'desktop') {
          await delay(100);
          for (const id of windows) {
            await command('/usr/bin/wmctrl', ['-ir', id, '-b', 'add,maximized_vert,maximized_horz']);
            if (originalHints.has(id)) await writeHints(id, originalHints.get(id));
          }
          originalHints.clear();
        } else {
          for (const id of originalHints.keys()) if (!windows.includes(id)) originalHints.delete(id);
        }
        activeMode = nextMode;
      } catch (cause) {
        // Restore the last usable screen and the precise pre-call hints; shutdown always wins.
        deadline = Date.now() + 5_000;
        let rolledBack = true;
        try {
          await command('/usr/bin/xrandr', ['--output', 'screen', '--mode', previousMode]);
          for (const [id, values] of before) await writeHints(id, values);
        } catch { rolledBack = false; }
        originalHints.clear();
        for (const [id, values] of savedBefore) originalHints.set(id, values);
        throw new Error(rolledBack ? 'Browser resize failed; previous size restored'
          : 'Browser resize failed; its current size could not be confirmed', { cause });
      }
    }
    const resize = (viewport) => {
      const request = { ...viewport };
      const task = resizeTail.then(() => resizeDesktop(request));
      resizeTail = task.catch(() => {});
      return task;
    };
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
    return { socketPath, close, closed: failed.promise.catch(close), resize };
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
