#!/usr/bin/env bash
# Install only this user's browser-manager units; never stop an existing browser service.
set -euo pipefail
umask 077

fail() { printf 'browser-manager: %s\n' "$*" >&2; exit 1; }
if [[ $# -lt 1 || $# -gt 2 || ${1:-} == --help ]]; then
  printf 'Usage: %s CONFIG_ENV [TUNNEL_TOKEN_FILE]\n' "$0"
  printf 'Run as the browser owner after npm ci && npm run build in browser-manager.\n'
  exit 1
fi
[[ $(id -u) != 0 ]] || fail 'Run as the browser owner, not root.'

bm_project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
bm_config_dir="$HOME/.config/browser-manager"
bm_unit_dir="$HOME/.config/systemd/user"
bm_bin_dir="$HOME/.local/bin"
bm_config="$bm_config_dir/browser-manager.env"
bm_token="$bm_config_dir/tunnel-token"
bm_node=$(command -v node) || fail 'Node.js 22.13 or newer is required.'

private_file() {
  [[ -f $1 && ! -L $1 && -O $1 && -s $1 ]] || fail 'Inputs must be nonempty, owned regular files, not symlinks.'
  local bm_mode
  bm_mode=$(stat -c '%a' -- "$1")
  (( (8#$bm_mode & 077) == 0 )) || fail 'Input files must not be readable or writable by group/others; use chmod 600.'
}
private_file "$1"
bm_source_config=$(realpath -e -- "$1")
bm_source_token=''
if [[ $# == 2 ]]; then
  private_file "$2"
  bm_source_token=$(realpath -e -- "$2")
  bm_cloudflared=$(command -v cloudflared) || fail 'Install cloudflared before supplying a tunnel token.'
  bm_tunnel_help=$("$bm_cloudflared" tunnel run --help)
  [[ $bm_tunnel_help == *--token-file* ]] || fail 'This cloudflared is too old: --token-file support is required.'
fi

# These paths enter systemd directives, not a shell; refuse characters with systemd
# expansion/escape semantics rather than accidentally reinterpret a checkout path.
for bm_path in "$bm_project" "$bm_config_dir" "$bm_node" "${bm_cloudflared:-/usr/bin/cloudflared}"; do
  [[ $bm_path != *[$'\n\r\\"%$']* ]] || fail 'Install paths must not contain quotes, escapes, newlines, dollar signs, or percent signs.'
done
[[ -f $bm_project/.next/BUILD_ID ]] || fail 'Build the application first: npm ci && npm run build.'
[[ -f $bm_project/server.mjs && -x $bm_project/bin/browserctl.mjs ]] || fail 'The application or browserctl entry point is missing.'
for bm_program in /usr/bin/Xvfb /usr/bin/x11vnc /usr/bin/openbox; do
  [[ -x $bm_program ]] || fail 'Install the desktop prerequisites: xvfb x11vnc openbox.'
done

# Parse data, never source it as shell code. Restrict EnvironmentFile to application
# settings so it cannot inject a connector credential or change Node's execution mode.
bm_browser_bin=$("$bm_node" --input-type=module - "$bm_source_config" "$bm_project" <<'JS'
import { accessSync, constants, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { parseEnv } from 'node:util';
import { pathToFileURL } from 'node:url';
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 13)) throw new Error('Node.js 22.13 or newer is required');
const env = parseEnv(readFileSync(process.argv[2], 'utf8'));
const allowed = new Set(['BM_BASE_URL', 'BM_ACCESS_AUD', 'BM_ACCESS_ISSUER', 'BM_OWNER_EMAIL', 'BM_PORT', 'BM_BROWSER_BIN']);
if (Object.keys(env).some((key) => !allowed.has(key))) throw new Error('Configuration may contain only documented BM_* settings');
const { readConfig } = await import(pathToFileURL(`${process.argv[3]}/lib/auth.mjs`));
const config = readConfig(env);
if (config.port !== 3210) throw new Error('The Terraform tunnel requires BM_PORT=3210');
const executable = (path) => {
  try { accessSync(path, constants.X_OK); return isAbsolute(path); } catch { return false; }
};
const browser = env.BM_BROWSER_BIN || ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'].find(executable);
if (!browser || !executable(browser) || /[\r\n"\\]/.test(browser)) {
  throw new Error('Set BM_BROWSER_BIN to an absolute, executable Chromium/Chrome path; no browser is downloaded or replaced');
}
if (!env.BM_BROWSER_BIN) console.log(browser);
JS
)

export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}"
systemctl --user show-environment >/dev/null || fail 'No user systemd bus. Log in as this user, then rerun the installer.'

for bm_dir in "$bm_config_dir" "$bm_unit_dir" "$bm_bin_dir"; do
  [[ ! -L $bm_dir ]] || fail 'Installation directories must not be symlinks.'
  mkdir -p -- "$bm_dir"
  [[ -O $bm_dir ]] || fail 'Installation directories must belong to the current user.'
done
chmod 700 -- "$bm_config_dir"
for bm_target in "$bm_config" "$bm_token"; do
  [[ ! -e $bm_target && ! -L $bm_target ]] || private_file "$bm_target"
done
for bm_unit in browser-manager browser-manager-tunnel; do
  bm_target="$bm_unit_dir/$bm_unit.service"
  if [[ -e $bm_target || -L $bm_target ]]; then
    [[ -f $bm_target && ! -L $bm_target && -O $bm_target ]] || fail 'Refusing to replace an unsafe systemd unit.'
    [[ $(head -n 1 -- "$bm_target") == '# Managed by browser-manager/scripts/install.sh' ]] || fail 'A different service already uses the browser-manager unit name.'
  fi
done
if [[ -e $bm_bin_dir/browserctl || -L $bm_bin_dir/browserctl ]]; then
  [[ -L $bm_bin_dir/browserctl && $(readlink -- "$bm_bin_dir/browserctl") == "$bm_project/bin/browserctl.mjs" ]] || fail 'Refusing to replace an existing browserctl command.'
fi

[[ $bm_source_config == "$bm_config" ]] || install -m 600 -- "$bm_source_config" "$bm_config"
# Record an auto-detected path once. Explicit configuration is preserved verbatim, and
# browser profiles are not inspected or changed here.
if [[ -n $bm_browser_bin ]]; then
  printf '\nBM_BROWSER_BIN="%s"\n' "$bm_browser_bin" >> "$bm_config"
fi
printf '%s\n' \
  '# Managed by browser-manager/scripts/install.sh' \
  '[Unit]' 'Description=Private browser manager' 'After=network-online.target' \
  '[Service]' 'Type=simple' "WorkingDirectory=$bm_project" \
  "EnvironmentFile=$bm_config" 'Environment=NODE_ENV=production' \
  "ExecStart=\"$bm_node\" \"$bm_project/server.mjs\"" \
  'Restart=on-failure' 'RestartSec=3' 'TimeoutStopSec=20' 'KillMode=control-group' 'UMask=0077' \
  '[Install]' 'WantedBy=default.target' > "$bm_unit_dir/browser-manager.service"
ln -sfn -- "$bm_project/bin/browserctl.mjs" "$bm_bin_dir/browserctl"

if [[ -n $bm_source_token ]]; then
  [[ $bm_source_token == "$bm_token" ]] || install -m 600 -- "$bm_source_token" "$bm_token"
  printf '%s\n' \
    '# Managed by browser-manager/scripts/install.sh' \
    '[Unit]' 'Description=Private browser-manager Cloudflare connector' \
    'After=network-online.target browser-manager.service' \
    '[Service]' 'Type=simple' \
    "ExecStart=\"$bm_cloudflared\" tunnel --no-autoupdate run --token-file \"$bm_token\"" \
    'Restart=on-failure' 'RestartSec=5' 'UMask=0077' \
    '[Install]' 'WantedBy=default.target' > "$bm_unit_dir/browser-manager-tunnel.service"
fi

systemctl --user daemon-reload
systemctl --user enable browser-manager.service
systemctl --user restart browser-manager.service
if [[ -n $bm_source_token ]]; then
  systemctl --user enable browser-manager-tunnel.service
  systemctl --user restart browser-manager-tunnel.service
fi
printf 'Installed browser-manager and %s/browserctl. Profiles are retained across restarts.\n' "$bm_bin_dir"
if [[ $(loginctl show-user "$(id -u)" -p Linger --value 2>/dev/null || true) != yes ]]; then
  printf 'For reboot/logout persistence, an administrator must run: loginctl enable-linger %s\n' "$(id -un)"
fi
