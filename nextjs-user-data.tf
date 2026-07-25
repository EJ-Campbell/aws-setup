# nextjs-user-data.tf
#
# Setup script for the Next.js dev box, published to S3 and fetched at boot (same
# pattern as the other dev boxes, so it can be updated without recreating the instance).
#
# Three things it sets up:
#   1. Separate Unix users (colton, connor, ej) so each has their own home, their own
#      `gh auth login`, and their own projects. Nobody shares a GitHub identity.
#   2. cloudflared, running as a system service, holding the tunnel to Cloudflare.
#   3. `ndev` -- run it in a Next.js project and it starts `next dev` on a deterministic
#      port, registers <name>.cc-games.dev -> that port with the tunnel, and prints the
#      URL. Cloudflare Access gates every hostname behind the Gmail allowlist.

locals {
  nextjs_tunnel_id = "60234535-279b-4b20-bbc3-7fd353abb7f6"
  nextjs_domain    = "cc-games.dev"

  # Unix accounts. Each gets the fcvm key initially so you can get in as them and help;
  # they can add their own keys to ~/.ssh/authorized_keys afterwards.
  nextjs_users = ["colton", "connor", "ej"]

  nextjs_user_data = <<-SCRIPT
#!/bin/bash
set -uxo pipefail

# ---------------------------------------------------------------- base packages
export DEBIAN_FRONTEND=noninteractive
apt-get update || true
apt-get install -y curl git build-essential zsh jq unzip || echo "WARNING: some packages failed"
# No awscli apt package on Ubuntu 24.04 -- use the official installer.
if ! command -v aws >/dev/null 2>&1; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o /tmp/awscliv2.zip
  (cd /tmp && unzip -qo awscliv2.zip && ./aws/install && rm -rf /tmp/aws /tmp/awscliv2.zip)
fi

# Node 22 (Next.js needs a modern runtime)
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y nodejs
fi
npm install -g pnpm >/dev/null 2>&1 || true

# ---------------------------------------------------------------- cloudflared
if ! command -v cloudflared >/dev/null 2>&1; then
  ARCH=$(dpkg --print-architecture)
  curl -fsSL -o /tmp/cloudflared.deb \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$${ARCH}.deb"
  dpkg -i /tmp/cloudflared.deb && rm -f /tmp/cloudflared.deb
fi

mkdir -p /etc/cloudflared
# Credentials come from Secrets Manager, never baked into this script or the AMI.
aws secretsmanager get-secret-value --secret-id cloudflare-tunnel-credentials \
  --region us-west-1 --query SecretString --output text > /etc/cloudflared/credentials.json
chmod 600 /etc/cloudflared/credentials.json

# ---------------------------------------------------------------- ndev registry
# hostname<TAB>port, one per line. ndev-register rewrites the cloudflared ingress from
# this file, so adding a project never means hand-editing YAML.
mkdir -p /var/lib/ndev
touch /var/lib/ndev/registry
chmod 666 /var/lib/ndev/registry

cat > /usr/local/bin/ndev-register <<'REG'
#!/bin/bash
# ndev-register <hostname> <port> <user> <projectdir>
#
# Records a published project, rewrites the cloudflared ingress, and enables the systemd
# unit that actually runs it. Runs as root via sudoers, so it validates every argument
# rather than trusting the caller -- the kids' accounts hold no other privilege and this
# is the single door through it.
set -euo pipefail
HOST="$1"; PORT="$2"; WHO="$3"; DIR="$4"

case "$HOST" in *.cc-games.dev) ;; *) echo "refusing: $HOST is not under cc-games.dev" >&2; exit 1 ;; esac
case "$PORT" in ''|*[!0-9]*) echo "refusing: bad port $PORT" >&2; exit 1 ;; esac
id "$WHO" >/dev/null 2>&1 || { echo "refusing: no such user $WHO" >&2; exit 1; }

# A user may only publish as themselves. Without this, colton could register a service
# that runs as connor, since sudoers cannot express "only your own username".
if [ -n "$${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ "$SUDO_USER" != "$WHO" ]; then
  echo "refusing: $SUDO_USER may not publish as $WHO" >&2; exit 1
fi
case "$DIR" in "/home/$WHO"|"/home/$WHO"/*) ;; *) echo "refusing: $DIR is outside /home/$WHO" >&2; exit 1 ;; esac
[ -f "$DIR/package.json" ] || { echo "refusing: no package.json in $DIR" >&2; exit 1; }

REGISTRY=/var/lib/ndev/registry
grep -v -P "^\Q$HOST\E\t" "$REGISTRY" > "$REGISTRY.new" 2>/dev/null || true
printf '%s\t%s\t%s\t%s\n' "$HOST" "$PORT" "$WHO" "$DIR" >> "$REGISTRY.new"
sort -u "$REGISTRY.new" > "$REGISTRY" && rm -f "$REGISTRY.new"

# What ndev@<user>.service reads on boot. This is why a reboot restores the site with
# nobody logged in: the unit needs no argument beyond the username.
printf 'HOST=%s\nPORT=%s\nDIR=%s\n' "$HOST" "$PORT" "$DIR" > "/var/lib/ndev/$WHO.env"

{
  echo "tunnel: ${local.nextjs_tunnel_id}"
  echo "credentials-file: /etc/cloudflared/credentials.json"
  echo "ingress:"
  while IFS=$'\t' read -r h p rest; do
    [ -n "$h" ] || continue
    echo "  - hostname: $h"
    echo "    service: http://127.0.0.1:$p"
  done < "$REGISTRY"
  echo "  - service: http_status:404"
} > /etc/cloudflared/config.yml

systemctl reload-or-restart cloudflared 2>/dev/null || systemctl restart cloudflared
systemctl enable --now "ndev@$WHO.service" >/dev/null 2>&1 || systemctl restart "ndev@$WHO.service"
echo "registered $HOST -> 127.0.0.1:$PORT (ndev@$WHO, enabled at boot)"
REG
chmod 755 /usr/local/bin/ndev-register

# ---------------------------------------------------------------- durability
# WHY THESE UNITS EXIST: this box is a spot instance, so AWS reclaims it and restarts it
# without warning -- twice in one hour on 2026-07-25. cloudflared came back on its own
# (it is a systemd service) but the `next dev` processes did not, because they had been
# started by hand in a tmux session. The tunnel kept resolving and forwarding to a dead
# port, so every URL authenticated correctly and then 502'd.
#
# On-demand would not have fixed this. Instances still reboot for host maintenance and
# kernel updates; the purchase model only changes how OFTEN. Durability has to come from
# something that restarts the work, which is what these units are.

cat > /usr/local/bin/ndev-run <<'RUN'
#!/bin/bash
# Started by ndev@<user>.service. Reads what ndev-register recorded and serves it.
set -euo pipefail
WHO="$1"
ENVF="/var/lib/ndev/$WHO.env"
[ -f "$ENVF" ] || { echo "$WHO has not published a project yet" >&2; exit 0; }
. "$ENVF"
cd "$DIR"
# node_modules lives on the root volume and survives reboots, but a fresh volume (or a
# dependency change) would otherwise leave the service crash-looping on a missing module.
[ -d node_modules ] || { echo "installing dependencies..."; pnpm install || npm install; }
exec npx next dev --port "$PORT" --hostname 127.0.0.1
RUN
chmod 755 /usr/local/bin/ndev-run

cat > /etc/systemd/system/ndev@.service <<'UNIT'
[Unit]
Description=next dev server for %i (published to the cc-games.dev tunnel)
After=network-online.target cloudflared.service
Wants=network-online.target

[Service]
Type=simple
User=%i
WorkingDirectory=/home/%i
Environment=HOME=/home/%i
Environment=NODE_ENV=development
ExecStart=/usr/local/bin/ndev-run %i
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

# Claude's --remote-control is the interactive TUI and refuses to run without a pty --
# piping it anywhere makes it fall into --print mode and exit. systemd gives a service no
# pty, so it runs inside tmux, on a dedicated socket so it never collides with the
# interactive t-claude session the kid may also have open.
# Where the agents should sit: the project the user actually published, so that the thing
# being served and the thing being edited are the same directory by construction. Falls
# back to $HOME, which matters on a fresh box -- before anyone has run ndev there is no
# project, and a unit pointed at a non-existent directory refuses to start at all.
cat > /usr/local/bin/agent-dir <<'ADIR'
#!/bin/bash
WHO="$1"
ENVF="/var/lib/ndev/$WHO.env"
DIR=""
[ -f "$ENVF" ] && . "$ENVF"
[ -n "$DIR" ] && [ -d "$DIR" ] || DIR="/home/$WHO"
printf '%s\n' "$DIR"
ADIR
chmod 755 /usr/local/bin/agent-dir

# Regenerates a user's ~/Documents/Codex/AGENTS.md from the repos actually on disk.
# GENERATED because a kid can add a second project at any time, and a hardcoded path would
# then be wrong. Runs at boot and from the nightly updater.
cat > /usr/local/bin/kid-agents-refresh <<'KIDAGENTS'
#!/bin/bash
set -uo pipefail
WHO="$${1:?usage: kid-agents-refresh <user>}"
id "$WHO" >/dev/null 2>&1 || { echo "no such user $WHO" >&2; exit 1; }
HOMEDIR="/home/$WHO"
OUT="$HOMEDIR/Documents/Codex/AGENTS.md"
install -d -o "$WHO" -g "$WHO" -m 755 "$HOMEDIR/Documents/Codex"

HOST=""; PORT=""
[ -f "/var/lib/ndev/$WHO.env" ] && . "/var/lib/ndev/$WHO.env"

# git must run AS the user: root gets "dubious ownership" on a user-owned repo and every
# command returns empty, which silently produces a project list with no projects in it.
#
# Built in this loop rather than inside `sudo -u ... bash -c '...'`. In that form the
# markdown backticks landed inside double quotes in the inner shell and were executed as
# command substitution -- `~/%s` became an attempt to run /home/<user>/%s, and one repo
# came out as three garbled lines. Here the backticks are backslash-escaped and never
# reach a nested shell.
BT='`'
REPOS=""
for d in "$HOMEDIR"/*/; do
  [ -d "$d/.git" ] || continue
  n=$(basename "$d")
  r=$(sudo -u "$WHO" git -C "$d" remote get-url origin 2>/dev/null | sed 's|https://github.com/||;s|\.git$||')
  b=$(sudo -u "$WHO" git -C "$d" branch --show-current 2>/dev/null)
  REPOS="$${REPOS}- $${BT}~/$${n}$${BT} — $${r:-no remote} (branch $${BT}$${b:-detached}$${BT})
"
done
REPOS=$(printf '%s' "$REPOS")

# Fail loudly rather than shipping an empty list. The metal-box generator produced one on
# its first run and `|| true` hid it; the file looked fine and told an agent nothing.
if [ -z "$REPOS" ]; then
  echo "kid-agents-refresh: found no git repos for $WHO -- keeping existing AGENTS.md" >&2
  [ -s "$OUT" ] && exit 0
  REPOS="- (no git repositories yet -- ask the user what to work on)"
fi

TMP=$(mktemp)
{
  printf '# Read this first\n\n'
  printf 'You have been started in an empty scratch folder under Documents/Codex/<date>/<task>/.\n'
  printf '**That folder is not the project.** The real work is in one of these:\n\n'
  printf '%s\n\n' "$REPOS"
  printf 'They are writable inside your sandbox. Run commands from the project directory.\n\n'
  printf '## The dev server is already running -- do not start one\n\n'
  if [ -n "$HOST" ]; then
    printf 'This project is live at https://%s on port %s.\n\n' "$HOST" "$PORT"
  fi
  printf 'It is a systemd service that starts at boot and restarts if it crashes. Running\n'
  printf '`next dev` or `npm run dev` yourself collides on the port and breaks the live site.\n\n'
  printf '**Your sandbox may have no network access, even to localhost.** When it does not,\n'
  printf '`curl http://localhost:...` fails identically whether the server is healthy or truly\n'
  printf 'stopped, so it tells you nothing. Never conclude from a failed curl that it is down.\n'
  printf 'Check the service instead -- these need no network:\n\n'
  printf '```bash\n'
  printf 'systemctl is-active ndev@%s      # "active" means the site is up\n' "$WHO"
  printf 'journalctl -u ndev@%s -n 50      # recent output, including compile errors\n' "$WHO"
  printf 'sudo systemctl restart ndev@%s   # only if a change needs a full restart\n' "$WHO"
  printf '```\n\n'
  printf 'Next.js hot-reloads on save, so most edits need no restart at all.\n\n'
  printf '## This machine\n\n'
  printf -- '- You have **full passwordless sudo**. Install whatever you need.\n'
  printf -- '- Your home directory persists across reboots and is backed up daily.\n'
  printf -- '- `git` is authenticated as your own GitHub account, and `vercel` as your own\n'
  printf '  Vercel account. Both kids share one Vercel project, so pushing to `main`\n'
  printf '  deploys the shared site.\n'
} > "$TMP"
install -m 644 -o "$WHO" -g "$WHO" "$TMP" "$OUT"
rm -f "$TMP"
echo "wrote $OUT ($(wc -c < "$OUT") bytes, $(printf '%s' "$REPOS" | grep -c '^- ') repo(s))"
KIDAGENTS
chmod 755 /usr/local/bin/kid-agents-refresh

cat > /usr/local/bin/agents-start <<'AGENTS'
#!/bin/bash
set -euo pipefail
WHO="$1"
export HOME="/home/$WHO"
WORKDIR="$(/usr/local/bin/agent-dir "$WHO")"
cd "$WORKDIR"
TM="/usr/local/bin/tmux -L agents"
$TM has-session -t claude 2>/dev/null && exit 0
$TM new-session -d -s claude -c "$WORKDIR" \
  "claude --dangerously-skip-permissions --remote-control; exec bash -l"
AGENTS
chmod 755 /usr/local/bin/agents-start

cat > /etc/systemd/system/claude-rc@.service <<'UNIT'
[Unit]
Description=Claude Code with remote control for %i
After=network-online.target
Wants=network-online.target

[Service]
# forking, not simple: tmux daemonises a server and the launching process exits. systemd
# then tracks the surviving server, so if Claude dies the unit restarts it.
Type=forking
User=%i
Environment=HOME=/home/%i
Environment=TERM=xterm-256color
WorkingDirectory=/home/%i
ExecStart=/usr/local/bin/agents-start %i
ExecStop=/usr/local/bin/tmux -L agents kill-server
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
UNIT

# Codex's remote control is a real daemon rather than a TUI, so it needs no pty and no
# tmux. It is NOT Type=forking though: codex backgrounds the daemon itself (pid backend,
# own socket under ~/.codex/app-server-control) and the CLI returns immediately, so
# systemd has no forked child to adopt and marks the unit failed while the daemon happily
# runs. oneshot + RemainAfterExit matches what actually happens.
#
# Success is asserted against `--json` rather than the exit status. The text output prints
# "the connection is errored" and exits non-zero while it is still establishing, even
# though it goes on to connect -- only the JSON reports the settled truth.
#
# Uses the standalone binary explicitly: `codex remote-control` refuses to run against the
# npm/system install, and $PATH is not dependable inside a unit.
cat > /etc/systemd/system/codex-rc@.service <<'UNIT'
[Unit]
Description=Codex app-server daemon with remote control for %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=%i
Environment=HOME=/home/%i
WorkingDirectory=/home/%i
# No -c overrides here on purpose. `remote-control start` DISCARDS them: only the bare
# foreground `codex remote-control` forwards root config overrides. And even if it did
# forward them they would lose -- the ChatGPT client sends approvalPolicy and sandbox with
# each thread/start, and codex merges them as
#   sandbox_mode_override.or(self.sandbox_mode)
# i.e. client beats config.toml (SessionFlags layer 30 > user config layer 20). Verified
# on this box: a session rollout recorded approval_policy="on-request" and
# sandbox_policy=workspace-write while config.toml said never/danger-full-access.
# The approval mode is the app's to choose; nothing host-side can outrank it.
ExecStart=/bin/sh -c 'cd "$(/usr/local/bin/agent-dir %i)" || cd /home/%i; CX="/home/%i/.local/bin/codex"; "$CX" remote-control start >/dev/null 2>&1 || true; for i in 1 2 3 4 5; do "$CX" remote-control start --json 2>/dev/null | grep -q "\\"status\\":\\"connected\\"" && exit 0; sleep 5; done; exit 1'
ExecStop=-/home/%i/.local/bin/codex remote-control stop

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

# seed an empty config so cloudflared can start before anything is registered
[ -s /etc/cloudflared/config.yml ] || {
  printf 'tunnel: %s\ncredentials-file: /etc/cloudflared/credentials.json\ningress:\n  - service: http_status:404\n' \
    "${local.nextjs_tunnel_id}" > /etc/cloudflared/config.yml
}

cat > /etc/systemd/system/cloudflared.service <<'SVC'
[Unit]
Description=Cloudflare Tunnel for cc-games.dev
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/cloudflared --config /etc/cloudflared/config.yml --no-autoupdate tunnel run
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload
systemctl enable --now cloudflared

# ---------------------------------------------------------------- ndev
cat > /usr/local/bin/ndev <<'NDEV'
#!/bin/bash
# ndev [name] -- start `next dev` in this project and expose it at <name>.cc-games.dev
#
# Defaults to your username, so `ndev` as colton publishes colton.cc-games.dev. Pass a
# name for a second project: `ndev tetris` -> tetris.cc-games.dev.
#
# The port is derived from the hostname, so restarting gives you the same port and the
# tunnel mapping stays valid. Binds 127.0.0.1 only -- the box has no inbound web ports;
# the tunnel is the sole path in, and Cloudflare Access gates it by Google login.
set -euo pipefail
DOMAIN=cc-games.dev
NAME="$${1:-$USER}"
NAME=$(printf '%s' "$NAME" | tr -c 'a-zA-Z0-9-' '-' | tr 'A-Z' 'a-z' | sed 's/^-*//;s/-*$//')
[ -n "$NAME" ] || { echo "usage: ndev [name]" >&2; exit 1; }
HOST="$NAME.$DOMAIN"
PORT=$(( 3100 + ( $(printf '%s' "$HOST" | cksum | awk '{print $1}') % 800 ) ))

[ -f package.json ] || { echo "no package.json here -- run ndev inside a Next.js project" >&2; exit 1; }

# Hand the project to systemd rather than running it in this terminal. Publishing and
# making it durable are then the same action -- there is no way to end up with a URL
# registered in the tunnel but nothing set to restart behind it, which is exactly the
# state a spot interruption left this box in before.
sudo /usr/local/bin/ndev-register "$HOST" "$PORT" "$USER" "$(pwd)"
echo ""
echo "  https://$HOST   (port $PORT)"
echo "  sign in with your Google account -- only the allowlist gets through"
echo ""
echo "  it keeps running after you log out, and comes back by itself if the box reboots."
echo "    logs:    journalctl -u ndev@$USER -f"
echo "    restart: sudo systemctl restart ndev@$USER"
echo "    stop:    sudo systemctl stop ndev@$USER"
echo ""
NDEV
chmod 755 /usr/local/bin/ndev

# ---------------------------------------------------------------- users
# One Unix account each, so GitHub logins, dotfiles and projects stay separate.
FCVM_KEY=$(cat /home/ubuntu/.ssh/authorized_keys 2>/dev/null | head -1)
for u in ${join(" ", local.nextjs_users)}; do
  if ! id "$u" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$u"
  fi
  install -d -m 700 -o "$u" -g "$u" "/home/$u/.ssh"
  if [ -n "$FCVM_KEY" ]; then
    grep -qxF "$FCVM_KEY" "/home/$u/.ssh/authorized_keys" 2>/dev/null || \
      echo "$FCVM_KEY" >> "/home/$u/.ssh/authorized_keys"
  fi
  chown "$u:$u" "/home/$u/.ssh/authorized_keys" 2>/dev/null || true
  chmod 600 "/home/$u/.ssh/authorized_keys" 2>/dev/null || true

  # FULL passwordless sudo, deliberately.
  #
  # This box IS the sandbox: it holds nothing but these projects, exposes no inbound web
  # ports, and its IAM role can read exactly one S3 object and two secrets. There is
  # nothing here worth protecting the kids from, and no credential they could reach that
  # they do not already own.
  #
  # The earlier version allowed only ndev-register plus their own three systemd units.
  # That looked tidy and cost real work: `sudo npx playwright install-deps` failed, so
  # Chromium could not launch, and an agent working in their account hits a wall it cannot
  # explain or escape. Every such wall becomes a support request rather than a safeguard.
  #
  # The protections that actually matter are elsewhere and unaffected: Cloudflare Access
  # still gates every URL, the instance still has no inbound web ports, and the jumpbox
  # key is no longer on any dev server.
  printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$u" > "/etc/sudoers.d/ndev-$u.new"
  if visudo -cf "/etc/sudoers.d/ndev-$u.new" >/dev/null 2>&1; then
    mv "/etc/sudoers.d/ndev-$u.new" "/etc/sudoers.d/ndev-$u"
    chmod 440 "/etc/sudoers.d/ndev-$u"
  else
    rm -f "/etc/sudoers.d/ndev-$u.new"
    echo "WARNING: sudoers for $u failed validation; leaving previous file in place"
  fi

  # Let their user services and tmux survive logout / start without a login session.
  loginctl enable-linger "$u" 2>/dev/null || true

  # Bring back the agents on every boot. Guarded on credentials existing: on a fresh box
  # nobody has logged in to Claude or Codex yet, and enabling the units then would just
  # crash-loop until someone does.
  [ -s "/home/$u/.claude/.credentials.json" ] && systemctl enable --now "claude-rc@$u.service" 2>/dev/null || true

  # `codex remote-control start` refuses to run against the system/npm codex -- it needs
  # the STANDALONE install, because the daemon self-updates app-server from a fixed path
  # (~/.codex/packages/standalone/current/codex). Without this the unit crash-loops with
  # "managed standalone Codex install not found". Per-user, since it lives under $HOME.
  # The -H and the cd are both load-bearing: the installer shells out to `find`, and if the
  # working directory is one the target user cannot read (e.g. /home/ubuntu, where this
  # script runs) it dies with "Failed to restore initial working directory" AFTER creating
  # releases/ but BEFORE creating current/ -- leaving a half-install that looks plausible.
  CODEX_STANDALONE="/home/$u/.codex/packages/standalone/current/codex"
  [ -x "$CODEX_STANDALONE" ] || sudo -u "$u" -H sh -c "cd /home/$u && curl -fsSL https://chatgpt.com/codex/install.sh | sh" >/dev/null 2>&1 || true

  # Codex's counterpart to Claude's --dangerously-skip-permissions. Deliberate: the EC2
  # instance IS the sandbox. It holds nothing but these projects, has no inbound web
  # ports, and its IAM role can read exactly one S3 object and one secret -- so a second
  # sandbox inside it buys approval prompts and no real containment. Codex's own help
  # says this mode is "intended solely for running in environments that are externally
  # sandboxed", which is this.
  #
  # Edited in place rather than appended: config.toml ends with [projects."..."] sections,
  # so a naive >> would bury these keys INSIDE a section and silently not apply. Missing
  # keys are inserted at line 1, above any section header.
  CFG="/home/$u/.codex/config.toml"
  if [ -f "$CFG" ]; then
    sed -i 's|^ *approval_policy *=.*|approval_policy = "never"|' "$CFG"
    sed -i 's|^ *sandbox_mode *=.*|sandbox_mode = "danger-full-access"|' "$CFG"
    grep -q '^approval_policy' "$CFG" || sed -i '1i approval_policy = "never"' "$CFG"
    grep -q '^sandbox_mode' "$CFG" || sed -i '1i sandbox_mode = "danger-full-access"' "$CFG"
  else
    install -d -o "$u" -g "$u" -m 700 "/home/$u/.codex"
    printf 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n' > "$CFG"
  fi
  # Pre-trust the published project so it never stops to ask on first use.
  PDIR=$(/usr/local/bin/agent-dir "$u" 2>/dev/null || echo "/home/$u")
  grep -qF "[projects.\"$PDIR\"]" "$CFG" 2>/dev/null || \
    printf '\n[projects."%s"]\ntrust_level = "trusted"\n' "$PDIR" >> "$CFG"

  # Guidance for remote-control sessions. ~/Documents/Codex is the parent of every
  # session's scratch dir (~/Documents/Codex/<date>/<task-name>), and codex reads AGENTS.md
  # by walking UP from its cwd -- so this reaches sessions the host cannot otherwise
  # configure. It is the only lever over app-created sessions besides writable_roots.
  install -d -o "$u" -g "$u" -m 755 "/home/$u/Documents/Codex"
  /usr/local/bin/kid-agents-refresh "$u" || echo "WARNING: AGENTS.md generation failed for $u"
  cat > "/home/$u/Documents/Codex/AGENTS.md.static" <<AGENTSMD
# Read this first

You have been started in an empty scratch folder under Documents/Codex/<date>/<task>/.
That folder is NOT the project.

The project is a Next.js game at:

    $PDIR

Work there: read, search and edit files in that directory and run commands from it. It is
a git repository, and it is writable inside your sandbox.

## The dev server is already running -- do not start one

It is a systemd service, not something you launch. It is published at
https://$u.cc-games.dev and listens on 127.0.0.1 only.

**Your sandbox has no network access, so \`curl http://localhost:...\` WILL FAIL even
though the server is running fine.** A failed curl does not mean the server is down. Do
not conclude that it stopped, and do not start your own \`next dev\` -- two servers on one
port just breaks the site.

To check on it, use these instead. They need no network:

    systemctl is-active ndev@$u          # "active" means it is up
    journalctl -u ndev@$u -n 50          # recent output, including compile errors
    sudo systemctl restart ndev@$u       # pick up a change that needs a restart

Next.js hot-reloads on save, so most edits need no restart at all.
AGENTSMD
  chown "$u:$u" "/home/$u/Documents/Codex/AGENTS.md"

  # THIS is what actually stops the endless "Always approve" prompts.
  #
  # The ChatGPT app sends sandbox="workspace-write" per session and that beats
  # sandbox_mode here -- the client always wins. But it sends the MODE, not the roots:
  # in workspace-write the writable set is the session cwd PLUS whatever config lists.
  # Remote-control sessions start in a throwaway ~/Documents/Codex/<date>/<task>/ dir, so
  # without this every single edit to the actual project is outside the sandbox and
  # escalates for approval.
  #
  # Appending a new [table] header is safe -- unlike bare keys, it cannot be swallowed by
  # a preceding [projects."..."] section.
  if ! grep -q '^\[sandbox_workspace_write\]' "$CFG" 2>/dev/null; then
    printf '\n[sandbox_workspace_write]\nwritable_roots = ["%s"]\nnetwork_access = true\n' "$PDIR" >> "$CFG"
  fi
  chown "$u:$u" "$CFG" 2>/dev/null || true
  { [ -s "/home/$u/.codex/auth.json" ] && [ -x "$CODEX_STANDALONE" ]; } && systemctl enable --now "codex-rc@$u.service" 2>/dev/null || true
  # Re-enable a previously published project (ndev-register wrote the env file).
  [ -s "/var/lib/ndev/$u.env" ] && systemctl enable --now "ndev@$u.service" 2>/dev/null || true
done

# ---------------------------------------------------------------- nightly agent update
# Keeps Claude and Codex current and bounces the units so the new binaries are actually in
# use -- an updated package does nothing while the old process is still running.
#
# Scheduled at 08:00 UTC (01:00 Pacific) because restarting claude-rc kills whatever
# conversation is open in it. RandomizedDelaySec spreads it so both kids' agents are not
# torn down in the same second. Persistent=true means a box that was off overnight catches
# up on the next boot rather than skipping a week of updates.
cat > /usr/local/bin/agent-update <<'AGENTUPD'
#!/bin/bash
# Update Claude Code, Codex and Vercel, then restart the agent services.
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
echo "=== agent-update $(date -u '+%F %T UTC') ==="

BEFORE_CLAUDE=$(claude --version 2>/dev/null | head -1)
npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 || echo "WARNING: claude update failed"
npm install -g vercel >/dev/null 2>&1 || echo "WARNING: vercel update failed"
echo "claude: $${BEFORE_CLAUDE:-none} -> $(claude --version 2>/dev/null | head -1)"

for u in colton connor ej; do
  id "$u" >/dev/null 2>&1 || continue
  # Codex ships its own installer and self-updates the standalone bundle; re-running it is
  # the supported refresh. Must run AS the user from a directory they can read -- from
  # elsewhere it dies in `find` after creating releases/ but before current/.
  if [ -s "/home/$u/.codex/auth.json" ]; then
    B=$(sudo -u "$u" -H /home/$u/.local/bin/codex --version 2>/dev/null | head -1)
    sudo -u "$u" -H sh -c "cd /home/$u && curl -fsSL https://chatgpt.com/codex/install.sh | sh" >/dev/null 2>&1 \
      || echo "WARNING: codex update failed for $u"
    echo "codex[$u]: $${B:-none} -> $(sudo -u "$u" -H /home/$u/.local/bin/codex --version 2>/dev/null | head -1)"
  fi
  # Refresh the project list too, so a repo added during the day shows up.
  /usr/local/bin/kid-agents-refresh "$u" 2>&1 | sed "s/^/agents-md[$u]: /"
done

for u in colton connor ej; do
  id "$u" >/dev/null 2>&1 || continue
  for s in claude-rc codex-rc; do
    systemctl is-enabled "$s@$u" >/dev/null 2>&1 || continue
    systemctl restart "$s@$u" && echo "restarted $s@$u"
  done
done

# ndev is deliberately NOT restarted: nothing here changes Next.js, and bouncing it would
# drop the live site for no reason.
echo "=== done ==="
AGENTUPD
chmod 755 /usr/local/bin/agent-update

cat > /etc/systemd/system/agent-update.service <<'UNIT'
[Unit]
Description=Update Claude/Codex and restart the agent services
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/agent-update
UNIT

cat > /etc/systemd/system/agent-update.timer <<'UNIT'
[Unit]
Description=Nightly Claude/Codex update

[Timer]
OnCalendar=*-*-* 08:00:00 UTC
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now agent-update.timer >/dev/null 2>&1 || true

# ---------------------------------------------------------------- swap
# 8GB is comfortable for two kids, but each `next dev` compile spikes hard and there are
# now six long-lived node processes (2x next, 2x claude, 2x codex). A swapfile costs
# nothing on a 50GB volume and turns a would-be OOM kill into a slow moment.
if ! swapon --show=NAME --noheadings | grep -q .; then
  fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ---------------------------------------------------------------- per-user shell env
# t-claude, atuin, starship, fzf, zsh plugins and the native-scrollback tmux.conf --
# identical for every account. This is local.user_shell_env, the SAME body the other dev
# boxes run for ubuntu, so there is one definition of "our shell" and no duplication.
# tmux and claude are installed once, system-wide, below.
if ! command -v tmux >/dev/null 2>&1 || ! /usr/local/bin/tmux -V 2>/dev/null | grep -q "3\.[6-9]"; then
  TARCH=$(uname -m)
  if curl -fsSL --retry 3 "https://github.com/ejc3/tmux/releases/download/binaries-3.x/tmux-$TARCH.tar.gz" -o /tmp/tmux.tgz && [ -s /tmp/tmux.tgz ]; then
    tar xzf /tmp/tmux.tgz -C /tmp && install -m 755 /tmp/tmux /usr/local/bin/tmux && rm -f /tmp/tmux.tgz /tmp/tmux
  else
    apt-get install -y tmux || true
  fi
fi
command -v claude >/dev/null 2>&1 || npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 || echo "WARNING: claude install failed"

# Vercel CLI. The project deploys to Vercel (the git integration on CoderColton/colton-games
# builds main automatically), and both kids are members of the Pro team that owns it, so
# they can also deploy and inspect from the box directly.
#
# Only the CLI is installed here. `vercel login` is an interactive device-code flow and
# each account must authenticate as ITSELF, so it cannot be baked in -- the tokens live in
# ~/.local/share/com.vercel.cli/auth.json, which is on the persistent volume and survives
# reboots and instance replacement.
command -v vercel >/dev/null 2>&1 || npm install -g vercel >/dev/null 2>&1 || echo "WARNING: vercel install failed"

# ---------------------------------------------------------------- dev-server hops
# Runs as root (it installs into /home/ubuntu as the ubuntu user) and only touches the
# ubuntu account -- colton and connor get no key to the Firecracker boxes, and cannot read
# /home/ubuntu anyway since it is 0700.
${local.dev_hop_setup}

# ---------------------------------------------------------------- codex sandbox
# Ubuntu 24.04 blocks unprivileged user namespaces via AppArmor. Codex's sandbox is bwrap,
# which needs a userns to bring up its loopback interface; it cannot, so EVERY sandboxed
# command fails and the model asks permission to run outside the sandbox instead. That is
# the "May I run ... outside the sandbox? The sandbox failed to initialize its loopback
# interface" prompt, on every single command.
#
# Verified on this host with the real bundled binary:
#   .../codex-resources/bwrap --unshare-all --ro-bind / / --proc /proc --dev /dev /bin/true
#   -> bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
#
# Do NOT test this with `unshare` -- it exits 0 here even while bwrap fails, because
# unconfined shells are exempt from the restriction. Testing unshare is what led me to the
# wrong conclusion the first time.
#
# Turning the restriction off is defensible on this box specifically: the EC2 instance IS
# the isolation boundary. It holds only these projects, exposes no inbound web ports, and
# its IAM role can read exactly one S3 object and one secret. Note this re-enables
# unprivileged userns for every process here, not just codex. 20- beats Ubuntu's own
# /usr/lib/sysctl.d/10-apparmor.conf, which is the override name Ubuntu recommends.
if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null)" != "0" ]; then
  echo 'kernel.apparmor_restrict_unprivileged_userns = 0' > /etc/sysctl.d/20-apparmor-userns.conf
  sysctl --system >/dev/null 2>&1 || true
  echo "userns restriction now: $(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null)"
fi

# ---------------------------------------------------------------- eternal terminal
# So the phone can reach THIS box directly, not only via the jumpbox. The security group
# has always opened 2022, but nothing was listening: ET was never installed here, so that
# rule was open to no purpose and the only way in was plain ssh on 22.
#
# Same vendored 7.x build the other dev boxes run (ejc3/EternalTerminal, binaries-7.x),
# fetched prebuilt rather than compiled -- building ET from source takes minutes on a
# 2 vCPU box and this script runs on every boot.
if ! /usr/bin/etserver --version 2>/dev/null | grep -q "7\."; then
  # The prebuilt binaries are dynamically linked. The metal dev boxes happen to have
  # protobuf because they build it, but this box never did, so etserver died with
  # "error while loading shared libraries: libprotobuf.so.32". Install the runtime first
  # -- the version probe below correctly refuses to install a binary that cannot run, so
  # without this ET silently never appears.
  apt-get install -y libprotobuf32t64 libsodium23 >/dev/null 2>&1 || \
    apt-get install -y libprotobuf32t64 >/dev/null 2>&1 || \
    echo "WARNING: could not install ET runtime deps"
  EARCH=$(uname -m)
  if curl -fsSL --retry 3 "https://github.com/ejc3/EternalTerminal/releases/download/binaries-7.x/et-$EARCH.tar.gz" -o /tmp/et.tgz && [ -s /tmp/et.tgz ]; then
    if tar xzf /tmp/et.tgz -C /tmp && [ -s /tmp/etserver ]; then
      # Prove it runs on this box before installing over anything. Check the OUTPUT, not
      # the exit status: this build prints its version and then aborts non-zero, so
      # `if /tmp/etserver --version` silently takes the failure branch and skips the
      # install even though the binary is fine. (dev-selfupdate.tf hit the same trap.)
      chmod +x /tmp/et /tmp/etserver /tmp/etterminal 2>/dev/null
      if /tmp/etserver --version 2>&1 </dev/null | grep -q "7\."; then
        install -m 755 /tmp/et /tmp/etserver /tmp/etterminal /usr/bin/
      else
        echo "WARNING: downloaded etserver did not report a 7.x version; leaving ET uninstalled"
      fi
    fi
    rm -f /tmp/et.tgz /tmp/et /tmp/etserver /tmp/etterminal
  else
    echo "WARNING: could not fetch Eternal Terminal binary"
  fi
fi

if [ -x /usr/bin/etserver ]; then
cat > /etc/systemd/system/etserver.service <<'UNIT'
[Unit]
Description=Eternal Terminal Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/etserver --port 2022
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now etserver.service 2>/dev/null || true
fi
curl -fsSL --retry 3 https://raw.githubusercontent.com/ejc3/t-claude/main/nosync-wrap -o /tmp/nw \
  && [ -s /tmp/nw ] && install -m 755 /tmp/nw /usr/local/bin/nosync-wrap && rm -f /tmp/nw

for u in ${join(" ", local.nextjs_users)} ubuntu; do
  id -u "$u" >/dev/null 2>&1 || continue
  echo "--- shell env for $u ---"
  sudo -u "$u" bash << 'USERSHELL' || echo "WARNING: shell env for $u had errors"
${local.user_shell_env}
USERSHELL
  chsh -s /usr/bin/zsh "$u" 2>/dev/null || true
done

# GitHub CLI, so each user can `gh auth login` under their own account
if ! command -v gh >/dev/null 2>&1; then
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list
  apt-get update || true
  apt-get install -y gh || echo "WARNING: gh install failed"
fi

echo "nextjs-dev ready: users=${join(",", local.nextjs_users)}, tunnel=${local.nextjs_tunnel_id}"
SCRIPT
}

resource "aws_s3_object" "nextjs_user_data" {
  count        = var.enable_nextjs_dev ? 1 : 0
  bucket       = aws_s3_bucket.dev_scripts.id
  key          = "user-data/nextjs.sh"
  content      = local.nextjs_user_data
  content_type = "text/x-shellscript"
  tags         = { Name = "nextjs-dev-user-data" }
}
