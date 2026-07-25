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
cat > /usr/local/bin/agents-start <<'AGENTS'
#!/bin/bash
set -euo pipefail
WHO="$1"
export HOME="/home/$WHO"
cd "$HOME"
TM="/usr/local/bin/tmux -L agents"
$TM has-session -t claude 2>/dev/null && exit 0
$TM new-session -d -s claude -c "$HOME" \
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
ExecStart=/bin/sh -c '/home/%i/.local/bin/codex remote-control start >/dev/null 2>&1 || true; for i in 1 2 3 4 5; do /home/%i/.local/bin/codex remote-control start --json 2>/dev/null | grep -q "\\"status\\":\\"connected\\"" && exit 0; sleep 5; done; exit 1'
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

  # Publishing a hostname, plus control of ONLY their own three units. Each systemctl verb
  # is spelled out with the unit name baked in rather than allowing `systemctl *`, which
  # would let any of them stop cloudflared or restart another kid's server.
  {
    echo "$u ALL=(root) NOPASSWD: /usr/local/bin/ndev-register"
    for unit in "ndev@$u" "claude-rc@$u" "codex-rc@$u"; do
      for verb in start stop restart status; do
        echo "$u ALL=(root) NOPASSWD: /usr/bin/systemctl $verb $unit.service"
      done
    done
  } > "/etc/sudoers.d/ndev-$u"
  chmod 440 "/etc/sudoers.d/ndev-$u"
  visudo -cf "/etc/sudoers.d/ndev-$u" >/dev/null || rm -f "/etc/sudoers.d/ndev-$u"

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
  { [ -s "/home/$u/.codex/auth.json" ] && [ -x "$CODEX_STANDALONE" ]; } && systemctl enable --now "codex-rc@$u.service" 2>/dev/null || true
  # Re-enable a previously published project (ndev-register wrote the env file).
  [ -s "/var/lib/ndev/$u.env" ] && systemctl enable --now "ndev@$u.service" 2>/dev/null || true
done

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
