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
# Register <hostname> -> <port> and reload the tunnel. Runs as root via sudoers so the
# kids' accounts can publish a project without holding any other privilege.
set -euo pipefail
HOST="$1"; PORT="$2"
case "$HOST" in *.cc-games.dev) ;; *) echo "refusing: $HOST is not under cc-games.dev" >&2; exit 1 ;; esac
case "$PORT" in ''|*[!0-9]*) echo "refusing: bad port $PORT" >&2; exit 1 ;; esac

REGISTRY=/var/lib/ndev/registry
grep -v -P "^\Q$HOST\E\t" "$REGISTRY" > "$REGISTRY.new" 2>/dev/null || true
printf '%s\t%s\n' "$HOST" "$PORT" >> "$REGISTRY.new"
sort -u "$REGISTRY.new" > "$REGISTRY" && rm -f "$REGISTRY.new"

{
  echo "tunnel: ${local.nextjs_tunnel_id}"
  echo "credentials-file: /etc/cloudflared/credentials.json"
  echo "ingress:"
  while IFS=$'\t' read -r h p; do
    [ -n "$h" ] || continue
    echo "  - hostname: $h"
    echo "    service: http://127.0.0.1:$p"
  done < "$REGISTRY"
  echo "  - service: http_status:404"
} > /etc/cloudflared/config.yml

systemctl reload-or-restart cloudflared 2>/dev/null || systemctl restart cloudflared
echo "registered $HOST -> 127.0.0.1:$PORT"
REG
chmod 755 /usr/local/bin/ndev-register

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

sudo /usr/local/bin/ndev-register "$HOST" "$PORT"
echo ""
echo "  https://$HOST   (port $PORT)"
echo "  sign in with your Google account -- only the allowlist gets through"
echo ""

if [ -d node_modules ]; then :; else
  echo "  installing dependencies first..."
  (pnpm install || npm install)
fi
exec npx next dev --port "$PORT" --hostname 127.0.0.1
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

  # Exactly one privileged action each: publishing a hostname to the tunnel.
  echo "$u ALL=(root) NOPASSWD: /usr/local/bin/ndev-register" > "/etc/sudoers.d/ndev-$u"
  chmod 440 "/etc/sudoers.d/ndev-$u"
done

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
npm install -g @anthropic-ai/claude-code >/dev/null 2>&1 || echo "WARNING: claude install failed"
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
