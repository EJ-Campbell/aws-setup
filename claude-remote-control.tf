# Boot-time Claude remote control for the two metal development hosts.
#
# Colton and Connor each have a claude-rc@ unit because they are separate Unix users and
# therefore own separate tmux servers. All metal repositories belong to ubuntu and share
# one default tmux server, so they must share one systemd cgroup too. Independent per-repo
# units would make whichever unit created tmux own the server; stopping that unit would
# then kill every other repository's Claude session.
locals {
  metal_claude_remote_control = <<-SETUP
# The managed boot service needs t-claude's argument-passthrough support. Keep a verified,
# immutable copy for systemd so a failed refresh of the interactive copy cannot silently
# turn `--remote-control` into an ordinary Claude session.
install -d -m 755 /usr/local/lib/fcvm
TCLAUDE_COMMIT=e4779daad04a6fe1b8e0dae8f486cd85dbdaa181
TCLAUDE_SHA256=6ffb51bad10d7023323cbd62ba8199b9cd410c867db439c97dbcdce3b93ea819
TCLAUDE_PINNED=/usr/local/lib/fcvm/t-claude.zsh
TCLAUDE_TMP=$(mktemp)
if curl -fsSL --retry 3 \
  "https://raw.githubusercontent.com/ejc3/t-claude/$TCLAUDE_COMMIT/t-claude.zsh" \
  -o "$TCLAUDE_TMP" \
  && [ "$(sha256sum "$TCLAUDE_TMP" | awk '{print $1}')" = "$TCLAUDE_SHA256" ]; then
  install -m 644 -o root -g root "$TCLAUDE_TMP" "$TCLAUDE_PINNED"
elif [ -f "$TCLAUDE_PINNED" ] \
  && [ "$(sha256sum "$TCLAUDE_PINNED" | awk '{print $1}')" = "$TCLAUDE_SHA256" ]; then
  echo "fcvm-claude: pinned t-claude download failed; keeping verified installed copy"
else
  echo "WARNING: fcvm-claude has no verified t-claude; boot service will stay skipped" >&2
fi
rm -f "$TCLAUDE_TMP"

# Record interactive t-claude use in host-local state. Claude history itself cannot be
# used for this: claude-code-sync deliberately merges history.jsonl across ARM and x86.
cat > /usr/local/bin/fcvm-claude-track <<'TRACKER'
#!/bin/bash
set -uo pipefail

export HOME=/home/ubuntu
export PATH=/home/ubuntu/.local/bin:/usr/local/bin:/usr/bin:/bin
candidate="$1"
repo=$(git -C "$candidate" rev-parse --show-toplevel 2>/dev/null) || exit 0
case "$repo" in
  /home/ubuntu/*) ;;
  *) exit 0 ;;
esac

origin=$(git -C "$repo" remote get-url origin 2>/dev/null) || exit 0
case "$origin" in
  https://github.com/ejc3/*|git@github.com:ejc3/*|ssh://git@github.com/ejc3/*) ;;
  # Collaboration repos owned by someone else, allowed ONE AT A TIME by exact name.
  # Deliberately not an org wildcard: this gate decides which checkouts get an agent
  # started with --dangerously-skip-permissions at boot, and a wildcard would opt in
  # every future repo of that owner -- including ones added without our review.
  https://github.com/skrutzler-disney/dolphin-labs|https://github.com/skrutzler-disney/dolphin-labs.git) ;;
  git@github.com:skrutzler-disney/dolphin-labs|git@github.com:skrutzler-disney/dolphin-labs.git) ;;
  ssh://git@github.com/skrutzler-disney/dolphin-labs|ssh://git@github.com/skrutzler-disney/dolphin-labs.git) ;;
  *) exit 0 ;;
esac
case "$origin" in
  */claude-code-history|*/claude-code-history.git|*/claude-code-sync|*/claude-code-sync.git) exit 0 ;;
esac

STATE="$HOME/.local/state/fcvm-claude"
umask 077
mkdir -p "$STATE"
key=$(printf '%s' "$repo" | sha256sum | awk '{print $1}')
tmp=$(mktemp "$STATE/.repo.XXXXXX") || exit 0
printf '%s\n' "$repo" > "$tmp"
mv -f "$tmp" "$STATE/repo-$key"
TRACKER
chmod 755 /usr/local/bin/fcvm-claude-track

# The interactive function remains the upstream t-claude implementation, with one small
# host-local bookkeeping call in front. The boot launcher sources the pinned implementation
# directly and therefore does not refresh these markers merely because the machine booted.
cat > /home/ubuntu/.config/fcvm-t-claude.zsh <<'WRAPPER'
# Use the same verified implementation as the boot service. Otherwise an upstream
# session-key change could make interactive t-claude miss the already-running window.
if [ -r /usr/local/lib/fcvm/t-claude.zsh ]; then
  source /usr/local/lib/fcvm/t-claude.zsh
  functions[_fcvm_t_claude_impl]="$${functions[t-claude]}"
elif (( ! $+functions[_fcvm_t_claude_impl] && $+functions[t-claude] )); then
  functions[_fcvm_t_claude_impl]="$${functions[t-claude]}"
fi
if (( $+functions[_fcvm_t_claude_impl] )); then
  t-claude() {
    /usr/local/bin/fcvm-claude-track "$PWD" >/dev/null 2>&1 || true
    _fcvm_t_claude_impl "$@"
  }
fi
WRAPPER
chown ubuntu:ubuntu /home/ubuntu/.config/fcvm-t-claude.zsh
grep -qxF '[ -f ~/.config/fcvm-t-claude.zsh ] && source ~/.config/fcvm-t-claude.zsh' \
  /home/ubuntu/.zshrc \
  || printf '%s\n' '[ -f ~/.config/fcvm-t-claude.zsh ] && source ~/.config/fcvm-t-claude.zsh' \
    >> /home/ubuntu/.zshrc
chown ubuntu:ubuntu /home/ubuntu/.zshrc

# Launch the host-local active set. It is the union of repositories used through
# interactive t-claude on this host during the last 30 days and local user-owned checkouts
# that have recent host-local HEAD movement or uncommitted work. Shallow home-directory
# globs cover ordinary clones; synchronized Claude history is used only to FIND possible
# nested roots, never as the activity signal.
cat > /usr/local/bin/fcvm-claude-active-repos <<'LAUNCHER'
#!/bin/bash
set -uo pipefail

export HOME=/home/ubuntu
export PATH=/home/ubuntu/.local/bin:/home/ubuntu/.npm-global/bin:/usr/local/bin:/usr/bin:/bin
STATE="$HOME/.local/state/fcvm-claude"
CUTOFF_S=$(( $(date +%s) - 30 * 24 * 60 * 60 ))
CUTOFF_MS=$(( CUTOFF_S * 1000 ))
REPOS=$(mktemp)
trap 'rm -f "$REPOS"' EXIT

add_repo() {
  local candidate="$1" repo origin
  [ -d "$candidate" ] || return 0
  repo=$(git -C "$candidate" rev-parse --show-toplevel 2>/dev/null) || return 0
  case "$repo" in
    /home/ubuntu/*) ;;
    *) return 0 ;;
  esac

  origin=$(git -C "$repo" remote get-url origin 2>/dev/null) || return 0
  case "$origin" in
    https://github.com/ejc3/*|git@github.com:ejc3/*|ssh://git@github.com/ejc3/*) ;;
    # Exact-name collaboration repos; see the note at the marker-writing gate above.
    https://github.com/skrutzler-disney/dolphin-labs|https://github.com/skrutzler-disney/dolphin-labs.git) ;;
    git@github.com:skrutzler-disney/dolphin-labs|git@github.com:skrutzler-disney/dolphin-labs.git) ;;
    ssh://git@github.com/skrutzler-disney/dolphin-labs|ssh://git@github.com/skrutzler-disney/dolphin-labs.git) ;;
    *) return 0 ;;
  esac
  case "$origin" in
    */claude-code-history|*/claude-code-history.git|*/claude-code-sync|*/claude-code-sync.git) return 0 ;;
  esac
  printf '%s\n' "$repo" >> "$REPOS"
}

locally_active() {
  local repo="$1" head_log head_activity dirty
  head_log=$(git -C "$repo" rev-parse --path-format=absolute --git-path logs/HEAD 2>/dev/null)
  head_activity=$(stat -c %Y "$head_log" 2>/dev/null || echo 0)
  dirty=$(git -C "$repo" status --porcelain --untracked-files=normal 2>/dev/null | sed -n '1p')
  [ "$head_activity" -ge "$CUTOFF_S" ] 2>/dev/null || [ -n "$dirty" ]
}

# Exact host-local t-claude use, including nested repositories and worktrees.
for marker in "$STATE"/repo-*; do
  [ -f "$marker" ] || continue
  marker_time=$(stat -c %Y "$marker" 2>/dev/null) || continue
  [ "$marker_time" -ge "$CUTOFF_S" ] || continue
  IFS= read -r repo < "$marker" || continue
  add_repo "$repo"
done

# First-deployment seed and automatic coverage for locally active top-level checkouts.
for candidate in /home/ubuntu/* /home/ubuntu/src/*; do
  [ -e "$candidate/.git" ] || continue
  repo=$(git -C "$candidate" rev-parse --show-toplevel 2>/dev/null) || continue
  locally_active "$repo" && add_repo "$repo"
done

# Claude sync merges history across hosts, so these paths are candidates only. Requiring
# this host's reflog/dirty state prevents activity on ARM from selecting an idle x86 clone
# (and vice versa) while still finding active nested worktrees without a recursive scan.
HISTORY="$HOME/.claude/history.jsonl"
if [ -s "$HISTORY" ]; then
  while IFS= read -r project; do
    case "$project" in
      /home/ubuntu/*) ;;
      *) continue ;;
    esac
    [ -d "$project" ] || continue
    repo=$(git -C "$project" rev-parse --show-toplevel 2>/dev/null) || continue
    locally_active "$repo" && add_repo "$repo"
  done < <(
    jq -r --argjson cutoff "$CUTOFF_MS" \
      'select((.timestamp? | type) == "number" and .timestamp >= $cutoff) | .project? // empty' \
      "$HISTORY" 2>/dev/null | sort -u
  )
fi

sort -u "$REPOS" -o "$REPOS"
mkdir -p "$STATE"
if [ ! -s "$REPOS" ]; then
  echo "fcvm-claude: no host-local repositories are currently active"
  printf 'ready=0 failed=0 at=%s\n' "$(date -Is)" > "$STATE/last-start"
  exit 0
fi

ready_count=0
failed_count=0
while IFS= read -r repo; do
  echo "fcvm-claude: starting remote control in $repo"

  # t-claude intentionally tries to attach after creating/reusing its tmux window. There
  # is no terminal under systemd, so that final attach fails harmlessly after launch.
  /usr/bin/zsh -c '
    source /usr/local/lib/fcvm/t-claude.zsh || exit 1
    cd -- "$1" || exit 1
    t-claude --remote-control
  ' fcvm-claude "$repo" || true

  key="$(printf '%s' "$repo" | cksum | awk '{print $1}')_$(printf '' | cksum | awk '{print $1}')"
  live=0
  for _attempt in $(seq 1 20); do
    window=$(tmux list-windows -a -F '#{window_id} #{@tclaude_key}' 2>/dev/null \
      | awk -v key="$key" '$2 == key {print $1; exit}')
    if [ -n "$window" ]; then
      pane_pid=$(tmux display-message -p -t "$window" '#{pane_pid}' 2>/dev/null)
      child_args=$(ps -o args= --ppid "$pane_pid" 2>/dev/null)
      if printf '%s\n' "$child_args" | grep -Fq -- '--remote-control' \
        && printf '%s\n' "$child_args" | grep -Eq 'claude|nosync-wrap'; then
        live=1
        break
      fi
    fi
    sleep 0.25
  done

  if [ "$live" -eq 1 ]; then
    ready_count=$((ready_count + 1))
    echo "fcvm-claude: ready in $repo"
  else
    failed_count=$((failed_count + 1))
    echo "fcvm-claude: no live --remote-control process in $repo" >&2
  fi
done < "$REPOS"

printf 'ready=%s failed=%s at=%s\n' "$ready_count" "$failed_count" "$(date -Is)" \
  > "$STATE/last-start"
echo "fcvm-claude: ready=$ready_count failed=$failed_count"
LAUNCHER
chmod 755 /usr/local/bin/fcvm-claude-active-repos

cat > /etc/systemd/system/fcvm-claude-rc.service <<'UNIT'
[Unit]
Description=Claude Code remote control for active FCVM repositories
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=ubuntu
Environment=HOME=/home/ubuntu
Environment=TERM=xterm-256color
Environment=PATH=/home/ubuntu/.local/bin:/home/ubuntu/.npm-global/bin:/usr/local/bin:/usr/bin:/bin
WorkingDirectory=/home/ubuntu
ExecCondition=/bin/sh -c 'echo "6ffb51bad10d7023323cbd62ba8199b9cd410c867db439c97dbcdce3b93ea819  /usr/local/lib/fcvm/t-claude.zsh" | sha256sum -c - >/dev/null 2>&1'
ExecCondition=/bin/sh -c 'command -v claude >/dev/null 2>&1 && claude auth status >/dev/null 2>&1'
ExecStart=/usr/local/bin/fcvm-claude-active-repos
TimeoutStartSec=300

# Every repository uses ubuntu's default tmux server. Keep all boot-launched sessions in
# one cgroup; separate per-repo units would let one unit kill the shared server.
KillMode=control-group

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
# Enable even before the personal Claude login exists. ExecCondition skips cleanly while
# auth is absent/expired, and a later boot retries without another provisioning pass.
systemctl enable --now fcvm-claude-rc.service >/dev/null 2>&1 || true
  SETUP
}
