# Common user_data scripts for development instances
# Shared between firecracker-dev.tf and x86-dev.tf

locals {
  # GitHub CLI authentication from Secrets Manager
  gh_auth_script = <<-SCRIPT
    # ============================================
    # GitHub CLI authentication (from Secrets Manager)
    # ============================================
    sudo -u ubuntu bash << 'GH_AUTH_SETUP'
    set -euxo pipefail

    # Fetch GitHub PAT from Secrets Manager
    GH_TOKEN=$(aws secretsmanager get-secret-value \
      --secret-id github-pat-ejc3 \
      --region us-west-1 \
      --query SecretString \
      --output text)

    # Configure gh CLI
    mkdir -p ~/.config/gh
    cat > ~/.config/gh/hosts.yml << EOF
github.com:
    users:
        ejc3:
            oauth_token: $GH_TOKEN
    oauth_token: $GH_TOKEN
    user: ejc3
EOF

    # Set up git credential helper
    gh auth setup-git
    GH_AUTH_SETUP
  SCRIPT

  # Claude Code Sync installation and initialization
  claude_sync_script = <<-SCRIPT
    # ============================================
    # Claude Code Sync (conversation history backup)
    # ============================================
    sudo -u ubuntu bash << 'CLAUDE_SYNC_SETUP'
    set -euxo pipefail

    # Clone and build from feature branch
    git clone -b feature/non-interactive-init https://github.com/ejc3/claude-code-sync.git ~/src/claude-code-sync
    cd ~/src/claude-code-sync
    ~/.cargo/bin/cargo install --path .

    # Create init config for non-interactive setup
    cat > ~/.claude-code-sync-init.toml << 'INITCFG'
repo_path = "~/claude-history-sync"
remote_url = "https://github.com/ejc3/claude-code-history.git"
clone = true
exclude_attachments = true
enable_lfs = true
INITCFG

    # Initialize (will clone the history repo)
    ~/.cargo/bin/claude-code-sync init || true
    CLAUDE_SYNC_SETUP
  SCRIPT

  # Combined script for GitHub auth + Claude Sync
  gh_and_claude_sync_script = join("\n", [
    local.gh_auth_script,
    local.claude_sync_script
  ])
}
