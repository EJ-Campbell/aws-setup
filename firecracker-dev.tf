# Firecracker Development Instance
# Single c5.large instance for Firecracker/KVM testing
# Cost: ~$0.085/hour = ~$61/month (stop when not in use!)

variable "enable_firecracker_instance" {
  description = "Enable standalone Firecracker development instance"
  type        = bool
  default     = false
}

# Security group for Firecracker dev instance
resource "aws_security_group" "firecracker_dev" {
  count       = var.enable_firecracker_instance ? 1 : 0
  name_prefix = "${var.project_name}-firecracker-dev-sg-"
  description = "Security group for Firecracker development instance"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Eternal Terminal (persistent SSH sessions)
  ingress {
    from_port   = 2022
    to_port     = 2022
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Eternal Terminal"
  }

  # All outbound traffic for package installs, etc.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-firecracker-dev-sg"
  }
}

# Firecracker dev instance
resource "aws_instance" "firecracker_dev" {
  count         = var.enable_firecracker_instance ? 1 : 0
  ami           = local.ubuntu2404_ami_id
  instance_type = "c5.large" # Nitro instance with KVM support

  # Network configuration
  subnet_id                   = aws_subnet.subnet_a.id
  vpc_security_group_ids      = [aws_security_group.firecracker_dev[0].id]
  associate_public_ip_address = true

  # IAM role for SSM access
  iam_instance_profile = aws_iam_instance_profile.dev[0].name

  # Root volume
  root_block_device {
    volume_size           = 150 # Large enough for Firecracker + VMs
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    iops                  = 3000
    throughput            = 125
  }

  # User data - install Firecracker and dependencies
  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euxo pipefail

    # Update system
    apt-get update
    apt-get upgrade -y

    # Install dependencies
    apt-get install -y \
      curl \
      wget \
      podman \
      uidmap \
      slirp4netns \
      fuse-overlayfs \
      containernetworking-plugins \
      nftables \
      iproute2 \
      dnsmasq \
      jq \
      build-essential \
      software-properties-common

    # Install Eternal Terminal for persistent SSH sessions
    add-apt-repository -y ppa:jgmath2000/et
    apt-get update
    apt-get install -y et
    systemctl enable --now et

    # Install Firecracker
    FIRECRACKER_VERSION="v1.10.0"
    wget -O /tmp/firecracker.tgz \
      "https://github.com/firecracker-microvm/firecracker/releases/download/$${FIRECRACKER_VERSION}/firecracker-$${FIRECRACKER_VERSION}-x86_64.tgz"
    tar -xzf /tmp/firecracker.tgz -C /tmp/
    mv /tmp/release-$${FIRECRACKER_VERSION}-x86_64/firecracker-$${FIRECRACKER_VERSION}-x86_64 /usr/local/bin/firecracker
    chmod +x /usr/local/bin/firecracker
    rm -rf /tmp/firecracker.tgz /tmp/release-$${FIRECRACKER_VERSION}-x86_64

    # Verify Firecracker installation
    firecracker --version

    # Configure Podman for rootless mode (ubuntu user)
    echo "ubuntu:100000:65536" >> /etc/subuid
    echo "ubuntu:100000:65536" >> /etc/subgid

    # Enable unprivileged user namespaces
    sysctl -w kernel.unprivileged_userns_clone=1
    echo "kernel.unprivileged_userns_clone=1" >> /etc/sysctl.conf

    # Create working directory for fcvm
    mkdir -p /opt/fcvm
    chown ubuntu:ubuntu /opt/fcvm

    # ============================================
    # Modern shell setup for ubuntu user
    # ============================================

    # Install zsh
    apt-get install -y zsh

    # Install shell tools and apply dotfiles via chezmoi as ubuntu user
    sudo -u ubuntu bash << 'SHELL_SETUP'
    set -e

    # Install starship prompt
    mkdir -p ~/.local/bin
    curl -sS https://starship.rs/install.sh | sh -s -- -y -b ~/.local/bin

    # Install fzf
    git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
    ~/.fzf/install --all --no-bash --no-fish --key-bindings --completion --update-rc

    # Install atuin (magical shell history)
    curl --proto '=https' --tlsv1.2 -sSf https://setup.atuin.sh | bash

    # Install zsh plugins
    mkdir -p ~/.zsh
    git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
    git clone https://github.com/zsh-users/zsh-syntax-highlighting ~/.zsh/zsh-syntax-highlighting

    # Install chezmoi and apply dotfiles from GitHub
    sh -c "$$(curl -fsLS get.chezmoi.io)" -- init --apply ejc3/dotfiles --branch main

    # Import bash history to atuin
    ~/.atuin/bin/atuin import auto || true
SHELL_SETUP

    # Change default shell to zsh
    chsh -s /usr/bin/zsh ubuntu

    # Install Node.js and Claude Code
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
    npm install -g @anthropic-ai/claude-code

    # Setup completion
    touch /tmp/firecracker-setup-complete
    echo "Firecracker dev instance ready!" | tee /tmp/firecracker-status
  EOF
  )

  # IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  # Monitoring
  monitoring = true

  tags = {
    Name        = "${var.project_name}-firecracker-dev"
    Purpose     = "firecracker-development"
    Environment = "dev"
    ManagedBy   = "terraform"
  }
}

# Output the instance ID and connection command
output "firecracker_dev_instance_id" {
  description = "Instance ID of Firecracker dev instance"
  value       = var.enable_firecracker_instance ? aws_instance.firecracker_dev[0].id : null
}

output "firecracker_dev_public_ip" {
  description = "Public IP of Firecracker dev instance"
  value       = var.enable_firecracker_instance ? aws_instance.firecracker_dev[0].public_ip : null
}

output "firecracker_dev_ssm_command" {
  description = "Command to connect to Firecracker dev instance via SSM"
  value       = var.enable_firecracker_instance ? "aws ssm start-session --target ${aws_instance.firecracker_dev[0].id} --region ${var.aws_region}" : null
}
