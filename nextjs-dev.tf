# nextjs-dev.tf
#
# Small dev box for running a few `next dev` servers at once, each reachable on a
# persistent, Gmail-gated URL under dev.colton-games.com via a Cloudflare Tunnel.
#
# WHY A SEPARATE BOX from fcvm-metal-arm: the metal boxes are for Firecracker/KVM and get
# reaped by the 12h idle auto-stop. These dev servers are meant to stay up so the URLs
# keep working, and they need none of the nested-virt machinery.
#
# NO INBOUND WEB PORTS. Cloudflare Tunnel dials OUT from this box, so nothing listens
# publicly: `next dev` binds 127.0.0.1 and cloudflared forwards to it. The security group
# opens SSH and Eternal Terminal for management and nothing else, so the dev servers
# cannot be reached except through Cloudflare Access (Google login + allowlist).
#
# LEAST PRIVILEGE. This box deliberately does NOT use aws_iam_role.dev_server -- that role
# can send SSM commands to runners, stop/start EC2, read the GitHub PAT, publish to
# CodeArtifact and call Bedrock. A box serving web content to other people should not hold
# any of that. It gets its own role below with exactly two permissions: read its own setup
# script from S3, and read the one Cloudflare tunnel secret.

# RUNS PERSISTENTLY. Deliberately absent from dev-auto-stop-lambda.tf's INSTANCE_IDS
# (which reaps only the two metal boxes after 12h idle) -- these URLs are meant to keep
# working, so the box must not be reaped for being quiet. Cost is kept down by size and
# spot pricing instead: t4g.large spot is roughly $12/month running 24/7.
variable "enable_nextjs_dev" {
  description = "Run the Next.js dev box (stays up; not covered by the idle auto-stop)."
  type        = bool
  default     = true
}

variable "nextjs_instance_type" {
  description = "t4g.large: 2 vCPU / 8GB Graviton, burstable. Enough for a handful of `next dev` processes (~0.5-1GB each)."
  type        = string
  default     = "t4g.large"
}

variable "nextjs_volume_size" {
  description = "Root volume GB. Holds the projects and their node_modules."
  type        = number
  default     = 50
}

# ---------------------------------------------------------------------------------
# Least-privilege instance role: setup script + tunnel secret, nothing else.
# ---------------------------------------------------------------------------------
resource "aws_iam_role" "nextjs_dev" {
  name = "nextjs-dev-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = { Name = "nextjs-dev-role" }
}

resource "aws_iam_instance_profile" "nextjs_dev" {
  name = "nextjs-dev-profile"
  role = aws_iam_role.nextjs_dev.name
}

resource "aws_iam_role_policy" "nextjs_dev" {
  name = "nextjs-dev-policy"
  role = aws_iam_role.nextjs_dev.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadOwnSetupScript"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.dev_scripts.arn}/user-data/nextjs.sh"
      },
      {
        # The tunnel credential only. Scoped to this one secret, not the whole store.
        Sid      = "ReadCloudflareTunnelCredential"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:cloudflare-tunnel-*"
      }
    ]
  })
}

resource "aws_security_group" "nextjs_dev" {
  name        = "nextjs-dev"
  description = "Next.js dev box: management access only, web traffic arrives via Cloudflare Tunnel"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH"
  }

  ingress {
    from_port   = 2022
    to_port     = 2022
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Eternal Terminal"
  }

  # Deliberately NO 3000-3999 / 80 / 443 ingress: cloudflared connects outbound and
  # proxies to 127.0.0.1, so opening web ports would only create a way to bypass Access.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound (incl. the tunnel to Cloudflare)"
  }

  tags = { Name = "nextjs-dev" }
}

resource "aws_instance" "nextjs_dev" {
  count = var.enable_nextjs_dev ? 1 : 0

  ami                    = var.firecracker_ami # Ubuntu 24.04 arm64, same as the ARM dev box
  instance_type          = var.nextjs_instance_type
  key_name               = var.firecracker_key_name
  subnet_id              = aws_subnet.subnet_a.id
  vpc_security_group_ids = [aws_security_group.nextjs_dev.id]
  iam_instance_profile   = aws_iam_instance_profile.nextjs_dev.name

  instance_market_options {
    market_type = "spot"
    spot_options {
      # Same shape as the other dev boxes: stop (not terminate) on interruption so the
      # persistent root volume -- and every project on it -- survives.
      spot_instance_type             = "persistent"
      instance_interruption_behavior = "stop"
    }
  }

  root_block_device {
    volume_size           = var.nextjs_volume_size
    volume_type           = "gp3"
    delete_on_termination = false
    encrypted             = true
  }

  user_data = base64encode(<<-BOOTSTRAP
    #!/bin/bash
    # Thin bootstrap: the real script is published to S3 (local.nextjs_user_data) so it
    # can be updated without recreating the instance.
    #
    # The stock Ubuntu AMI has NO aws CLI, so install it first -- without this the very
    # first line fails with "aws: command not found" and cloud-init aborts the whole
    # user-data run (observed on first boot).
    # AWS CLI v2 -- there is NO awscli apt package on Ubuntu 24.04 (the stock AMI has
    # none), so the official installer is the only reliable route. Without this the very
    # first S3 fetch dies with "aws: command not found" and cloud-init aborts the whole
    # user-data run.
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || true
    apt-get install -y unzip curl || true
    if ! command -v aws >/dev/null 2>&1; then
      curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o /tmp/awscliv2.zip
      cd /tmp && unzip -qo awscliv2.zip && ./aws/install && rm -rf /tmp/aws /tmp/awscliv2.zip
    fi
    aws s3 cp s3://ejc3-dev-scripts/user-data/nextjs.sh /tmp/user_data.sh --region us-west-1
    chmod +x /tmp/user_data.sh && /tmp/user_data.sh
  BOOTSTRAP
  )

  lifecycle {
    ignore_changes = [
      ami,
      user_data,
      user_data_base64,
    ]
  }

  tags = {
    Name    = "nextjs-dev"
    Purpose = "Next.js dev servers behind a Cloudflare Tunnel"
  }
}

resource "aws_eip" "nextjs_dev" {
  count  = var.enable_nextjs_dev ? 1 : 0
  domain = "vpc"
  tags   = { Name = "nextjs-dev" }
}

resource "aws_eip_association" "nextjs_dev" {
  count         = var.enable_nextjs_dev ? 1 : 0
  instance_id   = aws_instance.nextjs_dev[0].id
  allocation_id = aws_eip.nextjs_dev[0].id
}

output "nextjs_dev_public_ip" {
  description = "Public IP of the Next.js dev box (management only; web traffic goes via the tunnel)"
  value       = var.enable_nextjs_dev ? aws_eip.nextjs_dev[0].public_ip : null
}

output "nextjs_dev_ssh_command" {
  description = "SSH into the Next.js dev box"
  value       = var.enable_nextjs_dev ? "ssh -i ~/.ssh/fcvm-ec2 ubuntu@${aws_eip.nextjs_dev[0].public_ip}" : null
}
