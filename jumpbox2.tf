# jumpbox2.tf
#
# A second, independent admin box: same reach and privileges as jumpbox, but fully
# terraform-managed from creation -- unlike jumpbox itself, which predates this repo's
# user_data conventions (aws_instance.jumpbox sets none at all; see jumpbox.tf) and would
# need to be rebuilt by hand if it were ever lost. If jumpbox-2 is ever lost instead, this
# file plus a `terraform apply` reproduces it completely.
#
# SIZED FOR THE SMALLEST INSTANCE THAT STAYS USABLE, not the smallest that boots. t4g.nano
# (0.5GB RAM) was considered and rejected: terraform alone can use several hundred MB
# planning against this repo's ~155 resources, and that has to coexist with an AWS CLI
# call, a git operation, and potentially a Claude/Codex agent running at the same time.
# t4g.micro (2 vCPU / 1GB) is the practical floor; a swapfile in the boot script covers the
# rest of the margin, the same pattern used on nextjs-dev.
#
# DELIBERATELY ITS OWN SECURITY GROUP, not jumpbox's. jumpbox's SG is shared with
# fcvm-metal-arm (aws_security_group.firecracker_dev, see jumpbox.tf) -- any rule change
# for one silently changes exposure for the other. Two admin boxes sharing one SG would be
# the same coupling risk twice over; giving jumpbox-2 its own SG costs nothing and avoids it.
#
# REUSES jumpbox's IAM role and instance profile as-is (aws_iam_instance_profile.jumpbox_admin
# from jumpbox.tf) -- an instance profile is not exclusive to one instance, and "the same
# admin capabilities" means the same role, not a parallel copy of AdministratorAccess to
# keep in sync by hand.

variable "enable_jumpbox_2" {
  description = "Enable the second, fully terraform-managed admin box"
  type        = bool
  default     = true
}

variable "jumpbox_2_instance_type" {
  description = "t4g.micro: 2 vCPU / 1GB, smallest Graviton size that stays usable for terraform + AWS CLI + an agent running concurrently. See the file header for why nano was rejected."
  type        = string
  default     = "t4g.micro"
}

resource "aws_security_group" "jumpbox_2" {
  count       = var.enable_jumpbox_2 ? 1 : 0
  name        = "jumpbox-2"
  description = "jumpbox-2: SSH and Eternal Terminal only, deliberately not shared with any other instance"
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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = { Name = "jumpbox-2" }
}

# Single root volume, not jumpbox's root+home split -- jumpbox-2 has no boot-speed reason
# to separate them, and one persistent volume is simpler to reason about and back up.
# delete_on_termination = false + prevent_destroy: an instance replacement (AMI bump,
# instance_type change) must not silently discard everything installed on it.
resource "aws_instance" "jumpbox_2" {
  count                  = var.enable_jumpbox_2 ? 1 : 0
  ami                    = var.firecracker_ami # same Ubuntu 24.04 ARM64 image as the rest of the fleet
  instance_type          = var.jumpbox_2_instance_type
  key_name               = var.firecracker_key_name
  subnet_id              = aws_subnet.subnet_a.id
  vpc_security_group_ids = [aws_security_group.jumpbox_2[0].id]
  iam_instance_profile   = aws_iam_instance_profile.jumpbox_admin[0].name

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = false
    encrypted             = true
  }

  # Thin bootstrap: the real script is published to S3 (aws_s3_object.jumpbox_2_user_data,
  # local.jumpbox_2_user_data) so it can be updated and re-run without recreating the
  # instance -- the same pattern every other box in this repo uses. AWS CLI has to be
  # installed here, inline, before the very first S3 fetch can even happen: the stock
  # Ubuntu AMI ships none, and without it cloud-init aborts the whole user-data run before
  # ever reaching the real script.
  user_data = base64encode(<<-BOOTSTRAP
    #!/bin/bash
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || true
    apt-get install -y unzip curl || true
    if ! command -v aws >/dev/null 2>&1; then
      curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip" -o /tmp/awscliv2.zip
      cd /tmp && unzip -qo awscliv2.zip && ./aws/install && rm -rf /tmp/aws /tmp/awscliv2.zip
    fi
    aws s3 cp s3://ejc3-dev-scripts/user-data/jumpbox2.sh /tmp/user_data.sh --region us-west-1
    chmod +x /tmp/user_data.sh && /tmp/user_data.sh
  BOOTSTRAP
  )

  # The bootstrap above references the S3 object by a literal path string, not by
  # attribute (${aws_s3_object.jumpbox_2_user_data[0].id}), so terraform's dependency
  # graph has no edge between them from that reference alone -- caught by codex review: on
  # a from-scratch apply, the object upload and the instance boot could run concurrently,
  # and if cloud-init's `aws s3 cp` reaches the object before the upload finishes, the
  # fetch fails and the rest of the bootstrap never runs. depends_on makes the ordering
  # explicit instead of relying on apply-order luck.
  depends_on = [aws_s3_object.jumpbox_2_user_data]

  lifecycle {
    prevent_destroy = true
    ignore_changes = [
      ami,       # pin the boot image; bump deliberately, not on every provider AMI refresh
      user_data, # the S3 object is the thing that changes; re-fetch and re-run by hand
      user_data_base64,
    ]
  }

  tags = { Name = "jumpbox-2", Purpose = "Fully terraform-managed backup admin box" }
}

resource "aws_eip" "jumpbox_2" {
  count  = var.enable_jumpbox_2 ? 1 : 0
  domain = "vpc"
  tags   = { Name = "jumpbox-2-eip" }
}

resource "aws_eip_association" "jumpbox_2" {
  count         = var.enable_jumpbox_2 ? 1 : 0
  instance_id   = aws_instance.jumpbox_2[0].id
  allocation_id = aws_eip.jumpbox_2[0].id
}

output "jumpbox_2_public_ip" {
  description = "Public IP of jumpbox-2 (Elastic IP)"
  value       = var.enable_jumpbox_2 ? aws_eip.jumpbox_2[0].public_ip : null
}

output "jumpbox_2_ssh_command" {
  description = "SSH to jumpbox-2"
  value       = var.enable_jumpbox_2 ? "ssh -i ~/.ssh/${var.firecracker_key_name} ubuntu@${aws_eip.jumpbox_2[0].public_ip}" : null
}
