terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Future volumes and snapshot copies only; no existing data is re-encrypted and
# no KMS key is created or changed. Existing volume snapshots inherit that volume.
resource "aws_ebs_encryption_by_default" "security" {
  enabled = true
}

# Also blocks public access to already-public owned snapshots. Private sharing
# (including cross-account backups) is unaffected. EBS-backed AMIs are separate.
resource "aws_ebs_snapshot_block_public_access" "security" {
  state = "block-all-sharing"
}

# Future launch default, not hard enforcement: explicit launch options can
# override it. Existing hosts are unchanged. AWS provider 5.100 also writes
# no-preference for the other regional metadata options; preflight verified those
# are unset in all 34 regions/accounts. Review any non-default before applying.
resource "aws_ec2_instance_metadata_defaults" "security" {
  http_tokens = "required"
}
