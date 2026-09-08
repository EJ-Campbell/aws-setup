# Global per-account guardrails, not regional bucket/object/policy changes.
# Existing buckets already enforce all four flags; see README preflight evidence.
resource "aws_s3_account_public_access_block" "main" {
  account_id              = data.aws_caller_identity.current.account_id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_account_public_access_block" "staging" {
  provider                = aws.staging
  account_id              = data.aws_caller_identity.staging.account_id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}
