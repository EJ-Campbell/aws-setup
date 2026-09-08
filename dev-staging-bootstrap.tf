# dev-staging-bootstrap.tf
#
# Wire the dev-staging member account for jumpbox Terraform administration and
# cross-account backup copies. GitHub CI has no deployment role or state access.
# The shared administration path is not independent recovery custody.

# Cross-account provider: assume OrganizationAccountAccessRole in dev-staging.
provider "aws" {
  alias  = "staging"
  region = var.aws_region
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

data "aws_caller_identity" "staging" {
  provider = aws.staging
}

# Retain the old OIDC identity with an explicit deny for existing sessions too.
resource "aws_iam_openid_connect_provider" "github_staging" {
  provider        = aws.staging
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_actions_staging" {
  provider = aws.staging
  name     = "github-actions-terraform"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github_staging.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:ejc3/aws:ref:refs/heads/main"
        }
      }
    }]
  })
}

# No staging workload currently needs GitHub deployment rights. Retire the
# shared role rather than allowing CI to administer the recovery account.
resource "aws_iam_role_policy" "github_actions_staging_retired" {
  provider = aws.staging
  name     = "retired-ci-identity"
  role     = aws_iam_role.github_actions_staging.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "RetiredSharedCIIdentity", Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

# --- Cross-account backup copy target in dev-staging ---
resource "aws_backup_vault" "staging" {
  provider = aws.staging
  name     = "ejc3-backup"
  tags     = { Name = "ejc3-backup", Managed = "terraform", Purpose = "cross-account-copy-target" }
}

resource "aws_backup_vault_policy" "staging" {
  provider          = aws.staging
  backup_vault_name = aws_backup_vault.staging.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCopyFromMainAccount"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::928413605543:root" }
      Action    = "backup:CopyIntoBackupVault"
      Resource  = "*"
    }]
  })
}

# Enable cross-account backup at the org level (management account = main).
# Declare EVERY key AWS returns, not just the one we care about — otherwise the
# undeclared keys show as a diff on every plan (perpetual drift).
resource "aws_backup_global_settings" "main" {
  global_settings = {
    "isCrossAccountBackupEnabled" = "true"
    # Preserve the live Organizations synchronization setting read on 2026-09-07;
    # no delegated administrator is registered. Do not flip this global setting
    # as a side effect of deploying the detached-restore key repair.
    "isDelegatedAdministratorEnabled" = "true"
    "isMpaEnabled"                    = "false"
  }
}

output "dev_staging_github_role_arn" {
  description = "Retired GitHub CI role in dev-staging; all AWS actions denied"
  value       = aws_iam_role.github_actions_staging.arn
}
