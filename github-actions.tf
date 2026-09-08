# Terraform plans run on an administration jumpbox: even a read-only plan receives
# credential-bearing state and refreshes secret versions. GitHub validation never
# needs an AWS identity. OIDC is retained for the isolated AMI builder only.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# Retain the old identity with a deny instead of leaving a deceptively read-only
# credential path. Roll out the dedicated AMI role and switch its fcvm consumer
# BEFORE retiring this shared policy. No state, secret, Lambda-env or log reads.
resource "aws_iam_role" "github_actions_terraform" {
  name = "github-actions-terraform"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
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

resource "aws_iam_role_policy" "github_actions_terraform" {
  name = "github-actions-policy"
  role = aws_iam_role.github_actions_terraform.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "RetiredSharedCIIdentity"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}
