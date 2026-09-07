# Bootstrap resources already created while waiting for permanent-IP quota.
# Private certificate payloads live only in Secrets Manager, not Terraform state.

resource "aws_secretsmanager_secret" "prompt_vpn" {
  for_each                = toset(["authority", "server", "iphone"])
  name                    = "prompt-vpn-${each.key}"
  description             = "Prompt IKEv2 ${each.key}: payload bootstrapped outside Terraform; never stored in state"
  recovery_window_in_days = 30
  tags                    = { Name = "prompt-vpn-${each.key}", Managed = "terraform" }
  lifecycle { prevent_destroy = true }
}

resource "aws_secretsmanager_secret_policy" "prompt_vpn" {
  for_each   = aws_secretsmanager_secret.prompt_vpn
  secret_arn = each.value.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "KeepVPNPrivateKeysOffDevelopmentAndCIHosts"
      Effect    = "Deny"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = each.value.arn
      Condition = {
        ArnNotEquals = {
          "aws:PrincipalArn" = concat([
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
            aws_iam_role.jumpbox_admin[0].arn,
          ], each.key == "server" ? [aws_iam_role.prompt_vpn.arn] : [])
        }
      }
    }]
  })
}

resource "aws_iam_role" "prompt_vpn" {
  name = "prompt-vpn"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Managed = "terraform", Purpose = "prompt-vpn" }
}

resource "aws_servicequotas_service_quota" "prompt_vpn_eips" {
  service_code = "ec2"
  quota_code   = "L-0263D0A3"
  value        = 6
}

