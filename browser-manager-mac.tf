# The personal Mac is a browser host, not a replica of the AWS tunnel. Reusing a
# tunnel would load-balance requests between unrelated browser lists and profiles.
locals {
  browser_manager_mac_hostname = "mac-browsers.cc-games.dev"
}

resource "cloudflare_zero_trust_access_application" "browser_manager_mac" {
  account_id       = var.cloudflare_account_id
  name             = "Private Mac browser manager"
  domain           = local.browser_manager_mac_hostname
  type             = "self_hosted"
  session_duration = "12h"
  allowed_idps = concat(
    cloudflare_zero_trust_access_identity_provider.google[*].id,
    [cloudflare_zero_trust_access_identity_provider.onetimepin.id],
  )
  policies = [{
    id         = cloudflare_zero_trust_access_policy.browser_manager_owner.id
    precedence = 1
  }]
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "browser_manager_mac" {
  account_id = var.cloudflare_account_id
  name       = "browser-manager-mac"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "browser_manager_mac" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.browser_manager_mac.id
  config = {
    ingress = [
      {
        hostname = local.browser_manager_mac_hostname
        service  = "http://127.0.0.1:3210"
        origin_request = {
          access = {
            required  = true
            team_name = "ejc3"
            aud_tag   = [cloudflare_zero_trust_access_application.browser_manager_mac.aud]
          }
        }
      },
      { service = "http_status:404" },
    ]
  }
  depends_on = [cloudflare_zero_trust_access_application.browser_manager_mac]
}

resource "cloudflare_dns_record" "browser_manager_mac" {
  zone_id = var.cc_games_zone_id
  name    = local.browser_manager_mac_hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.browser_manager_mac.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "Owner-only native Mac browsers; independent of AWS browser desktops"
  depends_on = [
    cloudflare_zero_trust_access_application.browser_manager_mac,
    cloudflare_zero_trust_tunnel_cloudflared_config.browser_manager_mac,
  ]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "browser_manager_mac" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.browser_manager_mac.id
}

# The connector payload is already in protected Terraform state. It is not a
# Cloudflare API credential and cannot administer the account or any other tunnel.
resource "aws_secretsmanager_secret" "browser_manager_mac_tunnel" {
  name                    = "browser-manager-mac-tunnel-token"
  description             = "Connector token for the personal Mac browser-manager tunnel only"
  recovery_window_in_days = 30
  tags                    = { Managed = "terraform", Name = "browser-manager-mac-tunnel-token" }
}

resource "aws_secretsmanager_secret_version" "browser_manager_mac_tunnel" {
  secret_id     = aws_secretsmanager_secret.browser_manager_mac_tunnel.id
  secret_string = data.cloudflare_zero_trust_tunnel_cloudflared_token.browser_manager_mac.token
}

resource "aws_iam_role" "browser_manager_mac_connector" {
  name = "browser-manager-mac-connector"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Condition = {
        ArnLike = {
          "aws:PrincipalArn" = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess_*",
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_*",
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "browser_manager_mac_connector" {
  name = "read-own-connector-token"
  role = aws_iam_role.browser_manager_mac_connector.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = aws_secretsmanager_secret.browser_manager_mac_tunnel.arn
    }]
  })
}

resource "aws_secretsmanager_secret_policy" "browser_manager_mac_tunnel" {
  secret_arn = aws_secretsmanager_secret.browser_manager_mac_tunnel.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OnlyAdministrationAndTheMacConnectorCanRead"
      Effect    = "Deny"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = aws_secretsmanager_secret.browser_manager_mac_tunnel.arn
      Condition = {
        ArnNotEquals = {
          "aws:PrincipalArn" = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
            aws_iam_role.jumpbox_admin[0].arn,
            aws_iam_role.browser_manager_mac_connector.arn,
          ]
        }
      }
    }]
  })
}

output "browser_manager_mac_env" {
  description = "Public application settings for the native Mac browser-manager (no credentials)"
  value       = <<-ENV
    BM_BASE_URL=https://${local.browser_manager_mac_hostname}
    BM_ACCESS_AUD=${cloudflare_zero_trust_access_application.browser_manager_mac.aud}
    BM_ACCESS_ISSUER=${local.browser_manager_issuer}
    BM_OWNER_EMAIL=${local.browser_manager_owner}
    BM_PORT=3210
  ENV
}

output "browser_manager_mac_tunnel_secret_name" {
  value = aws_secretsmanager_secret.browser_manager_mac_tunnel.name
}

output "browser_manager_mac_connector_role_arn" {
  value = aws_iam_role.browser_manager_mac_connector.arn
}
