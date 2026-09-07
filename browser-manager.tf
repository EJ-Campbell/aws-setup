# A separate single-owner application; do not attach the cc-games family/service policies
# or the Dolphin GitHub organization policy. An exact hostname wins over *.cc-games.dev.
locals {
  browser_manager_hostname = "browsers.cc-games.dev"
  browser_manager_owner    = "ej.campbell@gmail.com"
  browser_manager_issuer   = "https://ejc3.cloudflareaccess.com"
}

resource "cloudflare_zero_trust_access_policy" "browser_manager_owner" {
  account_id       = var.cloudflare_account_id
  name             = "browser-manager owner only"
  decision         = "allow"
  session_duration = "12h"
  include          = [{ email = { email = local.browser_manager_owner } }]
}

resource "cloudflare_zero_trust_access_application" "browser_manager" {
  account_id       = var.cloudflare_account_id
  name             = "Private browser manager"
  domain           = local.browser_manager_hostname
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

resource "cloudflare_zero_trust_tunnel_cloudflared" "browser_manager" {
  account_id = var.cloudflare_account_id
  name       = "browser-manager"
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "browser_manager" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.browser_manager.id
  config = {
    ingress = [
      {
        hostname = local.browser_manager_hostname
        service  = "http://127.0.0.1:3210"
        origin_request = {
          access = {
            required  = true
            team_name = "ejc3"
            aud_tag   = [cloudflare_zero_trust_access_application.browser_manager.aud]
          }
        }
      },
      { service = "http_status:404" },
    ]
  }

  # Routing is not installed until the owner policy has been attached to Access.
  depends_on = [cloudflare_zero_trust_access_application.browser_manager]
}

resource "cloudflare_dns_record" "browser_manager" {
  zone_id = var.cc_games_zone_id
  name    = local.browser_manager_hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.browser_manager.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
  comment = "Owner-only browser-manager tunnel"

  depends_on = [
    cloudflare_zero_trust_access_application.browser_manager,
    cloudflare_zero_trust_tunnel_cloudflared_config.browser_manager,
  ]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "browser_manager" {
  account_id = var.cloudflare_account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.browser_manager.id
}

# Publish the existing connector token for the ARM/x86 dev hosts. The value is already
# sensitive Terraform state; Secrets Manager provides retrieval with their instance role.
resource "aws_secretsmanager_secret" "browser_manager_tunnel_token" {
  name                    = "browser-manager-tunnel-token"
  description             = "Cloudflare connector token for the private browser-manager tunnel"
  recovery_window_in_days = 7

  tags = { Name = "browser-manager-tunnel-token", Managed = "terraform" }
}

resource "aws_secretsmanager_secret_version" "browser_manager_tunnel_token" {
  secret_id     = aws_secretsmanager_secret.browser_manager_tunnel_token.id
  secret_string = data.cloudflare_zero_trust_tunnel_cloudflared_token.browser_manager.token
}

resource "aws_iam_role_policy" "dev_server_browser_manager" {
  name = "browser-manager-tunnel-read"
  role = aws_iam_role.dev_server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = aws_secretsmanager_secret.browser_manager_tunnel_token.arn
    }]
  })
}

output "browser_manager_tunnel_secret_name" {
  description = "Secrets Manager name for the connector token, readable by ARM/x86 dev hosts"
  value       = aws_secretsmanager_secret.browser_manager_tunnel_token.name
}

# Retained for apply-host compatibility. Dev hosts fetch the Secrets Manager value;
# only cloudflared receives the local 0600 token file path.
output "browser_manager_tunnel_token" {
  description = "Dedicated connector credential; save to a private token file, never argv"
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.browser_manager.token
  sensitive   = true
}

output "browser_manager_env" {
  description = "Public application settings for the installer's private EnvironmentFile"
  value       = <<-ENV
    BM_BASE_URL=https://${local.browser_manager_hostname}
    BM_ACCESS_AUD=${cloudflare_zero_trust_access_application.browser_manager.aud}
    BM_ACCESS_ISSUER=${local.browser_manager_issuer}
    BM_OWNER_EMAIL=${local.browser_manager_owner}
    BM_PORT=3210
  ENV
}
