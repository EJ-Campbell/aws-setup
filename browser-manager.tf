# A separate single-owner application; do not attach the cc-games family/service policies
# or the Dolphin GitHub organization policy. An exact hostname wins over *.cc-games.dev.
variable "browser_manager_hostname" {
  description = "Dedicated browser-manager hostname within the existing cc-games.dev zone"
  type        = string
  default     = "browsers.cc-games.dev"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.cc-games\\.dev$", var.browser_manager_hostname))
    error_message = "Use one concrete subdomain of cc-games.dev (no wildcard or path)."
  }
}

locals {
  browser_manager_owner  = "ej.campbell@gmail.com"
  browser_manager_issuer = "https://ejc3.cloudflareaccess.com"
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
  domain           = var.browser_manager_hostname
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
        hostname = var.browser_manager_hostname
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
  name    = var.browser_manager_hostname
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

# Transfer this output from the apply host to a 0600 file. Only cloudflared receives its
# file path; the application, browser processes, and their environment never receive it.
# The token is sensitive Terraform state, not a reason to grant the browser host AWS IAM.
output "browser_manager_tunnel_token" {
  description = "Dedicated connector credential; save to a private token file, never argv"
  value       = data.cloudflare_zero_trust_tunnel_cloudflared_token.browser_manager.token
  sensitive   = true
}

output "browser_manager_env" {
  description = "Public application settings for the installer's private EnvironmentFile"
  value       = <<-ENV
    BM_BASE_URL=https://${var.browser_manager_hostname}
    BM_ACCESS_AUD=${cloudflare_zero_trust_access_application.browser_manager.aud}
    BM_ACCESS_ISSUER=${local.browser_manager_issuer}
    BM_OWNER_EMAIL=${local.browser_manager_owner}
    BM_PORT=3210
  ENV
}
