# Preview hosting for the dolphin-labs project: *.dolphin-labs.dev, behind Cloudflare
# Access, gated by GitHub instead of Google.
#
# Same shape as cc-games.dev (see cloudflare.tf) -- a tunnel the dev box dials out to, one
# wildcard DNS record so new hostnames need no DNS change, and an Access application in
# front of everything. Two deliberate differences:
#
#   1. GITHUB, NOT GOOGLE. The people on this project are identified by GitHub account,
#      not Gmail. cc-games.dev keeps Google untouched; the two zones do not share an
#      identity provider, so changing one cannot lock anyone out of the other.
#   2. It is INERT until the domain exists. Everything below is gated on
#      enable_dolphin_zone, default false, because `dolphin-labs.dev` is not registered
#      yet and a zone id cannot be invented. Flipping the flag is the whole activation.
#
# ACTIVATION, in order -- neither step can be done from terraform:
#
#   1. Register dolphin-labs.dev through Cloudflare Registrar. Registering there creates
#      the zone automatically, which is why this takes a zone id rather than declaring a
#      cloudflare_zone: the zone already exists by the time terraform sees it.
#   2. Create a GitHub OAuth app (Settings -> Developer settings -> OAuth Apps) with the
#      callback URL printed by the cf_access_callback local in cloudflare.tf, and store
#      its client id/secret:
#
#        aws secretsmanager create-secret --name cloudflare-github-idp --region us-west-1 \
#          --secret-string '{"client_id":"...","client_secret":"..."}'
#
#   3. terraform apply -var enable_dolphin_zone=true -var dolphin_zone_id=<id>

variable "enable_dolphin_zone" {
  description = "Stand up *.dolphin-labs.dev. Needs the domain registered, a zone id, and the cloudflare-github-idp secret."
  type        = bool
  default     = false
}

variable "dolphin_zone_id" {
  description = "Cloudflare zone id for dolphin-labs.dev (created automatically when registered through Cloudflare Registrar)."
  type        = string
  default     = ""
}

variable "dolphin_allowed_github_org" {
  description = "GitHub org whose members may reach every *.dolphin-labs.dev host. Membership IS the access list -- add someone to the org, they get in."
  type        = string
  default     = "dolphin-labs-hq"
}

locals {
  # Fail loudly at plan time rather than producing a half-built zone. Every resource below
  # is counted on this, so a missing zone id cannot silently create a tunnel with nothing
  # pointing at it.
  dolphin_enabled = var.enable_dolphin_zone && var.dolphin_zone_id != ""
}

# ---------------------------------------------------------------------------------
# GitHub identity provider. The OAuth app lives in GitHub and CANNOT be created from
# terraform -- it needs an interactive browser session as the account that owns it, the
# same constraint the Google provider has in cloudflare.tf.
# ---------------------------------------------------------------------------------
data "aws_secretsmanager_secret_version" "github_idp" {
  count     = local.dolphin_enabled ? 1 : 0
  secret_id = "cloudflare-github-idp"
}

resource "cloudflare_zero_trust_access_identity_provider" "github" {
  count      = local.dolphin_enabled ? 1 : 0
  account_id = var.cloudflare_account_id
  name       = "GitHub"
  type       = "github"
  config = {
    client_id     = jsondecode(data.aws_secretsmanager_secret_version.github_idp[0].secret_string)["client_id"]
    client_secret = jsondecode(data.aws_secretsmanager_secret_version.github_idp[0].secret_string)["client_secret"]
  }
}

# ---------------------------------------------------------------------------------
# The tunnel. cloudflared on the dev box dials OUT to this, so the box needs no inbound
# web ports -- identical to the cc-games tunnel, and deliberately a SEPARATE tunnel:
# sharing one would mean a config mistake on either project could take down both.
# ---------------------------------------------------------------------------------
resource "cloudflare_zero_trust_tunnel_cloudflared" "dolphin_labs" {
  count      = local.dolphin_enabled ? 1 : 0
  account_id = var.cloudflare_account_id
  name       = "dolphin-labs-dev"
  config_src = "local" # ingress rules are managed on the box, same as cc-games

  # Generated once and held in Secrets Manager. Terraform must not rotate it on every
  # plan; that would break the running tunnel.
  tunnel_secret = jsondecode(data.aws_secretsmanager_secret_version.dolphin_tunnel_creds[0].secret_string)["TunnelSecret"]

  lifecycle {
    ignore_changes = [tunnel_secret]
  }
}

data "aws_secretsmanager_secret_version" "dolphin_tunnel_creds" {
  count     = local.dolphin_enabled ? 1 : 0
  secret_id = "cloudflare-dolphin-tunnel-credentials"
}

# ---------------------------------------------------------------------------------
# Wildcard DNS. One record covers every preview: a project invents a hostname and it
# resolves immediately, with no DNS change per project.
# ---------------------------------------------------------------------------------
resource "cloudflare_dns_record" "dolphin_wildcard" {
  count   = local.dolphin_enabled ? 1 : 0
  zone_id = var.dolphin_zone_id
  name    = "*"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.dolphin_labs[0].id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

# ---------------------------------------------------------------------------------
# Access. Who may reach a preview at all.
# ---------------------------------------------------------------------------------
resource "cloudflare_zero_trust_access_policy" "dolphin_allowed" {
  count            = local.dolphin_enabled ? 1 : 0
  account_id       = var.cloudflare_account_id
  name             = "dolphin-labs allowed people"
  decision         = "allow"
  session_duration = "24h"

  # Matched on ORG MEMBERSHIP, which is what this selector actually does. An earlier version
  # passed each person's LOGIN as the org name -- that applies cleanly and then denies
  # everyone, because there is no org called "ejc3". Cloudflare's github_organization rule
  # matches an organization (optionally a team); individuals are matched by email, and a
  # GitHub email can be private or change.
  #
  # Org membership is also the better list: both people here are already in dolphin-labs-hq
  # because that is where the repo lives, so access follows the repo instead of drifting
  # from it.
  include = [
    {
      github_organization = {
        identity_provider_id = cloudflare_zero_trust_access_identity_provider.github[0].id
        name                 = var.dolphin_allowed_github_org
      }
    }
  ]
}

resource "cloudflare_zero_trust_access_application" "dolphin_labs" {
  count            = local.dolphin_enabled ? 1 : 0
  account_id       = var.cloudflare_account_id
  name             = "dolphin-labs previews"
  domain           = "*.dolphin-labs.dev"
  type             = "self_hosted"
  session_duration = "24h"

  # The policy attachment MUST be declared here. Leaving it out makes terraform drop the
  # link on the next apply, which would leave every *.dolphin-labs.dev hostname reachable
  # with no login at all. That exact mistake is documented on the cc-games application in
  # cloudflare.tf; it is repeated here because the failure is silent and total.
  policies = [
    {
      id         = cloudflare_zero_trust_access_policy.dolphin_allowed[0].id
      precedence = 1
    },
  ]
}

output "dolphin_labs_status" {
  description = "Whether *.dolphin-labs.dev is stood up, and what is missing if not"
  value = local.dolphin_enabled ? "active: https://<name>.dolphin-labs.dev (GitHub login required)" : join(" ", compact([
    "inactive --",
    var.enable_dolphin_zone ? "" : "set enable_dolphin_zone=true;",
    var.dolphin_zone_id == "" ? "register dolphin-labs.dev and set dolphin_zone_id;" : "",
    "needs secrets cloudflare-github-idp and cloudflare-dolphin-tunnel-credentials",
  ]))
}
