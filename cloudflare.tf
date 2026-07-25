# cloudflare.tf
#
# The Cloudflare half of the Next.js dev setup: the tunnel that reaches the box, the
# wildcard DNS that points at it, and the Access application that puts a Google login in
# front of every hostname.
#
# These were originally created by hand through the API while bootstrapping; they are
# imported here so the whole thing is reproducible from `terraform apply` rather than
# living only in someone's shell history.
#
# CREDENTIALS: the API token lives in Secrets Manager (cloudflare-tunnel-token), scoped to
# this account with only what the resources below need -- Tunnel Write, Access Apps and
# Policies Write, Access Organizations/Identity Providers Write, DNS Write, Zone Read/Write.
# It is never written to disk or into the repo.
#
# The IdP permission is the non-obvious one: without it `terraform import` on the identity
# provider fails with a bare "auth.forbidden" that reads like a malformed import ID rather
# than a missing scope. If you re-mint this token, include it or the login method below
# becomes unmanageable.

data "aws_secretsmanager_secret_version" "cloudflare_token" {
  secret_id = "cloudflare-tunnel-token"
}

data "aws_secretsmanager_secret_version" "cloudflare_tunnel_creds" {
  secret_id = "cloudflare-tunnel-credentials"
}

provider "cloudflare" {
  api_token = data.aws_secretsmanager_secret_version.cloudflare_token.secret_string
}

variable "cloudflare_account_id" {
  description = "Cloudflare account (Ej.campbell@gmail.com's Account)"
  type        = string
  default     = "12ea67fb7ced068de03f35c22688e436"
}

variable "cc_games_zone_id" {
  description = "Zone id for cc-games.dev (registered through Cloudflare Registrar, so the zone was created automatically)"
  type        = string
  default     = "5a7a8d961d72744d2e7fd155dcdeb42b"
}

variable "dev_allowed_emails" {
  description = "Google accounts allowed through Cloudflare Access to every *.cc-games.dev host. Adding someone is a one-line change here."
  type        = list(string)
  default = [
    "thecoltonc2014@gmail.com",
    "theconnorc2014@gmail.com",
    "ej.campbell@gmail.com",
  ]
}

# ---------------------------------------------------------------------------------
# The tunnel. cloudflared on the dev box dials OUT to this, which is why the box needs
# no inbound web ports at all.
# ---------------------------------------------------------------------------------
resource "cloudflare_zero_trust_tunnel_cloudflared" "cc_games_dev" {
  account_id = var.cloudflare_account_id
  name       = "cc-games-dev"
  config_src = "local" # ingress rules are managed on the box by ndev-register

  # The secret is held in Secrets Manager and consumed by the box; terraform must not
  # rotate it on every plan, which would break the running tunnel.
  tunnel_secret = jsondecode(data.aws_secretsmanager_secret_version.cloudflare_tunnel_creds.secret_string)["TunnelSecret"]

  lifecycle {
    ignore_changes = [tunnel_secret]
  }
}

# ---------------------------------------------------------------------------------
# Wildcard DNS. One record covers every project: ndev invents hostnames freely
# (colton.cc-games.dev, tetris.cc-games.dev) with no DNS change per project.
# ---------------------------------------------------------------------------------
resource "cloudflare_dns_record" "cc_games_wildcard" {
  zone_id = var.cc_games_zone_id
  name    = "*"
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.cc_games_dev.id}.cfargotunnel.com"
  proxied = true # must be proxied -- cfargotunnel only resolves inside Cloudflare
  ttl     = 1    # 1 = automatic, required when proxied
  comment = "cc-games-dev tunnel"
}

# ---------------------------------------------------------------------------------
# Access: every *.cc-games.dev hostname requires a Google login from the allowlist.
# This is the only thing standing between the dev servers and the open internet, since
# the tunnel terminates inside Cloudflare.
# ---------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------
# Login method. Without this the only identity provider on a fresh Zero Trust account is
# type "cloudflare", which means "must be a member of the Cloudflare account" -- everyone
# else got "Cloudflare sign-in is restricted to members of the account" and had no way in.
# One-time PIN emails a code to whatever address is entered, and the policy above decides
# whether that address is allowed, so plain Gmail works with no Google OAuth app to set up.
# ---------------------------------------------------------------------------------
resource "cloudflare_zero_trust_access_identity_provider" "onetimepin" {
  account_id = var.cloudflare_account_id
  name       = "One-time PIN"
  type       = "onetimepin"
  config     = {}
}

resource "cloudflare_zero_trust_access_application" "cc_games_dev" {
  account_id       = var.cloudflare_account_id
  name             = "cc-games dev servers"
  domain           = "*.cc-games.dev"
  type             = "self_hosted"
  session_duration = "24h"

  # The policy attachment MUST be declared here. Leaving it out makes terraform drop the
  # link on the next apply -- which would leave every *.cc-games.dev hostname reachable
  # with no Google login at all. Caught by reading the plan before applying.
  policies = [{
    id         = cloudflare_zero_trust_access_policy.cc_games_allowed.id
    precedence = 1
  }]
}

resource "cloudflare_zero_trust_access_policy" "cc_games_allowed" {
  account_id       = var.cloudflare_account_id
  name             = "allowed people"
  decision         = "allow"
  session_duration = "24h"

  include = [
    for email in var.dev_allowed_emails : { email = { email = email } }
  ]
}

output "cc_games_tunnel_id" {
  description = "Cloudflare tunnel the dev box connects out through"
  value       = cloudflare_zero_trust_tunnel_cloudflared.cc_games_dev.id
}

output "cc_games_urls" {
  description = "How to publish a project"
  value       = "run `ndev` in a Next.js project -> https://<name>.cc-games.dev (Google login required)"
}
