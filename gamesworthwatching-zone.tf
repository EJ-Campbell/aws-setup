# gamesworthwatching-zone.tf
#
# gamesworthwatching.com, registered through Cloudflare Registrar on 2026-09-05
# ($10.46/yr, auto-renew on, WHOIS redaction, transfer lock on), and pointed at Vercel.
#
# WHY DNS RECORDS AND NOT NAMESERVER DELEGATION. Cloudflare Registrar will not let a domain
# it registers use anyone else's nameservers -- the Domain Registration Agreement says the
# registrant "MAY NOT CHANGE THE NAMESERVERS ON THE REGISTRAR SERVICES, AND ... MUST TRANSFER
# TO A THIRD PARTY REGISTRAR IF IT WISHES TO CHANGE NAMESERVERS." So "delegate to Vercel"
# here means Cloudflare stays authoritative and these records point at Vercel's edge, which
# is a fully supported Vercel setup. If you ever genuinely need Vercel as the NAMESERVER,
# the domain has to move to a different registrar first.
#
# PROXY MUST STAY OFF. An orange-clouded record terminates TLS at Cloudflare, and Vercel's
# domain verification and certificate issuance then fail against Cloudflare's edge rather
# than reaching Vercel. proxied = false is not a preference here, it is a requirement.

variable "gww_zone_id" {
  description = "Zone id for gamesworthwatching.com (registered through Cloudflare Registrar, so the zone was created automatically)"
  type        = string
  default     = "8548a478c6a0572e46d61d24ab2ca762"
}

# Vercel's long-standing shared endpoints. They still work and are what Vercel documents for
# an apex on external DNS.
#
# Vercel now ALSO hands out per-domain targets (e.g. xyz.vercel-dns-016.com) once a domain is
# attached to a project, and prefers those. Get them with `vercel domains inspect
# gamesworthwatching.com` after adding the domain to the project, then override these two
# variables rather than editing the resources.
variable "gww_vercel_a" {
  description = "Vercel apex A target. Override with the per-domain value from `vercel domains inspect` if Vercel issues one."
  type        = string
  default     = "76.76.21.21"
}

variable "gww_vercel_cname" {
  description = "Vercel www CNAME target. Override with the per-domain value from `vercel domains inspect` if Vercel issues one."
  type        = string
  default     = "cname.vercel-dns.com"
}

resource "cloudflare_dns_record" "gww_apex" {
  zone_id = var.gww_zone_id
  name    = "gamesworthwatching.com"
  type    = "A"
  content = var.gww_vercel_a
  proxied = false # see the header: proxying breaks Vercel cert issuance
  ttl     = 300
  comment = "vercel apex"
}

resource "cloudflare_dns_record" "gww_www" {
  zone_id = var.gww_zone_id
  name    = "www"
  type    = "CNAME"
  content = var.gww_vercel_cname
  proxied = false
  ttl     = 300
  comment = "vercel www"
}

output "gamesworthwatching" {
  description = "Domain status and what is left to do on the Vercel side"
  value       = "gamesworthwatching.com -> Vercel (A ${var.gww_vercel_a}, www CNAME ${var.gww_vercel_cname}, unproxied). Remaining: add the domain to the Vercel project, then `vercel domains inspect` and override gww_vercel_a/gww_vercel_cname if it issues per-domain targets."
}
