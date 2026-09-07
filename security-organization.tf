# Shared prerequisite for the staged backup and security-monitoring deployments.
# Adopt the existing organization; preserve SSO while enabling Backup and CloudTrail.
# Keep this resource at one address/file when the staged branches are integrated.
import {
  to = aws_organizations_organization.security
  id = "o-1d3o5eerdv"
}

resource "aws_organizations_organization" "security" {
  feature_set                   = "ALL"
  aws_service_access_principals = ["sso.amazonaws.com", "cloudtrail.amazonaws.com", "backup.amazonaws.com"]
  lifecycle { prevent_destroy = true }
}
