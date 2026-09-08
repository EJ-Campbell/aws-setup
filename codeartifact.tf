# Private npm registry via AWS CodeArtifact
# CodeArtifact is not available in us-west-1, use us-west-2

provider "aws" {
  alias  = "usw2"
  region = "us-west-2"
}

resource "aws_codeartifact_domain" "main" {
  provider = aws.usw2
  domain   = "ejc3"
  tags     = { Name = "ejc3-codeartifact" }
}

resource "aws_codeartifact_repository" "npm" {
  provider   = aws.usw2
  repository = "npm"
  domain     = aws_codeartifact_domain.main.domain

  upstream {
    repository_name = aws_codeartifact_repository.npm_upstream.repository
  }

  tags = { Name = "ejc3-npm" }
}

# Upstream proxy to public npmjs.com (so you can install public packages through CodeArtifact too)
resource "aws_codeartifact_repository" "npm_upstream" {
  provider   = aws.usw2
  repository = "npm-upstream"
  domain     = aws_codeartifact_domain.main.domain

  external_connections {
    external_connection_name = "public:npmjs"
  }

  tags = { Name = "ejc3-npm-upstream" }
}

# Same-account dev publishers continue using their identity policies. Remove the
# old shared CI role's resource-policy token/publish grants; the repositories and
# existing packages remain intact. CI has no replacement package-publishing grant.

# Outputs
output "npm_registry_domain" {
  description = "CodeArtifact domain name"
  value       = aws_codeartifact_domain.main.domain
}

output "npm_registry_repository" {
  description = "CodeArtifact repository name"
  value       = aws_codeartifact_repository.npm.repository
}

output "npm_registry_endpoint" {
  description = "npm registry endpoint (use with: aws codeartifact login --tool npm)"
  value       = "aws codeartifact login --tool npm --domain ${aws_codeartifact_domain.main.domain} --domain-owner ${data.aws_caller_identity.current.account_id} --repository ${aws_codeartifact_repository.npm.repository} --region us-west-2"
}
