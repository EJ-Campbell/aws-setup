# Tailscale configuration for secure access to infrastructure
# Requires TAILSCALE_OAUTH_CLIENT_ID and TAILSCALE_OAUTH_CLIENT_SECRET environment variables

provider "tailscale" {
  # Credentials from environment variables:
  # TAILSCALE_OAUTH_CLIENT_ID
  # TAILSCALE_OAUTH_CLIENT_SECRET
  # TAILSCALE_TAILNET (optional, defaults to "-")
  tailnet = "-" # Use default tailnet from OAuth credentials
}

# Generate auth key for EC2 instances
resource "tailscale_tailnet_key" "dev_instance" {
  reusable      = true
  ephemeral     = false
  preauthorized = true
  expiry        = 7776000 # 90 days
  description   = "AWS dev instance auto-enrollment"

  tags = [
    "tag:dev-server",
  ]
}

# Output the auth key (marked sensitive)
output "tailscale_auth_key" {
  value       = tailscale_tailnet_key.dev_instance.key
  sensitive   = true
  description = "Tailscale auth key for dev instance (expires in 90 days)"
}
