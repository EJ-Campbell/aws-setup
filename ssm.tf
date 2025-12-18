# SSM Parameter Store - Container Image Tags for Deployment

# Parameter for buckman-runner image tag
# Updated by CI on every deployment, read by EC2 user-data
resource "aws_ssm_parameter" "runner_image_tag" {
  name        = "/buckman/runner-image-tag"
  description = "Container image tag for buckman-runner (format: <sha>-<build-id>)"
  type        = "String"
  value       = "initial" # Placeholder value, CI will update immediately

  tags = {
    Name        = "buckman-runner-image-tag"
    Description = "Deployment version for buckman-runner service"
    ManagedBy   = "terraform"
    UpdatedBy   = "github-actions-ci"
  }

  lifecycle {
    ignore_changes = [value] # CI owns value updates, prevent Terraform drift
  }
}

# Parameter for buckman-version-server image tag
# Updated by CI on every deployment, read by EC2 user-data
resource "aws_ssm_parameter" "version_server_image_tag" {
  name        = "/buckman/version-server-image-tag"
  description = "Container image tag for buckman-version-server (format: <sha>-<build-id>)"
  type        = "String"
  value       = "initial" # Placeholder value, CI will update immediately

  tags = {
    Name        = "buckman-version-server-image-tag"
    Description = "Deployment version for buckman-version-server service"
    ManagedBy   = "terraform"
    UpdatedBy   = "github-actions-ci"
  }

  lifecycle {
    ignore_changes = [value] # CI owns value updates, prevent Terraform drift
  }
}
