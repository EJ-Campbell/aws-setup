# Launch Template for Auto Scaling Group
# Defines instance configuration for buckman infrastructure

resource "aws_launch_template" "buckman" {
  count       = var.enable_dev_instance ? 1 : 0
  name_prefix = "${var.project_name}-launch-template-"
  description = "Launch template for buckman infrastructure instances"

  # Instance configuration
  image_id      = local.ubuntu2404_ami_id
  instance_type = var.dev_instance_type

  # IAM instance profile for ECR + SSM + Secrets Manager access
  iam_instance_profile {
    name = aws_iam_instance_profile.dev[0].name
  }

  # Network configuration - security groups specified in network_interfaces
  # Public IP required for internet access (ALB, ECR pulls, etc.)
  network_interfaces {
    associate_public_ip_address = true
    delete_on_termination       = true
    security_groups             = [aws_security_group.dev[0].id]
  }

  # EBS root volume configuration
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.dev_volume_size
      volume_type           = "gp3"
      delete_on_termination = true # ASG instances are ephemeral
      encrypted             = true
      iops                  = 3000 # gp3 baseline
      throughput            = 125  # gp3 baseline (MB/s)
    }
  }

  # User data script - reads image tags from Parameter Store
  user_data = base64encode(templatefile("${path.module}/templates/userdata.sh.tpl", {
    aws_region   = var.aws_region
    account_id   = data.aws_caller_identity.current.account_id
    ecr_registry = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
  }))

  # Instance metadata configuration (IMDSv2 required for security)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 only
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  # Monitoring
  monitoring {
    enabled = true # Enable detailed CloudWatch monitoring
  }

  # Tags applied to instances launched from this template
  tag_specifications {
    resource_type = "instance"

    tags = {
      Name        = "${var.project_name}-asg-instance"
      Purpose     = "production"
      Environment = "prod"
      ManagedBy   = "terraform-asg"
      AutoDeploy  = "true"
    }
  }

  tag_specifications {
    resource_type = "volume"

    tags = {
      Name        = "${var.project_name}-asg-volume"
      ManagedBy   = "terraform-asg"
      Environment = "prod"
    }
  }

  # Lifecycle management
  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.project_name}-launch-template"
    Description = "Launch template for buckman infrastructure ASG"
    ManagedBy   = "terraform"
  }
}
