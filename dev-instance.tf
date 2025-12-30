# Production Instances - 2 instances behind ALB
# Cost: ~$16/month for 2 instances, high availability

# Ubuntu 24.04 LTS AMI (AMD64/x86_64)
# Podman installed via user-data on first boot
locals {
  ubuntu2404_ami_id = "ami-0e6a50b0059fd2cc3" # Ubuntu 24.04 LTS AMD64
}

# Security group for production instances
resource "aws_security_group" "dev" {
  count       = var.enable_dev_instance ? 1 : 0
  name_prefix = "${var.project_name}-prod-sg-"
  description = "Security group for production instances"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  # Proxy traffic from ALB (port 8080)
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
    description     = "Proxy traffic from ALB"
  }

  # Health check endpoint from ALB (port 8081)
  ingress {
    from_port       = 8081
    to_port         = 8081
    protocol        = "tcp"
    security_groups = [aws_security_group.alb[0].id]
    description     = "Health checks from ALB"
  }

  # All outbound traffic allowed for registry pulls, etc.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-prod-sg"
  }
}

# IAM role for dev instance (SSM access)
resource "aws_iam_role" "dev_instance" {
  count = var.enable_dev_instance ? 1 : 0
  name  = "${var.project_name}-dev-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-dev-instance-role"
  }
}

# Attach AWS managed policy for SSM
resource "aws_iam_role_policy_attachment" "dev_ssm" {
  count      = var.enable_dev_instance ? 1 : 0
  role       = aws_iam_role.dev_instance[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Policy to read GitHub token from Secrets Manager, access ECR, and read SSM parameters
resource "aws_iam_role_policy" "dev_secrets" {
  count = var.enable_dev_instance ? 1 : 0
  name  = "${var.project_name}-dev-secrets-policy"
  role  = aws_iam_role.dev_instance[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:github-deploy-token-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:github-ghcr-token-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:ListImages"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/buckman/*"
        ]
      }
    ]
  })
}

# Instance profile
resource "aws_iam_instance_profile" "dev" {
  count = var.enable_dev_instance ? 1 : 0
  name  = "${var.project_name}-dev-instance-profile"
  role  = aws_iam_role.dev_instance[0].name
}

# VPC Endpoints for SSM and S3 (private access, no public IP needed)
# S3 endpoint (Gateway type - free!) for package repos
resource "aws_vpc_endpoint" "s3" {
  count           = var.enable_dev_instance ? 1 : 0
  vpc_id          = local.vpc_id
  service_name    = "com.amazonaws.${var.aws_region}.s3"
  route_table_ids = [aws_route_table.public.id]

  tags = {
    Name = "${var.project_name}-s3-endpoint"
  }
}

# SSM endpoints (Interface type) for remote access
resource "aws_vpc_endpoint" "ssm" {
  count               = var.enable_dev_instance ? 1 : 0
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.subnet_a.id]
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-ssm-endpoint"
  }
}

resource "aws_vpc_endpoint" "ssmmessages" {
  count               = var.enable_dev_instance ? 1 : 0
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.subnet_a.id]
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-ssmmessages-endpoint"
  }
}

resource "aws_vpc_endpoint" "ec2messages" {
  count               = var.enable_dev_instance ? 1 : 0
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.subnet_a.id]
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = {
    Name = "${var.project_name}-ec2messages-endpoint"
  }
}

# Security group for VPC endpoints
resource "aws_security_group" "vpc_endpoints" {
  count       = var.enable_dev_instance ? 1 : 0
  name_prefix = "${var.project_name}-vpc-endpoints-sg-"
  description = "Security group for VPC endpoints"
  vpc_id      = local.vpc_id

  lifecycle {
    create_before_destroy = true
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
    description = "HTTPS from VPC"
  }

  tags = {
    Name = "${var.project_name}-vpc-endpoints-sg"
  }
}

# Static EC2 instances removed - replaced by Auto Scaling Group (see asg.tf and launch_template.tf)
# ASG automatically manages instance lifecycle and ALB target group registration
