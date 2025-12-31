# GitHub Actions Runner Auto-scaling
# Launches spot instances when jobs are queued, stops when idle

# ============================================
# Lambda Function for Webhook Handler
# ============================================

data "archive_file" "runner_webhook" {
  type        = "zip"
  output_path = "${path.module}/.terraform/runner-webhook.zip"

  source {
    content  = <<-EOF
      import json
      import boto3
      import os
      import hmac
      import hashlib

      ec2 = boto3.client('ec2', region_name='us-west-1')

      def verify_signature(payload, signature, secret):
          if not secret:
              return True  # Skip verification if no secret configured
          expected = 'sha256=' + hmac.new(
              secret.encode(), payload.encode(), hashlib.sha256
          ).hexdigest()
          return hmac.compare_digest(expected, signature)

      def get_running_runners():
          """Count running runner instances"""
          response = ec2.describe_instances(
              Filters=[
                  {'Name': 'tag:Role', 'Values': ['github-runner']},
                  {'Name': 'instance-state-name', 'Values': ['running', 'pending']}
              ]
          )
          count = sum(len(r['Instances']) for r in response['Reservations'])
          return count

      def launch_runner():
          """Launch a new spot runner instance"""
          response = ec2.request_spot_instances(
              InstanceCount=1,
              LaunchSpecification={
                  'ImageId': os.environ['AMI_ID'],
                  'InstanceType': os.environ['INSTANCE_TYPE'],
                  'KeyName': os.environ['KEY_NAME'],
                  'SubnetId': os.environ['SUBNET_ID'],
                  'SecurityGroupIds': [os.environ['SECURITY_GROUP_ID']],
                  'IamInstanceProfile': {'Name': os.environ['INSTANCE_PROFILE']},
                  'BlockDeviceMappings': [{
                      'DeviceName': '/dev/sda1',
                      'Ebs': {'VolumeSize': 100, 'VolumeType': 'gp3'}
                  }],
                  'UserData': os.environ['USER_DATA']
              },
              Type='one-time'
          )
          return response['SpotInstanceRequests'][0]['SpotInstanceRequestId']

      def handler(event, context):
          # Parse webhook
          body = event.get('body', '{}')
          headers = event.get('headers', {})

          # Verify signature
          signature = headers.get('x-hub-signature-256', '')
          secret = os.environ.get('WEBHOOK_SECRET', '')
          if not verify_signature(body, signature, secret):
              return {'statusCode': 401, 'body': 'Invalid signature'}

          payload = json.loads(body)
          action = payload.get('action', '')

          # Only act on queued jobs
          if action != 'queued':
              return {'statusCode': 200, 'body': f'Ignoring action: {action}'}

          # Check current runner count
          max_runners = int(os.environ.get('MAX_RUNNERS', '3'))
          running = get_running_runners()

          if running >= max_runners:
              return {'statusCode': 200, 'body': f'Max runners ({max_runners}) reached'}

          # Launch new runner
          spot_id = launch_runner()
          return {
              'statusCode': 200,
              'body': f'Launched runner: {spot_id}'
          }
    EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "runner_webhook" {
  count            = var.enable_github_runner ? 1 : 0
  filename         = data.archive_file.runner_webhook.output_path
  source_code_hash = data.archive_file.runner_webhook.output_base64sha256
  function_name    = "github-runner-webhook"
  role             = aws_iam_role.runner_lambda[0].arn
  handler          = "lambda_function.handler"
  runtime          = "python3.12"
  timeout          = 30

  environment {
    variables = {
      AMI_ID            = var.firecracker_ami
      INSTANCE_TYPE     = var.github_runner_instance_type
      KEY_NAME          = var.firecracker_key_name
      SUBNET_ID         = aws_subnet.subnet_a.id
      SECURITY_GROUP_ID = aws_security_group.firecracker_dev[0].id
      INSTANCE_PROFILE  = aws_iam_instance_profile.jumpbox_admin[0].name
      USER_DATA         = base64encode(local.runner_user_data)
      MAX_RUNNERS       = "3"
      WEBHOOK_SECRET    = var.github_webhook_secret
    }
  }

  tags = {
    Name = "github-runner-webhook"
  }
}

# ============================================
# IAM Role for Lambda
# ============================================

resource "aws_iam_role" "runner_lambda" {
  count = var.enable_github_runner ? 1 : 0
  name  = "github-runner-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "runner_lambda" {
  count = var.enable_github_runner ? 1 : 0
  name  = "github-runner-lambda-policy"
  role  = aws_iam_role.runner_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:RequestSpotInstances",
          "ec2:StopInstances",
          "ec2:CreateTags",
          "iam:PassRole",
          "cloudwatch:GetMetricStatistics"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================
# API Gateway for Webhook
# ============================================

resource "aws_apigatewayv2_api" "runner_webhook" {
  count         = var.enable_github_runner ? 1 : 0
  name          = "github-runner-webhook"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "runner_webhook" {
  count       = var.enable_github_runner ? 1 : 0
  api_id      = aws_apigatewayv2_api.runner_webhook[0].id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "runner_webhook" {
  count              = var.enable_github_runner ? 1 : 0
  api_id             = aws_apigatewayv2_api.runner_webhook[0].id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.runner_webhook[0].invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "runner_webhook" {
  count     = var.enable_github_runner ? 1 : 0
  api_id    = aws_apigatewayv2_api.runner_webhook[0].id
  route_key = "POST /webhook"
  target    = "integrations/${aws_apigatewayv2_integration.runner_webhook[0].id}"
}

resource "aws_lambda_permission" "runner_webhook" {
  count         = var.enable_github_runner ? 1 : 0
  statement_id  = "AllowAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.runner_webhook[0].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.runner_webhook[0].execution_arn}/*/*"
}

# ============================================
# Variables
# ============================================

variable "github_webhook_secret" {
  description = "GitHub webhook secret for signature verification"
  type        = string
  default     = ""
  sensitive   = true
}

# ============================================
# Outputs
# ============================================

output "runner_webhook_url" {
  description = "URL for GitHub webhook"
  value       = var.enable_github_runner ? "${aws_apigatewayv2_api.runner_webhook[0].api_endpoint}/webhook" : null
}

# ============================================
# Shared user data for runners
# ============================================

locals {
  runner_user_data = <<-EOF
    #!/bin/bash
    set -euxo pipefail

    # Tag this instance as a runner
    INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    aws ec2 create-tags --resources $INSTANCE_ID --tags Key=Role,Value=github-runner Key=Name,Value=github-runner-autoscale --region us-west-1

    # System packages
    apt-get update && apt-get upgrade -y
    apt-get install -y curl wget git jq build-essential podman uidmap slirp4netns fuse-overlayfs containernetworking-plugins

    # Node.js 22.x
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs

    # Rust
    sudo -u ubuntu bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y'

    # GitHub Actions Runner
    mkdir -p /opt/actions-runner && cd /opt/actions-runner
    RUNNER_VERSION=$(curl -s https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name' | sed 's/v//')
    curl -o actions-runner-linux-arm64.tar.gz -L "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-linux-arm64-$RUNNER_VERSION.tar.gz"
    tar xzf actions-runner-linux-arm64.tar.gz && rm actions-runner-linux-arm64.tar.gz
    chown -R ubuntu:ubuntu /opt/actions-runner
    ./bin/installdependencies.sh

    # Podman rootless
    echo "ubuntu:100000:65536" >> /etc/subuid
    echo "ubuntu:100000:65536" >> /etc/subgid

    # Get GitHub PAT and generate registration token
    PAT=$(aws ssm get-parameter --name /github-runner/pat --with-decryption --query 'Parameter.Value' --output text --region us-west-1 2>/dev/null || echo "")
    if [ -n "$PAT" ]; then
      TOKEN=$(curl -s -X POST -H "Authorization: token $PAT" \
        https://api.github.com/repos/ejc3/firepod/actions/runners/registration-token | jq -r '.token')
      sudo -u ubuntu ./config.sh --url https://github.com/ejc3/firepod --token "$TOKEN" --name "runner-$INSTANCE_ID" --labels self-hosted,Linux,ARM64 --unattended
      ./svc.sh install ubuntu
      ./svc.sh start
    fi
  EOF
}

# ============================================
# Idle Runner Cleanup (runs every 5 minutes)
# ============================================

data "archive_file" "runner_cleanup" {
  type        = "zip"
  output_path = "${path.module}/.terraform/runner-cleanup.zip"

  source {
    content  = <<-EOF
      import boto3
      from datetime import datetime, timezone, timedelta

      ec2 = boto3.client('ec2', region_name='us-west-1')
      cloudwatch = boto3.client('cloudwatch', region_name='us-west-1')

      def handler(event, context):
          # Find auto-scaled runners
          response = ec2.describe_instances(
              Filters=[
                  {'Name': 'tag:Role', 'Values': ['github-runner']},
                  {'Name': 'tag:Name', 'Values': ['github-runner-autoscale']},
                  {'Name': 'instance-state-name', 'Values': ['running']}
              ]
          )

          stopped = []
          for reservation in response['Reservations']:
              for instance in reservation['Instances']:
                  instance_id = instance['InstanceId']
                  launch_time = instance['LaunchTime']

                  # Skip if launched less than 30 minutes ago
                  if datetime.now(timezone.utc) - launch_time < timedelta(minutes=30):
                      continue

                  # Check CPU utilization
                  metrics = cloudwatch.get_metric_statistics(
                      Namespace='AWS/EC2',
                      MetricName='CPUUtilization',
                      Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                      StartTime=datetime.now(timezone.utc) - timedelta(minutes=30),
                      EndTime=datetime.now(timezone.utc),
                      Period=300,
                      Statistics=['Average']
                  )

                  # If avg CPU < 5% for last 30 mins, stop it
                  if metrics['Datapoints']:
                      avg_cpu = sum(d['Average'] for d in metrics['Datapoints']) / len(metrics['Datapoints'])
                      if avg_cpu < 5:
                          ec2.stop_instances(InstanceIds=[instance_id])
                          stopped.append(instance_id)

          return {'stopped': stopped}
    EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "runner_cleanup" {
  count            = var.enable_github_runner ? 1 : 0
  filename         = data.archive_file.runner_cleanup.output_path
  source_code_hash = data.archive_file.runner_cleanup.output_base64sha256
  function_name    = "github-runner-cleanup"
  role             = aws_iam_role.runner_lambda[0].arn
  handler          = "lambda_function.handler"
  runtime          = "python3.12"
  timeout          = 60

  tags = {
    Name = "github-runner-cleanup"
  }
}

resource "aws_cloudwatch_event_rule" "runner_cleanup" {
  count               = var.enable_github_runner ? 1 : 0
  name                = "github-runner-cleanup"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "runner_cleanup" {
  count     = var.enable_github_runner ? 1 : 0
  rule      = aws_cloudwatch_event_rule.runner_cleanup[0].name
  target_id = "runner-cleanup"
  arn       = aws_lambda_function.runner_cleanup[0].arn
}

resource "aws_lambda_permission" "runner_cleanup" {
  count         = var.enable_github_runner ? 1 : 0
  statement_id  = "AllowCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.runner_cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.runner_cleanup[0].arn
}

# SSM Parameter for GitHub PAT (set manually)
resource "aws_ssm_parameter" "github_runner_pat" {
  count = var.enable_github_runner ? 1 : 0
  name  = "/github-runner/pat"
  type  = "SecureString"
  value = "placeholder" # Set via: aws ssm put-parameter --name /github-runner/pat --value "ghp_xxx" --type SecureString --overwrite

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Name = "github-runner-pat"
  }
}
