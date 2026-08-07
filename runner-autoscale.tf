# GitHub Actions Runner Auto-scaling
# Launches spot instances when jobs are queued, stops when idle

locals {
  # Runner pool size per architecture. The webhook Lambda enforces it; the cleanup
  # Lambda bounds its queue scan and its per-poll launch count by it. One value so
  # the two can never disagree about how large the pool is.
  runner_max_per_arch = 4
}

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
      from datetime import datetime, timezone, timedelta

      ec2 = boto3.client('ec2', region_name='us-west-1')
      ssm = boto3.client('ssm', region_name='us-west-1')

      def get_user_data():
          """Fetch user_data from SSM Parameter Store"""
          param_name = os.environ.get('USER_DATA_PARAM', '/github-runner/user-data')
          resp = ssm.get_parameter(Name=param_name)
          return resp['Parameter']['Value']

      def get_latest_runner_ami(arch='arm64'):
          """Get the latest available AMI for the specified architecture"""
          response = ec2.describe_images(
              Owners=['self'],
              Filters=[
                  {'Name': 'tag:Purpose', 'Values': ['github-runner']},
                  {'Name': 'state', 'Values': ['available']},
                  {'Name': 'architecture', 'Values': [arch]}
              ]
          )
          if not response['Images']:
              return None
          # Sort by creation date, newest first
          images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
          return images[0]['ImageId']

      def verify_signature(payload, signature, secret):
          if not secret:
              return False  # Fail closed: no secret configured means reject, never accept
          expected = 'sha256=' + hmac.new(
              secret.encode(), payload.encode(), hashlib.sha256
          ).hexdigest()
          return hmac.compare_digest(expected, signature)

      def get_running_runners(arch=None):
          """Count runner instances that can still take a job.

          A launch stalled past the startup window is a husk, not a runner, and
          counting it holds a slot against work it will never do. On 2026-08-07
          three doomed c5d.metal launches sat pending while this answered "Max
          x86_64 runners (4) reached", until AWS terminated them at 20:31.
          """
          filters = [
              {'Name': 'tag:Role', 'Values': ['github-runner']},
              {'Name': 'instance-state-name', 'Values': ['pending', 'running']}
          ]
          if arch:
              name_value = f'github-runner-{arch}'
              filters.append({'Name': 'tag:Name', 'Values': [name_value]})
          response = ec2.describe_instances(Filters=filters)
          now = datetime.now(timezone.utc)
          return sum(1 for r in response['Reservations'] for i in r['Instances']
                     if not is_stalled_launch(i, now))

      def detect_architecture(labels):
          """Detect architecture from job labels, default to arm64"""
          labels_lower = [l.lower() for l in labels]
          if 'x64' in labels_lower or 'x86_64' in labels_lower or 'amd64' in labels_lower:
              return 'x86_64'
          # Default to arm64 (cheaper, faster for most workloads)
          return 'arm64'

      # A launch that has not reached `running` by now is never going to. AWS accepts
      # run_instances for a metal spot instance it cannot place, hands back an
      # instance ID, and only reports the failure much later: on 2026-08-07 three
      # c5d.metal launches at 18:41, 18:46 and 18:51 were not marked
      # instance-terminated-no-capacity until 20:31, nearly two hours after the first.
      STARTUP_TIMEOUT_MINUTES = 15

      # EC2 state-reason codes meaning a launch never got the capacity it asked for.
      # Deliberately excludes Server.SpotInstanceTermination, which is ambiguous: it
      # covers the ordinary reclaim of a runner that worked fine for an hour, and
      # rotating on that would send ARM to c7g.metal - a type with no instance-store
      # NVMe, so user_data never builds /mnt/fcvm-btrfs - after every routine
      # interruption. Rotate on launches that failed, not on runners that were taken
      # back. A reclaim that does mean no capacity still gets caught, one poll later,
      # by the stall check below.
      CAPACITY_STATE_REASONS = (
          'Server.InsufficientInstanceCapacity',
          'Server.CapacityOversubscribed',
      )

      def get_tag(instance, key):
          """Get tag value from instance"""
          for tag in instance.get('Tags', []):
              if tag['Key'] == key:
                  return tag['Value']
          return None

      def describe_runner_instances(arch):
          """Every runner instance EC2 still knows about, terminated ones included.

          Deliberately unfiltered by state: EC2 keeps a terminated instance visible
          for about an hour, and that record is the only place the reason a launch
          died survives. Filtering to pending/running would discard exactly the
          evidence the launcher needs to pick a different instance type.
          """
          response = ec2.describe_instances(Filters=[
              {'Name': 'tag:Role', 'Values': ['github-runner']},
              {'Name': 'tag:Name', 'Values': [f'github-runner-{arch}']}
          ])
          return [i for r in response['Reservations'] for i in r['Instances']]

      def is_stalled_launch(instance, now):
          """Still pending long after a metal instance should have booted"""
          if instance['State']['Name'] != 'pending':
              return False
          return now - instance['LaunchTime'] >= timedelta(minutes=STARTUP_TIMEOUT_MINUTES)

      def capacity_failed_types(instances, now):
          """Instance types whose most recent launch died for want of capacity.

          Three signals, all read from the one instance record: AWS's own state
          reason, the CapacityFailedAt tag the cleanup Lambda stamps on a launch it
          reaps for never booting, and a launch that is stalling right now.
          """
          failed = set()
          for instance in instances:
              instance_type = instance.get('InstanceType')
              if not instance_type:
                  continue
              if (instance.get('StateReason', {}).get('Code') in CAPACITY_STATE_REASONS
                      or get_tag(instance, 'CapacityFailedAt')
                      or is_stalled_launch(instance, now)):
                  failed.add(instance_type)
          return failed

      def get_instance_types(arch, deprioritized=()):
          """Instance types to try for architecture, recent capacity failures last.

          Reordering, never filtering: a type that just failed goes to the back but
          stays in the list, so a launch is still attempted when every type has
          failed. The loop in launch_runner cannot discover a capacity failure on
          its own - run_instances returns an instance ID for a spot request AWS
          cannot fulfil and kills the instance afterwards, so no exception is ever
          raised to advance it. The previous attempt's outcome is what advances the
          list, which is why this takes the failures as an argument.
          """
          if arch == 'x86_64':
              # Try multiple x86 metal types for better spot availability
              types = ['c5d.metal', 'c5.metal', 'c6i.metal', 'm5d.metal']
          else:
              types = ['c7gd.metal', 'c7g.metal']
          return ([t for t in types if t not in deprioritized]
                  + [t for t in types if t in deprioritized])

      # Lease duration in minutes - runners auto-terminate after this unless renewed
      LEASE_DURATION_MINUTES = 60

      def get_lease_expiry():
          """Calculate lease expiry time (now + LEASE_DURATION_MINUTES)"""
          return (datetime.now(timezone.utc) + timedelta(minutes=LEASE_DURATION_MINUTES)).isoformat()

      def launch_runner(arch='arm64'):
          """Launch a new spot runner instance, trying multiple instance types"""
          ami_id = get_latest_runner_ami(arch)
          if not ami_id:
              raise Exception(f"No runner AMI found for architecture: {arch}")

          # Which types just failed decides where this attempt starts. Without it
          # every retry re-picks the head of the list: on 2026-08-07 the poll
          # launched c5d.metal at 18:41, 18:46 and 18:51 and never reached
          # c5.metal, c6i.metal or m5d.metal at all.
          deprioritized = capacity_failed_types(describe_runner_instances(arch), datetime.now(timezone.utc))
          if deprioritized:
              print(f'Recent capacity failures on {sorted(deprioritized)}, trying other types first')
          instance_types = get_instance_types(arch, deprioritized)
          last_error = None

          # x86 AMI is from 300GB dev instance, ARM is smaller
          volume_size = 300 if arch == 'x86_64' else 100

          # Set initial lease - runner will auto-terminate if not renewed
          lease_expiry = get_lease_expiry()

          for instance_type in instance_types:
              try:
                  response = ec2.run_instances(
                      MinCount=1,
                      MaxCount=1,
                      ImageId=ami_id,
                      InstanceType=instance_type,
                      KeyName='fcvm-ec2',
                      NetworkInterfaces=[{
                          'DeviceIndex': 0,
                          'SubnetId': os.environ['SUBNET_ID'],
                          'Groups': [os.environ['SECURITY_GROUP_ID']],
                          'AssociatePublicIpAddress': True,
                          'Ipv6PrefixCount': 1,
                      }],
                      IamInstanceProfile={'Name': os.environ['INSTANCE_PROFILE']},
                      BlockDeviceMappings=[{
                          'DeviceName': '/dev/sda1',
                          'Ebs': {'VolumeSize': volume_size, 'VolumeType': 'gp3', 'DeleteOnTermination': True}
                      }],
                      UserData=get_user_data(),
                      InstanceMarketOptions={
                          'MarketType': 'spot',
                          'SpotOptions': {'SpotInstanceType': 'one-time'}
                      },
                      TagSpecifications=[{
                          'ResourceType': 'instance',
                          'Tags': [
                              {'Key': 'Name', 'Value': f'github-runner-{arch}'},
                              {'Key': 'Role', 'Value': 'github-runner'},
                              {'Key': 'Architecture', 'Value': arch},
                              {'Key': 'LeaseExpires', 'Value': lease_expiry}
                          ]
                      }]
                  )
                  return response['Instances'][0]['InstanceId'], instance_type
              except Exception as e:
                  last_error = e
                  print(f"Failed to launch {instance_type}: {e}, trying next...")
                  continue

          raise last_error or Exception(f"All instance types failed for {arch}")

      def handler(event, context):
          # Parse webhook
          body = event.get('body', '{}')
          headers = event.get('headers', {})

          # Requests via API Gateway carry requestContext (set by AWS, not the
          # caller) - that is the public, untrusted path, so it must pass HMAC
          # verification. The cleanup Lambda reaches us by direct lambda:Invoke
          # (IAM-authed, no requestContext) and is trusted without a forgeable header.
          if 'requestContext' in event:
              signature = headers.get('x-hub-signature-256', '')
              secret = os.environ.get('WEBHOOK_SECRET', '')
              if not verify_signature(body, signature, secret):
                  return {'statusCode': 401, 'body': 'Invalid signature'}

          payload = json.loads(body)
          action = payload.get('action', '')

          # Only act on queued jobs
          if action != 'queued':
              return {'statusCode': 200, 'body': f'Ignoring action: {action}'}

          # Get job labels to detect architecture
          workflow_job = payload.get('workflow_job', {})
          labels = workflow_job.get('labels', [])
          arch = detect_architecture(labels)

          # Check per-architecture runner count
          max_runners = int(os.environ.get('MAX_RUNNERS', '3'))
          running = get_running_runners(arch)

          if running >= max_runners:
              return {'statusCode': 200, 'body': f'Max {arch} runners ({max_runners}) reached'}

          # Launch new runner for detected architecture
          spot_id, instance_type = launch_runner(arch)
          return {
              'statusCode': 200,
              'body': f'Launched {arch} runner ({instance_type}): {spot_id}'
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

  # Serialize webhook processing to prevent race condition where concurrent
  # invocations all read the same runner count and over-launch instances
  reserved_concurrent_executions = 1

  environment {
    variables = {
      SUBNET_ID         = aws_subnet.runner[0].id
      SECURITY_GROUP_ID = aws_security_group.runner[0].id
      INSTANCE_PROFILE  = aws_iam_instance_profile.runner[0].name
      USER_DATA_PARAM   = aws_ssm_parameter.runner_user_data[0].name
      MAX_RUNNERS       = tostring(local.runner_max_per_arch) # Per architecture
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
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "iam:PassRole",
          "cloudwatch:GetMetricStatistics"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:us-west-1:928413605543:parameter/github-runner/*"
      },
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = "arn:aws:lambda:us-west-1:928413605543:function:github-runner-webhook"
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

variable "enable_github_runner" {
  description = "Enable GitHub Actions runner infrastructure"
  type        = bool
  default     = true
}

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
  # User data for pre-baked AMI - just set permissions and register runner
  # NOTE: Heredoc content starts at column 0 because <<-EOF only strips tabs, not spaces
  runner_user_data = <<-EOF
#!/bin/bash
set -euxo pipefail

# Disable apt auto-updates (daemon-reexec kills runner services)
systemctl stop apt-daily.timer apt-daily-upgrade.timer || true
systemctl disable apt-daily.timer apt-daily-upgrade.timer || true
systemctl mask apt-daily.service apt-daily-upgrade.service || true

# Console logging
cat >> /etc/rsyslog.d/50-console.conf << 'RSYSLOG'
*.emerg;*.alert;*.crit;*.err /dev/ttyS0
kern.* /dev/ttyS0
RSYSLOG
systemctl restart rsyslog || true
sysctl -w kernel.printk="7 4 1 7" || true

# Mount NVMe as btrfs RAID0 at /mnt/fcvm-btrfs
ROOT_DEV=$(lsblk -no PKNAME $(findmnt -no SOURCE /) | head -1)
NVME_DEVS=$(lsblk -dn -o NAME,TYPE | awk '$2=="disk" && /^nvme/ {print $1}' | grep -v "^$ROOT_DEV$")
NVME_COUNT=$(echo "$NVME_DEVS" | wc -w)
if [ "$NVME_COUNT" -gt 0 ]; then
  CURRENT_MOUNT=$(findmnt -no SOURCE /mnt/fcvm-btrfs 2>/dev/null || true)
  BTRFS_DEVS=$(btrfs filesystem show /mnt/fcvm-btrfs 2>/dev/null | grep -c 'devid' || echo 0)
  if [[ "$CURRENT_MOUNT" == /dev/nvme* ]] && [ "$BTRFS_DEVS" -ge "$NVME_COUNT" ]; then
    echo "RAID0 already mounted ($BTRFS_DEVS devices), skipping"
  else
    # Unmount existing (loop from AMI or single-NVMe from old service)
    mountpoint -q /mnt/fcvm-btrfs && umount /mnt/fcvm-btrfs || true
    which mkfs.btrfs || apt-get install -y btrfs-progs
    mkdir -p /mnt/fcvm-btrfs
    if [ "$NVME_COUNT" -ge 2 ]; then
      NVME_PATHS=$(echo "$NVME_DEVS" | sed 's|^|/dev/|' | tr '\n' ' ')
      echo "RAID0 across $NVME_COUNT NVMe: $NVME_PATHS"
      mkfs.btrfs -f -d raid0 -m raid0 $NVME_PATHS
      mount $(echo "$NVME_PATHS" | awk '{print $1}') /mnt/fcvm-btrfs
    else
      NVME_DEV=$(echo "$NVME_DEVS" | head -1)
      echo "Setting up NVMe as btrfs: /dev/$NVME_DEV"
      mkfs.btrfs -f /dev/$NVME_DEV
      mount /dev/$NVME_DEV /mnt/fcvm-btrfs
    fi
    chmod 1777 /mnt/fcvm-btrfs
  fi

  mkdir -p /mnt/fcvm-btrfs/{kernels,rootfs,initrd,state,snapshots,vm-disks,cache,image-cache,containers,cargo-target}
  chown -R ubuntu:ubuntu /mnt/fcvm-btrfs
  mkdir -p /home/ubuntu/.local/share
  ln -sf /mnt/fcvm-btrfs/containers /home/ubuntu/.local/share/containers
  chown -R ubuntu:ubuntu /home/ubuntu/.local
  echo 'export CARGO_TARGET_DIR=/mnt/fcvm-btrfs/cargo-target' >> /home/ubuntu/.bashrc
fi

# Runtime permissions
chmod 666 /dev/kvm
[ -e /dev/userfaultfd ] || mknod /dev/userfaultfd c 10 126
chmod 666 /dev/userfaultfd
sysctl -w vm.unprivileged_userfaultfd=1
sysctl -w kernel.unprivileged_userns_clone=1 || true
iptables -P FORWARD ACCEPT || true

# Assign a global IPv6 address to the ENI
# AWS run_instances can't set both Ipv6AddressCount and Ipv6PrefixCount in the same
# NetworkInterfaces entry, so we assign the IPv6 address post-launch.
TOKEN6=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
MAC=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN6" http://169.254.169.254/latest/meta-data/mac)
ENI_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN6" "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/interface-id")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN6" http://169.254.169.254/latest/meta-data/placement/region)
aws ec2 assign-ipv6-addresses --network-interface-id "$ENI_ID" --ipv6-address-count 1 --region "$REGION" && echo "IPv6 address assigned to $ENI_ID"

# Raise dirty_ratio to prevent writeback throttling during snapshot creation
sysctl -w vm.dirty_ratio=80
sysctl -w vm.dirty_background_ratio=50

# Fix podman rootless, enable linger, SSH keys
sort -u /etc/subuid > /tmp/subuid && mv /tmp/subuid /etc/subuid
sort -u /etc/subgid > /tmp/subgid && mv /tmp/subgid /etc/subgid
loginctl enable-linger ubuntu
mkdir -p /home/ubuntu/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINwtXjjTCVgT9OR3qrnz3zDkV2GveuCBlWFXSOBG2joe fcvm-ec2" >> /home/ubuntu/.ssh/authorized_keys
echo "${trimspace(tls_private_key.dev_to_runner.public_key_openssh)}" >> /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh
chmod 700 /home/ubuntu/.ssh
chmod 600 /home/ubuntu/.ssh/authorized_keys

snap start amazon-ssm-agent || true
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
ARCH=$(uname -m)

if [ "$ARCH" = "aarch64" ]; then
  RUNNER_ARCH="arm64"
  RUNNER_LABEL="ARM64"
else
  RUNNER_ARCH="x64"
  RUNNER_LABEL="X64"
fi

RUNNER_VERSION=$(curl -s https://api.github.com/repos/actions/runner/releases/latest | jq -r '.tag_name' | sed 's/^v//')
RUNNER_URL="https://github.com/actions/runner/releases/download/v$${RUNNER_VERSION}/actions-runner-linux-$${RUNNER_ARCH}-$${RUNNER_VERSION}.tar.gz"
mkdir -p /opt/actions-runner
cd /opt/actions-runner
curl -sL "$RUNNER_URL" | tar xz
chown -R ubuntu:ubuntu /opt/actions-runner

PAT=$(aws ssm get-parameter --name /github-runner/pat --with-decryption --query 'Parameter.Value' --output text --region us-west-1 2>/dev/null || echo "")
if [ -n "$PAT" ] && [ "$PAT" != "placeholder" ]; then
  REG_TOKEN=$(curl -s -X POST -H "Authorization: token $PAT" \
    https://api.github.com/repos/ejc3/fcvm/actions/runners/registration-token | jq -r '.token')
  sudo -u ubuntu ./config.sh --url https://github.com/ejc3/fcvm --token "$REG_TOKEN" \
    --name "runner-$INSTANCE_ID" --labels "self-hosted,Linux,$RUNNER_LABEL" --unattended --replace
  ./svc.sh install ubuntu
  ./svc.sh start
fi
EOF
}

# SSM Parameter to store user_data (avoids Lambda 4KB env var limit)
resource "aws_ssm_parameter" "runner_user_data" {
  count = var.enable_github_runner ? 1 : 0
  name  = "/github-runner/user-data"
  type  = "String"
  tier  = "Advanced"
  value = base64encode(local.runner_user_data)
  tags = {
    Name = "github-runner-user-data"
  }
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
      import urllib.request
      import json
      import os
      from datetime import datetime, timezone, timedelta

      ec2 = boto3.client('ec2', region_name='us-west-1')
      ssm = boto3.client('ssm', region_name='us-west-1')
      lambda_client = boto3.client('lambda', region_name='us-west-1')

      REPO = 'ejc3/fcvm'
      # Lease duration - busy runners get extended, idle runners expire
      LEASE_DURATION_MINUTES = 60

      def get_github_pat():
          """Get GitHub PAT from SSM"""
          try:
              resp = ssm.get_parameter(Name='/github-runner/pat', WithDecryption=True)
              pat = resp['Parameter']['Value']
              print(f'SSM PAT value starts with: {pat[:10] if pat else "None"}...')
              if pat and pat != 'placeholder':
                  return pat
          except Exception as e:
              print(f'SSM get_parameter failed: {e}')
          return None

      def get_runners(pat):
          """Get all runners from GitHub, returns dict of name -> {id, busy}"""
          # per_page is 30 by default, and a truncated list reads as "this runner is
          # not registered" - which is how instances get reaped or double-counted.
          url = f'https://api.github.com/repos/{REPO}/actions/runners?per_page=100'
          req = urllib.request.Request(url, headers={
              'Authorization': f'token {pat}',
              'Accept': 'application/vnd.github.v3+json'
          })
          try:
              with urllib.request.urlopen(req) as resp:
                  data = json.loads(resp.read())
                  return {r['name']: {'id': r['id'], 'busy': r['busy']} for r in data.get('runners', [])}
          except Exception as e:
              print(f'Failed to get runners: {e}')
          return {}

      def deregister_runner(runner_id, pat):
          """Remove runner from GitHub by ID"""
          try:
              del_url = f'https://api.github.com/repos/{REPO}/actions/runners/{runner_id}'
              del_req = urllib.request.Request(del_url, method='DELETE', headers={
                  'Authorization': f'token {pat}',
                  'Accept': 'application/vnd.github.v3+json'
              })
              urllib.request.urlopen(del_req)
              return True
          except Exception as e:
              print(f'Failed to deregister runner {runner_id}: {e}')
          return False

      def get_instance_state(instance_id):
          """Check if instance exists and is running"""
          try:
              resp = ec2.describe_instances(InstanceIds=[instance_id])
              for res in resp['Reservations']:
                  for inst in res['Instances']:
                      return inst['State']['Name']
          except Exception:
              pass
          return None

      def get_tag(instance, key):
          """Get tag value from instance"""
          for tag in instance.get('Tags', []):
              if tag['Key'] == key:
                  return tag['Value']
          return None

      # A runner instance that has not left `pending` by now is a failed launch, not
      # a runner. AWS accepts run_instances for a metal spot instance it cannot place
      # and only reports instance-terminated-no-capacity much later - on 2026-08-07
      # three c5d.metal launches waited nearly two hours for that verdict. Nothing
      # else reaps them: the lease phase only walks instances in `running`, so a husk
      # that never boots is never terminated and keeps occupying a slot.
      # Kept in step with STARTUP_TIMEOUT_MINUTES in the webhook Lambda, which uses
      # the same window to decide an instance type has just failed.
      STARTUP_TIMEOUT_MINUTES = 15

      def reap_stalled_launch(instance_id, now):
          """Record why this launch died, then terminate it.

          The tag has to be written before the terminate call. Once we terminate,
          the instance's state reason becomes Client.UserInitiatedShutdown and
          nothing records that capacity was the problem, so the webhook Lambda would
          pick the same instance type again on the next poll - which is exactly the
          loop that pinned x86 to c5d.metal for three consecutive attempts.
          """
          try:
              ec2.create_tags(
                  Resources=[instance_id],
                  Tags=[{'Key': 'CapacityFailedAt', 'Value': now.isoformat()}]
              )
          except Exception as e:
              print(f'Failed to tag {instance_id} as a capacity failure: {e}')
          try:
              ec2.terminate_instances(InstanceIds=[instance_id])
              return True
          except Exception as e:
              print(f'Failed to terminate stalled launch {instance_id}: {e}')
          return False

      def renew_lease(instance_id, now):
          """Extend the lease by LEASE_DURATION_MINUTES"""
          new_expiry = (now + timedelta(minutes=LEASE_DURATION_MINUTES)).isoformat()
          try:
              ec2.create_tags(
                  Resources=[instance_id],
                  Tags=[{'Key': 'LeaseExpires', 'Value': new_expiry}]
              )
              return new_expiry
          except Exception as e:
              print(f'Failed to renew lease on {instance_id}: {e}')
          return None

      # The queue scan is bounded by what the pool could serve, not by a fixed sample
      # of runs. Sampling the newest few runs with status=queued hides real work two
      # ways. A run that is `in_progress` still holds queued jobs, and the runs query
      # does not return it at all: on 2026-08-07 run 31202629167 went in_progress at
      # 17:40 and kept two arm64 jobs queued until 18:25, invisible for 45 minutes.
      # And ejc3/fcvm carries six runs from 2026-08-06 that are permanently
      # status=queued with zero jobs and cannot be cancelled, force-cancelled or
      # deleted through the API. The runs endpoint returns newest first, so those six
      # sit ahead of any older real work and a five-run sample can be nothing but
      # undrainable phantoms.
      QUEUE_SCAN_MAX_RUNS = 200

      def github_get(pat, url):
          """GET a GitHub API endpoint and return parsed JSON. Raises on failure."""
          req = urllib.request.Request(url, headers={
              'Authorization': f'token {pat}',
              'Accept': 'application/vnd.github.v3+json'
          })
          with urllib.request.urlopen(req, timeout=5) as resp:
              return json.loads(resp.read())

      def list_run_ids(pat, status, limit):
          """Run IDs with the given status, newest first, paged up to limit"""
          run_ids = []
          page = 1
          while len(run_ids) < limit:
              data = github_get(pat, f'https://api.github.com/repos/{REPO}/actions/runs?status={status}&per_page=100&page={page}')
              runs = data.get('workflow_runs', [])
              if not runs:
                  break
              run_ids.extend(run['id'] for run in runs)
              page += 1
          return run_ids[:limit]

      def queued_self_hosted_jobs(pat, run_id):
          """Queued self-hosted jobs in one run, following every page.

          The jobs endpoint returns 30 per page by default. A run with more jobs
          than that would silently hide every queued job past the page boundary.
          """
          jobs = []
          for page in range(1, 11):
              data = github_get(pat, f'https://api.github.com/repos/{REPO}/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}')
              batch = data.get('jobs', [])
              jobs.extend(batch)
              if len(batch) < 100:
                  break
          return [j for j in jobs
                  if j.get('status') == 'queued'
                  and 'self-hosted' in [l.lower() for l in j.get('labels', [])]]

      def queued_demand(pat, cap):
          """Count queued self-hosted jobs per architecture.

          `cap` is the only thing that stops the scan early, and only once both
          architectures already want more runners than the pool can hold - past that
          point more scanning cannot change what gets launched. Nothing else
          truncates: every queued and in-progress run is inspected, and a run with no
          queued jobs contributes nothing rather than consuming a sample slot.
          """
          demand = {'arm64': 0, 'x86_64': 0}
          run_ids = list(dict.fromkeys(
              list_run_ids(pat, 'queued', QUEUE_SCAN_MAX_RUNS)
              + list_run_ids(pat, 'in_progress', QUEUE_SCAN_MAX_RUNS)
          ))[:QUEUE_SCAN_MAX_RUNS]
          for scanned, run_id in enumerate(run_ids):
              if all(count >= cap for count in demand.values()):
                  print(f'Queue scan satisfied after {scanned} of {len(run_ids)} runs')
                  break
              for job in queued_self_hosted_jobs(pat, run_id):
                  labels = [l.lower() for l in job.get('labels', [])]
                  if 'x64' in labels or 'x86_64' in labels or 'amd64' in labels:
                      demand['x86_64'] += 1
                  else:
                      demand['arm64'] += 1
          return demand

      def handler(event, context):
          pat = get_github_pat()
          print(f'PAT available: {bool(pat)}')
          runners = get_runners(pat) if pat else {}
          print(f'Found {len(runners)} runners from GitHub')
          now = datetime.now(timezone.utc)

          # Phase 1: Clean up orphaned GitHub runners (instances gone)
          orphans_cleaned = []
          for runner_name, runner_info in runners.items():
              if not runner_name.startswith('runner-i-'):
                  print(f'Skipping {runner_name} (not runner-i- pattern)')
                  continue
              instance_id = runner_name.replace('runner-', '')
              state = get_instance_state(instance_id)
              print(f'Runner {runner_name}: instance state={state}')
              if state is None or state in ('terminated', 'shutting-down'):
                  print(f'Cleaning orphan: {runner_name} (state={state})')
                  if deregister_runner(runner_info['id'], pat):
                      orphans_cleaned.append(runner_name)

          # Phase 2: Lease-based runner management
          # - Busy runners: renew lease (extend expiry)
          # - Idle runners: don't renew (let lease expire)
          # - Expired lease: terminate
          response = ec2.describe_instances(
              Filters=[
                  {'Name': 'tag:Role', 'Values': ['github-runner']},
                  {'Name': 'instance-state-name', 'Values': ['running']}
              ]
          )

          terminated = []
          renewed = []
          expired = []

          for reservation in response['Reservations']:
              for instance in reservation['Instances']:
                  instance_id = instance['InstanceId']
                  launch_time = instance['LaunchTime']
                  runner_name = f'runner-{instance_id}'
                  lease_expires_str = get_tag(instance, 'LeaseExpires')

                  # Skip if launched less than 10 minutes ago (initial setup time)
                  if now - launch_time < timedelta(minutes=10):
                      print(f'{instance_id}: launched {(now - launch_time).seconds // 60}m ago, skipping (setup)')
                      continue

                  # Get runner status from GitHub
                  runner_info = runners.get(runner_name, {})
                  is_busy = runner_info.get('busy', False)

                  # Parse lease expiry
                  if lease_expires_str:
                      try:
                          lease_expires = datetime.fromisoformat(lease_expires_str.replace('Z', '+00:00'))
                      except Exception as e:
                          print(f'{instance_id}: failed to parse LeaseExpires={lease_expires_str}: {e}')
                          lease_expires = now + timedelta(minutes=LEASE_DURATION_MINUTES)
                  else:
                      # No lease tag - set one (legacy instance)
                      print(f'{instance_id}: no lease tag, setting initial lease')
                      lease_expires = now + timedelta(minutes=LEASE_DURATION_MINUTES)
                      renew_lease(instance_id, now)
                      continue

                  minutes_until_expiry = (lease_expires - now).total_seconds() / 60

                  if is_busy:
                      # Runner is working - RENEW the lease
                      new_expiry = renew_lease(instance_id, now)
                      print(f'{instance_id}: busy, renewed lease until {new_expiry}')
                      renewed.append(instance_id)
                      continue

                  # Runner is idle - check if lease expired
                  if lease_expires <= now:
                      print(f'Terminating expired: {instance_id} (lease expired {-minutes_until_expiry:.1f}m ago)')
                      if runner_info.get('id'):
                          deregister_runner(runner_info['id'], pat)
                      ec2.terminate_instances(InstanceIds=[instance_id])
                      terminated.append(instance_id)
                      expired.append(instance_id)
                  else:
                      print(f'{instance_id}: idle, lease expires in {minutes_until_expiry:.1f}m (not renewing)')

          # Phase 3: Clean up stale AMI builder instances (> 2 hours old)
          ami_builder_terminated = []
          ami_response = ec2.describe_instances(
              Filters=[
                  {'Name': 'tag:Name', 'Values': ['ami-builder-temp']},
                  {'Name': 'instance-state-name', 'Values': ['running', 'pending']}
              ]
          )
          for reservation in ami_response['Reservations']:
              for instance in reservation['Instances']:
                  instance_id = instance['InstanceId']
                  launch_time = instance['LaunchTime']
                  age_hours = (now - launch_time).total_seconds() / 3600
                  if age_hours > 2:
                      print(f'Terminating stale AMI builder: {instance_id} (age={age_hours:.1f}h)')
                      ec2.terminate_instances(InstanceIds=[instance_id])
                      ami_builder_terminated.append(instance_id)

          # Phase 3b: Reap launches that never came up
          # A spot metal launch AWS cannot place sits in `pending`, where the lease
          # phase above cannot see it - that phase only walks `running` instances.
          # Left alone the husk holds one of MAX_RUNNERS slots and, worse, takes the
          # record of which instance type failed to the grave with it.
          stalled_launches = []
          pending_response = ec2.describe_instances(
              Filters=[
                  {'Name': 'tag:Role', 'Values': ['github-runner']},
                  {'Name': 'instance-state-name', 'Values': ['pending']}
              ]
          )
          for reservation in pending_response['Reservations']:
              for instance in reservation['Instances']:
                  instance_id = instance['InstanceId']
                  pending_minutes = (now - instance['LaunchTime']).total_seconds() / 60
                  if pending_minutes < STARTUP_TIMEOUT_MINUTES:
                      print(f'{instance_id}: pending {pending_minutes:.0f}m, inside the startup window')
                      continue
                  print(f'Reaping stalled launch: {instance_id} ({instance.get("InstanceType")}, pending {pending_minutes:.0f}m)')
                  if reap_stalled_launch(instance_id, now):
                      stalled_launches.append(instance_id)

          # Phase 4: Launch runners for queued jobs
          # GitHub does not redeliver workflow_job webhooks, so a delivery lost to a
          # bad secret, or a launch lost to spot capacity, is only ever recovered
          # here. That makes this poll the last line of defence, and it has to see
          # the whole queue rather than a sample of it.
          launched = []
          if pat:
              try:
                  max_runners = int(os.environ.get('MAX_RUNNERS', '4'))
                  demand = queued_demand(pat, max_runners)
                  print(f'Queued self-hosted jobs by architecture: {demand}')
                  webhook_fn = os.environ.get('WEBHOOK_FUNCTION', '')
                  for arch in sorted(demand):
                      labels = ['self-hosted', 'Linux', 'X64'] if arch == 'x86_64' else ['self-hosted', 'Linux', 'ARM64']
                      # One invoke per queued job, capped at the pool size. The
                      # webhook Lambda stays the single authority on that cap - it
                      # has reserved concurrency 1, so invocations serialise and each
                      # re-reads the live count - and answers any surplus with "max
                      # reached". Sending a single invoke per architecture instead
                      # filled the pool at one runner per five minutes no matter how
                      # deep the queue was.
                      for _ in range(min(demand[arch], max_runners)):
                          # Direct invoke: no requestContext, so the handler trusts it
                          # without a header. Skips HMAC, which API Gateway callers cannot.
                          payload = {
                              'body': json.dumps({'action': 'queued', 'workflow_job': {'labels': labels}}),
                              'headers': {}
                          }
                          try:
                              lambda_client.invoke(
                                  FunctionName=webhook_fn,
                                  InvocationType='Event',
                                  Payload=json.dumps(payload)
                              )
                              launched.append(arch)
                          except Exception as e:
                              print(f'Failed to invoke webhook for {arch}: {e}')
                              break
              except Exception as e:
                  print(f'Failed to check queued jobs: {e}')

          return {'terminated': terminated, 'renewed': renewed, 'expired': expired, 'orphans_cleaned': orphans_cleaned, 'stalled_launches': stalled_launches, 'ami_builder_terminated': ami_builder_terminated, 'retry_launched': launched}
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

  # The queue scan is one GitHub call per candidate run, and it must not have to
  # choose between finishing and seeing the whole queue. 240s leaves headroom
  # under the 5-minute schedule so invocations cannot overlap.
  timeout = 240

  environment {
    variables = {
      WEBHOOK_FUNCTION = var.enable_github_runner ? aws_lambda_function.runner_webhook[0].function_name : ""
      MAX_RUNNERS      = tostring(local.runner_max_per_arch) # Bounds the queue scan and per-poll launches
    }
  }

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
