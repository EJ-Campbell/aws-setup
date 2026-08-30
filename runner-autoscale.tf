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
      import urllib.request
      from datetime import datetime, timezone, timedelta

      ec2 = boto3.client('ec2', region_name='us-west-1')
      ssm = boto3.client('ssm', region_name='us-west-1')

      REPO = 'ejc3/fcvm'

      # An instance younger than this counts toward the cap even though GitHub has
      # no registration for it yet. A *.metal instance spends several minutes in
      # hardware POST before user_data starts, and it only registers after that
      # script installs and configures the runner. The cleanup Lambda already
      # treats "younger than 10 minutes" as still-setting-up; 15 is that window
      # plus one 5-minute poll interval, so the two Lambdas can never disagree
      # about the same instance. Without the window a booting instance would be
      # invisible and every poll would launch another one on top of it.
      BOOT_GRACE_MINUTES = 15

      # Ceiling on non-terminated instances per architecture, regardless of health.
      # Health filtering is what lets scale-up step over a wedged runner, but if the
      # health signal is ever wrong in the "nothing is healthy" direction it would
      # launch metal spot instances without limit. Two spare slots absorb a poll's
      # worth of reaping lag and cap the blast radius of a bad signal at two extra
      # instances per architecture.
      LAUNCH_HEADROOM = 2

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

      def github_get(pat, url):
          """GET a GitHub API endpoint and return parsed JSON. Raises on failure."""
          req = urllib.request.Request(url, headers={
              'Authorization': f'token {pat}',
              'Accept': 'application/vnd.github.v3+json'
          })
          with urllib.request.urlopen(req, timeout=5) as resp:
              return json.loads(resp.read())

      def get_github_pat():
          """Read the runner PAT from SSM; None when unset or still the placeholder"""
          try:
              resp = ssm.get_parameter(Name='/github-runner/pat', WithDecryption=True)
              pat = resp['Parameter']['Value']
              if pat and pat != 'placeholder':
                  return pat
          except Exception as e:
              print(f'SSM get_parameter failed: {e}')
          return None

      # Same two bounds as the cleanup Lambda's roster read, for the same reason.
      ROSTER_PAGE_LIMIT = 10
      ROSTER_PAGE_SIZE = 100

      def get_online_runner_names():
          """Names of runners GitHub can currently reach, or None if that is unknown.

          None is deliberately distinct from the empty set: it means GitHub could
          not be asked, and callers must fall back to counting instances instead of
          concluding that every instance is dead.

          A read that came back INCOMPLETE is unknown too. One page was taken as
          the whole roster, so an online runner past the page boundary counted as
          absent, `counted` fell below the cap and the launcher added metal to a
          pool that was already full. GitHub reports total_count beside the page,
          so short is detectable rather than silently partial.

          A record with no name is skipped rather than raising. The set
          comprehension used to sit outside the try, so one malformed entry took
          KeyError out of get_capacity and out of the handler, and nothing was
          launched - and GitHub delivers a workflow_job event once, without
          redelivery.
          """
          pat = get_github_pat()
          if not pat:
              print('No usable PAT in SSM; runner health is unknown')
              return None
          names = set()
          runner_names = set()
          runner_ids = set()
          collected = 0
          total = None
          try:
              for page in range(1, ROSTER_PAGE_LIMIT + 1):
                  data = github_get(pat, f'https://api.github.com/repos/{REPO}/actions/runners?per_page={ROSTER_PAGE_SIZE}&page={page}')
                  batch = data.get('runners')
                  if not isinstance(batch, list):
                      print('Runner list carries no runners array; runner health is unknown')
                      return None
                  page_total = data.get('total_count')
                  if (not isinstance(page_total, int) or isinstance(page_total, bool)
                          or page_total < 0):
                      print('Runner list carries no usable total_count; runner health is unknown')
                      return None
                  if total is None:
                      total = page_total
                  elif page_total != total:
                      print('Runner list total_count changed while paging; runner health is unknown')
                      return None
                  if collected + len(batch) > total:
                      print('Runner list contains more records than total_count; runner health is unknown')
                      return None
                  for record in batch:
                      name = record.get('name') if isinstance(record, dict) else None
                      runner_id = record.get('id') if isinstance(record, dict) else None
                      if (not isinstance(name, str) or not name.strip()
                              or not isinstance(runner_id, int)
                              or isinstance(runner_id, bool) or runner_id <= 0):
                          print('Runner list carries an unusable runner identity; runner health is unknown')
                          return None
                      if name in runner_names or runner_id in runner_ids:
                          print('Runner list contains a duplicate identity; runner health is unknown')
                          return None
                      runner_names.add(name)
                      runner_ids.add(runner_id)
                      if record.get('status') == 'online':
                          names.add(name)
                  collected += len(batch)
                  if collected == total:
                      return names
                  if len(batch) < ROSTER_PAGE_SIZE:
                      print(f'Runner list came back with {collected} of the {total} GitHub reports; '
                            f'runner health is unknown')
                      return None
          except Exception as e:
              print(f'Failed to list GitHub runners: {e}')
              return None
          print(f'Runner list runs past {ROSTER_PAGE_LIMIT} pages; runner health is unknown')
          return None

      def get_capacity(arch):
          """Count runner instances for arch that can actually take work.

          The cap has to be held by runners GitHub can hand a job to, not by EC2
          instances that merely exist. On 2026-08-07 two wedged ARM instances stayed
          'running' to EC2 and held 2 of the 4 ARM slots for 3.5 hours while CI
          queued. An instance counts when GitHub has it registered and online, or
          when it is still inside BOOT_GRACE_MINUTES and no registration is due yet.

          The boot-grace boundary is also the stalled-launch boundary: a launch
          still pending past STARTUP_TIMEOUT_MINUTES (== BOOT_GRACE_MINUTES) is a
          husk, not a runner - on 2026-08-07 three doomed c5d.metal launches sat
          pending while the old instance count answered "Max x86_64 runners (4)
          reached" until AWS terminated them at 20:31. Such an instance is neither
          online nor inside the grace window, so it stops counting here at exactly
          the moment the cleanup Lambda becomes willing to reap it.
          """
          filters = [
              {'Name': 'tag:Role', 'Values': ['github-runner']},
              {'Name': 'instance-state-name', 'Values': ['pending', 'running']}
          ]
          if arch:
              name_value = f'github-runner-{arch}'
              filters.append({'Name': 'tag:Name', 'Values': [name_value]})
          response = ec2.describe_instances(Filters=filters)
          instances = [i for r in response['Reservations'] for i in r['Instances']]
          if not instances:
              # Nothing to classify, so don't spend a GitHub call on it. This is the
              # cold-start case, which is also the one that must answer fastest.
              return {'counted': 0, 'instances': 0, 'online': 0, 'booting': 0, 'degraded': False}

          online_names = get_online_runner_names()
          if online_names is None:
              # Health is unknown, so degrade to the pre-2026-08-07 instance count.
              # Over-counting only delays CI and self-heals on the next poll;
              # under-counting launches metal spot instances on data we could not
              # verify. Fail toward the cheaper mistake.
              return {'counted': len(instances), 'instances': len(instances),
                      'online': 0, 'booting': 0, 'degraded': True}

          now = datetime.now(timezone.utc)
          online = 0
          booting = 0
          for inst in instances:
              if f'runner-{inst["InstanceId"]}' in online_names:
                  online += 1
              elif now - inst['LaunchTime'] < timedelta(minutes=BOOT_GRACE_MINUTES):
                  booting += 1
          return {'counted': online + booting, 'instances': len(instances),
                  'online': online, 'booting': booting, 'degraded': False}

      def emit_decision(arch, queued_jobs, capacity, max_runners, decision, detail):
          """One CloudWatch Embedded Metric Format line per scale-up decision.

          The only evidence that scale-up was gated for 3.5 hours on 2026-08-07 was
          an unstructured log line nobody was watching. EMF makes this line both
          greppable in Logs Insights and a real metric, with no PutMetricData call
          and no extra IAM.
          """
          # Work is queued and this decision refused to add capacity for it.
          #
          # Deliberately NOT gated on counted < max_runners, which is what this
          # started as. On 2026-08-07 both wedged ARM runners were GitHub-online, so
          # counted was 4 of 4 for the whole 3.5-hour window -- that gate pinned the
          # metric to 0 for precisely the incident it was written for. A metric that
          # reads 0 through its own motivating outage is worse than none: it gets
          # trusted.
          #
          # Ordinary saturation raises this too, and -- worth being straight about --
          # a single poll CANNOT separate the two. In the incident the wedged runners
          # reported busy=true to GitHub, which is exactly what a healthy runner mid-job
          # reports, so there is no field here that distinguishes "working" from "stuck
          # holding a job forever".
          #
          # So the alarm does not try. It is keyed on the queue failing to drain for two
          # hours, which is longer than several waves of the longest measured job
          # (43.5 min) and is worth a look whichever cause it turns out to be: a pool
          # that is wedged and a pool that is genuinely two hours behind are both
          # situations someone wants to know about. An earlier version claimed 60 min
          # separated them by comparing against a SINGLE job duration; it does not,
          # because consecutive waves keep the queue non-empty indefinitely.
          starved = 1 if decision == 'blocked' and queued_jobs > 0 else 0
          # Jobs are waiting and there is nothing that can take them: nothing online,
          # and nothing on the way either.
          #
          # `booting == 0` is load-bearing, not caution. A normal cold start emits a
          # successful launch decision with online == 0, and metal takes minutes to
          # register -- BOOT_GRACE_MINUTES allows 15 of them. Keying on `online` alone
          # would raise this on the poll after every cold start and page in ten minutes
          # while all requested capacity was arriving exactly as intended.
          #
          # Suppressed while degraded too: with GitHub unreachable `online` is 0 by
          # construction and this would be pure noise; runner-pat-unusable covers that.
          no_online = 1 if (queued_jobs > 0 and not capacity['degraded']
                            and capacity['online'] == 0 and capacity['booting'] == 0) else 0
          print(json.dumps({
              '_aws': {
                  'Timestamp': int(datetime.now(timezone.utc).timestamp() * 1000),
                  'CloudWatchMetrics': [{
                      'Namespace': 'GitHubRunners',
                      'Dimensions': [['Architecture']],
                      'Metrics': [
                          {'Name': 'QueuedJobs', 'Unit': 'Count'},
                          {'Name': 'HealthyRunners', 'Unit': 'Count'},
                          {'Name': 'OnlineRunners', 'Unit': 'Count'},
                          {'Name': 'InstancesCounted', 'Unit': 'Count'},
                          {'Name': 'ScaleUpStarved', 'Unit': 'Count'},
                          {'Name': 'ZeroOnlineRunners', 'Unit': 'Count'}
                      ]
                  }]
              },
              'event': 'runner_scale_decision',
              'Architecture': arch,
              'QueuedJobs': queued_jobs,
              'HealthyRunners': capacity['counted'],
              'InstancesCounted': capacity['instances'],
              'ScaleUpStarved': starved,
              # Promoted from the plain `online_runners` property to a real metric:
              # a value you can only reach by grepping logs is not something an alarm
              # can watch, and this is the number that says whether anything can
              # actually take a job.
              'OnlineRunners': capacity['online'],
              'ZeroOnlineRunners': no_online,
              'booting_runners': capacity['booting'],
              'max_runners': max_runners,
              'health_source': 'instances-only' if capacity['degraded'] else 'github',
              'decision': decision,
              'detail': detail
          }))

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
          # ARM types must ALSO be Graviton3 or newer (family digit >= 7).
          # fcvm's nested-virtualisation tests need FEAT_NV2, which Graviton2
          # does not have, so a job landing on c6gd/m6gd.metal fails every
          # test_kvm case. That is exactly what happened on 2026-08-15: adding
          # c6gd.metal and m6gd.metal for spot availability turned main red
          # with 9 failures (nested KVM, NFS, reflink, copy_file_range) on
          # runner-i-01eb621cc8b41c0bf, a c6gd.metal. Storage is necessary,
          # not sufficient.
          #
          # Every type here must have instance storage - the 'd' families -
          # because THIS BOOTSTRAP builds /mnt/fcvm-btrfs only from instance-store
          # NVMe. fcvm itself does not need it (setup falls back to a loopback
          # btrfs image, src/setup/storage.rs); what fcvm requires is btrfs, for
          # reflink CoW. So a storeless type is unusable until user_data grows
          # that fallback, not unusable in principle. On 2026-08-15 a c7g.metal
          # spot instance came up, died in user_data at NVME_DEVS with no disk to
          # find, never registered, and sat there billing while jobs queued.
          # Verify additions with:
          #   aws ec2 describe-instance-types --instance-types <t> \
          #     --query 'InstanceTypes[].InstanceStorageSupported'
          if arch == 'x86_64':
              types = ['c5d.metal', 'm5d.metal', 'r5d.metal', 'm6id.metal']
          else:
              types = ['c7gd.metal', 'm7gd.metal', 'r7gd.metal']
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
          # Case-insensitive header lookup. This line IS the webhook fix: the API
          # Gateway route uses payload format 1.0, which preserves original header
          # casing, and GitHub sends X-Hub-Signature-256 -- so a lowercase-only
          # lookup read the signature as absent and fail-closed 401'd EVERY real
          # delivery, regardless of any secret. (Format 2.0 lowercases headers,
          # which is how the bug hid in every lowercase-header test.)
          headers = {k.lower(): v for k, v in (event.get('headers') or {}).items()}

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

          # Check per-architecture capacity. queued_jobs is supplied by the cleanup
          # Lambda's poll (it counts them); a real GitHub delivery is one job.
          max_runners = int(os.environ.get('MAX_RUNNERS', '3'))
          try:
              # Coerce: a non-numeric value would make the EMF line invalid and
              # silently drop every metric on it, including ScaleUpStarved.
              queued_jobs = int(payload.get('queued_jobs', 1))
          except (TypeError, ValueError):
              queued_jobs = 1
          capacity = get_capacity(arch)

          if capacity['counted'] >= max_runners:
              detail = f'Max {arch} runners ({max_runners}) reached'
              emit_decision(arch, queued_jobs, capacity, max_runners, 'blocked', detail)
              return {'statusCode': 200, 'body': detail}

          if capacity['instances'] >= max_runners + LAUNCH_HEADROOM:
              detail = (f'{arch} instance ceiling ({max_runners + LAUNCH_HEADROOM}) reached '
                        f'with only {capacity["counted"]} able to take work')
              emit_decision(arch, queued_jobs, capacity, max_runners, 'blocked', detail)
              return {'statusCode': 200, 'body': detail}

          # How many to launch in THIS invocation. A real GitHub delivery is always
          # one job -> one launch. The cleanup poll instead sends its whole deficit
          # as launch_count in a SINGLE invocation per architecture: DescribeInstances
          # is eventually consistent, so a burst of separate invocations - even
          # serialized by reserved concurrency 1 - can each miss the instance the
          # previous one just launched and overshoot the cap. Inside one invocation
          # the loop counts its own launches, which no consistency lag can hide.
          # launch_count is honored only on IAM-authed direct invokes (no
          # requestContext), so a signed public delivery cannot amplify.
          requested = 1
          if 'requestContext' not in event:
              try:
                  requested = max(1, min(int(payload.get('launch_count', 1)), max_runners))
              except (TypeError, ValueError):
                  requested = 1
          # Bounded by whichever ceiling is tighter: healthy-capacity cap or the
          # absolute instance ceiling. Both were checked >= 1 slot free above.
          budget = min(requested,
                       max_runners - capacity['counted'],
                       max_runners + LAUNCH_HEADROOM - capacity['instances'])

          launched_here = []
          instance_type = None
          try:
              for _ in range(budget):
                  spot_id, instance_type = launch_runner(arch)
                  launched_here.append(spot_id)
          except Exception as e:
              emit_decision(arch, queued_jobs, capacity, max_runners, 'launch-failed',
                            f'{e} (after {len(launched_here)} launched this invocation)')
              raise
          detail = f'Launched {len(launched_here)} {arch} runner(s) ({instance_type}): {",".join(launched_here)}'
          emit_decision(arch, queued_jobs, capacity, max_runners, 'launched', detail)
          return {'statusCode': 200, 'body': detail}
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
      WEBHOOK_SECRET    = random_password.github_webhook[0].result
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

# ============================================
# Webhook HMAC secret -- generated once, written to both sides
# ============================================
#
# The secret GitHub signs `workflow_job` deliveries with, and the secret the Lambda
# verifies them against, are now the same Terraform-generated value. They used to be two
# hand-carried copies: an operator pasted one string into GitHub's webhook form and a
# matching one into the gitignored `terraform.tfvars` as `github_webhook_secret`. Nothing
# checked that the copies still agreed, and at some point they stopped agreeing.
#
# `verify_signature` fails closed, so the mismatch was total: every one of the 5,026
# deliveries GitHub still retains for hook 589197362 (2026-08-05T21:11Z through
# 2026-08-07T22:49Z) returned 401 or 503 and not one returned 200. Event-driven scale-up
# was dead for two days -- the pool survived only on the five-minute cleanup poll, which
# contributed to a multi-hour runner-pool collapse on 2026-08-07.
#
# No human chooses, transcribes, or stores this value now, so the two halves cannot drift.

resource "random_password" "github_webhook" {
  count = var.enable_github_runner ? 1 : 0

  # Alphanumeric on purpose. An HMAC-SHA256 key gains nothing from punctuation, and the
  # value passes through a Lambda environment variable, a JSON API body and whatever
  # someone eventually pastes into a shell to debug it. 64 chars is ~380 bits.
  length  = 64
  special = false
}

# ============================================
# GitHub side of the webhook
# ============================================
#
# CREDENTIALS: a dedicated fine-grained PAT in Secrets Manager, the same shape as the
# Cloudflare token in `cloudflare.tf` -- minted by hand, never in the repo, and readable
# only by the administrator roles that run Terraform. It needs exactly one repository
# permission on `ejc3/fcvm`: **Webhooks: Read and write** (the classic-PAT equivalent is
# `admin:repo_hook`). Nothing else.
#
# Why a third token rather than reusing one of the two that already exist: measured on
# 2026-08-07, neither can do this. `github-pat-ejc3` (Secrets Manager, readable by
# `dev-server-role` on both metal boxes) and `/github-runner/pat` (SSM, readable by the
# runner instance role, i.e. by CI jobs) are both fine-grained PATs without the Webhooks
# permission -- each returns 403 "Resource not accessible by personal access token" on
# `GET /repos/ejc3/fcvm/hooks`. Adding the permission to either would let any dev box, or
# any job running on a self-hosted runner, repoint or disable the CI webhook. This account
# already keeps GitHub PATs scoped one per purpose; this is the third.

# Gated so that disabling the runner stack (or losing the secret) can never break
# unrelated plans: an ungated data source is read on EVERY plan, and a missing
# secret would fail the documented one-flip teardown along with everything else.
data "aws_secretsmanager_secret_version" "github_webhook_admin_pat" {
  count     = var.enable_github_runner ? 1 : 0
  secret_id = "github-webhook-admin-pat"
}

provider "github" {
  owner = "ejc3"
  token = var.enable_github_runner ? data.aws_secretsmanager_secret_version.github_webhook_admin_pat[0].secret_string : null
}

# The pre-existing hook is 589197362 and MUST be imported before the first apply, or this
# creates a second hook delivering to the same URL:
#
#   terraform import 'github_repository_webhook.runner[0]' fcvm/589197362
#
# Not a declarative `import` block: this resource is count-gated, and an import block whose
# `to` is `...runner[0]` fails to resolve the moment `enable_github_runner` goes false,
# which would break the documented one-flip teardown. Cloudflare's resources were adopted
# with the same CLI import, so this matches how the rest of the repo was reconciled.
#
# Its live configuration already matches every attribute below, so the import is clean and
# in-place: only `repository` is ForceNew, and GitHub never returns the secret. The first
# plan after import therefore shows no replacement of the hook -- just the in-place
# `configuration.secret` change from the API's "********" placeholder to the generated
# value, alongside the creation of `random_password.github_webhook[0]` itself and the
# webhook Lambda's WEBHOOK_SECRET env update that consumes it. The hook keeps its id.
resource "github_repository_webhook" "runner" {
  count      = var.enable_github_runner ? 1 : 0
  repository = "fcvm"
  events     = ["workflow_job"]
  active     = true

  configuration {
    url          = "${aws_apigatewayv2_api.runner_webhook[0].api_endpoint}/webhook"
    content_type = "json"
    insecure_ssl = false
    secret       = random_password.github_webhook[0].result
  }

  # Only the API Gateway is referenced above, so without this the hook could be created
  # before the Lambda behind that route exists. Ordering it after the function means
  # GitHub is never pointed at a live URL with nothing to answer it, and it fixes the
  # direction of a rotation window: Lambda takes the new secret first, GitHub second.
  #
  # Rotation (`terraform apply -replace='random_password.github_webhook[0]'`) changes both
  # halves in one apply, but not atomically -- for the seconds between the two API calls
  # GitHub still signs with the old value and deliveries 401. That is the fail-closed
  # direction and the five-minute cleanup poll picks up anything missed, so it is fine.
  depends_on = [aws_lambda_function.runner_webhook]
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
# `|| true`: on a storeless instance type grep matches nothing and returns 1,
# which under `set -e` killed the whole bootstrap right here -- before the
# NVME_COUNT check below could report anything, before the IPv6 gate, and before
# registration. The box then sat billing, unregistered, with the real reason
# only visible in its console log.
NVME_DEVS=$(lsblk -dn -o NAME,TYPE | awk '$2=="disk" && /^nvme/ {print $1}' | grep -v "^$ROOT_DEV$" || true)
NVME_COUNT=$(echo "$NVME_DEVS" | wc -w)
if [ "$NVME_COUNT" -eq 0 ]; then
  echo "FATAL: no instance-store NVMe on this instance type; /mnt/fcvm-btrfs cannot be built, refusing to register this runner"
  lsblk -dn -o NAME,TYPE,SIZE || true
  exit 1
fi
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

# Assign a global IPv6 address, make the OS acquire it, and PROVE it before
# this runner is allowed to register.
#
# AWS run_instances can't set both Ipv6AddressCount and Ipv6PrefixCount in the same
# NetworkInterfaces entry, so we assign the IPv6 address post-launch. Assigning it
# to the ENI is only half the job: the guest still has to pick it up over DHCPv6,
# on its own schedule. On 2026-08-15 a job ran on a runner whose ENI already held
# 2600:1f1c:208:c01::baca while the OS had no global IPv6 at all; every routed and
# IPv6 test failed with "No global IPv6 address found on host", which reads as a
# code flake rather than the runner defect it is. A runner that cannot run the
# suite must not take jobs, so this fails closed: no address, no registration.

# Same rule fcvm uses (detect_host_ipv6 in src/network/routed.rs): a
# non-deprecated scope-global inet6 that is not a ULA, either carrying a /64
# prefix or a /128 backed by an on-link /64 route.
have_global_v6() {
  local addrs a p
  addrs=$(ip -6 addr show scope global 2>/dev/null | awk '/inet6 /&&!/deprecated/{print $2}' | grep -v '^fd') || return 1
  [ -n "$addrs" ] || return 1
  if echo "$addrs" | grep -q '/64$'; then return 0; fi
  for a in $addrs; do
    p=$(echo "$a" | cut -d/ -f1 | awk -F: '{printf "%s:%s:%s:%s", $1,$2,$3,$4}')
    if ip -6 route show | grep -q "^$p::/64 "; then return 0; fi
  done
  return 1
}

TOKEN6=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
MAC=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN6" http://169.254.169.254/latest/meta-data/mac)
ENI_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN6" "http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/interface-id")
REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN6" http://169.254.169.254/latest/meta-data/placement/region)

# Idempotent: only add an address if the ENI has none, and retry the API rather
# than letting one throttled call decide the fate of the instance.
ENI_V6=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI_ID" --region "$REGION" \
  --query 'NetworkInterfaces[0].Ipv6Addresses[*].Ipv6Address' --output text 2>/dev/null || true)
if [ -z "$ENI_V6" ]; then
  for attempt in 1 2 3 4 5; do
    if aws ec2 assign-ipv6-addresses --network-interface-id "$ENI_ID" --ipv6-address-count 1 --region "$REGION"; then
      echo "IPv6 address assigned to $ENI_ID"
      break
    fi
    sleep $((attempt * 3))
  done
else
  echo "ENI $ENI_ID already holds IPv6: $ENI_V6"
fi

# Ask the OS for it now instead of waiting for the next DHCPv6 renew.
V6_IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
for round in 1 2 3; do
  if have_global_v6; then break; fi
  netplan apply || true
  networkctl renew "$V6_IFACE" || true
  for i in $(seq 1 15); do
    if have_global_v6; then break; fi
    sleep 2
  done
done

if ! have_global_v6; then
  echo "FATAL: no global IPv6 on $V6_IFACE after assign+renew; refusing to register this runner"
  ip -6 addr show || true
  ip -6 route show || true
  exit 1
fi
echo "global IPv6 ready on $V6_IFACE:"
ip -6 addr show scope global

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
#
# GZIPPED, not just base64. The two runner gates pushed this script from 5,482 to 8,386
# characters, and base64 inflates by a third: 11,184 against a hard ceiling of 8,192.
# Advanced is the largest SSM tier, so the apply failed outright --
#
#   ValidationException: The specified parameter value is too large.
#   Advanced-tier parameters support a maximum parameter value of 8192 characters.
#
# base64gzip brings it to 4,712, with room for the script to keep growing.
#
# Safe because BOTH decoders are already in the path, and neither is new behaviour:
#   - cloud-init's EC2 datasource calls util.maybe_b64decode on the raw user-data
#     (sources/DataSourceEc2.py), which validates and decodes, or passes it through
#     untouched. That is why the existing double-encoding works at all: botocore
#     base64-encodes UserData again in before-parameter-build.ec2.RunInstances.
#   - cloud-init then calls util.decomp_gzip (user_data.py) on the payload.
#
# Anything that reads this parameter back must gunzip as well as decode:
#   aws ssm get-parameter ... --output text | base64 -d | gunzip
resource "aws_ssm_parameter" "runner_user_data" {
  count = var.enable_github_runner ? 1 : 0
  name  = "/github-runner/user-data"
  type  = "String"
  tier  = "Advanced"
  value = base64gzip(local.runner_user_data)
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

      # A runner instance's life is bounded in two steps: a SOFT CAP where it stops
      # being useful and starts draining, and a HARD CEILING it can never outlive.
      #
      # Why a bound exists at all: renewal is only safe while 'busy' means "making
      # progress". A wedged host (leaked VMs, load average in the hundreds,
      # unkillable D-state processes) keeps its assigned job forever, so GitHub keeps
      # reporting busy=true and the renewal loop below never lets the lease expire -
      # the broken instance becomes immortal and permanently occupies one of
      # MAX_RUNNERS slots per architecture (ejc3/fcvm#871).
      #
      # 12h is a deliberate LOCAL policy, not a platform limit. GitHub allows a
      # self-hosted job to run for up to 5 days (the 6h cap is for GitHub-hosted
      # runners only), and these runners are not ephemeral, so one instance can
      # legitimately chain many short jobs past 12h of age. Every ejc3/fcvm CI job
      # finishes in well under 2 hours, so a runner this old has outlived its
      # usefulness and is quite likely wedged.
      #
      # Past this age the instance DRAINS rather than dying: it is terminated on the
      # first poll that observes it idle, and a job already in flight is left to
      # finish. See DRAIN_GRACE_MINUTES for the bound that keeps that from being
      # open-ended.
      MAX_INSTANCE_AGE_HOURS = 12

      # Grace added on top of the soft cap. MAX_INSTANCE_AGE_HOURS + this is the HARD
      # CEILING - 13h30m, the absolute maximum lifetime of a runner instance - and it
      # is enforced regardless of busy state, regardless of whether GitHub answered,
      # regardless of anything else. It is evaluated on the 5-minute poll, so the
      # observed maximum is 13h30m plus at most one poll interval.
      #
      # Why the cap alone was wrong: it terminated the instance whatever it was
      # doing. On 2026-08-28/29 it killed i-09fff3a7d97fd4066 at 12.07h and
      # i-02fefa9deeb59e9c8 at 12.02h with jobs in flight. EC2 recorded "User
      # initiated" and the spot request said instance-terminated-by-user, but on
      # GitHub both jobs read as "The self-hosted runner lost communication with the
      # server" - indistinguishable from a spot reclaim. That cost six reruns in one
      # night, and a rerun can land on another near-cap runner and die the same way
      # (ejc3/fcvm#884; the symptom was first recorded in ejc3/fcvm#834).
      #
      # Why 90 minutes: it covers the job that is in flight AT the moment a runner
      # crosses the soft cap, plus the poll that notices it finished. The longest
      # legitimate self-hosted job measured on this fleet is 43.5 minutes
      # (Host-Root-arm64-SnapshotEnabled) and a full matrix is about 35, so 90 is a
      # little over 2x that with the poll interval included. It also keeps the
      # absolute lifetime at 13h30m, well inside the property ejc3/fcvm#871 needs:
      # a wedged host dies on a schedule nothing broken can extend.
      #
      # Be clear about what it does NOT cover. A draining runner stays registered
      # and schedulable (the DRAIN branch says why it is not deregistered), so
      # GitHub can hand it a fresh job in the up-to-5-minute gap between its last
      # job ending and the poll that notices. A job starting late in the window can
      # still be cut short at the ceiling, and no value of this constant prevents
      # that - only an on-box graceful shutdown would, which this Lambda has no
      # channel to request. The drain removes the guaranteed kill of every job in
      # flight at 12h; it does not make the ceiling harmless.
      #
      # If fcvm ever gains a legitimately long job, raise the SOFT CAP, not this.
      # This number is sized to one job, not to a working day.
      DRAIN_GRACE_MINUTES = 90

      # A runner whose current job has been executing this long is stuck by
      # definition. Across five recent green CI runs the longest legitimate
      # self-hosted job was 43.5 minutes (Host-Root-arm64-SnapshotEnabled), so 180
      # leaves better than 4x headroom and cannot reap healthy work. Nothing else
      # bounds it: GitHub enforces no server-side job-execution limit for
      # self-hosted runners, and the runner-side timeout-minutes default (360) is
      # enforced by the runner process on the box - exactly what a wedged host
      # cannot do. On 2026-08-07 a job sat in_progress for 5h18m on a box with load
      # 523 while GitHub still reported that runner online and busy, so neither the
      # lease nor a liveness check can see it. The job's own age is the one
      # server-side signal that separates "holds a job" from "makes progress".
      MAX_JOB_RUNTIME_MINUTES = 180

      # Cap on per-run job lookups in a single poll, so a backlog of stale
      # in-progress runs cannot walk this Lambda into its timeout.
      MAX_STUCK_SCAN_RUNS = 10

      def github_get(pat, url):
          """GET a GitHub API endpoint and return parsed JSON. Raises on failure."""
          req = urllib.request.Request(url, headers={
              'Authorization': f'token {pat}',
              'Accept': 'application/vnd.github.v3+json'
          })
          with urllib.request.urlopen(req, timeout=5) as resp:
              return json.loads(resp.read())

      def parse_ts(value):
          """Parse a GitHub ISO-8601 timestamp as UTC-aware; None if unusable.

          The result is compared against an aware `now`, and mixing the two raises
          TypeError - out of get_stuck_runners, out of the handler, and out of the
          whole poll, so NOTHING gets reaped that invocation, the hard age ceiling
          included. A timestamp carrying no offset is therefore stamped UTC rather
          than returned naive: GitHub documents these fields as UTC, and a value
          that cannot be made comparable is worth less than the poll it would kill.
          """
          if not value:
              return None
          try:
              parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
          except Exception:
              return None
          return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

      def get_stuck_runners(pat, now):
          """Runners whose in-progress job started over MAX_JOB_RUNTIME_MINUTES ago.

          Returns {runner_name: (job_name, minutes_running)}.

          Fail-safe: every GitHub error yields no candidates, so an outage or rate
          limit reaps nothing, and a runner is only named when GitHub itself says
          that runner is still executing that job.

          Cheap: a job cannot have started before its run did, so a run that started
          inside the ceiling is skipped without a jobs call. In steady state that is
          one list call per poll and no per-run calls at all.
          """
          cutoff = now - timedelta(minutes=MAX_JOB_RUNTIME_MINUTES)
          stuck = {}
          try:
              runs = github_get(pat, f'https://api.github.com/repos/{REPO}/actions/runs?status=in_progress&per_page=50')
          except Exception as e:
              print(f'Stuck-job scan: cannot list in-progress runs: {e}')
              return stuck

          candidates = []
          for run in runs.get('workflow_runs', []):
              started = parse_ts(run.get('run_started_at') or run.get('created_at'))
              # Unparseable start time: keep it as a candidate. Checking costs one
              # call and reaping still needs per-job evidence below.
              if started is not None and started > cutoff:
                  continue
              candidates.append((started or cutoff, run))
          candidates.sort(key=lambda c: c[0])

          # Rotate the scan WINDOW across polls instead of pinning the same
          # oldest-first prefix: with more than MAX_STUCK_SCAN_RUNS over-age runs,
          # a fixed prefix of stale hosted-only runs would starve a wedged
          # self-hosted runner in position N+1 forever. The window index is derived
          # from wall clock (stateless -- Lambda invocations share nothing) and
          # advances by a WHOLE window per 5-minute poll, so consecutive polls
          # select disjoint chunks and every candidate is inspected within
          # ceil(N / MAX_STUCK_SCAN_RUNS) polls. (Advancing the offset by one
          # candidate per poll would overlap windows and stretch full coverage to
          # N polls.)
          if len(candidates) > MAX_STUCK_SCAN_RUNS:
              num_windows = -(-len(candidates) // MAX_STUCK_SCAN_RUNS)  # ceil
              start = (int(now.timestamp() // 300) % num_windows) * MAX_STUCK_SCAN_RUNS
              window = candidates[start:start + MAX_STUCK_SCAN_RUNS]
          else:
              window = candidates

          for _, run in window:
              try:
                  jobs = github_get(pat, f'https://api.github.com/repos/{REPO}/actions/runs/{run["id"]}/jobs?per_page=50')
              except Exception as e:
                  print(f'Stuck-job scan: cannot list jobs for run {run.get("id")}: {e}')
                  continue
              for job in jobs.get('jobs', []):
                  if job.get('status') != 'in_progress':
                      continue
                  started = parse_ts(job.get('started_at'))
                  if started is None or started > cutoff:
                      continue
                  name = job.get('runner_name') or ''
                  if name.startswith('runner-i-'):
                      stuck[name] = (job.get('name'), (now - started).total_seconds() / 60)
          return stuck

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

      # How many pages of the runner roster one poll will follow, and how big a
      # page it asks for. The repo holds at most MAX_RUNNERS per architecture
      # plus whatever registrations the orphan phase has not cleaned up yet, so
      # one page is the steady state; the bound is here so a runaway list cannot
      # walk this Lambda into its timeout.
      ROSTER_PAGE_LIMIT = 10
      ROSTER_PAGE_SIZE = 100

      def read_runner_roster_once(pat):
          """Read one complete, duplicate-free pagination of the runner roster."""
          roster = {}
          runner_ids = set()
          collected = 0
          total = None
          try:
              for page in range(1, ROSTER_PAGE_LIMIT + 1):
                  url = (f'https://api.github.com/repos/{REPO}/actions/runners'
                         f'?per_page={ROSTER_PAGE_SIZE}&page={page}')
                  req = urllib.request.Request(url, headers={
                      'Authorization': f'token {pat}',
                      'Accept': 'application/vnd.github.v3+json'
                  })
                  with urllib.request.urlopen(req, timeout=10) as resp:
                      data = json.loads(resp.read())
                  batch = data.get('runners')
                  if not isinstance(batch, list):
                      print('ROSTER UNREAD: the runners response carries no runners array')
                      return None
                  page_total = data.get('total_count')
                  if (not isinstance(page_total, int) or isinstance(page_total, bool)
                          or page_total < 0):
                      print('ROSTER UNREAD: total_count is not a non-negative integer')
                      return None
                  if total is None:
                      total = page_total
                  elif page_total != total:
                      print(f'ROSTER UNREAD: total_count changed from {total} to '
                            f'{page_total} while paging')
                      return None
                  if collected + len(batch) > total:
                      print(f'ROSTER UNREAD: more records than total_count={total}')
                      return None

                  # status is preserved as-absent when GitHub omits it. A missing
                  # status can neither renew nor expire a lease; only an explicit
                  # offline status identifies the wedged-busy case.
                  #
                  # A malformed or duplicate identity makes the WHOLE answer
                  # unread. Dropping or overwriting one record turns pagination
                  # churn into false evidence that whichever runner was skipped is
                  # absent. Names need text, and ids feed both re-read and DELETE
                  # URLs, so they must be positive integers rather than bools (a
                  # bool is an int subclass in Python).
                  for record in batch:
                      name = record.get('name') if isinstance(record, dict) else None
                      runner_id = record.get('id') if isinstance(record, dict) else None
                      if (not isinstance(name, str) or not name.strip()
                              or not isinstance(runner_id, int)
                              or isinstance(runner_id, bool) or runner_id <= 0):
                          print('ROSTER UNREAD: a runner record has no usable name or id')
                          return None
                      if name in roster or runner_id in runner_ids:
                          print(f'ROSTER UNREAD: duplicate runner identity '
                                f'name={name!r} id={runner_id!r}')
                          return None
                      runner_ids.add(runner_id)
                      roster[name] = {'id': runner_id, 'busy': record.get('busy'),
                                      'status': record.get('status')}

                  collected += len(batch)
                  if collected == total:
                      return roster
                  if len(batch) < ROSTER_PAGE_SIZE:
                      print(f'ROSTER UNREAD: read {collected} of the {total} registrations '
                            f'GitHub reports')
                      return None
          except Exception as e:
              print(f'ROSTER UNREAD: {type(e).__name__}: {e}')
              return None
          print(f'ROSTER UNREAD: more than {ROSTER_PAGE_LIMIT} pages of runners')
          return None

      def get_runners(pat):
          """A stable registered-runner snapshot, or None when absence is unproved.

          None is deliberately distinct from {} ("GitHub answered twice, and
          nothing is registered"). Lease expiry and orphan cleanup both destroy
          resources on roster absence. A count-complete pagination is not enough:
          registrations can move across a page boundary during the read, repeating
          one record while skipping another. Each pass therefore rejects duplicate
          names and ids, and two complete passes must agree exactly before any
          absence is actionable.
          """
          first = read_runner_roster_once(pat)
          if first is None:
              return None
          second = read_runner_roster_once(pat)
          if second is None:
              return None
          if first != second:
              print('ROSTER UNREAD: runner roster changed between complete reads')
              return None
          return first

      def still_idle(runner_id, pat):
          """Re-read ONE runner and confirm GitHub still says it holds no job.

          The busy flags this poll acts on were read at the top of the handler,
          before the orphan scan's per-runner EC2 lookups and the stuck-job scan,
          which between them can spend tens of seconds. GitHub hands out jobs
          throughout, so terminating on that snapshot destroys whatever the runner
          picked up in the gap - and does it on the quiet path, where nothing is
          recorded as a possible loss.

          Fails safe in both directions: unanswerable means "not confirmed idle",
          so the caller drains instead of terminating, and the hard ceiling still
          bounds how long that can last.
          """
          try:
              record = github_get(pat, f'https://api.github.com/repos/{REPO}/actions/runners/{runner_id}')
          except Exception as e:
              print(f'Cannot re-read runner {runner_id} before terminating it: {type(e).__name__}: {e}')
              return False
          return record.get('busy') is False

      def deregister_runner(runner_id, pat):
          """Remove runner from GitHub by ID"""
          try:
              del_url = f'https://api.github.com/repos/{REPO}/actions/runners/{runner_id}'
              del_req = urllib.request.Request(del_url, method='DELETE', headers={
                  'Authorization': f'token {pat}',
                  'Accept': 'application/vnd.github.v3+json'
              })
              urllib.request.urlopen(del_req, timeout=10)
              return True
          except Exception as e:
              print(f'Failed to deregister runner {runner_id}: {e}')
          return False

      def get_instance_state(instance_id):
          """The instance's state, 'gone' when EC2 says there is no such instance,
          or None when EC2 could not be asked.

          None has to be distinct from 'gone'. The orphan phase deregisters a runner whose
          instance has disappeared, and GitHub documents that DELETE as forcing the
          removal - so reading one transient DescribeInstances failure as "gone"
          forces out a HEALTHY runner in the middle of a job. That is work
          destroyed on absent evidence, the same defect as ejc3/fcvm#884 wearing a
          different phase.

          "Gone" genuinely arrives as an exception: a terminated instance drops out
          of DescribeInstances about an hour later and the call then raises
          InvalidInstanceID.NotFound. The error code is what separates the two, so
          orphans are still cleaned up.
          """
          try:
              resp = ec2.describe_instances(InstanceIds=[instance_id])
          except Exception as e:
              code = getattr(e, 'response', {}).get('Error', {}).get('Code')
              if code in ('InvalidInstanceID.NotFound', 'InvalidInstanceID.Malformed'):
                  return 'gone'
              print(f'Cannot read the state of {instance_id}: {type(e).__name__}: {e}')
              return None
          for res in resp['Reservations']:
              for inst in res['Instances']:
                  return inst['State']['Name']
          return 'gone'

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
              # Do NOT terminate on a failed tag: terminating rewrites the state
              # reason and the capacity evidence is gone forever, so the launcher
              # would re-pick the same doomed type - the exact loop this function
              # exists to break. The instance stays pending; the next poll retries
              # both the tag and the terminate.
              print(f'Failed to tag {instance_id} as a capacity failure: {e}; deferring the terminate')
              return False
          try:
              ec2.terminate_instances(InstanceIds=[instance_id])
              return True
          except Exception as e:
              print(f'Failed to terminate stalled launch {instance_id}: {e}')
          return False

      def terminate(instance_id, reason):
          """Terminate one instance; True only if EC2 accepted the call.

          The per-instance guard in the sweep must not absorb this. A rejected
          terminate (an IAM change, DisableApiTermination, a transient 5xx) leaves
          the instance RUNNING, and an invocation that swallowed it would report
          success while the fleet's only lifetime bound quietly did nothing - and,
          worse, would log the cause as an unreadable EC2 record. The next poll
          retries; the age it is judged on only grows.
          """
          try:
              ec2.terminate_instances(InstanceIds=[instance_id])
              return True
          except Exception as e:
              print(f'TERMINATE FAILED: {instance_id} ({reason}) is STILL RUNNING: '
                    f'{type(e).__name__}: {e}. Retried on the next poll.')
          return False

      # Explicit registration provenance. RunnerSeenAt records every complete
      # roster that listed an instance. LeaseRenewedAt is written atomically with
      # an actual busy-runner renewal, so a failed separate seen write cannot lose
      # the fact. Neither signal is inferred from timestamp arithmetic.
      SEEN_TAG = 'RunnerSeenAt'
      RENEWED_TAG = 'LeaseRenewedAt'

      def renew_lease(instance_id, now):
          """Extend a working runner's lease and persist why it moved."""
          new_expiry = (now + timedelta(minutes=LEASE_DURATION_MINUTES)).isoformat()
          try:
              ec2.create_tags(
                  Resources=[instance_id],
                  Tags=[
                      {'Key': 'LeaseExpires', 'Value': new_expiry},
                      {'Key': RENEWED_TAG, 'Value': now.isoformat()},
                  ]
              )
              return new_expiry
          except Exception as e:
              print(f'Failed to renew lease on {instance_id}: {e}')
          return None

      def set_initial_lease(instance_id, now):
          """Give a legacy instance one lease without claiming it registered."""
          expiry = (now + timedelta(minutes=LEASE_DURATION_MINUTES)).isoformat()
          try:
              ec2.create_tags(Resources=[instance_id],
                              Tags=[{'Key': 'LeaseExpires', 'Value': expiry}])
              return expiry
          except Exception as e:
              print(f'Failed to set initial lease on {instance_id}: {e}')
          return None

      # The four things the age phase can decide. Named constants rather than bare
      # strings so a typo is a NameError at import, not a termination that silently
      # stops happening.
      KEEP = 'keep'
      DRAIN = 'drain'
      TERMINATE_IDLE = 'terminate_idle'
      TERMINATE_CEILING = 'terminate_ceiling'

      def observed_idle(runner_info):
          """True only when GitHub answered AND says this runner holds no job.

          Anything else - no record for the instance, no 'busy' key, an exception
          get_runners() swallowed into an empty dict - is absence of evidence, and
          absence of evidence must never be read as idle. Reading it that way is
          how a healthy in-flight job gets destroyed on a GitHub blip.
          """
          return bool(runner_info) and runner_info.get('busy') is False

      def age_policy(now, launch_time, runner_info):
          """What the age phase does with one running runner instance. Pure.

          (clock, launch time, GitHub's record for this runner) in, one action out.
          No AWS or GitHub calls, so scripts/test-runner-lambdas.py pins every
          branch, including the ones that only occur during a GitHub outage.

          TERMINATE_CEILING is derived from launch_time ALONE. No busy flag, no
          missing runner record and no failed API call can defer it, because the
          property ejc3/fcvm#871 needs is that a wedged host dies on a schedule
          nothing broken can extend. TERMINATE_IDLE requires positive evidence of idleness.
          Everything else past the soft cap drains.

          This reads `busy` WITHOUT the status == 'online' qualifier the lease phase
          uses. There, treating an offline-but-busy runner as idle is what stops a
          wedged host renewing its lease forever. Here the same reading would kill
          the job of a runner whose connection blipped for one poll, and it buys
          nothing: the ceiling bounds the wedge, and the stuck-job phase reaps a
          job running past MAX_JOB_RUNTIME_MINUTES at any age.
          """
          age = now - launch_time
          if age >= timedelta(hours=MAX_INSTANCE_AGE_HOURS, minutes=DRAIN_GRACE_MINUTES):
              return TERMINATE_CEILING
          if age <= timedelta(hours=MAX_INSTANCE_AGE_HOURS):
              return KEEP
          return TERMINATE_IDLE if observed_idle(runner_info) else DRAIN

      # What GitHub's roster says about ONE runner, and therefore what the lease
      # phase may do with its instance. Named constants for the same reason as
      # the age policy's: a typo is a NameError at import rather than a
      # termination that quietly stops happening.
      RENEW = 'renew'
      EXPIRE = 'expire'
      HOLD = 'hold'

      # Stamped on an instance on every poll where GitHub's roster listed its
      # runner. LeaseRenewedAt is independent explicit evidence of the same fact,
      # written in the same CreateTags call as a busy runner's new expiry. Two jobs
      # need that recorded fact:
      #
      #  - it separates "GitHub answered and does not list this runner" from
      #    "this runner has never been registered at all". The first is
      #    ambiguous: a real deregistration and an answer that dropped records
      #    look identical from here. The second is a box that booted and never
      #    joined - user_data refuses to register without a global IPv6 address,
      #    and skips registration entirely when the PAT does not read back from
      #    SSM - and the lease is the only thing that reaps one of those. It sits
      #    in `running`, where the stalled-launch phase (which walks `pending`)
      #    cannot see it.
      #  - it dates an outage. This Lambda is stateless and polls every 5
      #    minutes, so without a timestamp a held lease logs the same line
      #    forever and a blip is indistinguishable from a three-hour outage.
      #
      def mark_seen(instance_id, now):
          """Record that GitHub's roster listed this instance's runner."""
          try:
              ec2.create_tags(Resources=[instance_id],
                              Tags=[{'Key': SEEN_TAG, 'Value': now.isoformat()}])
          except Exception as e:
              print(f'Failed to stamp {SEEN_TAG} on {instance_id}: {e}')

      def lease_verdict(roster, runner_name, registered_before):
          """What GitHub's answer lets the lease phase do with one runner. Pure.

          RENEW  GitHub reports the runner online and holding a job, so the
                 lease is extended.
          EXPIRE GitHub answered with something that cannot mean "working". The
                 lease is allowed to lapse, and the instance is terminated once
                 it has.
          HOLD   GitHub said nothing usable about this runner. The lease stays
                 exactly where it is - not renewed, because a wedged host must
                 still reach the age ceiling, and not acted on when it expires,
                 because absence of evidence is not idleness.

          HOLD is what ejc3/aws#45 added. Before it, every answer that was not
          an explicit busy+online took the idle path, so a GitHub outage lasting
          longer than the remaining lease reaped runners that were executing
          jobs, up to 60 minutes in, while still under the soft cap.

          A host that wedges mid-job reports busy=true and status=offline, and
          renewing on that made it immortal (ejc3/fcvm#871). That explicit pair
          still lets the lease lapse. A missing or unrecognised status is not the
          same evidence: it holds the lease rather than terminating a working
          runner on a field GitHub did not send.
          """
          if roster is None:
              return HOLD
          record = roster.get(runner_name)
          if record is None:
              # A roster we could read is authoritative about REGISTRATION. If it
              # has never once listed this runner, the box never joined and cannot
              # be holding a job GitHub handed out, so the lease reaps it as it
              # always has. If it listed the runner before and does not now, the
              # two explanations are not separable here, so hold and let the
              # ceiling bound it.
              return HOLD if registered_before else EXPIRE
          busy = record.get('busy')
          if busy is True:
              status = record.get('status')
              if status == 'online':
                  return RENEW
              if status == 'offline':
                  return EXPIRE
              return HOLD
          if busy is False:
              return EXPIRE
          # A record with no usable busy flag. `.get('busy', False)` used to read
          # the missing key as "holds no job", which is a termination decided out
          # of a field GitHub did not send.
          return HOLD

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
      # Applied PER STATUS, never to the concatenated list: a combined cap would
      # let permanently-queued phantom runs (which sort ahead of real work) evict
      # every in_progress run from the scan. Worst-case runtime is governed by the
      # time budget below, not by this count.
      QUEUE_SCAN_MAX_RUNS = 200

      # Hard wall-clock budget for the queue scan. The worst case without it is
      # one 5s-timeout GitHub call per scanned run - far beyond the Lambda
      # timeout, which is not catchable, so a long scan would kill the whole poll
      # and launch NOTHING. A truncated scan under-counts demand, which the next
      # poll corrects; a dead poll corrects nothing.
      QUEUE_SCAN_TIME_BUDGET_SECONDS = 120

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

          Three bounds, each reported when it fires: the saturation exit (both
          architectures already want at least as many runners as the pool holds,
          so more scanning cannot change what gets launched), QUEUE_SCAN_MAX_RUNS
          per status (per status so phantom queued runs can never evict the
          in_progress runs from the scan), and a wall-clock budget (a Lambda
          timeout is not catchable and would kill the whole poll). Truncation
          under-counts demand; the next poll corrects it. A run with no queued
          jobs contributes nothing rather than consuming a sample slot.
          """
          demand = {'arm64': 0, 'x86_64': 0}
          scan_start = datetime.now(timezone.utc)
          run_ids = list(dict.fromkeys(
              list_run_ids(pat, 'queued', QUEUE_SCAN_MAX_RUNS)
              + list_run_ids(pat, 'in_progress', QUEUE_SCAN_MAX_RUNS)
          ))
          for scanned, run_id in enumerate(run_ids):
              if all(count >= cap for count in demand.values()):
                  print(f'Queue scan satisfied after {scanned} of {len(run_ids)} runs')
                  break
              elapsed = (datetime.now(timezone.utc) - scan_start).total_seconds()
              if elapsed > QUEUE_SCAN_TIME_BUDGET_SECONDS:
                  print(f'Queue scan hit its {QUEUE_SCAN_TIME_BUDGET_SECONDS}s budget after {scanned} of {len(run_ids)} runs; demand is a lower bound')
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
          # `roster is None` means the answer never arrived: the call failed, the
          # payload was unusable, the read was short of GitHub's own total_count,
          # or there was no PAT to ask with. It is NOT the same as an empty
          # roster, and every decision below that ends an instance on roster
          # evidence goes through lease_verdict() or observed_idle(), both of
          # which can tell the two apart. (The stuck-job phase ends instances
          # too, but on per-job evidence, and it reaps nothing when GitHub does
          # not answer.) `runners` is the same thing flattened for the phases
          # that only iterate it.
          roster = get_runners(pat) if pat else None
          if roster is None:
              print('ROSTER UNREAD this poll: no lease may lapse on it, and the age '
                    'ceiling is the only bound still in force')
          else:
              print(f'Found {len(roster)} runners from GitHub')
          runners = roster if roster is not None else {}
          now = datetime.now(timezone.utc)

          # Phase 1: the lifetime bound - the lease sweep and the age policy.
          #
          # FIRST on purpose. Every other phase here is optional work that can
          # spend the 240-second budget: per-runner EC2 describes, GitHub DELETEs
          # at a 10-second timeout, a stuck-job scan of up to eleven 5-second
          # calls. A Lambda timeout is not catchable, so running any of that ahead
          # of the sweep means a slow poll never reaches the age check at all and
          # the hard ceiling silently does not happen.
          #
          # - Busy runners: renew lease (extend expiry)
          # - Idle runners: don't renew (let lease expire)
          # - Expired lease: terminate
          # - Runners GitHub said nothing usable about: hold the lease where it
          #   is, terminating nothing, until the age ceiling
          # - Past MAX_INSTANCE_AGE_HOURS: drain, then the hard ceiling
          response = ec2.describe_instances(
              Filters=[
                  {'Name': 'tag:Role', 'Values': ['github-runner']},
                  {'Name': 'instance-state-name', 'Values': ['running']}
              ]
          )

          terminated = []
          renewed = []
          expired = []
          over_age = []
          # Instances past the soft cap that were left alive to finish work, and
          # instances the hard ceiling killed without ever seeing them idle. The
          # second list is the count that matters: it is work we may have destroyed.
          draining = []
          hard_killed = []
          # Instances whose lease was neither renewed nor allowed to expire,
          # because GitHub said nothing usable about them this poll.
          held = []
          # Instances EC2 refused to terminate. They are STILL RUNNING, so they must
          # never appear in `terminated`, and the poll must not read as a clean sweep.
          terminate_failed = []

          # Pass 1 is the fleet-wide hard bound. It does nothing except read each
          # instance's identity/launch time and attempt required ceiling
          # terminations. In particular it performs no registration stamp or lease
          # renewal. A CreateTags call for a younger instance can consume the
          # Lambda's remaining runtime, so checking only "before writes to this
          # instance" leaves every older instance later in the response unbounded.
          ceiling_instances = set()
          ceiling_terminated = []
          for reservation in response['Reservations']:
              for instance in reservation['Instances']:
                  try:
                      instance_id = instance['InstanceId']
                      launch_time = instance['LaunchTime']
                      if age_policy(now, launch_time, {}) != TERMINATE_CEILING:
                          continue
                      ceiling_instances.add(instance_id)
                      age_hours = (now - launch_time).total_seconds() / 3600
                      if not terminate(instance_id, 'hard ceiling'):
                          terminate_failed.append(instance_id)
                          continue
                      terminated.append(instance_id)
                      over_age.append(instance_id)
                      ceiling_terminated.append((instance_id, age_hours))
                  except Exception as e:
                      broken = instance.get('InstanceId') if isinstance(instance, dict) else None
                      print(f'UNREADABLE INSTANCE RECORD ({broken or "no InstanceId"}) IN '
                            f'CEILING PASS: {type(e).__name__}: {e}. Its age cannot be '
                            f'computed, so this instance is NOT covered by the lifetime '
                            f'bound until its record reads cleanly. Every other instance '
                            f'is still checked before optional writes.')

          # All ceiling terminations have now been attempted. Deregistration and
          # detailed outcome logging are optional follow-up work and can safely run
          # before the ordinary lease pass starts writing tags.
          ceiling_hours = MAX_INSTANCE_AGE_HOURS + DRAIN_GRACE_MINUTES / 60
          for instance_id, age_hours in ceiling_terminated:
              runner_name = f'runner-{instance_id}'
              runner_info = runners.get(runner_name, {})
              if runner_info.get('id'):
                  deregister_runner(runner_info['id'], pat)
              if observed_idle(runner_info):
                  print(f'Terminating over-age: {instance_id} (age={age_hours:.2f}h '
                        f'>= ceiling {ceiling_hours:.2f}h, GitHub reports it idle)')
              else:
                  hard_killed.append(instance_id)
                  print(f'HARD-CEILING KILL: {instance_id} terminated at '
                        f'age={age_hours:.2f}h (ceiling {ceiling_hours:.2f}h = '
                        f'{MAX_INSTANCE_AGE_HOURS}h + {DRAIN_GRACE_MINUTES}m) without '
                        f'ever being observed idle (github '
                        f'busy={runner_info.get("busy")} '
                        f'status={runner_info.get("status")}). Any job it was running '
                        f'is now dead, and GitHub will report "The self-hosted runner '
                        f'lost communication with the server" for it - that is THIS '
                        f'termination, not an AWS spot reclaim.')

          for reservation in response['Reservations']:
              for instance in reservation['Instances']:
                  # One unreadable record must cost that instance, not the ordinary
                  # lease/age pass. The ceiling-only pass above already attempted
                  # every hard-bound termination it could compute. This pass still
                  # isolates malformed fields so one record cannot suppress every
                  # younger instance's lease decision.
                  try:
                      instance_id = instance['InstanceId']
                      if instance_id in ceiling_instances:
                          # Successful and failed attempts both stop here. A runner
                          # already over the ceiling must never receive an optional
                          # tag write after EC2 rejects its required termination.
                          continue
                      launch_time = instance['LaunchTime']
                      runner_name = f'runner-{instance_id}'
                      lease_expires_str = get_tag(instance, 'LeaseExpires')

                      # Skip if launched less than 10 minutes ago (initial setup time)
                      if now - launch_time < timedelta(minutes=10):
                          print(f'{instance_id}: launched {(now - launch_time).seconds // 60}m ago, skipping (setup)')
                          continue

                      # Get runner status from GitHub
                      runner_info = runners.get(runner_name, {})
                      # What that answer lets the lease phase do, and the one fact
                      # a later poll cannot recover for itself: that some poll saw
                      # this runner registered.
                      registered_before = (
                          get_tag(instance, SEEN_TAG) is not None
                          or get_tag(instance, RENEWED_TAG) is not None
                      )
                      verdict = lease_verdict(roster, runner_name, registered_before)

                      # Age policy: drain at MAX_INSTANCE_AGE_HOURS, hard ceiling
                      # DRAIN_GRACE_MINUTES later. Both are documented at those
                      # constants; age_policy() is the whole decision.
                      age_hours = (now - launch_time).total_seconds() / 3600
                      ceiling_hours = MAX_INSTANCE_AGE_HOURS + DRAIN_GRACE_MINUTES / 60
                      action = age_policy(now, launch_time, runner_info)

                      # The fleet-wide ceiling pass has completed before any
                      # registration or lease tag write reaches this point.
                      if roster is not None and runner_name in roster:
                          mark_seen(instance_id, now)

                      if action == TERMINATE_IDLE:
                          # Past the soft cap and holding nothing: go now, before GitHub
                          # can hand it another job. This is what stops a drained runner
                          # taking further work, so it fires on the first poll that
                          # observes idleness rather than waiting for lease expiry.
                          #
                          # Confirmed against a FRESH read first, because the snapshot
                          # this decision came from is tens of seconds old by now and
                          # this path reports nothing as a possible loss.
                          if runner_info.get('id') and not still_idle(runner_info['id'], pat):
                              print(f'Draining: {instance_id} (age={age_hours:.2f}h > '
                                    f'{MAX_INSTANCE_AGE_HOURS}h, idle in the poll snapshot but '
                                    f'not on re-read; leaving it alone)')
                              draining.append(instance_id)
                              continue
                          if not terminate(instance_id, 'drained, past the soft cap'):
                              # Left registered on purpose: it is alive and idle, so it
                              # should keep taking work rather than be forced out of
                              # GitHub and left running with nothing to do.
                              terminate_failed.append(instance_id)
                              continue
                          if runner_info.get('id'):
                              deregister_runner(runner_info['id'], pat)
                          print(f'Terminating drained: {instance_id} (age={age_hours:.2f}h > '
                                f'{MAX_INSTANCE_AGE_HOURS}h, GitHub reports it idle)')
                          terminated.append(instance_id)
                          over_age.append(instance_id)
                          continue

                      if action == DRAIN:
                          # Left running on purpose: GitHub says it holds a job, or could
                          # not be asked. Deliberately NOT deregistered. GitHub documents
                          # that DELETE as "forces the removal of a self-hosted runner"
                          # and does not define what becomes of a job the runner is
                          # part-way through; a forced removal that ends the job is the
                          # exact failure being fixed here, so the shared fleet is not
                          # where we find out. It dies at the ceiling whatever happens.
                          ceiling_at = launch_time + timedelta(hours=MAX_INSTANCE_AGE_HOURS,
                                                               minutes=DRAIN_GRACE_MINUTES)
                          print(f'Draining: {instance_id} (age={age_hours:.2f}h > '
                                f'{MAX_INSTANCE_AGE_HOURS}h, github '
                                f'busy={runner_info.get("busy")} '
                                f'status={runner_info.get("status")}; hard ceiling in '
                                f'{(ceiling_at - now).total_seconds() / 60:.0f}m)')
                          draining.append(instance_id)
                          continue

                      if verdict == HOLD:
                          # Hold the lease where it is. Not renewed: renewing on
                          # an answer we do not have is how a wedged host became
                          # immortal (ejc3/fcvm#871), and this instance still has
                          # to reach the age ceiling. Not expired either: that is
                          # ejc3/aws#45, a job destroyed because GitHub was down.
                          # An instance with no lease tag at all does not get one
                          # here for the same reason; the next answered poll sets it.
                          seen_at = parse_ts(get_tag(instance, SEEN_TAG))
                          unobserved = (f'{(now - seen_at).total_seconds() / 60:.0f}m'
                                        if seen_at else 'its whole life')
                          held.append(instance_id)
                          print(f'{instance_id}: HOLDING the lease at '
                                f'{lease_expires_str or "unset"} - GitHub has said nothing '
                                f'usable about {runner_name} for {unobserved} '
                                f'(roster {"unread" if roster is None else "readable"}, '
                                f'busy={runner_info.get("busy")} '
                                f'status={runner_info.get("status")}). This instance ends '
                                f'at the age ceiling if the answer never comes back.')
                          continue

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
                          if verdict == RENEW:
                              # GitHub explicitly listed this runner online and
                              # busy, so this is a real renewal and carries
                              # provenance even though the old lease was absent.
                              new_expiry = renew_lease(instance_id, now)
                              print(f'{instance_id}: busy, renewed lease until {new_expiry}')
                              renewed.append(instance_id)
                          else:
                              # Grace for a legacy box is not evidence that the
                              # runner ever registered. Keep the write distinct
                              # from renew_lease so a husk still expires next poll.
                              set_initial_lease(instance_id, now)
                          continue

                      minutes_until_expiry = (lease_expires - now).total_seconds() / 60

                      if verdict == RENEW:
                          # Runner is working - RENEW the lease
                          new_expiry = renew_lease(instance_id, now)
                          print(f'{instance_id}: busy, renewed lease until {new_expiry}')
                          renewed.append(instance_id)
                          continue

                      # Runner is idle - check if lease expired
                      if lease_expires <= now:
                          if terminate(instance_id, 'lease expired'):
                              if runner_info.get('id'):
                                  deregister_runner(runner_info['id'], pat)
                              print(f'Terminating expired: {instance_id} '
                                    f'(lease expired {-minutes_until_expiry:.1f}m ago)')
                              terminated.append(instance_id)
                              expired.append(instance_id)
                          else:
                              terminate_failed.append(instance_id)
                      else:
                          print(f'{instance_id}: idle, lease expires in {minutes_until_expiry:.1f}m (not renewing)')
                  except Exception as e:
                      broken = instance.get('InstanceId') if isinstance(instance, dict) else None
                      print(f'UNREADABLE INSTANCE RECORD ({broken or "no InstanceId"}): '
                            f'{type(e).__name__}: {e}. Its age cannot be computed, so there is '
                            f'no safe verdict and it is skipped - this instance is NOT covered '
                            f'by the lifetime bound until its record reads cleanly. Every other '
                            f'instance is still swept.')

          # Phase 2: runners whose current job has run past MAX_JOB_RUNTIME_MINUTES.
          #
          # Wrapped because this is the only GitHub-derived phase that runs BEFORE
          # the reaping phases, and it parses arbitrary API payloads. An exception
          # escaping it takes the whole invocation down before a single instance is
          # examined, which would let the hard age ceiling be deferred indefinitely
          # by one malformed field. Reaping must not depend on this scan succeeding;
          # losing it costs only the stuck-job check, which the next poll retries.
          stuck_runners = {}
          if pat:
              try:
                  stuck_runners = get_stuck_runners(pat, now)
              except Exception as e:
                  print(f'Stuck-job scan failed, continuing without it: {type(e).__name__}: {e}')
          if stuck_runners:
              print(f'Stuck jobs detected on: {sorted(stuck_runners)}')

          # Reap them. The sweep above cannot see this case: GitHub reports the
          # runner online and busy
          # the whole time, so the lease is renewed on every poll forever. The job's
          # own age is per-job, so back-to-back healthy jobs never accumulate
          # toward it and a healthy busy runner is never reaped.
          stuck_terminated = []
          # .get, because the sweep above deliberately tolerates a record it cannot
          # read; rebuilding this set with [] would re-raise on the same record and
          # take every phase after it with it, on every poll.
          running_ids = {i.get('InstanceId') for r in response['Reservations'] for i in r['Instances']}
          for runner_name, (job_name, minutes) in sorted(stuck_runners.items()):
              instance_id = runner_name.replace('runner-', '')
              if instance_id not in running_ids or instance_id in terminated:
                  continue
              # Through terminate(), like every site in the sweep. A raw call here
              # raised straight out of the handler on a rejected TerminateInstances
              # and took every later phase with it, the queued-job launcher
              # included - and since the sweep moved ahead of the orphan cleanup,
              # that cleanup no longer runs before this point either.
              if not terminate(instance_id, 'job past MAX_JOB_RUNTIME_MINUTES'):
                  terminate_failed.append(instance_id)
                  continue
              runner_info = runners.get(runner_name, {})
              if runner_info.get('id'):
                  deregister_runner(runner_info['id'], pat)
              print(f'Terminating stuck: {instance_id} (job {job_name!r} in_progress '
                    f'{minutes:.0f}m > {MAX_JOB_RUNTIME_MINUTES}m)')
              terminated.append(instance_id)
              stuck_terminated.append(instance_id)

          # Phase 3: Clean up orphaned GitHub runners (instances gone)
          orphans_cleaned = []
          for runner_name, runner_info in runners.items():
              if not runner_name.startswith('runner-i-'):
                  print(f'Skipping {runner_name} (not runner-i- pattern)')
                  continue
              instance_id = runner_name.replace('runner-', '')
              if instance_id in running_ids:
                  # The sweep listed this instance as running moments ago, so it is
                  # demonstrably alive whatever a per-id lookup says now.
                  # DescribeInstances is eventually consistent and AWS documents
                  # InvalidInstanceID.NotFound as transient after RunInstances, so
                  # that error alone is not proof of absence - and acting on it
                  # forces a live runner out of GitHub, killing whatever it is
                  # running.
                  continue
              state = get_instance_state(instance_id)
              print(f'Runner {runner_name}: instance state={state}')
              # None means EC2 could not be asked. Leave the registration alone:
              # a runner mid-job would be forced out on nothing but an API blip.
              if state in ('gone', 'terminated', 'shutting-down'):
                  print(f'Cleaning orphan: {runner_name} (state={state})')
                  if deregister_runner(runner_info['id'], pat):
                      orphans_cleaned.append(runner_name)

          # Phase 4: Clean up stale AMI builder instances (> 2 hours old)
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
                      # Through terminate() for the same reason as the sweep: a raw
                      # call here loses the stalled-launch reap and the launcher to
                      # one rejected TerminateInstances.
                      if terminate(instance_id, 'stale AMI builder'):
                          print(f'Terminating stale AMI builder: {instance_id} (age={age_hours:.1f}h)')
                          ami_builder_terminated.append(instance_id)

          # Phase 5: Reap launches that never came up
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

          # Phase 6: Launch runners for queued jobs
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
                      queued_jobs = demand[arch]
                      labels = ['self-hosted', 'Linux', 'X64'] if arch == 'x86_64' else ['self-hosted', 'Linux', 'ARM64']
                      # ONE invoke per architecture, carrying the whole deficit as
                      # launch_count and the raw demand as queued_jobs (the latter
                      # rides into the webhook's decision record). The webhook
                      # launches launch_count runners inside a single invocation,
                      # where its own loop count bounds the total - a burst of
                      # single-launch invocations, even serialized by reserved
                      # concurrency 1, can each miss the instance the previous one
                      # just launched (DescribeInstances is eventually consistent)
                      # and overshoot MAX_RUNNERS.
                      count = min(queued_jobs, max_runners)
                      if count <= 0:
                          continue
                      # Direct invoke: no requestContext, so the handler trusts it
                      # without a header. Skips HMAC, which API Gateway callers cannot.
                      payload = {
                          'body': json.dumps({
                              'action': 'queued',
                              'workflow_job': {'labels': labels},
                              'queued_jobs': queued_jobs,
                              'launch_count': count
                          }),
                          'headers': {}
                      }
                      print(f'Requesting up to {count} {arch} runner(s) in one invocation ({queued_jobs} queued jobs)')
                      try:
                          lambda_client.invoke(
                              FunctionName=webhook_fn,
                              InvocationType='Event',
                              Payload=json.dumps(payload)
                          )
                          launched.extend([arch] * count)
                      except Exception as e:
                          print(f'Failed to invoke webhook for {arch}: {e}')
              except Exception as e:
                  print(f'Failed to check queued jobs: {e}')

          return {'terminated': terminated, 'renewed': renewed, 'expired': expired, 'over_age': over_age, 'draining': draining, 'hard_killed': hard_killed, 'held': held, 'terminate_failed': terminate_failed, 'stuck_terminated': stuck_terminated, 'stalled_launches': stalled_launches, 'orphans_cleaned': orphans_cleaned, 'ami_builder_terminated': ami_builder_terminated, 'retry_launched': launched}
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
  # Worst-case budget: stuck-job scan <= 10 lookups x 5s, queue scan hard-capped
  # at QUEUE_SCAN_TIME_BUDGET_SECONDS (120s) plus run-listing pages, and the
  # lease/reap phases' EC2 calls. 240s covers that with headroom under the
  # 5-minute schedule so invocations cannot overlap; the queue scan's own budget
  # is what guarantees the Lambda timeout (uncatchable) is never the thing that
  # ends a poll.
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

# Async invocations (the cleanup poll's direct invokes) must never be retried by
# Lambda itself: a retry after a partial launch re-reads eventually-consistent
# DescribeInstances, can miss the instances the failed attempt already launched,
# and overshoots the cap. The 5-minute poll IS the retry path, and it re-derives
# the deficit from fresh state.
resource "aws_lambda_function_event_invoke_config" "runner_webhook" {
  count                  = var.enable_github_runner ? 1 : 0
  function_name          = aws_lambda_function.runner_webhook[0].function_name
  maximum_retry_attempts = 0
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
