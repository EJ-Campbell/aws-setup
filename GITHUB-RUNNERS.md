# GITHUB-RUNNERS.md — how CI reaches this AWS account

How `ejc3` repos get CI into AWS account `928413605543` (us-west-1), and what crosses
the GitHub↔AWS boundary to make it work. Defined in `github-actions.tf`,
`runner-autoscale.tf`, and `runner-vpc.tf`.

**The model:** two integrations, opposite directions of trust. GitHub-hosted runners
reach *into* AWS with **no stored credential** — short-lived OIDC federation. Self-hosted
runners run *inside* AWS on spot metal and reach *back* to GitHub with **one long-lived
secret**, a PAT in SSM. Every resource below belongs to one of those two patterns.

|  | Pattern A — hosted → AWS | Pattern B — self-hosted in AWS |
|--|--|--|
| Repos | `ejc3/aws`, `ejc3/fcvm` | `ejc3/fcvm` (uses both) |
| Runs on | GitHub's `ubuntu-latest` | spot `*.metal` in this account |
| Secret across the boundary | none (federated token) | GitHub PAT + webhook HMAC |
| What it does | Terraform drift, AMI builds, CodeArtifact | KVM/Firecracker CI that needs bare metal |
| Credential lifetime | ~1h STS session | PAT until manually rotated |

## Pattern A — hosted runners reach into AWS with OIDC (keyless)

A GitHub-hosted job authenticates to AWS by presenting an OIDC token GitHub signs for it,
which AWS STS exchanges for a ~1-hour role session. Nothing long-lived is stored on either
side — there is no AWS access key in repo secrets to leak or rotate.

The trust chain:
- **OIDC provider** (`aws_iam_openid_connect_provider.github`) — `token.actions.githubusercontent.com`,
  audience `sts.amazonaws.com`, thumbprint `6938fd4d98bab03faadb97b34396831e3780aea1` pinned.
- **Role** `github-actions-terraform` — assumable only via `sts:AssumeRoleWithWebIdentity`
  when the token's `aud` is `sts.amazonaws.com` **and** its `sub` matches
  `repo:ejc3/aws:*` or `repo:ejc3/fcvm:*`. The `sub` is the only thing tying a given
  GitHub repo to this role.
- **Permissions** on that role: account-wide read-only (`Describe*`/`Get*`/`List*` across
  ec2, iam, s3, cloudwatch, logs, rds, lambda, apigateway, budgets, ses, ssm, backup,
  events, sns, sms-voice); Terraform state on `aws-infrastructure-*-tf-state`; the lock table
  `ejc3-terraform-locks` (`GetItem`/`PutItem`/`DeleteItem`); an AMI-builder block
  (`RunInstances`, `Stop`/`TerminateInstances`, `CreateImage`, `CreateTags`, `Register`/`DeregisterImage`);
  `iam:PassRole` on `jumpbox-admin-role`; and CodeArtifact read + publish.

The consumer is `.github/workflows/drift.yml` — daily at 08:00 UTC (and `workflow_dispatch`),
requesting `id-token: write`, then `aws-actions/configure-aws-credentials@v4` with
`role-to-assume: arn:aws:iam::928413605543:role/github-actions-terraform` and a
`terraform plan -detailed-exitcode` to detect drift. No `aws-access-key-id` anywhere in
the workflow.

## Pattern B — self-hosted autoscaling runners on spot metal

`ejc3/fcvm` needs bare metal (nested KVM, Firecracker), which GitHub's hosted runners can't
provide. So a job queued on `ejc3/fcvm` triggers AWS to launch a spot `*.metal` instance
that registers itself back as a self-hosted runner, serves the job, and is reaped when idle.

**Launch path.** GitHub fires a `workflow_job` webhook — the hook itself is Terraform-managed
(`github_repository_webhook.runner`, adopted from hook id 589197362) → API Gateway HTTP API
(`POST /webhook`, output `runner_webhook_url`) → Lambda `github-runner-webhook`
(`reserved_concurrent_executions = 1`, so concurrent webhooks can't all read the same count
and over-launch). The Lambda HMAC-verifies `x-hub-signature-256` against `WEBHOOK_SECRET` on
every request that arrives through API Gateway, **failing closed** if the secret is unset (the
cleanup Lambda's direct `lambda:Invoke` retries carry no `requestContext`, so they're trusted
without a forgeable header); it acts only on `action == "queued"`, reads the job labels to pick
an architecture
(`x64`/`x86_64`/`amd64` → x86, else arm64), and launches a one-time spot instance from a
self-built AMI (`tag:Purpose = github-runner`, newest matching the arch) up to **4 runners
per architecture** (`local.runner_max_per_arch`, shared with the cleanup Lambda). ARM tries
`c7gd`/`m7gd`/`c6gd`/`m6gd.metal`; x86 tries `c5d`/`m5d`/`r5d`/`m6id.metal`, with any type
that recently failed for capacity moved to the back of that order. Each instance is tagged
with a `LeaseExpires` 60 minutes out.

Every type in those lists has instance storage (the `d` families). That is a constraint of
**this bootstrap**, not of fcvm: user_data builds `/mnt/fcvm-btrfs` only from instance-store
NVMe, and the asset directories, the `containers` symlink and `CARGO_TARGET_DIR` all sit
inside that branch, so on a storeless box the mount never happens and every job fails.

fcvm itself does not need instance store. `fcvm setup` falls back to a sparse loopback image
formatted as btrfs when the mount point is not already btrfs (`src/setup/storage.rs`, root
required). What fcvm genuinely requires is **btrfs**, because clone disks are reflink CoW
copies; it refuses to run on a non-btrfs mount at that path. Instance store is what makes it
big and fast — 3.8 TB of local NVMe against a 100 GB gp3 root on ARM, for a workload that
writes multi-GB memory snapshots and a container image cache.

So a storeless type is unusable *until user_data grows that fallback*, which is a real option
if spot capacity for the `d` families ever gets tight. Until then it must not be launched: the
lists previously carried `c7g.metal`, `c5.metal` and `c6i.metal`, all
`InstanceStorageSupported=false`, and on 2026-08-15 a `c7g.metal` spot instance came up, died
in user_data with no disk to find, never registered, and billed while jobs queued. Verify any
addition before adding it:

```bash
aws ec2 describe-instance-types --instance-types <type> \
  --query 'InstanceTypes[].InstanceStorageSupported'
```

`case_every_launchable_type_has_instance_storage` in `scripts/test-runner-lambdas.py` fails
if a storeless type is added back.

**What holds a slot.** The cap counts runners that can *take work*, not EC2 instances that
exist. The Lambda reads the same PAT from SSM, lists `GET /repos/ejc3/fcvm/actions/runners`,
and counts an instance only if GitHub has `runner-<instance-id>` **online**, or the instance
is younger than **`BOOT_GRACE_MINUTES` (15)** and no registration is due yet — a `*.metal`
box spends minutes in POST before user_data starts, and without that window every poll would
launch another instance on top of a booting one. Because booting instances still count, the
cap still binds during a cold start and the herd can never exceed `MAX_RUNNERS` in flight.
A second ceiling, `MAX_RUNNERS + LAUNCH_HEADROOM (2)` **instances** per architecture
regardless of health, caps the blast radius if the health signal is ever wrong in the
"nothing is healthy" direction. If GitHub cannot be reached the Lambda **degrades to the
plain instance count**: over-counting only delays CI and self-heals next poll, while
under-counting launches metal spot instances on data it could not verify.

**Scale-up is observable.** Every decision prints one CloudWatch Embedded Metric Format
line (`event: runner_scale_decision`) carrying `QueuedJobs`, `HealthyRunners`,
`InstancesCounted`, `ScaleUpStarved`, the `Architecture` dimension, and the reason — a
structured log and a real metric in `GitHubRunners` with no `PutMetricData` call and no
extra IAM. `ScaleUpStarved` is 1 only when the instance ceiling blocks a launch that
healthy-runner accounting would have allowed; `cost-alerts.tf` alarms on it
(`runner-scale-up-starved`).

**Registration.** The instance's user_data lives in SSM (`/github-runner/user-data`,
Advanced tier, base64 — too big for Lambda's 4 KB env limit). On boot it sets up the box
(btrfs RAID0 over instance NVMe, `/dev/kvm` permissions, IPv6), reads the PAT from SSM
(`/github-runner/pat`, decrypted), exchanges it for a short-lived **registration token** via
`POST /repos/ejc3/fcvm/actions/runners/registration-token`, and runs
`config.sh --url https://github.com/ejc3/fcvm --token <reg> --name runner-<instance-id>
--labels self-hosted,Linux,<ARM64|X64> --unattended --replace`, then installs the runner as
a service. The PAT itself never leaves AWS; what touches `config.sh` is the ephemeral
registration token derived from it.

Two of those setup steps are **gates, and they run before `config.sh`**: a runner that
cannot host a job must not join the pool, because from CI's side a broken runner is
indistinguishable from a code defect.

- **Instance store.** No instance-store NVMe means `/mnt/fcvm-btrfs` cannot be built, so the
  script refuses to register.
- **Global IPv6.** Assigning the address to the ENI is only half the job; the guest still has
  to acquire it over DHCPv6, on its own schedule. user_data assigns it (idempotently, with
  retries), runs `netplan apply` / `networkctl renew` to ask for it now rather than at the
  next renew, then polls until a usable address appears, using the same rule fcvm's
  `detect_host_ipv6` uses: a non-deprecated scope-global inet6 that is not a ULA, either /64
  or /128 with an on-link /64 route. No address within ~90s, no registration.

  Not hypothetical: on 2026-08-15 a job ran on a runner whose ENI held
  `2600:1f1c:208:c01::baca` while the OS had nothing, and every routed and IPv6 test in the
  fcvm suite failed with `No global IPv6 address found on host` — on a PR that had touched
  only `bench/chromium/*.py`.

`scripts/test-runner-userdata.sh` extracts the real heredoc from the `.tf` and checks that
both gates refuse the shapes they exist for, and that each precedes registration.

**Reaping.** A second Lambda, `github-runner-cleanup`, runs every 5 minutes
(`rate(5 minutes)`) and does six things, four of them using the PAT: deregisters GitHub
runners whose instance is gone; renews the lease on busy runners (+60m) and lets idle ones
expire, then terminates and deregisters anything past its lease (instances younger than 10
minutes are skipped so setup isn't interrupted); **terminates any runner whose current job
has been `in_progress` longer than `MAX_JOB_RUNTIME_MINUTES` (180)**; terminates stray
`ami-builder-temp` instances older than 2 hours (pure EC2, no PAT); reaps launches still
`pending` after 15 minutes; and counts GitHub's queued jobs to launch what the queue
actually needs — GitHub doesn't redeliver webhooks, so this poll is the retry, and it
passes the per-architecture queued count along so the decision record has the demand side
too.

**Why job duration is the health signal.** A wedged host keeps its assigned job, so
`busy` stays true and the lease renews forever; the host is still online, so a liveness check
sees nothing either. GitHub enforces no server-side job-execution limit for self-hosted
runners, and the runner-side `timeout-minutes` default (360) runs *on the box* — exactly what
a wedged box cannot do. The job's own age is the one server-side signal that separates
"holds a job" from "makes progress", and it is per-job, so back-to-back healthy jobs never
accumulate toward it. 180 minutes is over 4x the longest legitimate self-hosted job observed
(43.5m, `Host-Root-arm64-SnapshotEnabled`). The scan is cheap because a job cannot start
before its run: only `in_progress` runs already older than the ceiling get a jobs lookup
(capped at 10 per poll), so steady state is one list call. Every GitHub error yields no
candidates, so an outage or rate limit reaps nothing. This is a control-plane check on
purpose — the runner AMI publishes no CloudWatch metrics, and an on-box guard (the pattern
`ejc3/fcvm` uses for disk in `runner-disk-guard.timer`) cannot be trusted to run on a host
whose scheduler is the thing that failed.

**Two bounds keep a broken runner from becoming immortal.** Renewal treats a runner as busy
only while GitHub explicitly reports it `online` (a missing `status` fails closed to
not-busy), and no instance outlives `MAX_INSTANCE_AGE_HOURS` (12h) regardless of busy
state. Both exist because `busy` means "holds a job", not "makes progress": on 2026-08-07
two ARM runners wedged with ~490 leaked `firecracker` processes and load averages of 389
and 523 (disk was fine at 46%/67%). They kept their assigned jobs, so GitHub kept
reporting `busy=true`, so the lease was renewed every 5 minutes for 21 hours. They
occupied 2 of the 4 ARM slots while doing no work, and `get_running_runners` — which
counts EC2 instances, not healthy runners — reported the pool at max, so no replacement
ever launched and CI sat queued.

The 12h ceiling is a deliberate **local policy**, not a platform limit: GitHub allows a
self-hosted job to run for up to 5 days (the 6h cap applies to GitHub-hosted runners
only), and these runners are not ephemeral, so one instance can legitimately chain many
short jobs past 12h of age. The trade, made explicitly: every fcvm CI job finishes in
well under 2 hours, so a 12h-old runner is overwhelmingly likely wedged. Worst case the
cap kills one healthy in-flight job, which a re-run fixes; a wedged slot silently starves
the whole pool indefinitely, which no re-run fixes. Raise `MAX_INSTANCE_AGE_HOURS` if a
legitimately long job is ever added.

**A spot capacity failure has to move the launcher to the next instance type.** It cannot
discover one by itself: `run_instances` returns an instance ID for a spot request AWS cannot
fulfil and terminates the instance afterwards, so no exception is ever raised and the
`except` branch that was supposed to advance the fallback list never fires. On 2026-08-07 the
poll launched `c5d.metal` at 18:41, 18:46 and 18:51; all three were still `pending` when AWS
marked them `instance-terminated-no-capacity` at 20:31, nearly two hours later, and
`c5.metal`, `c6i.metal` and `m5d.metal` were never tried at all. Three things close that
loop. A launch still `pending` after `STARTUP_TIMEOUT_MINUTES` (15) is a failed launch, not a
runner, so it stops counting toward the cap. The cleanup Lambda stamps `CapacityFailedAt` on
it and terminates it — the tag has to be written first, because terminating rewrites the
state reason to `Client.UserInitiatedShutdown` and the evidence would be lost. And the
launcher reads that record — AWS's own capacity state reasons, the tag, and anything
stalling right now — to move failed types to the back of the list. Back, not out: if every
type has failed the list is only reordered, so a launch is still attempted.

**The queue poll counts jobs, not a sample of runs.** It asks for runs with `status=queued`
*and* `status=in_progress`, pages both, pages each run's jobs, and counts the queued
self-hosted jobs themselves. Three bounds, each logged when it fires: a saturation exit
(both architectures already want at least as many runners as the pool holds, so more
scanning cannot change the launch), `QUEUE_SCAN_MAX_RUNS` (200) applied per status — per
status so phantom queued runs can never evict the in-progress runs from the scan — and a
120-second wall-clock budget, because a Lambda timeout is uncatchable and would kill the
whole poll; a truncated scan merely under-counts, and the next poll corrects it. Sampling the newest five `queued` runs hid real work two
ways. A run that is `in_progress` still holds queued jobs and the `queued` query does not
return it: run 31202629167 went `in_progress` at 17:40 on 2026-08-07 and kept two arm64 jobs
queued until 18:25, invisible for 45 minutes. And `ejc3/fcvm` carries six runs from
2026-08-06 that are permanently `status=queued` with **zero jobs** and cannot be cancelled,
force-cancelled or deleted through the API. Runs come back newest first, so those six sit
ahead of any older real work — more than the five-run sample held. The scan sends the whole
per-architecture deficit to the webhook Lambda as `launch_count` in a single invocation —
one runner per poll used to fill the pool at one runner every five minutes however deep
the queue was, and a burst of single-launch invocations could overshoot the cap, because
DescribeInstances is eventually consistent and each invocation can miss the instance the
previous one just launched. Inside one invocation the handler's own loop bounds the total,
and the webhook Lambda stays the single authority on the cap.


## What crosses the boundary (secrets inventory)

| Secret | Where it lives | Direction | Who reads it | Set / rotated by |
|--|--|--|--|--|
| **GitHub PAT** | `/github-runner/pat`, SSM `SecureString` | GitHub-issued, stored in AWS | `github-runner-instance-role`, `github-runner-lambda-role` | manual `put-parameter`; TF stores `placeholder` with `ignore_changes = [value]` |
| **Webhook HMAC** | `random_password.github_webhook` → Lambda env `WEBHOOK_SECRET` *and* the GitHub hook's `configuration.secret` | shared, both sides | the webhook Lambda; GitHub signs with it | Terraform generates it; both sides written in one apply. Rotate with `terraform apply -replace='random_password.github_webhook[0]'` |
| **Registration token** | minted at boot, never persisted | GitHub-issued, ephemeral | the booting runner only | GitHub API, single use, ~1h TTL |
| **OIDC federation** | no secret — thumbprint pinned on the provider | GitHub asserts, AWS verifies | n/a | trust policy on `github-actions-terraform` |
| **`dev_to_runner` SSH key** | private in SSM `SecureString` `/dev-servers/runner-ssh-key`, public baked into runner `authorized_keys` | AWS-internal (dev box → runner) | dev-server role fetches the private key | TF-generated `tls_private_key` (ED25519) |
| **`fcvm-ec2` keypair** | EC2 keypair `fcvm-ec2` (launch `KeyName`); public key baked into runner `authorized_keys` | AWS-internal (operator → runner) | whoever holds `~/.ssh/fcvm-ec2` (the jumpbox operator) | manual EC2 keypair, never rotated |
| **Webhook admin PAT** | `github-webhook-admin-pat`, Secrets Manager `us-west-1` | GitHub-issued, stored in AWS | the `integrations/github` provider only — no instance role can read it | manual; fine-grained PAT, one permission: `Webhooks: Read and write` on `ejc3/fcvm` |

The one credential GitHub itself holds for Pattern B is the webhook HMAC. Everything else is
either federated (Pattern A) or stored AWS-side and read through IAM.

**Three GitHub PATs, one job each, deliberately not interchangeable.** `github-pat-ejc3`
clones private repos from dev boxes, `/github-runner/pat` registers and reaps runners, and
`github-webhook-admin-pat` owns the webhook. The first two are read by machines that run
other people's code — `dev-server-role` on the metal boxes and the runner instance role on
CI hosts — so neither may hold webhook-write: that would let a dev box or a CI job repoint
the launch endpoint. Measured 2026-08-07, both return 403 "Resource not accessible by
personal access token" on `GET /repos/ejc3/fcvm/hooks`, which is the correct answer.

## IAM boundaries — who can read what

- **`github-runner-instance-role`** (on the runner): `AmazonSSMManagedInstanceCore` for
  Session Manager, `ssm:GetParameter` scoped to **the PAT parameter only**, and
  `ec2:AssignIpv6Addresses` + `ec2:DescribeNetworkInterfaces` (`Resource: *`, for the
  boot-time IPv6 self-assign). A runner cannot read the `dev_to_runner` key or any other
  parameter.
- **`github-runner-lambda-role`** (both Lambdas): logs; EC2
  `Describe`/`Run`/`Stop`/`Terminate`/`CreateTags`; `iam:PassRole`;
  `cloudwatch:GetMetricStatistics`; `ssm:GetParameter` on `/github-runner/*`; and
  `lambda:InvokeFunction` on the webhook function (for the cleanup retry).
- **`github-actions-terraform`** (Pattern A): the read-only + state + AMI-builder set above.
  Its only write into IAM is `PassRole` on `jumpbox-admin-role`.

## Network posture

Runners live in an **isolated VPC** (`10.1.0.0/16`) with no peering to the dev VPC — a
single public `/24` (`10.1.1.0/24`) in **`us-west-1a` only**, internet gateway, dual-stack
IPv6, public IP on launch. That one AZ is the ceiling on the spot fallback: the launcher
walks several instance types but never another subnet/AZ, so a `us-west-1a` capacity gap
fails the launch outright (the cleanup poll is the only retry). The security group allows
**inbound SSH (22) from within the VPC** (`10.1.0.0/16` + the VPC's IPv6 block) **and the
operator's three static EIPs** (jumpbox + the two dev servers, so the `dev_to_runner` debug
path works) and all egress; shell access from anywhere else is via **SSM Session Manager**
(the runner role carries `AmazonSSMManagedInstanceCore`). SSH is closed to the public internet
at large; everything else (webhook, registration, job dispatch) is runner-initiated outbound
to GitHub and the AWS APIs.

## Trade-offs and sharp edges

These are deliberate simplifications for a single-owner CI account, not recommendations to
copy blindly.

Closed (were sharp edges, now hardened):

- **The webhook fails closed and verifies every public request.** `verify_signature` rejects
  when `WEBHOOK_SECRET` is unset, and HMAC verification runs on everything arriving through
  API Gateway — identified by `requestContext`, which AWS sets and a caller can't forge. The
  shared secret is set on the GitHub `workflow_job` webhook and in the Lambda env, so an
  anonymous POST to `/webhook` no longer launches instances and no header skips verification
  (the old `x-internal-invoke: cleanup-retry` bypass is gone — cleanup retries are trusted
  by being direct `lambda:Invoke`, which carry no `requestContext`).
- **Both halves of that secret come from one Terraform value.** It used to be two hand-copied
  strings, a tfvar and a form field, with nothing checking they still matched — a real
  structural flaw, though NOT what killed the webhook. The measured root cause: the API
  Gateway route uses payload format 1.0, which preserves header casing, GitHub sends
  `X-Hub-Signature-256`, and the handler looked the header up in lowercase only — so it
  read the signature as absent and fail-closed 401'd every genuine delivery regardless of
  any secret (all 5,026 deliveries retained for hook 589197362 up to 2026-08-07 were 401
  or 503, zero 200). Whether the hand-copied secrets also drifted is unknowable from the
  outside — the case bug alone produces exactly this failure. Both are fixed: the handler
  normalizes header case, and the secret cannot drift again because there is only one.
  `random_password.github_webhook` feeds the Lambda env and the hook's
  `configuration.secret`, so there is no second copy to drift. This ownership begins at
  the one-time import + apply documented below — until that apply lands on a given state,
  the live hook still carries whatever secret it had before, and deliveries keep failing.
- **SSH is restricted to known hosts.** Port 22 is reachable from `10.1.0.0/16` (intra-VPC)
  and the operator's three static EIPs (jumpbox + the two dev servers) — not the public
  internet; shell access from anywhere else is via SSM Session Manager. The runners still run
  with `/dev/kvm` exposed and `iptables -P FORWARD ACCEPT`, so keeping them off the open
  internet matters.

Still open (accepted for now):

- **The OIDC role is admin-capable by composition.** Its inline policy reads as scoped, but
  `ec2:RunInstances` (`Resource: *`) plus `iam:PassRole` on `jumpbox-admin-role` (which
  carries `AdministratorAccess`) lets a run launch an instance under the admin profile and
  act as admin from there. The `sub` is `repo:ejc3/aws:*` / `repo:ejc3/fcvm:*` — any ref,
  not pinned to a protected branch or a GitHub environment.
- **PAT blast radius.** `/github-runner/pat` can register and remove runners on `ejc3/fcvm`;
  any process on a runner that reaches instance-role SSM can read it. Self-hosted runners and
  untrusted PRs don't mix.

## Operating it

- All of Pattern B is gated on `var.enable_github_runner` — flip it to `false` to tear the
  self-hosted side down in one apply.
- Set the PAT out of band (it's never in Terraform state):
  `aws ssm put-parameter --name /github-runner/pat --value ghp_xxx --type SecureString --overwrite`.
- The webhook is Terraform's, both halves. It is `github_repository_webhook.runner`, pointed
  at `runner_webhook_url`, event `workflow_job`, secret generated by
  `random_password.github_webhook`. **Import the live hook once before the first apply on any
  state that doesn't already have it** — without this the apply adds a *second* hook to
  `ejc3/fcvm` delivering to the same URL, doubling every event:

  ```bash
  terraform import 'github_repository_webhook.runner[0]' fcvm/589197362
  ```

  Rotate the HMAC with `terraform apply -replace='random_password.github_webhook[0]'`; the
  same apply writes both sides.
- Pattern A needs nothing in GitHub but the workflow's `permissions: id-token: write` and the
  role ARN — no repo secret to manage.
