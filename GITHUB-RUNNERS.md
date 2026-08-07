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

**Launch path.** GitHub fires a `workflow_job` webhook → API Gateway HTTP API
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
`c7gd.metal`→`c7g.metal`; x86 tries `c5d`/`c5`/`c6i`/`m5d.metal`, with any type that
recently failed for capacity moved to the back of that order. Each instance is tagged with a
`LeaseExpires` 60 minutes out.

**Registration.** The instance's user_data lives in SSM (`/github-runner/user-data`,
Advanced tier, base64 — too big for Lambda's 4 KB env limit). On boot it sets up the box
(btrfs RAID0 over instance NVMe, `/dev/kvm` permissions, IPv6), reads the PAT from SSM
(`/github-runner/pat`, decrypted), exchanges it for a short-lived **registration token** via
`POST /repos/ejc3/fcvm/actions/runners/registration-token`, and runs
`config.sh --url https://github.com/ejc3/fcvm --token <reg> --name runner-<instance-id>
--labels self-hosted,Linux,<ARM64|X64> --unattended --replace`, then installs the runner as
a service. The PAT itself never leaves AWS; what touches `config.sh` is the ephemeral
registration token derived from it.

**Reaping.** A second Lambda, `github-runner-cleanup`, runs every 5 minutes
(`rate(5 minutes)`) and does five things, three of them using the PAT: deregisters GitHub
runners whose instance is gone; renews the lease on busy runners (+60m) and lets idle ones
expire, then terminates and deregisters anything past its lease (instances younger than 10
minutes are skipped so setup isn't interrupted); terminates stray `ami-builder-temp`
instances older than 2 hours (pure EC2, no PAT); reaps launches still `pending` after 15
minutes; and counts GitHub's queued jobs to launch what the queue actually needs — GitHub
doesn't redeliver webhooks, so this poll is the retry.

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
self-hosted jobs themselves; the only early exit is when both architectures already want more
runners than the pool can hold. Sampling the newest five `queued` runs hid real work two
ways. A run that is `in_progress` still holds queued jobs and the `queued` query does not
return it: run 31202629167 went `in_progress` at 17:40 on 2026-08-07 and kept two arm64 jobs
queued until 18:25, invisible for 45 minutes. And `ejc3/fcvm` carries six runs from
2026-08-06 that are permanently `status=queued` with **zero jobs** and cannot be cancelled,
force-cancelled or deleted through the API. Runs come back newest first, so those six sit
ahead of any older real work — more than the five-run sample held. The scan now also launches
one runner per queued job rather than one per architecture per poll, which used to fill the
pool at one runner every five minutes however deep the queue was; the webhook Lambda stays
the single authority on the cap, so surplus invocations are simply answered with "max
reached".

## What crosses the boundary (secrets inventory)

| Secret | Where it lives | Direction | Who reads it | Set / rotated by |
|--|--|--|--|--|
| **GitHub PAT** | `/github-runner/pat`, SSM `SecureString` | GitHub-issued, stored in AWS | `github-runner-instance-role`, `github-runner-lambda-role` | manual `put-parameter`; TF stores `placeholder` with `ignore_changes = [value]` |
| **Webhook HMAC** | `github_webhook_secret` tfvar (sensitive) → Lambda env `WEBHOOK_SECRET` | shared, both sides | the webhook Lambda; mirror in GitHub webhook config | `terraform.tfvars`; must match GitHub |
| **Registration token** | minted at boot, never persisted | GitHub-issued, ephemeral | the booting runner only | GitHub API, single use, ~1h TTL |
| **OIDC federation** | no secret — thumbprint pinned on the provider | GitHub asserts, AWS verifies | n/a | trust policy on `github-actions-terraform` |
| **`dev_to_runner` SSH key** | private in SSM `SecureString` `/dev-servers/runner-ssh-key`, public baked into runner `authorized_keys` | AWS-internal (dev box → runner) | dev-server role fetches the private key | TF-generated `tls_private_key` (ED25519) |
| **`fcvm-ec2` keypair** | EC2 keypair `fcvm-ec2` (launch `KeyName`); public key baked into runner `authorized_keys` | AWS-internal (operator → runner) | whoever holds `~/.ssh/fcvm-ec2` (the jumpbox operator) | manual EC2 keypair, never rotated |

The one credential GitHub itself holds for Pattern B is the webhook HMAC. Everything else is
either federated (Pattern A) or stored AWS-side and read through IAM.

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
- The GitHub webhook points at the `runner_webhook_url` output, event `workflow_job`.
- Pattern A needs nothing in GitHub but the workflow's `permissions: id-token: write` and the
  role ARN — no repo secret to manage.
