# AWS development infrastructure

This is the live Terraform control plane for the `ejc3` development fleet. It is not a
generic module or a tutorial environment: the defaults describe the deployed system.

It manages roughly 185 resources across the main AWS account, an isolated staging account,
Cloudflare, and several regions. The platform provides:

- persistent ARM64 and x86 bare-metal Firecracker development servers;
- two independent Terraform administration jumpboxes;
- authenticated, permanent URLs for the kids' Next.js projects;
- ephemeral high-speed shared storage and on-demand 96/192-core compute;
- autoscaled ARM64 and x86 GitHub Actions runners;
- backups, cross-region/cross-account recovery, and cost alerts;
- a scheduled drift-detection workflow whose current IAM path is incomplete;
- scoped IAM capabilities for agents, including temporary EBS volumes and Bedrock access.

## Start here

The supported control plane is the original jumpbox, with `jumpbox-2` as the independent
fallback. Terraform runs directly there. There is no container wrapper and no Makefile.

The operating rules are:

1. Make permanent AWS and Cloudflare changes in Terraform. Do not mutate managed
   infrastructure with the AWS CLI.
2. Run `terraform plan` immediately before `terraform apply` and read the plan. A plan has
   previously caught a change that would have exposed every kids' URL publicly.
3. Commit and push every applied change. Git, Terraform state, and live infrastructure
   should describe the same system.
4. Do not run concurrent plans or applies. State uses an S3 backend with DynamoDB locking,
   but a fresh plan is still required after another operator changes anything.
5. Treat every instance-store NVMe disk as disposable. Persistent data belongs on EBS or
   in a backed-up repository.

Normal operation from an admin box:

```bash
cd ~/aws
git pull --ff-only
terraform fmt -recursive
terraform validate
terraform plan
terraform apply
git add <changed-files>
git commit -m "<what changed>"
git push origin main
```

The jumpboxes already have Terraform, Git, the AWS CLI, this repository, and an EC2
administrator instance role. There is no AWS login or credential-refresh step. The
committed `.terraform.lock.hcl` keeps provider resolution identical across admin hosts;
review and commit any intentional provider upgrade.

## Prerequisites

### Existing deployment

To operate the existing system, a new person or agent needs:

- SSH access to either jumpbox as `ubuntu`;
- the private `fcvm-ec2` SSH key;
- access to the `ejc3/aws` GitHub repository;
- a clean, current `main` checkout at `~/aws`;
- exclusive use of the Terraform state lock for the duration of plan/apply.

Run `terraform output` for the current addresses and ready-to-use SSH commands. The
`fcvm-ec2` private key is backed up in Secrets Manager for jumpbox disaster recovery; AWS
itself stores only the public half of an EC2 key pair.

### Replacement admin host and empty-state recovery

This repository is the control plane for one existing account, not a portable new-account
installer. A replacement admin host should use the existing S3 state. It additionally
needs:

- Terraform 1.10.3 to match both jumpboxes, plus Git and AWS CLI v2;
- AWS administrator credentials in the Organizations management account;
- access to the existing S3 backend bucket `ejc3-terraform-state` and DynamoDB lock table
  `ejc3-terraform-locks`;
- the existing `fcvm-ec2` EC2 key pair and its private key;
- the existing `AWSBackupDefaultServiceRole`;
- the Cloudflare `cc-games.dev` zone and Secrets Manager values
  `cloudflare-tunnel-token`, `cloudflare-tunnel-credentials`, and
  `cloudflare-google-idp`;
- the `github-pat-ejc3` Secrets Manager value, the runner-only
  GitHub PAT, and `github_webhook_secret` in the ignored `terraform.tfvars`;
- current ARM64 and x86 runner AMIs tagged `Purpose=github-runner`;
- the Google OAuth callback
  `https://ejc3.cloudflareaccess.com/cdn-cgi/access/callback` when Google login is enabled.

Clone and initialize the configuration:

```bash
git clone https://github.com/ejc3/aws.git ~/aws
cd ~/aws
terraform init
```

`terraform plan` should then refresh the recovered remote state and propose no unexplained
re-creation. Stop if the backend appears empty. The configuration contains imported
resources, fixed account identities, and protected volumes; applying it against an empty
state or a different account is not a supported bootstrap and can collide with or replace
live infrastructure. Recover the backend state first, or inventory and import every
pre-existing resource before any full apply.

The alert address, runner PAT, and SSH-key backup use Terraform-managed containers whose
payloads are intentionally kept out of Terraform state. For a true cold start, create
those three containers only after state/import reconciliation is complete:

```bash
terraform apply \
  -target=aws_ssm_parameter.alert_email \
  -target='aws_ssm_parameter.github_runner_pat[0]' \
  -target=aws_secretsmanager_secret.fcvm_ec2_ssh_key
```

Then populate `/alerts/email`, `/github-runner/pat`, and `fcvm-ec2-ssh-key` through the AWS
console or AWS CLI without printing their values. This is a one-time secret-payload
bootstrap, not a parallel way to manage infrastructure. The alert sender address must also
be verified in SES in `us-west-1`.

After state, prerequisites, and secret payloads are reconciled, run and review the full
plan:

```bash
terraform plan
terraform apply
```

Configure the `ejc3/fcvm` `workflow_job` webhook with `runner_webhook_url` and the same HMAC
value as `github_webhook_secret`, then confirm the SNS email subscription. Do not leave
placeholder secret/parameter values in a live account. Optional Mac development needs
available EC2 Dedicated Host quota and an explicit new `mac_teardown_at` at least 24 hours
after allocation; its checked-in date is historical and must not be reused. Terraform
creates its VNC password.

## Fleet

| Resource | Region / purchase | Persistent state | Purpose and lifecycle |
|---|---|---|---|
| `jumpbox` | `us-west-1`, on-demand `t4g.large` | 20 GB protected `/home/ubuntu` EBS; separate 8 GB root | Primary admin host. Runs Terraform with an administrator instance role and stays up. |
| `jumpbox-2` | `us-west-1`, on-demand `t4g.micro` | Protected 20 GB encrypted root | Fully Terraform-bootstrapable backup admin host with the same IAM reach. |
| `fcvm-metal-arm` | `us-west-1`, persistent Spot `c7gd.metal` | 300 GB EBS root; local NVMe is ephemeral | 64-vCPU ARM64 Firecracker/KVM and nested-virtualization work. Uses the 12-hour idle-stop policy. |
| `fcvm-metal-x86` | `us-west-1`, persistent Spot `c5d.metal` | 300 GB EBS root; 3.6 TB local NVMe is ephemeral | x86 Firecracker/KVM work. Uses the 12-hour idle-stop policy. |
| `nextjs-dev` | `us-west-1`, on-demand `t4g.medium` | 50 GB encrypted EBS root, protected by AWS Backup | Always-on kids' development box. Deliberately not Spot and not idle-stopped. |
| `io-box` | `us-west-2d`, persistent Spot `i8ge.large` | 20 GB EBS root; 1.25 TB shared NVMe is ephemeral | Private NFS bulk scratch at `/mnt/io`. Uses a 12-hour multi-metric idle policy and returns with an empty scratch disk after every stop. |
| `parallel-box` | `us-west-2d`, one-time Spot, normally 96 or 192 vCPU | Protected 100 GB EBS at `/mnt/work`; root is disposable | Temporary fan-out compute. Terminates after 30 idle minutes; `pbox` recreates it. |
| GitHub runners | `us-west-1`, one-time Spot metal | Disposable | Webhook-launched ARM64/x86 runners. Four per architecture maximum; idle/expired leases terminate. |
| Mac dev | `us-west-2`, optional Dedicated Host | Disposable 200 GB gp3 root | Temporary macOS build host. Disabled by default; teardown terminates the instance and releases the host after its 24-hour minimum. |

The primary VPC is `10.0.0.0/16` in `us-west-1`. A private inter-region VPC peer reaches
the `172.31.0.0/16` default VPC in `us-west-2`; NFS is never exposed publicly.

```text
GitHub workflow jobs -> API Gateway -> Lambda -> disposable Spot runners

Cloudflare Access -> outbound tunnel -> nextjs-dev -> 127.0.0.1 project ports

us-west-1 dev VPC <-> private VPC peer <-> us-west-2 io-box + parallel-box
        |
        +-> AWS Backup -> us-east-1 DR vault + dev-staging account vault
```

## Access and trust boundaries

List current connection commands:

```bash
cd ~/aws
terraform output
```

The `ubuntu` account on ARM, x86, and `nextjs-dev` has stable aliases:

```bash
ssh fcvm-arm
ssh fcvm-x86
ssh nextjs
ssh io
```

The aliases use Elastic IPs for the three long-lived `us-west-1` boxes and fixed private
address `172.31.48.10` for `io-box`. Dev servers carry a dedicated dev-hop key, not the
`fcvm-ec2` admin key, so ordinary dev-to-dev access does not grant an admin shell on a
jumpbox. `pbox` has a separate forced-command-only key that can ask the jumpbox to run the
parallel-box Terraform workflow and nothing else.

SSH and Eternal Terminal provide interactive access. `t-claude` supplies Claude's
phone-oriented remote-control workflow; Codex uses its own app-server remote-control
daemon. Conversation history is synchronized through `claude-code-sync`. On each metal
box, `fcvm-claude-rc.service` starts remote-control sessions at boot for the user's
active repositories under `/home/ubuntu`. “Active” means t-claude was used for that
repository on this host during the preceding 30 days, its local Git checkout has moved
during that period, or its worktree has uncommitted changes. Only `github.com/ejc3/*`
checkouts qualify. The launcher uses the normal path-derived `t-claude` session so a later
interactive launch attaches to the same work when run from that repository root.

## Start a Codex session

Codex is installed per Unix account on the metal boxes, `jumpbox-2`, and `nextjs-dev`.
Authentication is deliberately not stored in Terraform. On a fresh account, SSH in as the
person who will own the sessions and complete the one-time logins. That person needs
Codex access in their ChatGPT account/workspace, the current ChatGPT app with Remote
available, and device-code login enabled by either their account or workspace admin.

```bash
codex --version
codex login --device-auth
codex login status

gh auth login
gh auth setup-git
```

Device authentication prints a URL and one-time code for a browser or phone. Use the same
ChatGPT account and workspace that will open the remote session. Device-code login may
first need to be enabled in the account's ChatGPT security settings or by its workspace
administrator. `~/.codex/auth.json` is a persistent credential: never copy it between
users, print it, or commit it. See the official
[Codex authentication guide](https://learn.chatgpt.com/docs/auth).

GitHub authentication is separate from Codex. The metal boxes have a limited PAT fallback
for a brand-new bootstrap, but each person should run `gh auth login` for their own
identity. On `nextjs-dev`, log in as `colton`, `connor`, or `ej` rather than sharing
credentials, then also run:

```bash
vercel login
claude login
```

Claude login is also personal and persistent on each metal box. After the first login,
start the already-enabled boot service once if the machine is currently running:

```bash
claude login
claude auth status
sudo systemctl start fcvm-claude-rc.service
systemctl status fcvm-claude-rc.service --no-pager
```

The service checks `claude auth status` on every boot and skips cleanly if the login is
missing or expired. To seed a new repository, open it once with
`t-claude --remote-control`; a host-local marker makes subsequent boots include it while
it remains recent. All metal repositories share one tmux server and one aggregate service,
so do not restart or stop this service just to refresh one repository: that can end every
managed and interactive `t-claude` session on the host. Check the most recent aggregate
result with `cat ~/.local/state/fcvm-claude/last-start`.

Refresh the generated instructions that seed app-created Codex sessions:

```bash
# ubuntu on a metal box or jumpbox-2
sudo codex-agents-refresh

# a personal account on nextjs-dev
sudo kid-agents-refresh "$USER"
```

The first command inventories the repositories under `/home/ubuntu`. The second points a
kids' session at that user's published project and explains that its `ndev` service is
already running. Both write `~/Documents/Codex/AGENTS.md`.

Enable remote control only after `codex login` succeeds:

```bash
sudo systemctl enable --now "codex-rc@$USER.service"
systemctl status "codex-rc@$USER.service" --no-pager
codex remote-control start --json
```

Open Remote in ChatGPT while signed in to that same account and workspace. If it asks for
a manual pairing code, generate one with:

```bash
codex remote-control pair
```

The command creates a short-lived code; see the official
[remote-control CLI reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli#cli-codex-remote-control).
Remote control is currently marked experimental upstream.

A phone-created task starts in
`~/Documents/Codex/<date>/<task>/`, which is an empty scratch directory, not a checkout.
The generated parent `AGENTS.md` tells Codex where the real repositories are. Name the
repository in the first prompt; if no repository is named, the agent should ask instead
of editing the scratch directory. For a terminal session that should start in this
repository directly:

```bash
cd ~/aws
codex
```

The ChatGPT client sends the approval and sandbox mode for each remote thread, and those
settings override `~/.codex/config.toml`. Enable the Remote setting called dangerous mode
only when full host access is intended. These EC2 development machines are designed as
the external isolation boundary; the generated config supplies their real project roots
when the app selects workspace-write mode.

Once enabled, `codex-rc@` returns on every boot. Machine convergence also enables it when
it sees an existing login. `nextjs-dev` refreshes the seed files, updates
Codex/Claude/Vercel, and restarts enabled agent services nightly. Codex, GitHub, Vercel,
and Claude remain four independent logins.

## Firecracker development

The two metal boxes are the main `fcvm` workstations:

- ARM64 uses `c7gd.metal`; x86 uses `c5d.metal`.
- Both are persistent Spot instances with `stop` interruption behavior and static EIPs.
- Their 300 GB EBS roots survive a normal stop/start.
- Instance-store NVMe is for VM images, build output, caches, and temporary Btrfs data.
  It is erased by a stop, Spot interruption, or host loss.
- ARM nested virtualization requires the custom `-nested-dsb` kernel and the DSB/MMFR4
  patches documented in `AGENTS.md`.
- An hourly Lambda queries a 12-hour range of five-minute peak CPU points. Any returned
  point at or above 5% keeps the instance running; otherwise it stops the instance and
  sends an SNS notification.

Terraform manages the configuration of a stopped metal box, but an `aws_instance` resource
does not itself wake an already-stopped instance. Unlike `io-box`, ARM and x86 currently
have no `aws_ec2_instance_state` wake resource. A normal plan/apply therefore will not wake
them. Do not hide a mutating AWS CLI call in a script: either obtain explicit authorization
for the break-glass start procedure in `AGENTS.md`, or add and review a Terraform-modeled
lifecycle first. Persistent Spot can start only after its request reaches
`disabled / instance-stopped-by-user`.

The idle check is a cost-saving heuristic, not proof of 12 uninterrupted idle hours. The
current Lambda accepts 12 returned CPU datapoints even though a complete 12-hour,
five-minute series contains about 144; missing metric periods can therefore count as idle.

## Shared high-speed I/O

`io-box` exports its local 1.25 TB NVMe disk as private NFSv4.2. ARM, x86, Next.js, and
new parallel boxes receive a bounded soft automount:

```text
/mnt/io -> 172.31.48.10:/  (the server's `/srv/io` export)
```

Use it for bulk scratch, caches, and reproducible artifacts. Do not put the only copy of
source or results there: every stop creates a new empty filesystem. Clients idle-unmount
after ten minutes so a stopped server does not block boot or hang a shell indefinitely.

The I/O watchdog queries CPU, disk bytes, and network bytes over the same intended 12-hour
window. A returned five-minute point with CPU at least 5%, disk I/O at least 1 MiB, or
network I/O at least 64 MiB keeps it up. Missing I/O series currently count as zero, so
this is also a heuristic rather than a continuity guarantee. Wake it through the modeled
Terraform state resource:

```bash
terraform apply -target=aws_ec2_instance_state.io_box
```

A normal full `terraform apply` also reconciles that resource to `running`; the target is
just the narrow wake command. The root EBS volume survives the stop; `/mnt/io` data does
not.

## On-demand parallel compute

From ARM or x86:

```bash
pbox status
pbox up       # launch through Terraform, then connect
pbox ssh
pbox down     # terminate compute; keep /mnt/work
```

The launcher tries several 96/192-vCPU Graviton Spot pools in the availability zone that
contains the persistent 100 GB work volume. A watchdog checks every five minutes and
terminates the box after 30 minutes below 5% CPU.

Use only `pbox` (or `scripts/parallel-box.sh` on a jumpbox) for this lifecycle. The Terraform
default is `enable_parallel_box=false`; an unrelated full apply while the box is running
can otherwise propose terminating it. Read the plan and never apply that change during a
live job.

## Temporary EBS for agents

Permanent fleet infrastructure remains Terraform-managed. As a deliberate runtime
exception, development boxes have a narrow IAM policy for temporary working volumes:

- region must be `us-west-1` or `us-west-2`;
- volume type must be encrypted `gp3`;
- creation must include the tag `DevEBS=true`;
- attach/detach is allowed only between tagged volumes and tagged dev instances;
- deletion is allowed only for tagged volumes.

EBS volumes are availability-zone scoped. An agent must create the volume in the same AZ
as its target instance, mount it safely by volume ID rather than a guessed NVMe name, and
delete it when no longer needed. This permission does not make `/mnt/io` persistent.

## Kids' Next.js environment

`nextjs-dev` hosts separate Unix, GitHub, Vercel, Claude, and Codex identities for Colton
and Connor. It is intentionally on-demand after repeated Spot reclamations made the URLs
unavailable.

Inside a project:

```bash
ndev
```

`ndev` derives a stable port, registers the hostname, and enables a systemd service. The
project becomes `https://<name>.cc-games.dev`. `cloudflared` dials out to Cloudflare, so
there are no inbound web ports and `next dev` remains bound to `127.0.0.1`. Cloudflare
Access enforces the email allowlist through Google or one-time PIN; a separate service
token supports non-interactive checks.

Once credentials exist and their units have been enabled, services and remote-control
agents start at boot. A reboot restores the published URLs without another interactive
login.

## GitHub Actions and package infrastructure

The `workflow_job` webhook launches one-time Spot runners from prebuilt ARM64 or x86 AMIs.
Labels select the architecture; the launcher tries several metal families when capacity is
scarce. A runner receives a 60-minute lease, renews while GitHub reports it busy, and is
terminated when idle/expired. Cleanup runs every five minutes and also replaces missing
runners for queued jobs.

The maximum is four runners per architecture. Runner roots and instance-store data are
disposable. See `GITHUB-RUNNERS.md` for the webhook, AMI, lease, and cleanup internals.

The repository also manages:

- a private CodeArtifact npm repository in `us-west-2`;
- GitHub OIDC roles for drift detection and AMI builds;
- a separate administrator deploy role inside the `dev-staging` account;
- a daily Terraform drift workflow on `main`.

The drift workflow is not currently healthy: recent scheduled runs fail because its OIDC
role cannot read the Secrets Manager, Organizations, and CodeArtifact data required by a
full refresh, and the workflow does not supply `github_webhook_secret`. Treat drift
detection as scheduled but non-functional until those IAM/input gaps are fixed.

## Bootstrap, authentication, and convergence

Large instance setup scripts are rendered by Terraform and versioned in S3. Metal boxes run
`dev-selfupdate.service` at boot: it compares the architecture script checksum and replays
the complete bootstrap only when the published script changed. Inspect:

```bash
cat /var/lib/dev-selfupdate/status
sudo less /var/log/dev-selfupdate.log
```

Do not casually run `dev-selfupdate.sh` to deploy one small edit; it reapplies the whole
machine configuration. Existing personal `gh auth login` state is preserved. The
`github-pat-ejc3` secret provides a fresh-box fallback and a separately scoped credential
for `claude-code-sync`; it must never overwrite a person's GitHub login.

Next.js users authenticate independently. Jumpboxes intentionally leave interactive
Claude/Codex login to the operator rather than storing those device credentials in
Terraform.

## Backups, safety, and cost controls

- AWS Backup covers the ARM and x86 roots, the Next.js root, the original jumpbox home
  volume, and the `jumpbox-2` root with daily, weekly, and monthly retention.
- The parallel box's persistent `/mnt/work` volume is protected from Terraform destroy but
  is **not backed up**. `prevent_destroy` is not a backup; keep important results elsewhere.
- The primary backup vault uses governance Vault Lock.
- Weekly/monthly recovery points copy to `us-east-1`; a second copy target lives in the
  isolated `dev-staging` account.
- Daily cost reports, AWS Budget notifications, runner-count/age alarms, EC2 spend alarms,
  and instance-status alarms publish through SNS/email.
- The original jumpbox's protected home volume and the fully reproducible `jumpbox-2`
  provide two administration recovery paths.
- Terraform state is encrypted in S3 and locked with DynamoDB.

The jumpbox's gp3 volumes are capped at 125 MB/s. Never run broad recursive searches across
`/home/ubuntu` or `/tmp`; one such scan saturated both disks and made SSH unusable. Scope
searches to the repository, prefer `rg`, and move large scans/builds to ARM or the parallel
box.

## File map

| Area | Main files |
|---|---|
| Backend, providers, VPC, routing | `main.tf`, `.terraform.lock.hcl`, `variables.tf`, `runner-vpc.tf` |
| Admin hosts | `jumpbox.tf`, `jumpbox2.tf`, `jumpbox2-user-data.tf` |
| Metal dev boxes | `firecracker-dev.tf`, `x86-dev.tf`, `dev-user-data.tf` |
| Shared dev setup | `dev-instance-common.tf`, `dev-selfupdate.tf`, `dev-hop-key.tf`, `dev-ebs.tf` |
| Kids' environment | `nextjs-dev.tf`, `nextjs-user-data.tf`, `cloudflare.tf` |
| Shared I/O and burst compute | `io-box.tf`, `parallel-box.tf`, `parallel-box-watchdog.tf`, `scripts/parallel-box.sh` |
| GitHub runners and OIDC | `runner-autoscale.tf`, `github-actions.tf`, `GITHUB-RUNNERS.md` |
| Recovery and monitoring | `backups.tf`, `cost-alerts.tf`, `fcvm-ec2-key-backup.tf` |
| Optional Mac | `mac-dev.tf`, `mac-dev-secrets.tf`, `mac-dev-teardown.tf` |
| Staging and packages | `dev-staging-account.tf`, `dev-staging-bootstrap.tf`, `codeartifact.tf` |

`AGENTS.md` contains the deeper operational constraints, nested-virtualization details,
persistent-Spot recovery procedure, and live-system safety notes that an automation agent
must read before changing the repository.
