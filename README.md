# AWS development infrastructure

This is the live Terraform control plane for the `ejc3` development fleet. It is not a
generic module or a tutorial environment: the defaults describe the deployed system.

It manages roughly 195 resources across the main AWS account, an isolated staging account,
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
terraform init
terraform fmt -recursive
terraform validate
terraform providers
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

`main.tf` enforces Terraform `1.10.3`, which is the version on both jumpboxes and supports
the ephemeral Workers Builds control-token read. Any Terraform upgrade must update the
constraint, both jumpboxes, and the drift workflow together.

Cloudflare is intentionally pinned to the signed `ejc3/cloudflare` `5.24.0`
provider release. That fork adds typed Worker-native Access destinations and the Workers
Builds APIs used below while preserving ordinary `terraform init` on both ARM64 jumpboxes
and amd64 CI; there is no local provider override or machine-specific installation step.
Return to `cloudflare/cloudflare` only after an upstream release includes the same fields
and regression coverage.

The fork has a different provider source address. On the first live-jumpbox update to the
fork, stop after `terraform providers` if state still lists `cloudflare/cloudflare`.
Under the exclusive state lock, migrate all existing Cloudflare resources before
planning:

```bash
terraform state replace-provider \
  registry.terraform.io/cloudflare/cloudflare \
  registry.terraform.io/ejc3/cloudflare
```

Terraform writes a mandatory state backup. Do not repeat the command once state lists
`ejc3/cloudflare`, and never apply a plan made before the migration. The reverse command
is required when the stack eventually returns to the upstream provider namespace.

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
  `cloudflare-tunnel-token` (including Workers Scripts Read/Write),
  `cloudflare-tunnel-credentials`, and
  `cloudflare-google-idp`;
- the raw user-owned Cloudflare token in
  `cloudflare-workers-builds-control-token` when the checked-in Workers Builds rollout
  gate is enabled. From
  [Create Additional Tokens](https://dash.cloudflare.com/profile/api-tokens), choose
  **Use template**, retain User → API Tokens → Edit, and add Workers Builds Configuration
  Edit plus Workers Scripts Read for account `12ea67fb7ced068de03f35c22688e436`;
  an account-owned token is rejected;
- the Cloudflare Workers and Pages GitHub App authorized for only
  `CoderColton/colton-games` by that repository's owner, starting from the target Worker's
  Settings → Builds → Connect → GitHub flow. `ejc3` has write, not admin, and cannot grant
  the App;
- the `github-pat-ejc3` Secrets Manager value, the runner-only GitHub PAT, and
  `github-webhook-admin-pat` in Secrets Manager -- a fine-grained PAT whose only
  repository permission is `Webhooks: Read and write` on `ejc3/fcvm`, used by the
  `integrations/github` provider to own the runner webhook;
- current ARM64 and x86 runner AMIs tagged `Purpose=github-runner`;
- the Google OAuth callback
  `https://ejc3.cloudflareaccess.com/cdn-cgi/access/callback` when Google login is enabled.

Clone and initialize the configuration:

```bash
git clone https://github.com/ejc3/aws.git ~/aws
cd ~/aws
terraform init
```

Follow the normal provider-migration gate above before planning from a replacement host.

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

Do not create the Workers Builds control-token container in this generic bootstrap. Its
first creation is deliberately deferred until after the 15-minute S3 versioning wait in
the staged rollout below; that Terraform write is the backend `VersionId` probe.

Terraform owns the `ejc3/fcvm` `workflow_job` webhook and generates its HMAC secret, so
there is nothing to mirror by hand. **Before the first full apply**, if the recovered
state does not already contain the hook, adopt it -- otherwise the apply adds a *second*
hook delivering to the same URL and every event arrives twice:

```bash
terraform import 'github_repository_webhook.runner[0]' fcvm/589197362
```

Only then, with state, prerequisites, secret payloads, and the hook import reconciled,
run and review the full plan:

```bash
terraform plan
terraform apply
```

Then confirm the SNS email subscription. Do not leave placeholder secret/parameter values
in a live account. Optional Mac development needs available EC2 Dedicated Host quota and an
explicit new `mac_teardown_at` at least 24 hours after allocation; its checked-in date is
historical and must not be reused. Terraform creates its VNC password.

## Fleet

| Resource | Region / purchase | Persistent state | Purpose and lifecycle |
|---|---|---|---|
| `jumpbox` | `us-west-1`, on-demand `t4g.large` | 40 GB protected `/home/ubuntu` EBS; separate 40 GB root | Primary admin host. Runs Terraform with an administrator instance role and stays up. |
| `jumpbox-2` | `us-west-1`, on-demand `t4g.micro` | Protected 20 GB encrypted root | Fully Terraform-bootstrapable backup admin host with the same IAM reach. |
| `fcvm-metal-arm` | `us-west-1`, persistent Spot `c7gd.metal` | 400 GB backed-up EBS root, including `/home/ubuntu`; local NVMe is ephemeral | 64-vCPU ARM64 Firecracker/KVM and nested-virtualization work. Uses the 12-hour idle-stop policy. |
| `fcvm-metal-x86` | `us-west-1`, persistent Spot `c5d.metal` | 300 GB EBS root; 3.6 TB local NVMe is ephemeral | x86 Firecracker/KVM work. Uses the 12-hour idle-stop policy. |
| `nextjs-dev` | `us-west-1`, on-demand `t4g.medium` | 50 GB encrypted EBS root, protected by AWS Backup | Always-on kids' development box. Deliberately not Spot and not idle-stopped. |
| `io-box` | `us-west-2d`, persistent Spot `i8ge.large` | 20 GB EBS root; 1.25 TB shared NVMe is ephemeral | Private NFS bulk scratch at `/mnt/io`. Uses a 12-hour multi-metric idle policy and returns with an empty scratch disk after every stop. |
| `parallel-box`, `parallel-box-2` | `us-west-2d`, one-time Spot, normally 96 or 192 vCPU | Protected 100 GB EBS each at `/mnt/work`; roots are disposable | Temporary fan-out compute, two independent boxes so two jobs can run at once. Each terminates after 30 idle minutes; `pbox` recreates them. |
| GitHub runners | `us-west-1`, one-time Spot metal | Disposable | Webhook-launched ARM64/x86 runners. Four healthy runners per architecture maximum; idle, expired, and wedged runners terminate. Maximum instance lifetime 13h30m (drains from 12h). |
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
jumpbox. Nothing on a dev server can reach a jumpbox at all -- there is no key, and no
delegation of any kind. `pbox` launches the parallel boxes itself with a tag-scoped IAM
grant (`parallel-box-launch.tf`); the forced-command key it used to carry is gone.

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
identity. On `nextjs-dev`, log in as `colton`, `connor`, `ejc3`, or `skevh` rather than sharing
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
- Their EBS roots survive a normal stop/start: 400 GB on ARM and 300 GB on x86.
- Instance-store NVMe is for VM images, build output, caches, and temporary Btrfs data.
  It is erased by a stop, Spot interruption, or host loss.
- ARM nested virtualization requires the custom fcvm kernel and patch set documented in
  `AGENTS.md`; `uname -r` reports `<version>-fcvm-<build-sha>` on a correctly installed
  host.
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

Two independent boxes (`parallel-box`, `parallel-box-2`), each with its own persistent
100 GB work volume, so two jobs can run at once. From ARM or x86:

```bash
pbox status      # both boxes
pbox up          # launch box 1 from its launch template, then connect
pbox up 2        # launch box 2 (independent volume and lifecycle)
pbox ssh [2]
pbox down [2]    # terminate compute; keep that box's /mnt/work
```

The launcher tries several 96/192-vCPU Graviton Spot pools in the availability zone that
contains the persistent work volumes. One shared watchdog checks every five minutes and
terminates either box after 30 minutes below 5% CPU.

Use only `pbox` (or `scripts/parallel-box.sh`, which is the same script) for this
lifecycle. Terraform owns the durable half -- work volumes, security group, key pair and
the two launch templates -- while the instances themselves are deliberately not in state.
That removes the old hazard entirely: an unrelated full apply can no longer propose
terminating a box in the middle of a live job.

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

`ndev` derives a stable port, registers the hostname, and enables a systemd service.
`cloudflared` dials out to Cloudflare, so there are no inbound web ports and `next dev`
remains bound to `127.0.0.1`.

**The zone follows the account, not a flag.** `colton` and `connor` publish to
`https://<name>.cc-games.dev`; `ejc3` and `skevh` publish to `https://<name>.dolphin-labs.dev`.
`/usr/local/bin/ndev-zone` is the single source of truth for user -> zone -> tunnel, and
`ndev-register` refuses a hostname outside the caller's zone -- it runs as root through
sudoers, so that check is a privilege boundary, not a convenience.

Each zone has its own tunnel, its own credentials, its own registry, and its own
`cloudflared@<zone>.service`, so a bad ingress rewrite on one project cannot take the other
project's URLs down. Access gates both: `cc-games.dev` through Google or one-time PIN
against an email allowlist, `dolphin-labs.dev` through GitHub against membership of the
`dolphin-labs-hq` organization. A separate service token supports non-interactive checks.

Once credentials exist and their units have been enabled, services and remote-control
agents start at boot. A reboot restores the published URLs without another interactive
login.

### Colton Games Cloudflare staging and previews

The `colton-games-stage` Worker is deployed from `CoderColton/colton-games` with Wrangler
and OpenNext. Terraform owns the Worker envelope and its Worker-native Access boundary;
Workers Builds owns versions, application assets, bindings, and deployments. This prevents
an infrastructure apply from replacing an application bundle.

The existing Worker is adopted through the checked-in import block with both `workers.dev`
and preview URLs still disabled, matching its current remote state. Read the plan and stop if
it proposes creating, replacing, or deleting the Worker or changing its deployed code.

The checked-in Worker-native Access application uses a `worker` destination with no domain.
That single application follows every request routed to this Worker, including its
`workers.dev` hostname once enabled, immutable and branch previews, future Custom Domains,
and future zone routes. It reuses the family email allowlist and the non-interactive Access
service-token policy. The URL switches intentionally remain off until the application has
been applied and a second clean plan confirms the policy attachment. Do not use hostname
wildcard applications or a generic REST/local-exec bridge as a substitute.

The pinned fork manages the account's `cc-games.workers.dev` label, a dedicated deployment
API token, the GitHub repository connection, separate staging and preview triggers, and
their complete build-time environment maps. The ordinary `cloudflare-tunnel-token` is
account-owned and cannot call Workers Builds. The aliased provider instead reads the raw
user-owned control token ephemerally from `cloudflare-workers-builds-control-token`, so
its value is not persisted in Terraform state; do not reuse, copy, or replace the ordinary
Cloudflare credential.

Open [Create Additional Tokens](https://dash.cloudflare.com/profile/api-tokens) and choose
**Use template** for that template, not the Custom Token builder: API Tokens Edit is
unavailable in the Custom Token permission list. Keep the template's User → API Tokens →
Edit permission (called API Tokens Write by the API), then add account-level Workers
Builds Configuration Edit and Workers Scripts Read scoped only to account
`12ea67fb7ced068de03f35c22688e436`. Those permissions let Terraform configure Builds and
mint the narrower Workers Scripts Write token that build jobs receive. Store the raw
control-token string in the existing Secrets Manager container without JSON wrapping.
Terraform creates the deploy token; do not make or paste a second deploy credential.

The other one-time prerequisite starts in Cloudflare: Workers & Pages →
`colton-games-stage` → Settings → Builds → Connect → GitHub. The `CoderColton` repository
owner must then authorize the Cloudflare Workers and Pages GitHub App for **only**
`CoderColton/colton-games`; `ejc3` has write access, not administration access, and cannot
make the grant. The
[GitHub App page](https://github.com/apps/cloudflare-workers-and-pages) is a reference,
not the primary setup entry point because a bare install can miss the Cloudflare account
connection context. When authorization returns to Cloudflare, **stop**: do not select,
save, or connect the repository and do not create build settings in the dashboard.
Terraform owns those objects. It cannot perform the interactive GitHub grant, and the
repository-connection API has no read/list endpoint or import path, so an out-of-band
connection cannot be adopted safely. The managed resource is protected from destroy and
its last confirmed UUID exists only in versioned, encrypted Terraform state.

The managed builds are:

| Deployment | Branches | Build command | Deploy command |
|---|---|---|---|
| Production staging | `main` | `npm run cf:build` | `npm run cf:deploy:built` |
| Pull-request preview | all except `main` | `npm run cf:build` | `npm run cf:upload:built` |

Use `/` as the root directory and Node 24 from the application's `.nvmrc`. Preview builds
must remain limited to trusted branches because they inherit the staging Worker's bindings
and secrets. `stage.colton-games.com` and the production Vercel serving path remain outside
this change until the domain is deliberately moved to Cloudflare.

Roll this out in order; do not collapse the safety gates into one apply:

1. After signed provider `5.24.0` is visible in the Terraform Registry, update only its
   stale lock selection, then initialize without allowing any further lock changes:

   ```bash
   terraform providers lock \
     -platform=linux_arm64 -platform=linux_amd64 \
     registry.terraform.io/ejc3/cloudflare
   git diff -- .terraform.lock.hcl
   terraform init -lockfile=readonly
   terraform validate
   ```

   The diff must change only the `ejc3/cloudflare` block to signed `5.24.0` hashes for
   both platforms. Commit that lock update. Do **not** use broad `terraform init -upgrade`;
   it can advance unrelated providers allowed by their `~>` constraints.
2. Leave both `colton_games_workers_builds_enabled` and
   `colton_games_worker_urls_enabled` false. Save and review a targeted backend-versioning
   plan, then apply that exact plan:

   ```bash
   terraform plan \
     -target=aws_s3_bucket_versioning.terraform_state \
     -out=/tmp/colton-games-backend-versioning.tfplan
   terraform show -no-color /tmp/colton-games-backend-versioning.tfplan
   terraform apply /tmp/colton-games-backend-versioning.tfplan
   aws s3api get-bucket-versioning --bucket ejc3-terraform-state \
     --region us-west-1 --query Status --output text
   ```

   Require the saved plan to contain only the versioning resource, require `Enabled` after
   applying it, then wait **at least 15 minutes** for S3 versioning to propagate.
3. After that wait, apply only the control-token container. This legitimate Terraform
   state write is also the versioning probe. Again, save and review the targeted plan,
   then apply that exact plan:

   ```bash
   terraform plan \
     -target=aws_secretsmanager_secret.cloudflare_workers_builds_control_token \
     -out=/tmp/colton-games-control-token-container.tfplan
   terraform show -no-color /tmp/colton-games-control-token-container.tfplan
   terraform apply /tmp/colton-games-control-token-container.tfplan
   aws s3api head-object --bucket ejc3-terraform-state \
     --key aws-infrastructure/terraform.tfstate --region us-west-1 \
     --query VersionId --output text
   ```

   Require the saved plan to contain only the empty secret container. The backend object's
   `VersionId` must then be non-empty and not `null` or `None`. Stop if it is not: do not
   create a deployment token or repository connection without a verified versioned state
   write.
4. Keep both gates false and return to a full saved plan:

   ```bash
   terraform plan -out=/tmp/colton-games-base.tfplan
   terraform apply /tmp/colton-games-base.tfplan
   terraform plan
   ```

   The saved plan should contain only the account Workers subdomain and any other already
   reviewed base configuration from this change. It must not create Builds credentials,
   connections, triggers, or environment maps; update the Worker; change Access; or
   destroy anything. Apply the saved plan immediately and require the follow-up plan to
   be empty.
5. Create and store the raw control token, then have the `CoderColton` repository owner
   complete the repository-only GitHub App authorization.
6. Change only `colton_games_workers_builds_enabled` to true. Re-plan immediately. This
   stage may create only the narrow deploy API token, its Builds registration, and the
   repository connection. It must not create either trigger or environment map, update
   the Worker, or change Access. Apply, then require an empty follow-up plan.
7. Change only `colton_games_worker_urls_enabled` to true. The plan should contain one
   in-place Worker update plus the two triggers and their two environment maps. The
   trigger dependency guarantees the already-protected URL surfaces are enabled before a
   GitHub event can deploy. Apply, immediately run a fresh plan, and require it to be
   empty. Only then verify an unauthenticated request is denied and the existing Access
   service token succeeds.
8. While pull request `CoderColton/colton-games#26` is still open, cause a `synchronize`
   event with a new commit and verify both its protected immutable preview and branch
   alias. A preview cannot exist while `previews_enabled` is false, so do not perform this
   check before step 7 or after merging the pull request.
9. Only after that preview succeeds, merge pull request #26 to `main`. Verify the
   resulting staging build and protected `workers.dev` deployment.

Every gate change is a reviewed, committed Terraform change. Do not disable either gate
after its protected resources exist; `prevent_destroy` is intended to stop that rollback.

## GitHub Actions and package infrastructure

The `workflow_job` webhook launches one-time Spot runners from prebuilt ARM64 or x86 AMIs.
Labels select the architecture; the launcher tries several metal families when capacity is
scarce, moving a family that just failed for capacity to the back of that order. Each new
instance carries `RunnerRegistrationProtocol=ddb-v1`. After GitHub configuration, bootstrap
validates the exact identity in `.runner`, conditionally records `State=registered` under its
instance ARN in DynamoDB, and starts the service only after that identity is confirmed.

Cleanup runs every five minutes. A registered `ddb-v1` runner is checked by its exact
GitHub runner id, and one with no row is reaped after its lease through a conditional
`State=reaping` claim on that row, so a bootstrap arriving at the same moment finds the row
taken and does not start the service. A missing row beside evidence that the runner did
register (GitHub still lists it, a `RunnerSeenAt` stamp, or a renewed lease) is a lost row,
and the instance is held to the age ceiling rather than reaped. Instances launched before the tag
existed keep the roster-based rules: a renewed lease or a `RunnerSeenAt` stamp holds them
on roster absence, and a readable roster that has never listed one expires its lease.
Cleanup also reaps stalled launches, terminates jobs running for more than three hours,
and counts queued jobs to retry scale-up.

A runner instance lives at most **13 hours 30 minutes**, checked on the five-minute poll,
so the observed maximum is that plus one interval. Past 12 hours it drains:
GitHub-idle means terminate now, and a job already in flight is left to finish. 13h30m is
the hard ceiling, computed from the instance's launch time alone and applied whatever the
runner is doing and whatever GitHub says, so a wedged host cannot outlive it. A ceiling
termination that never saw the runner idle logs `HARD-CEILING KILL`; that job will appear
on GitHub as "the self-hosted runner lost communication with the server", which is
otherwise indistinguishable from an AWS Spot reclaim.

The EC2 hard-ceiling pass completes before cleanup reads the PAT or calls GitHub, so GitHub
latency cannot defer the bound.

Terraform owns both halves of that webhook: it generates the HMAC secret, sets it on the
`ejc3/fcvm` hook through the `integrations/github` provider, and passes the same value to
the Lambda. There is no operator-held copy to fall out of sync -- which it did, silently
and completely, until 2026-08-07. That ownership takes effect at the one-time hook import
and the first apply after it (see Prerequisites); a state that has not run them yet still
has the pre-Terraform secret live on the hook.

The maximum is four runners per architecture, counted as runners GitHub can actually hand a
job to rather than instances that merely exist, so a wedged box cannot hold a slot. Each
scale-up decision emits a `GitHubRunners` metric and a structured log line. Two alarms
watch them: `runner-scale-up-starved` fires when queued work goes unserved for two hours
(a wedged pool, or one genuinely that far behind — a single poll cannot tell them apart,
because a host that wedges mid-job keeps reporting `busy` to GitHub), and
`runner-zero-online` fires within ten minutes when jobs are queued and nothing is online
or booting to take them.
Runner roots and instance-store data are disposable. See `GITHUB-RUNNERS.md` for the
webhook, AMI, lease, health, and cleanup internals.

The repository also manages:

- a private CodeArtifact npm repository in `us-west-2`;
- GitHub OIDC roles for drift detection and AMI builds;
- a separate administrator deploy role inside the `dev-staging` account;
- a daily Terraform drift workflow on `main`.

The drift workflow is not currently healthy: recent scheduled runs fail because its OIDC
role cannot read the Secrets Manager, Organizations, and CodeArtifact data required by a
full refresh. Secrets Manager is now the harder blocker of the three -- the Cloudflare and
GitHub provider tokens both come from there, so a plan cannot even configure its providers
without that read. Treat drift detection as scheduled but non-functional until that IAM gap
is fixed.

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
- Daily cost reports, AWS Budget notifications, runner-count/age alarms, the
  `runner-scale-up-starved` alarm, EC2 spend alarms, and instance-status alarms publish
  through SNS/email.
- The original jumpbox's protected home volume and the fully reproducible `jumpbox-2`
  provide two administration recovery paths.
- Terraform state is encrypted in S3 and locked with DynamoDB.

The jumpbox's gp3 volumes are capped at 125 MB/s. Never run broad recursive searches across
`/home/ubuntu` or `/tmp`; one such scan saturated both disks and made SSH unusable. Scope
searches to the repository, prefer `rg`, and move large scans/builds to ARM or the parallel
box.

## Private browser manager

`browser-manager/` is a separate, single-owner Next.js dashboard and `browserctl` CLI for
multiple named browser desktops on one host. One dedicated Cloudflare Tunnel hostname routes
`/browsers/<name>` to that exact desktop; it does not modify Dolphin Labs or its tunnel.
The dashboard can create/start/stop browsers and rename their display labels; the CLI prints the same shareable desktop URLs.
It is single-owner, not a multi-tenant service: separate profiles isolate browser sessions,
but are not separate OS security boundaries. These browsers have the host user's normal
network and filesystem access. Only that owner should have Cloudflare Access permission.

The dashboard and VNC WebSocket both require a verified Cloudflare Access
JWT for the configured audience and owner. Mutations require the expected Origin. The local
CLI uses an owner-only Unix socket, not a public bearer token. VNC uses private Unix sockets,
not public ports; unknown instance names cannot become arbitrary network or filesystem targets.
Every managed desktop has its own display and persistent browser profile. Stopping a desktop
retains its profile. There is no profile-deletion command, arbitrary executable launcher,
or remote CDP endpoint. Browser processes remain sandboxed. An expired Access session loses
its live desktop connection and must sign in again before reconnecting.

### 1. Apply on your administration host

Use this repository's Terraform 1.10.3 and existing backend/provider setup. Review the plan
for the whole stack; do not use `-target` to bypass unrelated changes. No Terraform plan or
apply runs on the browser/dev host, and it does not delegate one to a jumpbox.

```bash
umask 077
bm_handoff=$(mktemp -d)
terraform init -lockfile=readonly
terraform plan -out="$bm_handoff/plan"
terraform apply "$bm_handoff/plan"
terraform output -raw browser_manager_env > "$bm_handoff/browser-manager.env"
```

The hostname is fixed at `browsers.cc-games.dev`. Terraform creates a dedicated tunnel,
DNS record, and owner-only Access application using the existing Google/one-time-PIN providers.
It does not reuse the kids' family policy or Dolphin's GitHub policy. The browser host needs no Terraform,
AWS administration credentials, or Cloudflare account API token.

Terraform stores the raw connector token in AWS Secrets Manager as
`browser-manager-tunnel-token` in `us-west-1`. The shared ARM/x86 dev-server instance role
can read only this secret through its dedicated policy. Fetching it requires no additional
AWS login; the Next.js, runner, and temporary-compute roles do not receive this grant.

Transfer the public environment file privately to the browser host, owned by the browser
user with mode `0600`. On the ARM/x86 host, retrieve the connector token as `ubuntu`:

```bash
umask 077
install -d -m 0700 /home/ubuntu/.config/browser-manager
bm_token_tmp=$(mktemp /home/ubuntu/.config/browser-manager/.tunnel-token.XXXXXX)
if aws secretsmanager get-secret-value --region us-west-1 \
  --secret-id browser-manager-tunnel-token --query SecretString --output text > "$bm_token_tmp" \
  && test -s "$bm_token_tmp"; then
  mv -f "$bm_token_tmp" /home/ubuntu/.config/browser-manager/tunnel-token
else
  rm -f "$bm_token_tmp"
  echo 'Tunnel token retrieval failed; the existing token file was preserved.' >&2
fi
```

The connector token and saved Terraform plan are sensitive. Do not print or check them in.
The application receives the public Access settings; only `cloudflared` receives the token
file path. A public URL cannot work until both this apply and the host installation are done.

### 2. Install on the browser host

Use Linux with Node.js 22.13+ and an installed, sandbox-capable Chromium/Chrome. Install the
desktop prerequisites (`sudo apt-get install xvfb x11vnc openbox x11-xserver-utils x11-utils wmctrl python3 dbus libglib2.0-bin at-spi2-core python3-dbus`) and a current
[`cloudflared`](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/)
with `--token-file` support. Do not disable the Chrome sandbox to make installation pass.

In the transferred environment file, add `BM_BROWSER_BIN=/absolute/path/to/chrome` if Chrome
is not installed at a standard `/usr/bin/chromium`, `/usr/bin/chromium-browser`, or
`/usr/bin/google-chrome` path. The installer never downloads/replaces a browser or imports
any browser's credentials. Then, from this checkout:

```bash
cd browser-manager
npm ci --ignore-scripts
npm run build
./scripts/install.sh /absolute/path/browser-manager.env /home/ubuntu/.config/browser-manager/tunnel-token
```

Run the installer as the browser owner, not root. It installs two **user** systemd units,
`browser-manager.service` and `browser-manager-tunnel.service`, and `~/.local/bin/browserctl`.
Only these units are restarted. Existing browser services and Dolphin remain untouched.
The checkout must stay at the same path; to update it, rebuild and rerun the installer.
If prompted, an administrator can enable logout/reboot persistence with
`loginctl enable-linger <browser-user>`.

State and profiles live under `~/.local/state/browser-manager` (private to the owner).
Configuration and token files live under `~/.config/browser-manager`. The supported installer
uses that fixed state location so the CLI and service always agree. The application listens
only on `127.0.0.1:3210`; raw VNC and local CLI traffic use private Unix sockets.

### 3. Use it

```bash
browserctl start claude --url https://claude.ai
browserctl start research --url https://example.com
browserctl list
browserctl url claude
browserctl rename claude "Claude · Personal"
browserctl stop research
```

Open `https://browsers.cc-games.dev`, sign in through Google as the configured owner, then
open either desktop (for example `/browsers/claude`). Log in to websites within that desktop;
those logins stay in its host-side profile. Closing a viewer tab does not stop the browser.
Up to 32 names can be registered. Stop retains a name and its profile, and Start reuses it.
On service restart, previously running managed desktops are restored from saved desired state.

Use **Rename** on a browser card to edit its display label (1–80 characters, no control characters).
Labels are trimmed and saved; the dashboard and desktop title show them. Renaming never changes
the stable name used by CLI commands, `/browsers/<name>` URL, profile, saved logins, or live connection,
and does not restart the browser. Older browsers initially display their stable name as the label.

Use **Back** beside the desktop title to go back in the remote browser's history. The separate
top-left arrow returns to the browser-manager dashboard instead. Back follows the active remote
Chrome window/tab's native toolbar state, including navigation from other viewers. It is disabled
while disconnected or when the native state is unavailable. Foreground viewers refresh this
read-only state every 500 ms after the previous read completes; background polling pauses.
Each desktop uses its own private accessibility bus; no browsing history URLs are returned and
no remote-debugging endpoint is exposed. Host accessibility preferences are not changed.
On a phone, use **Fit to screen**, or turn it off for an actual-size scrollable desktop.
Use **Phone** to switch the remote browser itself to a narrow, responsive layout. On a phone,
the size follows the viewer's available width and height when tapped (bounded to 320–500 ×
480–900 pixels); desktop viewers use a 390 × 844 preset. Tap **Phone** again to return to
the 1440 × 900 desktop. This changes only the selected browser's shared display, so other
viewers of that same browser also see the change; separate browser instances are unaffected.
Tabs, page state, and logins remain in place: switching modes does not restart or reload the
browser. The mode survives viewer reconnects, but a browser/service restart starts in Desktop
mode. Phone changes the viewport, not the browser's user agent; it is not an iOS emulator.
**Keyboard** opens explicit text/paste and special-key controls; desktop keyboards and pointer
input also work directly. **Fit to screen** scales independently for each viewer; only the
explicit **Phone** toggle resizes the shared desktop. **Fullscreen** is shown only where the
viewing browser supports it.

VNC uses 24-bit true color with high JPEG quality (9/9) by default. When the viewing browser
reports Data Saver, a 2G/3G connection, or a positive downlink below 2 Mbps, it uses quality 6/9 and
stronger compression; changing connection hints updates the live connection. Browsers without
these hints, including Safari, keep high quality. These are browser hints, not a throughput test.

Disconnected viewers retry automatically while their tab is visible and focused, waiting
1, 2, 4, 8, then at most 10 seconds between failed attempts. Returning to the tab reconnects
immediately, including after phone suspension; background retries pause. A successful connection
resets the delay. Manual **Reconnect** remains available. Retries never bypass Access sign-in;
if it has expired, reload to sign in again. Reconnecting the viewer does not restart the browser.

To reuse an existing login profile without copying it, first close its existing browser using
that browser's normal service controls, then run
`browserctl start <name> --profile /absolute/profile/path` on this host. The CLI alone permits
explicit profiles; public API requests cannot select a filesystem path. External profiles with
Chrome locks are refused. Do not remove locks while another browser could be running. Reusing
a profile starts a new managed desktop; it does not attach VNC to an already-running display.

For service diagnostics use `systemctl --user status browser-manager browser-manager-tunnel`
and `journalctl --user -u browser-manager -u browser-manager-tunnel`. If the shell has no user
bus address, prefix these with `DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus`.
Cloudflare errors before sign-in usually mean the apply/connector is not ready; a stopped
desktop can be started from the dashboard. A profile remains on disk even if startup fails.

### Development and acceptance

`npm test`, `npm run typecheck`, and `npm run build` are the focused CI gate. Install `x11vnc`
before testing (CI does this automatically). Tests cover signed Access identities, Origin
enforcement, exact socket routing, expiry, and lifecycle without needing a Cloudflare account.
A small native VNC regression checks that the real server accepts Unix-socket connections
and owns no IPv4 or IPv6 TCP listeners; it does not need Chrome or the full UI. After building,
`BM_BROWSER_BIN=/absolute/path/to/chrome npm run test:live` runs two real sandboxed desktops and the production UI
on loopback with an ephemeral signed test identity; it does not add a production auth bypass.
It checks desktop/phone layout, real VNC input, native phone-width reflow and restoration,
phone-mode navigation, reconnect, and profile retention. Screenshots
go to `~/browser-manager-ui-artifacts`, never Git; test-only profiles are retained under the
printed temporary directory and all test desktops are stopped. New E2E findings should get
the smallest practical regression at the layer responsible, not a new proof framework.

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
| Private browser desktops | `browser-manager/`, `browser-manager.tf` |
| Optional Mac | `mac-dev.tf`, `mac-dev-secrets.tf`, `mac-dev-teardown.tf` |
| Staging and packages | `dev-staging-account.tf`, `dev-staging-bootstrap.tf`, `codeartifact.tf` |

`AGENTS.md` contains the deeper operational constraints, nested-virtualization details,
persistent-Spot recovery procedure, and live-system safety notes that an automation agent
must read before changing the repository.
