# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Nested Virtualization (NV2) Kernel

**CRITICAL**: The fcvm project requires a custom kernel with DSB patches for nested virtualization.

The host kernel must have these patches from `fcvm/kernel/patches/`:
- `nv2-vsock-cache-sync.patch` - DSB in KVM nested exit path
- `nv2-vsock-rx-barrier.patch` - DSB in vsock RX path
- `mmfr4-override.patch` - ID register override for recursive nesting

**Rebuild host kernel after adding new patches:**
```bash
cd /home/ubuntu/fcvm
./kernel/build.sh  # Builds guest kernel with patches

# For HOST kernel (needs modules too):
KERNEL_VERSION=6.18.3 BUILD_DIR=/tmp/kernel-build-host ./kernel/build.sh
cd /tmp/kernel-build-host/linux-6.18.3
sudo make ARCH=arm64 modules_install
sudo cp arch/arm64/boot/Image /boot/vmlinuz-6.18.3-nested-dsb
sudo update-grub
sudo reboot
```

**Current kernel on instance:** Check with `uname -r` - should show `-nested-dsb` suffix if DSB patches are applied.

## Project Philosophy

**KISS - Keep It Simple, Stupid**

This project is opinionated and minimal:
- One way to do things (no options)
- Make-driven (no manual commands)
- Automatic dependencies (no setup steps)
- Zero configuration (sensible defaults)

## Key Principles

1. **Makefile Does Everything**: All setup, login, config creation is handled automatically via Makefile dependencies
2. **No Options**: Device code flow only, 0 ACU auto-pause only, us-west-1 only
3. **Sensible Defaults**: Everything pre-configured for maximum cost savings
4. **No Extra Docs**: README.md is the only user-facing documentation
5. **ALL AWS CHANGES VIA TERRAFORM**: Never use AWS CLI to create/modify/delete resources. Always update .tf files and run `terraform apply`. Read-only `aws` commands (describe/list/get) are fine.

## Preventing Terraform Drift

**Fixed drift sources:**
- Removed CloudWatch alarms that referenced instance IDs (caused drift on spot instance recreation)
- Backup plans now terraform-managed (were manually created)
- Auto-stop uses Lambda instead of CloudWatch EC2 actions (works with spot instances)

**Rules to prevent drift:**
- **Never use `aws` CLI to create/modify/delete resources** - always edit `.tf` files
- Run `terraform plan` before `terraform apply` to catch issues
- Keep all infrastructure changes in git
- Avoid resources that reference instance IDs directly (they change on spot recreation)

## Project Overview

AWS infrastructure for a small set of personal dev boxes: a jumpbox, two Firecracker
metal servers, and a Next.js box serving the kids' games behind Cloudflare Access.

- Terraform infrastructure-as-code, S3 backend (`ejc3-terraform-state`) + DynamoDB locks
- ~155 managed resources across us-west-1 (plus a DR backup vault in us-east-1)
- No Aurora, and no database of any kind -- that was removed; ignore older references

## User Workflow

**Run terraform directly. Do not use `make` on the jumpbox.**

```bash
cd ~/aws
terraform plan
terraform apply
```

The Makefile drives terraform inside a container and needs podman or docker. Neither is
installed on the jumpbox, so every `make` target fails here. It was written for the Mac,
which has since been decommissioned. The jumpbox has terraform, the AWS CLI and an
instance role with the access it needs, so running terraform directly is the supported
path -- not a workaround.

Commit AND push every change: the live infrastructure, the terraform files and git must
not drift apart.

## Technical Details

### How this repo is driven

Terraform runs directly on the jumpbox, against the S3 backend with DynamoDB locking. The
instance role supplies credentials, so there is no login step and nothing to auto-refresh.

The `Dockerfile`, `Makefile`, `.container-built` and `.aws-login` machinery in this repo
predates that: it ran terraform inside a container from a Mac that no longer exists. It is
kept only because deleting it has not been worth the churn. **Do not follow it** -- the
jumpbox has no container runtime, so every `make` target fails here.

### Cost notes

- The dev boxes are the cost. Two metal spot instances dominate; the small boxes are noise
- `dev-auto-stop-lambda.tf` stops the metal boxes after 12h idle. nextjs-dev and the
  jumpbox are deliberately excluded -- they are meant to stay up
- There is no database. Older notes about Aurora Serverless auto-pause no longer apply

### File Structure

```
.
├── Dockerfile              # Container with Terraform, AWS CLI, utilities
├── Makefile               # Everything is a make target
├── main.tf                # Infrastructure definition
├── variables.tf           # Config with sensible defaults
├── outputs.tf             # Output values
├── terraform.tfvars       # User values (auto-created, gitignored)
└── README.md             # Simple guide
```

## When Working on This Project

### Do:
- **Run terraform directly on the jumpbox** - `terraform plan`, `terraform apply`, `terraform fmt`
- **Read the plan before applying.** It has caught real damage: an apply that would have
  dropped the Cloudflare Access policy and left every kid's dev URL publicly reachable
- Maintain single opinionated way to do things
- Keep README.md concise
- Test "wake up" scenario (expired sessions)
- **Prefer Makefile targets over direct CLI commands** for reproducibility

### Don't:
- Add options or alternatives
- Create extra documentation files
- Add manual setup steps
- Make users think about configuration
- Cache auth state without re-checking (breaks session expiration)
- **Use `make` on the jumpbox** - it needs a container runtime that is not installed here
- **NEVER add Claude Code attribution to git commits** - no "Generated with Claude Code" or "Co-Authored-By: Claude" in commit messages

### Common Pitfalls

**File-based auth tracking**: Don't do `touch .aws-login` without making it PHONY. Sessions expire but files don't.

**Stale plans**: `terraform plan` refreshes state against AWS, so a plan from before someone else's change is not safe to apply. Re-plan if the apply is not immediate.

**Manual setup steps**: Don't make users copy/paste values. Extract from Terraform state automatically.

## Development Instances

Three "snowflake" dev instances with static Elastic IPs:

| Instance | Type | Purchase | Purpose | Terraform |
|----------|------|----------|---------|-----------|
| jumpbox | t4g.large (2 vCPU / 8GB) | on-demand | Remote management, admin AWS access | jumpbox.tf |
| fcvm-metal-arm | c7gd.metal (64 vCPU) | spot | Firecracker/KVM on ARM64 | firecracker-dev.tf |
| fcvm-metal-x86 | c5d.metal | spot | Firecracker/KVM on x86 | x86-dev.tf |
| nextjs-dev | t4g.medium (2 vCPU / 4GB) | **on-demand** | Kids' Next.js games behind Cloudflare Access | nextjs-dev.tf |

**nextjs-dev is deliberately on-demand.** It ran as spot until 2026-07-25, when it was
reclaimed six times in one day and then could not restart at all -- the spot request
reported `capacity-not-available` and the kids' URLs were simply down with no ETA. Spot
placement score was 3/10 in every US region and for every alternative instance type, so
neither moving region nor changing family was a way out. Sized down large -> medium so the
durable option costs about what the unreliable one did (~$29/mo vs ~$24/mo spot).

### The kids' dev box and `cc-games.dev`

Each kid has their own Unix account, GitHub login, Vercel identity, and a permanent URL:

| account | URL | port |
|---------|-----|------|
| colton | https://colton.cc-games.dev | 3729 |
| connor | https://connor.cc-games.dev | 3641 |

Nothing listens publicly. `next dev` binds 127.0.0.1, and `cloudflared` dials **out** to
Cloudflare, so there is no inbound web port to open:

```
phone -> Cloudflare edge -> Access (Google login, email allowlist) -> tunnel -> 127.0.0.1:<port>
```

- Ports are derived (`3100 + cksum(hostname) % 800`), so they survive restarts and rebuilds
- `ndev` inside a project publishes it: registers the hostname and starts a systemd unit
- Each server runs as `ndev@<user>.service`; agents run as `claude-rc@` and `codex-rc@`.
  All are enabled at boot -- a reboot restores every URL with nobody logged in
- `cloudflare.tf` holds the tunnel, wildcard DNS, Access app and policies. A service token
  (`cc-games-access-service-token` in Secrets Manager) allows non-interactive access
- The kids have **full passwordless sudo**. The instance is the sandbox: no inbound web
  ports, and an IAM role that reads one S3 object and two secrets. Don't re-narrow it

### Hopping between dev servers

Dev boxes reach each other with a dedicated key (`dev-hop-key.tf`), never the jumpbox key:

```bash
ssh fcvm-arm      # aliases regenerated at boot by devhop-refresh from live private IPs
ssh nextjs
```

`~/.ssh/fcvm-ec2` is deliberately **absent** from the dev servers. It opens the jumpbox,
where the AWS admin session lives, and nothing on a dev box used it. The hop key's public
half is authorized on dev servers only, so holding it gets you another dev box and nothing
more. Verified: dev -> dev succeeds, dev -> jumpbox gives `Permission denied (publickey)`.

### Do not run recursive greps on the jumpbox

Its two volumes are gp3 capped at **125 MB/s**. On 2026-07-25 a
`grep -rl <pattern> /home/ubuntu /tmp` pinned both at exactly 125.19 MB/s for twenty
minutes, starving writes to zero -- journald stopped mid-heartbeat, and SSH accepted the
TCP connection then hung because PAM and lastlog never got I/O. It needed a reboot.

Scope searches to the directory you actually need, prefer `rg` over `grep -r`, and push
genuinely large scans to fcvm-metal-arm (64 vCPU) instead.

### Jumpbox Storage

The jumpbox has separate root and home volumes:
- **Root volume**: 8GB (`/dev/nvme0n1`) - OS, packages, boot
- **Home volume**: 20GB (`/dev/nvme1n1`) mounted at `/home/ubuntu` - user data, projects
- **Swap**: 4GB at `/home/ubuntu/.swapfile` (on home volume to save root space)

The home volume is backed up daily/weekly via AWS Backup.

### ARM Dev Server Storage (fcvm-metal-arm)

The ARM dev server (c7gd.metal) has instance NVMe storage for fast I/O:
- **Root volume**: 300GB EBS (`/dev/nvme2n1`) - OS, persistent data
- **NVMe 1**: 1.7TB (`/dev/nvme0n1`) - instance storage (ephemeral)
- **NVMe 2**: 1.7TB (`/dev/nvme1n1`) - instance storage, mounted at `/mnt/fcvm-btrfs`

**IMPORTANT**: The NVMe drives are ephemeral - data is lost on stop/start. Use for:
- VM images and caches (`/mnt/fcvm-btrfs/image-cache`)
- Build artifacts and temp files
- Firecracker VM storage

**Setup after instance start** (if NVMe not mounted):
```bash
# Check if already mounted
mount | grep nvme1n1

# If not mounted, format and mount:
sudo mkfs.btrfs -f /dev/nvme1n1
sudo mount /dev/nvme1n1 /mnt/fcvm-btrfs

# Add to fstab (use nofail since ephemeral)
echo '/dev/nvme1n1 /mnt/fcvm-btrfs btrfs defaults,nofail 0 0' | sudo tee -a /etc/fstab
```

**DO NOT** use loop device images (`/var/fcvm-btrfs.img`) - use NVMe directly for performance.

### SSH Access

```bash
# Get current IPs from terraform output
cd ~/aws && terraform output

# Or use the SSH commands directly
ssh -i ~/.ssh/fcvm-ec2 ubuntu@<jumpbox_public_ip>
ssh -i ~/.ssh/fcvm-ec2 ubuntu@<firecracker_dev_public_ip>
ssh -i ~/.ssh/fcvm-ec2 ubuntu@<x86_dev_public_ip>
```

### Shared Configuration

Common user_data scripts are in `dev-instance-common.tf`:
- `local.gh_auth_script` - GitHub CLI auth from Secrets Manager
- `local.claude_sync_script` - Claude Code Sync installation
- `local.gh_and_claude_sync_script` - Combined script

### GitHub PAT in Secrets Manager

GitHub authentication for private repos is stored in AWS Secrets Manager:
- **Secret name**: `github-pat-ejc3`
- **Region**: us-west-1
- **Used by**: claude-code-sync to clone private history repo

Instances fetch the token during user_data bootstrap:
```bash
GH_TOKEN=$(aws secretsmanager get-secret-value \
  --secret-id github-pat-ejc3 \
  --region us-west-1 \
  --query SecretString \
  --output text)
```

### Claude Code Sync

All dev instances have [claude-code-sync](https://github.com/ejc3/claude-code-sync) installed:
- Syncs Claude Code conversation history to GitHub
- Config: `~/.claude-code-sync-init.toml`
- Repo: `~/claude-history-sync`
- Remote: `https://github.com/ejc3/claude-code-history.git`

To sync manually:
```bash
claude-code-sync push   # Push local history to GitHub
claude-code-sync pull   # Pull history from GitHub
claude-code-sync        # Bidirectional sync (default)
```

### Elastic IPs

All dev instances have Elastic IPs for static addressing:
- IPs persist across stop/start cycles
- Defined in each instance's .tf file
- Cost: ~$3.60/month per unused EIP (free when attached to running instance)

### Auto-Stop Lambda

Dev servers are automatically stopped after **12 hours** of idle time to save costs. This is handled by a Lambda function (`dev-auto-stop-lambda.tf`) that runs hourly.

**How it works:**
- Checks CloudWatch CPU metrics (Maximum per hour, not average)
- If **all** hours in the last 12 have peak CPU < 5%, stops the instance
- Only counts metrics since instance `LaunchTime` (prevents false positives after restart)
- Sends SNS notification on stop (or if stop fails)

**Why Lambda instead of CloudWatch alarms:**
- CloudWatch EC2 stop actions don't work reliably with spot instances
- Lambda can check LaunchTime to avoid stale metric issues
- More control over logic (peak CPU vs average)

**Configuration:**
- `IDLE_HOURS = 12` - Hours of idle before auto-stop
- `INSTANCE_IDS` - Comma-separated list of instances to monitor
- `SNS_TOPIC_ARN` - For notifications

### Persistent Root Volumes (Spot Instances)

Dev instances use **spot instances** for ~70% cost savings, with persistent EBS root volumes to preserve data.

**The Challenge**: Spot instances can be terminated by AWS at any time. When terraform recreates the instance, it creates a NEW root volume from the AMI, orphaning the old volume with user data.

**Our Approach**:
1. Use spot with `persistent` type + `stop` interruption behavior
2. Set `delete_on_termination = false` on root volume
3. **Manual one-time volume swap** when instance is recreated

**CRITICAL: Spot Instance Restart Timing**

When you stop a persistent spot instance, AWS transitions the spot request state:
- `active` / `fulfilled` → `disabled` / `instance-stopped-by-user`

**There is a DELAY in this transition!** If you try to `start-instances` before the transition completes, you get:
```
IncorrectSpotRequestState: You can't start the Spot Instance because the associated Spot Instance request is not in an appropriate state
```

**Solution**: Wait for the spot request to show `disabled` state before starting:
```bash
# Check spot request state
aws ec2 describe-spot-instance-requests --region us-west-1 \
  --query "SpotInstanceRequests[?InstanceId=='$INSTANCE_ID'].{State:State,Status:Status.Code}" \
  --output table

# Wait until it shows: State=disabled, Status=instance-stopped-by-user
# Then start-instances will work
```

**Volume Swap Procedure** (after terraform creates new instance):
```bash
INSTANCE_ID="i-xxx"  # New instance ID from terraform output
PERSISTENT_VOL="vol-09e5c3cee32bb67dc"  # ARM dev server

# 1. Stop the new instance
aws ec2 stop-instances --instance-ids $INSTANCE_ID --region us-west-1
aws ec2 wait instance-stopped --instance-ids $INSTANCE_ID --region us-west-1

# 2. WAIT for spot request state transition (critical!)
echo "Waiting for spot request to transition to disabled state..."
while true; do
  STATE=$(aws ec2 describe-spot-instance-requests --region us-west-1 \
    --query "SpotInstanceRequests[?InstanceId=='$INSTANCE_ID'].State" --output text)
  echo "Spot request state: $STATE"
  if [ "$STATE" = "disabled" ]; then break; fi
  sleep 5
done

# 3. Swap volumes
CURRENT_VOL=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --region us-west-1 \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName==`/dev/sda1`].Ebs.VolumeId' \
  --output text)
echo "Swapping $CURRENT_VOL -> $PERSISTENT_VOL"

aws ec2 detach-volume --volume-id $CURRENT_VOL --region us-west-1
sleep 10
aws ec2 attach-volume --volume-id $PERSISTENT_VOL --instance-id $INSTANCE_ID \
  --device /dev/sda1 --region us-west-1
sleep 5

# 4. Start instance (now it will work!)
aws ec2 start-instances --instance-ids $INSTANCE_ID --region us-west-1

# 5. Cleanup temp volume
aws ec2 delete-volume --volume-id $CURRENT_VOL --region us-west-1

# 6. Re-associate EIP (terraform loses the association on recreate)
# ARM: eipalloc-034a515771765d101, x86: eipalloc-0173c9b5e3d294cc5
EIP_ALLOC="eipalloc-034a515771765d101"  # ARM
aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $EIP_ALLOC --region us-west-1

# 7. Wait for instance and clear old SSH host key
aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region us-west-1
IP="184.72.40.255"  # ARM EIP
ssh-keygen -R $IP
ssh -i ~/.ssh/fcvm-ec2 -o StrictHostKeyChecking=accept-new ubuntu@$IP "hostname; uptime"
echo "Done!"
```

**Persistent Volume IDs** (don't delete these!):
- ARM (fcvm-metal-arm): `vol-09e5c3cee32bb67dc`, EIP: `184.72.40.255` (`eipalloc-034a515771765d101`)
- x86 (fcvm-metal-x86): `vol-071f114b67441e776`, EIP: `50.18.109.164` (`eipalloc-0173c9b5e3d294cc5`)

**When to run the manual swap**: After `terraform apply` creates a new instance (you'll see a new instance ID in the output). Check if data is missing, then run the swap.

## Common Tasks

**Add a new Terraform variable**:
1. Add to `variables.tf` with sensible default
2. Add to `terraform.tfvars.example`
3. Update README.md if user needs to change it

**Change authentication**:
Don't. Device code flow is the only way.

**Add alternative regions**:
Don't. us-west-1 is the choice.

**Add deployment options**:
Don't. 0 ACU auto-pause is the way.

## Philosophy in Action

User says: "I want options for..."
Answer: No. One opinionated way.

User says: "Can I use access keys instead of SSO?"
Answer: No. Device code flow only.

User says: "I want to configure..."
Answer: Makefile handles it automatically.

The goal is zero decisions, zero configuration, maximum simplicity.
