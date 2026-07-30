#!/usr/bin/env bash
#
# Bring the on-demand many-core Graviton boxes up and down. There are TWO independent
# boxes (parallel-box.tf, parallel-box2.tf), each with its own persistent work volume,
# so two parallel jobs can run at once.
#
#   parallel-box.sh up [2]       launch box 1 (or 2); tries several instance types
#   parallel-box.sh down [2]     terminate it. Its work volume is KEPT.
#   parallel-box.sh status       both boxes: running? cost? disk?
#   parallel-box.sh status 2     just box 2
#   parallel-box.sh ssh [2]      connect
#   parallel-box.sh ip [2]       print the IP (used by the pbox wrapper)
#
# CAPACITY IS THE HARD PART. A 192-core spot request pinned to one AZ and one instance
# type scores 1/10 for fulfilment; allowing several instance types raises that
# materially. The persistent volumes are AZ-locked, so we cannot roam AZs without
# snapshotting -- but we CAN try every Graviton family in the volume's AZ, which is what
# the list below does. Each attempt is reported, so a failure is visible rather than a
# silent five-minute hang.
#
# All changes go through terraform, never the AWS CLI, so state never drifts.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGION="us-west-2"
JUMPBOX="10.0.1.72"

# Candidate pools, all offered in us-west-2d and all Graviton (incl. gen-5 c9g/m9g). The floor is "better
# than the dev box" (c7gd.metal, 64 cores / 128GB Graviton3), so nothing here is under
# 96 cores.
#
# Order matters:
#   1. 192-core virtualized, cheapest family first (c8g < c8gn < m8g < r8g < r8gd)
#   2. 96-core virtualized -- half the cores but a much likelier pool
# Metal is excluded entirely: it boots in many minutes, which defeats fast startup, and
# us-west-2d has enough virtualized pools that we should never need it.
TYPES="${PARALLEL_BOX_TYPES:-c8g.48xlarge c8gb.48xlarge c8gd.48xlarge c8gn.48xlarge c9g.48xlarge c9gd.48xlarge m8g.48xlarge m8gd.48xlarge m9g.48xlarge m9gd.48xlarge i8g.48xlarge i8ge.48xlarge r8g.48xlarge r8gd.48xlarge c8g.24xlarge c8gb.24xlarge c8gd.24xlarge c8gn.24xlarge c9g.24xlarge c9gd.24xlarge m8g.24xlarge m8gd.24xlarge m9g.24xlarge m9gd.24xlarge i8g.24xlarge i8ge.24xlarge r8g.24xlarge r8gd.24xlarge}"

# The dev servers hold a restricted IAM role with no ec2:RunInstances, and terraform
# state lives on the jumpbox, so delegate the terraform half rather than widening
# dev-box permissions.
on_jumpbox() { [ -d "$REPO/.terraform" ] && command -v terraform >/dev/null 2>&1; }

# KEY differs by where this script is actually running:
#   - on the jumpbox: fcvm-ec2, which every box in the fleet trusts for inbound SSH
#   - on a dev box: dev_hop -- the only key dev boxes hold that reaches another host
#     (fcvm-ec2 is deliberately absent from dev boxes; see dev-hop-key.tf). The parallel
#     boxes' own authorized_keys carry the dev_hop public key for exactly this reason,
#     so this is what a dev box uses for the direct hop once one is up.
# JUMPBOX_KEY is different again: a forced-command-only key (pbox-key.tf) that lets a dev
# box trigger THIS script on the jumpbox without holding anything admin-capable.
if on_jumpbox; then
  KEY="${HOME}/.ssh/fcvm-ec2"
else
  KEY="${HOME}/.ssh/dev_hop"
fi
JUMPBOX_KEY="${HOME}/.ssh/pbox"

delegate() {
  ssh -i "$JUMPBOX_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=no "ubuntu@$JUMPBOX" "$*"
}

cd "$REPO" 2>/dev/null || true

say() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------------------------
# Box selection. Box 1 keeps the original, unnumbered names (tag "parallel-box",
# enable_parallel_box, aws_instance.parallel_box) so nothing existing moves in state;
# box 2 is the "-2"/"_2" twin from parallel-box2.tf. Each box's terraform targets are
# ONLY its own instance+attachment, so operating one box can never touch the other
# mid-job.
# ---------------------------------------------------------------------------------
CMD="${1:-status}"
BOX="${2:-}"
case "$BOX" in
  ""|1|2) ;;
  *) say "unknown box '$BOX' (use 1 or 2)"; exit 1 ;;
esac

set_box() {
  if [ "$1" = "2" ]; then
    NAME="parallel-box-2" VOLTAG="parallel-box-2-work"
    EN_VAR="enable_parallel_box_2" TYPE_VAR="parallel_box_2_type"
    TGT_INST="aws_instance.parallel_box_2" TGT_ATT="aws_volume_attachment.parallel_work_2"
  else
    NAME="parallel-box" VOLTAG="parallel-box-work"
    EN_VAR="enable_parallel_box" TYPE_VAR="parallel_box_type"
    TGT_INST="aws_instance.parallel_box" TGT_ATT="aws_volume_attachment.parallel_work"
  fi
}
set_box "${BOX:-1}"

box_ip() {
  aws ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:Name,Values=$NAME" "Name=instance-state-name,Values=running" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null | grep -v '^None$' || true
}

if ! on_jumpbox; then
  case "$CMD" in
    up)
      delegate "up $BOX" || exit 1
      IP="$(delegate "ip $BOX")"
      [ -n "$IP" ] || { say "could not determine box IP"; exit 1; }
      say "Connecting to $IP ..."
      exec ssh -i "$KEY" -o StrictHostKeyChecking=no "ubuntu@$IP"
      ;;
    ssh)
      IP="$(delegate "ip $BOX")"
      [ -n "$IP" ] || { say "Box is down. Run: pbox up $BOX"; exit 1; }
      exec ssh -i "$KEY" -o StrictHostKeyChecking=no "ubuntu@$IP"
      ;;
    *) delegate "$CMD $BOX"; exit $? ;;
  esac
fi

status_one() {
  set_box "$1"
  echo "parallel-box $1:"
  IP="$(box_ip)"
  if [ -n "$IP" ]; then
    T=$(aws ec2 describe-instances --region "$REGION" \
      --filters "Name=tag:Name,Values=$NAME" "Name=instance-state-name,Values=running" \
      --query 'Reservations[0].Instances[0].InstanceType' --output text 2>/dev/null)
    echo "  state:  RUNNING at $IP ($T)"
    ssh -i "$KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
      "ubuntu@$IP" 'echo "  cores:  $(nproc)"; echo "  load:   $(uptime | sed "s/.*load average: //")"; echo "  work:   $(df -h /mnt/work | awk "NR==2{print \$3\" used of \"\$2}")"' 2>/dev/null \
      || echo "  (running, but SSH not answering yet)"
  else
    echo "  state:  down (\$0 compute)"
  fi
  echo "  volume: $(aws ec2 describe-volumes --region "$REGION" \
    --filters "Name=tag:Name,Values=$VOLTAG" \
    --query 'Volumes[0].[VolumeId,Size,State]' --output text 2>/dev/null) (persistent)"
}

case "$CMD" in
  ip) box_ip ;;

  up)
    IP="$(box_ip)"
    if [ -n "$IP" ]; then say "Already running at $IP"; exit 0; fi

    AZ=$(aws ec2 describe-volumes --region "$REGION" \
      --filters "Name=tag:Name,Values=$VOLTAG" \
      --query 'Volumes[0].AvailabilityZone' --output text 2>/dev/null)
    say "Work volume is in $AZ -- the box must launch there (EBS is AZ-locked)."
    say "Spot capacity for 192-core instances is scarce; trying each type in turn."
    say ""

    ok=0
    for T in $TYPES; do
      CORES=$(aws ec2 describe-instance-types --region "$REGION" --instance-types "$T" \
        --query 'InstanceTypes[0].VCpuInfo.DefaultVCpus' --output text 2>/dev/null)
      PRICE=$(aws ec2 describe-spot-price-history --region "$REGION" --instance-types "$T" \
        --product-descriptions "Linux/UNIX" --availability-zone "$AZ" --max-items 1 \
        --query 'SpotPriceHistory[0].SpotPrice' --output text 2>/dev/null)
      say "--> trying $T (${CORES:-?} cores, \$${PRICE:-?}/hr) in $AZ ..."

      # Stream terraform's own output so a slow step is visible as it happens.
      if terraform apply -auto-approve -no-color \
           -var "$EN_VAR=true" \
           -var "$TYPE_VAR=$T" \
           -target="$TGT_INST" \
           -target="$TGT_ATT" 2>&1 \
         | sed -u 's/^/    /' ; then
        # terraform's exit status, not sed's
        if [ "${PIPESTATUS[0]}" -eq 0 ]; then ok=1; CHOSEN="$T"; break; fi
      fi

      say "    no capacity for $T -- trying the next type"
      say ""
    done

    if [ "$ok" -ne 1 ]; then
      say ""
      say "FAILED: no spot capacity in $AZ for any of: $TYPES"
      say "Options:"
      say "  - retry later; spot capacity fluctuates hour to hour"
      say "  - override the list:  PARALLEL_BOX_TYPES='c8g.16xlarge' $0 up $BOX"
      say "  - move the volume to another AZ via snapshot (ask Claude for the roaming setup)"
      exit 1
    fi

    say ""
    say "Launched $CHOSEN. Waiting for SSH and the work disk to mount..."
    for i in $(seq 1 60); do
      IP="$(box_ip)"
      if [ -n "$IP" ] && ssh -i "$KEY" -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
           -o BatchMode=yes "ubuntu@$IP" true 2>/dev/null; then
        say "Ready at $IP"
        ssh -i "$KEY" -o StrictHostKeyChecking=no "ubuntu@$IP" \
          'echo "  cores: $(nproc)"; echo "  work:  $(df -h /mnt/work 2>/dev/null | awk "NR==2{print \$2\" total, \"\$4\" free\"}" || echo "not mounted yet")"' 2>/dev/null || true
        exit 0
      fi
      [ $((i % 6)) -eq 0 ] && say "    still booting (${i}0s)..."
      sleep 10
    done
    say "Launched but SSH did not come up in 10 min; check: $0 status"
    exit 1
    ;;

  down)
    # Targeted, unlike the original single-box version: with two boxes, a full apply
    # here would also reconcile (i.e. terminate) the OTHER box, whose enable var
    # defaults to false. The targets pin the destroy to this box's own resources.
    say "Terminating $NAME (its 100GB work volume is kept)..."
    terraform apply -auto-approve -no-color \
      -var "$EN_VAR=false" \
      -target="$TGT_INST" \
      -target="$TGT_ATT" 2>&1 | sed -u 's/^/    /'
    say "Down. Volume retained: $(aws ec2 describe-volumes --region "$REGION" \
      --filters "Name=tag:Name,Values=$VOLTAG" --query 'Volumes[0].VolumeId' --output text 2>/dev/null)"
    ;;

  status)
    # No explicit box -> show both; a numbered ask shows just that one.
    if [ -z "$BOX" ]; then
      status_one 1
      status_one 2
    else
      status_one "$BOX"
    fi
    ;;

  ssh)
    IP="$(box_ip)"
    [ -n "$IP" ] || { say "Box is down. Run: $0 up $BOX"; exit 1; }
    exec ssh -i "$KEY" -o StrictHostKeyChecking=no "ubuntu@$IP"
    ;;

  *)
    sed -n '3,13p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
    exit 1
    ;;
esac
