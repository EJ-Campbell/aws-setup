#!/bin/bash
# Exercise the runner user_data's IPv6 readiness gate against fakes.
#
# Why this exists: the user_data is an inline heredoc inside runner-autoscale.tf,
# so nothing runs it before it is deployed onto a real runner. On 2026-08-15 a CI
# job landed on a runner whose ENI already held 2600:1f1c:208:c01::baca while the
# guest OS had no global IPv6 at all. Every routed and IPv6 test failed with
# "No global IPv6 address found on host" -- a runner defect that reads as a code
# flake. The gate added in response refuses to register a runner in that state,
# and a gate that cannot fail is worse than no gate, so this proves it fails.
#
# Like scripts/test-runner-lambdas.py, this extracts the REAL heredoc body out of
# runner-autoscale.tf rather than keeping a copy that can drift.
#
# Run from the repo root:  bash scripts/test-runner-userdata.sh
# Exit code 1 if any case fails.
set -uo pipefail

TF_FILE="$(dirname "$0")/../runner-autoscale.tf"
[ -f "$TF_FILE" ] || { echo "cannot find runner-autoscale.tf next to $0" >&2; exit 2; }
VPC_FILE="$(dirname "$0")/../runner-vpc.tf"
[ -f "$VPC_FILE" ] || { echo "cannot find runner-vpc.tf next to $0" >&2; exit 2; }

# `<<-EOF` here only strips tabs and the content starts at column 0, so the body
# needs no dedent. Terraform's `$${` escape becomes a literal `${` on the host.
USERDATA=$(mktemp)
trap 'rm -f "$USERDATA"' EXIT
awk '/runner_user_data = <<-EOF/{f=1;next} f&&/^EOF$/{exit} f' "$TF_FILE" \
  | sed 's/\$\${/${/g' > "$USERDATA"
[ -s "$USERDATA" ] || { echo "extracted an EMPTY user_data from $TF_FILE" >&2; exit 2; }

PASS=0; FAIL=0
ok()   { echo "  ok   $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL $1"; FAIL=$((FAIL+1)); }

# --- 1. The whole script must parse. A syntax error here bricks every runner
#        launched afterwards, and the failure would only show up on a live box.
echo "user_data:"
if bash -n "$USERDATA" 2>/tmp/ud-syntax.$$; then
    ok "user_data parses ($(wc -l < "$USERDATA") lines)"
else
    bad "user_data has a syntax error: $(head -2 /tmp/ud-syntax.$$)"
fi
rm -f /tmp/ud-syntax.$$

# --- 2. The gate itself, lifted from the real file.
FN=$(awk '/^have_global_v6\(\) \{/{f=1} f{print} f&&/^\}$/{exit}' "$USERDATA")
if [ -z "$FN" ]; then
    bad "have_global_v6 not found in user_data (was the IPv6 gate removed?)"
    echo; echo "passed=$PASS failed=$FAIL"; exit 1
fi
ok "extracted have_global_v6 from the deployed user_data"

eval "$FN"

ADDR_OUT=""; ROUTE_OUT=""
ip() {  # stub: only the two queries the gate makes
    case "$*" in
        *"addr show scope global"*) printf '%s\n' "$ADDR_OUT" ;;
        *"route show"*)             printf '%s\n' "$ROUTE_OUT" ;;
    esac
}

check() {  # name want_rc
    have_global_v6; local got=$?
    if [ "$got" = "$2" ]; then ok "$1 (rc=$got)"; else bad "$1: wanted rc=$2, got rc=$got"; fi
}

echo "must REFUSE to register:"
ADDR_OUT=""; ROUTE_OUT=""
check "no global address at all -- the 2026-08-15 shape" 1

ADDR_OUT="    inet6 fd00:1234::5/64 scope global"
ROUTE_OUT=""
check "ULA only" 1

ADDR_OUT="    inet6 2600:1f1c:208:c01::baca/64 scope global deprecated"
ROUTE_OUT=""
check "deprecated /64 only" 1

ADDR_OUT="    inet6 2600:1f1c:208:c01::baca/128 scope global"
ROUTE_OUT="fe80::/64 dev enp0s1 proto kernel metric 256"
check "/128 with no on-link /64 route" 1

echo "must ALLOW registration:"
ADDR_OUT="    inet6 2600:1f1c:208:c01::baca/64 scope global dynamic mngtmpaddr"
ROUTE_OUT=""
check "plain /64" 0

ADDR_OUT="    inet6 2600:1f1c:208:c01::baca/128 scope global dynamic"
ROUTE_OUT="2600:1f1c:208:c01::/64 dev enp0s1 proto ra metric 100 pref medium"
check "/128 backed by an on-link /64 -- the AWS DHCPv6 shape" 0

ADDR_OUT="    inet6 fd00:1::1/64 scope global
    inet6 2600:1f1c:208:c01::baca/128 scope global"
ROUTE_OUT="2600:1f1c:208:c01::/64 dev enp0s1 proto ra metric 100"
check "ULA alongside a usable /128" 0

# --- 3. A storeless instance type must fail legibly, not take the bootstrap
#        down at an unrelated line. `grep -v` matching nothing returns 1, and
#        under `set -e` that killed everything after it (2026-08-15, c7g.metal).
echo "instance store:"
# shellcheck disable=SC2016 # The extracted script must contain literal $ROOT_DEV.
if grep -q 'grep -v "\^\$ROOT_DEV\$" || true' "$USERDATA"; then
    ok "NVMe probe tolerates a no-match instead of aborting the bootstrap"
else
    bad "NVMe probe can still abort the bootstrap when there is no instance store"
fi
if grep -q "no instance-store NVMe on this instance type" "$USERDATA"; then
    ok "storeless instance refuses to register, with a reason"
else
    bad "no explicit refusal for a storeless instance"
fi

# --- 4. The gate must actually be wired to the registration decision. A gate
#        nothing consults is the same as no gate.
echo "wiring:"
CONFIG_LINE=$(grep -n "config.sh --url" "$USERDATA" | head -1 | cut -d: -f1)
if [ -z "$CONFIG_LINE" ]; then
    bad "config.sh registration not found -- cannot tell whether any gate precedes it"
else
    ok "found the registration call (line $CONFIG_LINE)"
fi

# Each gate is checked BY ITS OWN message: both say "refusing to register", so a
# single grep would let one of them sit after registration unnoticed.
gate_precedes_registration() {  # label, message
    local line
    line=$(grep -n "$2" "$USERDATA" | head -1 | cut -d: -f1)
    if [ -z "$line" ]; then
        bad "$1: no refusal path found -- does a failed gate still register the runner?"
    elif [ -n "$CONFIG_LINE" ] && [ "$line" -lt "$CONFIG_LINE" ]; then
        ok "$1 refuses before registration (line $line < $CONFIG_LINE)"
    else
        bad "$1 does not precede registration (gate=$line config=$CONFIG_LINE)"
    fi
}
gate_precedes_registration "IPv6 gate"  "no global IPv6 on"
gate_precedes_registration "NVMe gate"  "no instance-store NVMe on this instance type"

# --- 5. Registration provenance must be persisted before the service can take
#        work. Successful config reads the runner id GitHub assigned, atomically
#        claims this instance ARN in DynamoDB, and only then starts the service.
echo "registration provenance:"
TRACE_OFF_LINE=$(grep -n '^set +x$' "$USERDATA" | head -1 | cut -d: -f1)
PAT_LINE=$(grep -n '^PAT=' "$USERDATA" | head -1 | cut -d: -f1)
RUNNER_ID_LINE=$(grep -n '\.agentId' "$USERDATA" | head -1 | cut -d: -f1)
CLAIM_LINE=$(grep -n 'aws dynamodb put-item' "$USERDATA" | head -1 | cut -d: -f1)
CONSISTENT_LINE=$(grep -n -- '--consistent-read' "$USERDATA" | head -1 | cut -d: -f1)
INSTALL_LINE=$(grep -n './svc.sh install' "$USERDATA" | head -1 | cut -d: -f1)
START_LINE=$(grep -n './svc.sh start' "$USERDATA" | head -1 | cut -d: -f1)

if [ -n "$TRACE_OFF_LINE" ] && [ -n "$PAT_LINE" ] \
   && [ "$TRACE_OFF_LINE" -lt "$PAT_LINE" ]; then
    ok "xtrace is disabled before either GitHub token is read"
else
    bad "GitHub tokens can reach cloud-init xtrace (set+x=$TRACE_OFF_LINE PAT=$PAT_LINE)"
fi

if [ -n "$RUNNER_ID_LINE" ] && [ -n "$CLAIM_LINE" ] \
   && [ -n "$INSTALL_LINE" ] && [ -n "$START_LINE" ] \
   && [ "$CONFIG_LINE" -lt "$RUNNER_ID_LINE" ] \
   && [ "$RUNNER_ID_LINE" -lt "$CLAIM_LINE" ] \
   && [ "$CLAIM_LINE" -lt "$INSTALL_LINE" ] \
   && [ "$CLAIM_LINE" -lt "$START_LINE" ]; then
    ok "config identity is claimed before service installation and startup"
else
    bad "registration identity ordering is unsafe (config=$CONFIG_LINE id=$RUNNER_ID_LINE claim=$CLAIM_LINE install=$INSTALL_LINE start=$START_LINE)"
fi

if [ -n "$CONSISTENT_LINE" ] \
   && grep -q "attribute_not_exists(InstanceArn)" "$USERDATA" \
   && grep -q 'State: {S: "registered"}' "$USERDATA" \
   && grep -q 'refusing to start runner service' "$USERDATA"; then
    ok "uncertain or lost registration claims fail closed through a consistent read"
else
    bad "registration claim lacks conditional-create, strong-read, or fail-closed handling"
fi

# shellcheck disable=SC2016 # Terraform must emit the literal IAM policy variable.
if grep -q 'dynamodb:LeadingKeys' "$VPC_FILE" \
   && grep -q '\$${ec2:SourceInstanceARN}' "$VPC_FILE" \
   && grep -q 'dynamodb:GetItem' "$VPC_FILE" \
   && grep -q 'dynamodb:PutItem' "$VPC_FILE" \
   && ! grep -Eq 'dynamodb:(Scan|Query|UpdateItem|DeleteItem)' "$VPC_FILE"; then
    ok "runner role can claim only its source-instance ARN row"
else
    bad "runner role lacks source-instance-scoped registration-table access"
fi

if grep -q 'aws_lambda_function.runner_cleanup,' "$TF_FILE" \
   && grep -q 'aws_iam_role_policy.runner_lambda,' "$TF_FILE" \
   && grep -q 'aws_iam_role_policy.runner,' "$TF_FILE" \
   && grep -q 'aws_ssm_parameter.runner_user_data,' "$TF_FILE" \
   && grep -q 'WEBHOOK_FUNCTION   = "github-runner-webhook"' "$TF_FILE"; then
    ok "ddb-v1 launcher activation waits for cleanup, IAM, and user data"
else
    bad "Terraform rollout can activate ddb-v1 before both protocol participants"
fi

# --- 6. Execute the real registration tail against command fakes. Static line
#        ordering cannot prove the losing branch actually stops before svc.sh.
echo "registration interleavings:"
REG_TMP=$(mktemp -d)
trap 'rm -f "$USERDATA"; rm -rf "$REG_TMP"' EXIT
mkdir -p "$REG_TMP/bin" "$REG_TMP/work"
REG_BLOCK="$REG_TMP/registration.sh"
{
    echo 'set -euo pipefail'
    # shellcheck disable=SC2016 # Replace a literal Terraform interpolation in the extracted text.
    sed -n '/# Do not xtrace either token/,$p' "$USERDATA" \
      | sed 's/${local\.runner_registration_table_name}/github-runner-registration/g'
} > "$REG_BLOCK"

cat > "$REG_TMP/bin/aws" <<'FAKE_AWS'
#!/bin/bash
set -eu
if [ "$1 $2" = "ssm get-parameter" ]; then
    echo ghp_test
elif [ "$1 $2" = "dynamodb put-item" ]; then
    echo put-item >> "$JOURNAL"
    [ "$FAKE_SCENARIO" = bootstrap ] && exit 0
    exit 1
elif [ "$1 $2" = "dynamodb get-item" ]; then
    echo get-item >> "$JOURNAL"
    if [ "$FAKE_SCENARIO" = unknown_registered ]; then
        jq -cn --arg arn "arn:aws:ec2:$REGION:928413605543:instance/$INSTANCE_ID" \
          --arg instance "$INSTANCE_ID" \
          '{Item:{InstanceArn:{S:$arn},State:{S:"registered"},
            InstanceId:{S:$instance},RunnerName:{S:("runner-"+$instance)},
            RunnerId:{N:"77"},RegisteredAt:{S:"2026-08-07T20:00:00Z"}}}'
    elif [ "$FAKE_SCENARIO" = cleanup ]; then
        jq -cn --arg arn "arn:aws:ec2:$REGION:928413605543:instance/$INSTANCE_ID" \
          --arg instance "$INSTANCE_ID" \
          '{Item:{InstanceArn:{S:$arn},State:{S:"reaping"},
            InstanceId:{S:$instance},ReapingAt:{S:"2026-08-07T20:00:00Z"}}}'
    else
        exit 1
    fi
else
    echo "unexpected aws call: $*" >&2
    exit 90
fi
FAKE_AWS

cat > "$REG_TMP/bin/curl" <<'FAKE_CURL'
#!/bin/bash
set -eu
case "$*" in
  *dynamic/instance-identity/document*)
    printf '%s\n' '{"accountId":"928413605543","region":"us-west-1"}' ;;
  *registration-token*)
    printf '%s\n' '{"token":"registration-token"}' ;;
  *"-X DELETE"*)
    echo delete >> "$JOURNAL" ;;
  *)
    echo "unexpected curl call: $*" >&2; exit 91 ;;
esac
FAKE_CURL

cat > "$REG_TMP/bin/sudo" <<'FAKE_SUDO'
#!/bin/bash
set -eu
if [ "${1:-}" = -u ]; then shift 2; fi
exec "$@"
FAKE_SUDO

# The runner writes `.runner` with camelCase keys (RunnerSettings goes
# through VssCamelCasePropertyNamesContractResolver); the fake writes the
# same shape, so a bootstrap that reads the wrong key fails here.
cat > "$REG_TMP/work/config.sh" <<'FAKE_CONFIG'
#!/bin/bash
set -eu
printf '{"agentId":77,"agentName":"runner-%s","poolId":1,"poolName":"Default","serverUrl":"https://pipelines.actions.githubusercontent.com/x","gitHubUrl":"https://github.com/ejc3/fcvm","workFolder":"_work"}\n' "$INSTANCE_ID" > .runner
FAKE_CONFIG

cat > "$REG_TMP/work/svc.sh" <<'FAKE_SVC'
#!/bin/bash
set -eu
echo "svc:$*" >> "$JOURNAL"
FAKE_SVC
chmod +x "$REG_TMP/bin/aws" "$REG_TMP/bin/curl" "$REG_TMP/bin/sudo" \
  "$REG_TMP/work/config.sh" "$REG_TMP/work/svc.sh" "$REG_BLOCK"

registration_case() { # scenario expected_rc expected_service expected_delete
    local scenario=$1 want_rc=$2 want_service=$3 want_delete=$4 rc=0
    local journal="$REG_TMP/$scenario.log"
    : > "$journal"
    rm -f "$REG_TMP/work/.runner"
    (
      cd "$REG_TMP/work"
      PATH="$REG_TMP/bin:$PATH" \
      FAKE_SCENARIO="$scenario" JOURNAL="$journal" \
      INSTANCE_ID=i-test RUNNER_LABEL=ARM64 TOKEN=imdsv2-token REGION=us-west-1 \
        bash "$REG_BLOCK"
    ) >/dev/null 2>&1 || rc=$?
    local service=0 deleted=0
    grep -q '^svc:start$' "$journal" && service=1
    grep -q '^delete$' "$journal" && deleted=1
    if [ "$rc" = "$want_rc" ] && [ "$service" = "$want_service" ] \
       && [ "$deleted" = "$want_delete" ]; then
        ok "$scenario (rc=$rc service=$service delete=$deleted)"
    else
        bad "$scenario: rc=$rc service=$service delete=$deleted, wanted $want_rc/$want_service/$want_delete ($(tr '\n' ' ' < "$journal"))"
    fi
}

registration_case bootstrap          0 1 0
registration_case unknown_registered 0 1 0
registration_case cleanup            1 0 1
registration_case unread             1 0 1

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
