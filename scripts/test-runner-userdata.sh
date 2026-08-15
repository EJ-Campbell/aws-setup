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

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" = 0 ]
