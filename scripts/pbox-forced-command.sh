#!/bin/bash
# Forced command for the restricted pbox SSH key (see pbox-key.tf). Whatever the caller
# asked to run arrives in $SSH_ORIGINAL_COMMAND, set by sshd. This script is the entire
# blast radius of that key: it can only ever run parallel-box.sh, never an arbitrary
# command or an interactive shell.
#
# The command is word-split (unquoted expansion below) so multi-word requests like
# "up 2" address box 2 -- but ONLY after the whitelist check: nothing outside
# [a-z0-9 ] is accepted, so shell metacharacters, paths, and option injection are
# rejected before the split, and the split itself cannot glob or re-parse syntax.
set -euo pipefail
CMD="${SSH_ORIGINAL_COMMAND:-status}"
case "$CMD" in
  *[!a-z0-9\ ]*) echo "pbox: rejected command" >&2; exit 1 ;;
esac
cd /home/ubuntu/aws
# shellcheck disable=SC2086
exec ./scripts/parallel-box.sh $CMD
