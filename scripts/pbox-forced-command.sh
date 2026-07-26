#!/bin/bash
# Forced command for the restricted pbox SSH key (see pbox-key.tf). Whatever the caller
# asked to run arrives in $SSH_ORIGINAL_COMMAND, set by sshd -- passed here as a single
# argument via `exec`, so it lands as inert data in argv[1], never re-parsed as shell
# syntax. This script is the entire blast radius of that key: it can only ever run
# parallel-box.sh, never an arbitrary command or an interactive shell.
set -euo pipefail
cd /home/ubuntu/aws
exec ./scripts/parallel-box.sh "${SSH_ORIGINAL_COMMAND:-status}"
