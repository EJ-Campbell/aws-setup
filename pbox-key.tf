# pbox-key.tf
#
# THE PROBLEM THIS SOLVES: `pbox` (dev-selfupdate.tf, installed on fcvm-metal-arm/x86) needs
# to trigger scripts/parallel-box.sh on the jumpbox, because terraform state and the AWS
# admin role live there, not on the dev boxes (dev-selfupdate.tf: "the dev servers hold a
# restricted IAM role with no ec2:RunInstances"). That went silently broken when
# dev-hop-key.tf removed ~/.ssh/fcvm-ec2 from the dev boxes -- correctly, for the reason
# documented there (a leaked key on a box running agents with --dangerously-skip-permissions
# must not reach the jumpbox's admin session). pbox's own delegation SSH was never updated,
# so every `pbox up/down/status` from a dev box has been failing with
# "Permission denied (publickey)" ever since.
#
# THE FIX is the same shape as dev-hop-key.tf: a dedicated keypair, not the general admin
# key. But unlike dev-hop (which grants a normal shell on other dev boxes), this one is
# authorized on the jumpbox with a FORCED COMMAND -- scripts/pbox-forced-command.sh, which
# always runs parallel-box.sh and nothing else, regardless of what a caller asks for. Even
# a full leak of this key from a dev box grants nothing beyond "start/stop/check the
# 192-core box," never an admin shell, never arbitrary commands.
#
# codex-remote-control.tf's generated AGENTS.md said "no key to the jumpbox... do not add
# one" -- true for a general-purpose key, which this is not. That doc has been updated to
# describe this one narrow, forced-command exception.

resource "tls_private_key" "pbox" {
  algorithm = "ED25519"
}

resource "aws_secretsmanager_secret" "pbox" {
  name        = "pbox-ssh-key"
  description = "SSH key for dev-box -> jumpbox pbox delegation. Forced to scripts/pbox-forced-command.sh on the jumpbox side (see the authorized_keys entry installed by null_resource.pbox_authorized_key below) -- grants nothing else, unlike the general admin key."

  recovery_window_in_days = 7

  tags = { Name = "pbox-ssh-key", Managed = "terraform" }
}

resource "aws_secretsmanager_secret_version" "pbox" {
  secret_id = aws_secretsmanager_secret.pbox.id
  secret_string = jsonencode({
    private = tls_private_key.pbox.private_key_openssh
    public  = trimspace(tls_private_key.pbox.public_key_openssh)
  })
}

# ---------------------------------------------------------------------------------
# Installs the forced-command authorized_keys line on the ORIGINAL jumpbox.
#
# jumpbox.tf's own user_data is frozen (it predates this repo's conventions; see that
# file's header), so this can't ride the normal boot-time setup path the way dev boxes do.
# local-exec is the right tool anyway: AGENTS.md's own convention is "terraform runs
# directly on the jumpbox," so a local-exec provisioner here runs ON the jumpbox, which is
# exactly the machine whose authorized_keys needs the line.
#
# grep -qxF before appending, same idiom dev-hop-key.tf uses, so re-applying never grows
# a duplicate entry.
# ---------------------------------------------------------------------------------
resource "null_resource" "pbox_authorized_key" {
  triggers = {
    pubkey = trimspace(tls_private_key.pbox.public_key_openssh)
  }

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      LINE='command="/home/ubuntu/aws/scripts/pbox-forced-command.sh",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty ${trimspace(tls_private_key.pbox.public_key_openssh)} pbox'
      touch /home/ubuntu/.ssh/authorized_keys
      grep -qxF "$LINE" /home/ubuntu/.ssh/authorized_keys || echo "$LINE" >> /home/ubuntu/.ssh/authorized_keys
    EOT
  }
}

# ---------------------------------------------------------------------------------
# Boot-time fetch onto the dev boxes -- mirrors dev_hop_setup's fetch idiom
# (dev-hop-key.tf), but this key is OUTBOUND only: nothing needs to authorize it for
# inbound login anywhere, so there is no authorized_keys step here, just the private
# half landing at ~/.ssh/pbox.
# ---------------------------------------------------------------------------------
locals {
  pbox_key_setup = <<-EOT
PBOXJSON=$(aws secretsmanager get-secret-value --secret-id pbox-ssh-key \
  --region us-west-1 --query SecretString --output text 2>/dev/null)
if [ -n "$PBOXJSON" ]; then
  install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
  printf '%s' "$PBOXJSON" | python3 -c 'import sys,json;print(json.load(sys.stdin)["private"])' \
    > /home/ubuntu/.ssh/pbox
  chmod 600 /home/ubuntu/.ssh/pbox
  chown ubuntu:ubuntu /home/ubuntu/.ssh/pbox
else
  echo "WARNING: could not read pbox-ssh-key; pbox will not be able to reach the jumpbox"
fi
  EOT
}
