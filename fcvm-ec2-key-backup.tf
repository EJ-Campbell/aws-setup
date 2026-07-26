# fcvm-ec2-key-backup.tf
#
# Backs up the PRIVATE half of the `fcvm-ec2` EC2 keypair to Secrets Manager.
#
# WHY THIS EXISTS: every box in this fleet (jumpbox, both metal servers, nextjs-dev) trusts
# this key for inbound SSH -- it is what "ssh -i ~/.ssh/fcvm-ec2 ubuntu@<box>" has meant all
# along. AWS only ever stores the PUBLIC half of an EC2 keypair (`aws ec2
# describe-key-pairs` proves this -- it returns no private material). The private half has
# existed as exactly one file, ~/.ssh/fcvm-ec2 on the original jumpbox, since 2025-11-09,
# and nowhere else. If that box's volume were ever lost, this key is gone permanently, and
# every other box's authorized_keys entry becomes permanently useless -- there would be no
# way back in except SSM Session Manager or the EC2 console, and no way to reissue the key
# without also editing every box's authorized_keys by some other channel.
#
# jumpbox-2 (jumpbox2.tf) needs this key to reach the rest of the fleet exactly the way the
# original jumpbox does, which is what made this gap visible -- but the gap existed
# regardless of jumpbox-2, and fixing it here fixes it for both.
#
# THE CONTAINER is declared here, in terraform, like every other secret in this repo. THE
# VALUE is deliberately NOT set via terraform: the key already exists and must be preserved
# exactly, not generated fresh (every box's authorized_keys already trusts this specific
# public key), and reading the existing private key file into a `.tf`-evaluated expression
# would mean either committing key material to git (if hardcoded) or making every future
# `terraform plan` depend on that exact file still being present on whatever machine runs
# it (if read via `file()`) -- which defeats the entire disaster-recovery purpose: a future
# plan run from jumpbox-2, after jumpbox-1 is gone, would fail evaluating the expression.
#
# ONE-TIME BOOTSTRAP (already performed as part of standing this up; repeat only if the key
# is ever rotated):
#   aws secretsmanager put-secret-value --secret-id fcvm-ec2-ssh-key --region us-west-1 \
#     --secret-string file://<(cat ~/.ssh/fcvm-ec2)
# This is a deliberate, narrow exception to "all AWS changes via terraform" -- CLAUDE.md
# already carves out disaster-recovery bootstrapping, and populating a pre-existing secret's
# value one time is exactly that class of action, not an ongoing resource this repo manages.

resource "aws_secretsmanager_secret" "fcvm_ec2_ssh_key" {
  name        = "fcvm-ec2-ssh-key"
  description = "Private half of the fcvm-ec2 EC2 keypair (id ed25519, registered 2025-11-09). Every box's inbound SSH trusts its public half. Value populated once by hand -- see the file header for why terraform does not manage it."

  recovery_window_in_days = 30

  tags = { Name = "fcvm-ec2-ssh-key", Managed = "terraform-container-only" }
}
