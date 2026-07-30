# parallel-box2.tf
#
# A SECOND on-demand Graviton spot box, so two independent parallel jobs can run at the
# same time -- e.g. one driven from each metal dev box. Same shape as parallel-box.tf:
# disposable spot instance, persistent 100GB work volume that outlives it, reaped by the
# same idle watchdog (parallel-box-watchdog.tf matches both Name tags).
#
# DELIBERATE DUPLICATION, same as jumpbox2.tf duplicates jumpbox.tf: two explicit,
# independent box definitions instead of a count/for_each parameterization. count would
# couple their lifecycles (destroying index 0 renumbers index 1); independent resources
# mean `pbox up 2` / `pbox down 2` can never touch box 1 mid-job. The only intentionally
# SHARED pieces are the security group, key pair, AMI/AZ variables and the watchdog --
# all stateless -- plus the spot-capacity walk in scripts/parallel-box.sh.
#
# Address it as box 2 from any dev box or jumpbox:
#     pbox up 2 | pbox down 2 | pbox ssh 2 | pbox status
#
# COST: the volume is ~$8/month, always. The instance is ~$3.14/hr, only while up.

variable "enable_parallel_box_2" {
  description = "Run the second Graviton spot box. ~$3.14/hr while up. Use scripts/parallel-box.sh (pbox up 2)."
  type        = bool
  default     = false
}

variable "parallel_box_2_type" {
  description = "Instance type for box 2. scripts/parallel-box.sh overrides this per attempt, walking the same pool list as box 1."
  type        = string
  default     = "c8g.48xlarge" # 192 cores / 384GB
}

# Its own persistent disk -- two boxes working one disk is exactly the contention this
# second box exists to avoid. Same prevent_destroy reasoning as parallel_work.
resource "aws_ebs_volume" "parallel_work_2" {
  provider          = aws.west2
  availability_zone = var.parallel_box_az
  size              = 100
  type              = "gp3"
  encrypted         = true

  tags = {
    Name    = "parallel-box-2-work"
    Purpose = "persistent scratch for the second on-demand parallel box"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_instance" "parallel_box_2" {
  provider = aws.west2
  count    = var.enable_parallel_box_2 ? 1 : 0

  ami           = var.parallel_box_ami # Ubuntu 24.04 arm64, us-west-2
  instance_type = var.parallel_box_2_type
  key_name      = aws_key_pair.parallel_box.key_name

  availability_zone      = var.parallel_box_az
  subnet_id              = "subnet-095349c0fcef8c47f" # default VPC, us-west-2d
  vpc_security_group_ids = [aws_security_group.parallel_box.id]
  iam_instance_profile   = aws_iam_instance_profile.dev_ebs_only.name

  instance_market_options {
    market_type = "spot"
    spot_options {
      spot_instance_type             = "one-time"
      instance_interruption_behavior = "terminate"
    }
  }

  # Root is DISPOSABLE and recreated on every launch. Anything you care about belongs
  # on /mnt/work, which is the persistent volume.
  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
  }

  # Identical bootstrap to box 1 except for the volume it mounts. If you change one,
  # change both -- they are kept textually parallel on purpose.
  user_data = <<-INIT
    #!/bin/bash
    set -uxo pipefail

    # Authorize the dev-hop key (dev-hop-key.tf) for direct login. This box is launched
    # and used from a dev box (fcvm-metal-arm/x86), which holds no key to the jumpbox and
    # no fcvm-ec2 key at all (dev-hop-key.tf) -- dev_hop is the ONLY key those boxes carry
    # that reaches another host, so it has to be what this box trusts too.
    install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.ssh
    touch /home/ubuntu/.ssh/authorized_keys
    grep -qxF "${trimspace(tls_private_key.dev_hop.public_key_openssh)}" /home/ubuntu/.ssh/authorized_keys || \
      echo "${trimspace(tls_private_key.dev_hop.public_key_openssh)}" >> /home/ubuntu/.ssh/authorized_keys
    chmod 600 /home/ubuntu/.ssh/authorized_keys
    chown ubuntu:ubuntu /home/ubuntu/.ssh/authorized_keys

    # Mount the persistent work volume.
    #
    # SAFETY: this must never reformat a disk that already holds data, and must never
    # touch the wrong disk. Two guards:
    #   1. Find the device by matching the EBS volume ID against the NVMe serial, rather
    #      than guessing /dev/nvme1n1 -- device order is not stable on Nitro.
    #   2. Only mkfs when blkid reports NO filesystem at all. No -f, ever.
    VOL_ID="${aws_ebs_volume.parallel_work_2.id}"
    SERIAL=$(echo "$VOL_ID" | tr -d '-')

    DEV=""
    for _ in $(seq 1 30); do
      DEV=$(lsblk -dn -o NAME,SERIAL 2>/dev/null | awk -v s="$SERIAL" '$2==s {print $1}' | head -1)
      [ -n "$DEV" ] && break
      sleep 2
    done

    if [ -z "$DEV" ]; then
      echo "FATAL: could not find the EBS volume $VOL_ID by serial; refusing to format anything" >&2
      exit 1
    fi
    DEV="/dev/$DEV"

    if ! blkid "$DEV" >/dev/null 2>&1; then
      echo "no filesystem on $DEV (first use) -- creating ext4"
      mkfs.ext4 -L parallel-work "$DEV"
    else
      echo "$DEV already has a filesystem -- mounting as-is, NOT formatting"
    fi

    mkdir -p /mnt/work
    mount "$DEV" /mnt/work
    chown ubuntu:ubuntu /mnt/work
    grep -q "$DEV" /etc/fstab || echo "$DEV /mnt/work ext4 defaults,nofail 0 2" >> /etc/fstab

    # Parallel-work basics. GNU parallel is the usual driver for this shape of job.
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y parallel build-essential git htop

    # Shared bulk scratch/cache on the separate i8ge I/O box. This is an automount, so
    # the parallel box still boots cleanly when the I/O box is stopped.
    ${local.io_box_client_setup}

    # Raise the file-descriptor ceiling: 192-way fan-out hits the 1024 default fast.
    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf

    echo "parallel-box-2 ready: $(nproc) cores, /mnt/work mounted"
  INIT

  tags = {
    Name    = "parallel-box-2"
    Purpose = "second on-demand embarrassingly-parallel compute"
    DevEBS  = "true"
  }

  lifecycle {
    # The root is disposable and a live run must never be stopped just because its
    # next-launch bootstrap changed. count=0 -> 1 still uses the newest user_data.
    ignore_changes = [user_data]
  }
}

resource "aws_volume_attachment" "parallel_work_2" {
  provider    = aws.west2
  count       = var.enable_parallel_box_2 ? 1 : 0
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.parallel_work_2.id
  instance_id = aws_instance.parallel_box_2[0].id

  # Detach cleanly when the box goes away; the VOLUME itself is untouched.
  force_detach = true
}

output "parallel_box_2_ssh" {
  description = "SSH command for the second on-demand parallel box"
  value       = var.enable_parallel_box_2 ? "ssh -i ~/.ssh/fcvm-ec2 ubuntu@${aws_instance.parallel_box_2[0].public_ip}" : "down (pbox up 2)"
}

output "parallel_box_2_work_volume" {
  description = "Persistent 100GB work volume for box 2 (survives the instance)"
  value       = aws_ebs_volume.parallel_work_2.id
}
