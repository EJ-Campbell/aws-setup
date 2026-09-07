# One-time restore acceptance test, deliberately absent until all five destination recovery
# points have been verified in the recovery account's us-east-1 LAG vault.
# Set a literal UTC minute at least 30 minutes after a fresh plan, for example the
# value printed by: date -u -d '+45 minutes' '+%Y-%m-%dT%H:%M:00Z'
# Verify the future time immediately before apply; do not reuse a stale saved plan.
# Retain the past one-off plan for audit after validation AND cleanup finish. A
# moving-time precondition would block unrelated permission repairs during a test.
# The explicit year makes this a single occurrence, not an annual/monthly schedule.
locals {
  backup_initial_restore_at = null
  # Provider validation still requires a non-null schedule when count=0. The past
  # placeholder is never created: null disables both resources, and malformed
  # non-null input is rejected by the plan precondition below.
  backup_initial_restore_cron = try(
    "cron(${formatdate("m h D M ? YYYY", local.backup_initial_restore_at)})", "cron(0 0 1 1 ? 1970)"
  )

  # Separate, one-off source capture proves processing-copy-cleanup behavior before
  # moving either existing backup selection. A null timestamp creates no resources.
  backup_initial_capture_at = "2026-09-07T20:30:00Z"
  backup_initial_capture_cron = try(
    "cron(${formatdate("m h D M ? YYYY", local.backup_initial_capture_at)})", "cron(0 0 1 1 ? 1970)"
  )
}

resource "aws_backup_restore_testing_plan" "initial" {
  provider                     = aws.staging_dr
  count                        = local.backup_initial_restore_at == null ? 0 : 1
  name                         = "fleet_initial_detached_ebs"
  schedule_expression          = local.backup_initial_restore_cron
  schedule_expression_timezone = "Etc/UTC"
  # AWS can start anywhere in this window; this is not an exact-time execution SLA.
  start_window_hours = 1

  recovery_point_selection {
    algorithm             = "LATEST_WITHIN_WINDOW"
    include_vaults        = [aws_backup_logically_air_gapped_vault.staging_recovery_dr.arn]
    recovery_point_types  = ["SNAPSHOT"]
    selection_window_days = 35
  }

  lifecycle {
    precondition {
      condition = (
        can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:00Z$", local.backup_initial_restore_at)) &&
        can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", local.backup_initial_restore_at))
      )
      error_message = "backup_initial_restore_at must be a real UTC date in YYYY-MM-DDTHH:MM:00Z format; the schedule has minute precision."
    }
  }
}

resource "aws_backup_restore_testing_selection" "initial_ebs" {
  provider                  = aws.staging_dr
  count                     = local.backup_initial_restore_at == null ? 0 : 1
  name                      = "fleet_initial_ebs"
  restore_testing_plan_name = aws_backup_restore_testing_plan.initial[0].name
  # '*' is constrained by the plan's one dedicated vault, containing only the
  # protected fleet volumes. EBS restores detached volumes, never EC2 instances.
  protected_resource_type = "EBS"
  protected_resource_arns = ["*"]
  iam_role_arn            = aws_iam_role.backup_restore_test.arn
  validation_window_hours = 2
  restore_metadata_overrides = {
    availabilityZone = data.aws_availability_zones.backup_restore_staging_dr.names[0]
    volumeType       = "gp3"
  }
  # AWS restore testing infers encrypted=true for EBS. 'encrypted' is not an
  # overridable key; the restore role additionally allows only encrypted gp3
  # volumes and explicitly denies RunInstances/AttachVolume/PassRole.
  # https://docs.aws.amazon.com/aws-backup/latest/devguide/restore-testing-inferred-metadata.html
  depends_on = [aws_iam_role_policy.backup_restore_test]
}

# Capture one new-generation processing point per protected volume without touching
# the legacy schedules or selections. Set a future literal UTC minute only after
# reviewing the pipeline deployment. These points deliberately have no expiry: a
# failed copy must retain its source, and verified cleanup is separately gated.
# Keep this past, explicit-year plan for audit after the one-off run. Do not add a
# moving-time precondition that would prevent repairing a failed capture later.
resource "aws_backup_plan" "initial_capture" {
  count = local.backup_initial_capture_at == null ? 0 : 1
  name  = "fleet-initial-processing-capture"

  rule {
    rule_name                    = "initial_processing_capture"
    target_vault_name            = aws_backup_vault.processing.name
    schedule                     = local.backup_initial_capture_cron
    schedule_expression_timezone = "Etc/UTC"
    start_window                 = 60
    completion_window            = 300
    recovery_point_tags          = { BackupPipeline = "fleet-processing-v2" }
  }

  tags = { Managed = "terraform", Purpose = "one-off-processing-capture-acceptance" }

  lifecycle {
    precondition {
      condition = (
        can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:00Z$", local.backup_initial_capture_at)) &&
        can(formatdate("YYYY-MM-DD'T'hh:mm:ssZ", local.backup_initial_capture_at))
      )
      error_message = "backup_initial_capture_at must be a real UTC date in YYYY-MM-DDTHH:MM:00Z format; the schedule has minute precision."
    }
  }
}

resource "aws_backup_selection" "initial_capture" {
  count        = local.backup_initial_capture_at == null ? 0 : 1
  name         = "fleet-initial-processing-capture"
  plan_id      = aws_backup_plan.initial_capture[0].id
  iam_role_arn = local.backup_service_role_arn
  resources    = local.backup_protected_volume_arns
}
