terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "central_event_bus_arn" { type = string }
variable "forwarding_role_arn" { type = string }
variable "audit_bucket_name" { type = string }
variable "audit_bucket_arn" { type = string }
variable "posture_enabled" { type = bool }
variable "record_global_iam" { type = bool }

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Account defaults have a single independent owner in modules/security-defaults.
locals {
  # CreateDetector enables omitted optional features. AWS provider 5.100's typed
  # feature enum predates AI_PROTECTION/AI_ANALYST; use its existing Cloud Control
  # resource, not a provisioner, provider upgrade, or a second detector owner.
  # RUNTIME_MONITORING covers EKS too; AWS rejects specifying both runtime names.
  guardduty_optional_features = [
    "S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS", "RUNTIME_MONITORING",
    "AI_PROTECTION", "AI_ANALYST",
  ]
  guardduty_runtime_agents = ["EKS_ADDON_MANAGEMENT", "ECS_FARGATE_AGENT_MANAGEMENT", "EC2_AGENT_MANAGEMENT"]
}

# The live regional CloudFormation schema accepts current feature names. All
# optional features are disabled in the initial request, with no auto-enrollment
# interval between detector creation and separate UpdateDetector calls.
resource "aws_cloudcontrolapi_resource" "guardduty" {
  type_name = "AWS::GuardDuty::Detector"
  desired_state = jsonencode({
    Enable                     = true
    FindingPublishingFrequency = "FIFTEEN_MINUTES"
    Features = [for name in local.guardduty_optional_features : merge({
      Name = name, Status = "DISABLED"
      }, name == "RUNTIME_MONITORING" ? {
      AdditionalConfiguration = [for agent in local.guardduty_runtime_agents : {
        Name = agent, Status = "DISABLED"
      }]
    } : {})]
    Tags = [{ Key = "Managed", Value = "terraform" }, { Key = "Purpose", Value = "security-baseline" }]
  })
  lifecycle {
    prevent_destroy = true
    # The generic provider refreshes properties, not desired_state. Assert the
    # actual service response so drift cannot silently look like a clean plan.
    postcondition {
      condition = try(jsondecode(self.properties).Enable == true &&
      jsondecode(self.properties).FindingPublishingFrequency == "FIFTEEN_MINUTES", false)
      error_message = "GuardDuty is not enabled with the reviewed finding interval; inspect the live detector before proceeding."
    }
    postcondition {
      condition = try(alltrue([for name in local.guardduty_optional_features :
        lookup({ for feature in jsondecode(self.properties).Features : feature.Name => feature.Status }, name, "MISSING") == "DISABLED"
        ]) && alltrue([for feature in jsondecode(self.properties).Features :
        contains(["FLOW_LOGS", "CLOUD_TRAIL", "DNS_LOGS"], feature.Name) || feature.Status == "DISABLED"
      ]), false)
      error_message = "GuardDuty optional feature readback differs from the reviewed disabled set; do not accept hidden enrollment or omit an unsupported regional feature silently."
    }
    postcondition {
      condition = try(alltrue([for agent in local.guardduty_runtime_agents :
        lookup({ for setting in one([for feature in jsondecode(self.properties).Features : feature if feature.Name == "RUNTIME_MONITORING"]).AdditionalConfiguration : setting.Name => setting.Status }, agent, "MISSING") == "DISABLED"
        ]) && alltrue(flatten([for feature in jsondecode(self.properties).Features :
          [for setting in try(feature.AdditionalConfiguration, []) : setting.Status == "DISABLED"]
      ])), false)
      error_message = "GuardDuty nested agent-management readback must explicitly disable every configured agent, even when Runtime Monitoring itself is disabled."
    }
  }
}

# Free account-zone analyzers and their service-linked roles are owned separately
# by security-external-access.tf; this module only forwards their findings.

# Forward useful security events without requiring email confirmation in 34 regions.
# Public SSH/ET is an explicit operator requirement. Controls continue to evaluate
# it; no blanket suppression hides unrelated new public administration exposures.
resource "aws_cloudwatch_event_rule" "findings" {
  name        = "security-forward-findings"
  description = "Forward security findings and high-risk control-plane changes to the admin account"
  event_pattern = jsonencode({
    "$or" = [
      {
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail        = { severity = [{ numeric = [">=", 4] }], service = { archived = [false] } }
      },
      {
        source        = ["aws.access-analyzer"]
        "detail-type" = ["Access Analyzer Finding"]
        detail        = { status = ["ACTIVE"] }
      },
      {
        source        = ["aws.securityhub"]
        "detail-type" = ["Security Hub Findings - Imported"]
        detail = { findings = {
          Severity    = { Label = ["HIGH", "CRITICAL"] }
          RecordState = ["ACTIVE"]
          Workflow    = { Status = ["NEW"] }
        } }
      },
      {
        source        = ["aws.inspector2"]
        "detail-type" = ["Inspector2 Finding"]
        detail        = { severity = ["HIGH", "CRITICAL"], status = ["ACTIVE"] }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      },
      {
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail        = { eventName = ["ConsoleLogin"], responseElements = { ConsoleLogin = ["Failure"] } }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["cloudtrail.amazonaws.com", "guardduty.amazonaws.com", "config.amazonaws.com", "securityhub.amazonaws.com", "access-analyzer.amazonaws.com"]
          eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector", "UpdateDetector", "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DisableSecurityHub", "DeleteAnalyzer"]
        }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName   = ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile", "AddUserToGroup", "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "UpdateAssumeRolePolicy", "DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"]
        }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["kms.amazonaws.com"]
          eventName   = ["DisableKey", "ScheduleKeyDeletion", "PutKeyPolicy", "DisableKeyRotation"]
        }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["backup.amazonaws.com"]
          eventName   = ["DeleteBackupVault", "DeleteBackupPlan", "DeleteBackupSelection", "UpdateBackupPlan", "PutBackupVaultAccessPolicy", "DeleteBackupVaultAccessPolicy", "PutBackupVaultLockConfiguration", "DeleteBackupVaultLockConfiguration", "UpdateRecoveryPointLifecycle", "UpdateGlobalSettings", "UpdateRegionSettings"]
        }
      },
      # Normal processing/checkpoint cleanup deliberately does not page the owner.
      # Attempts to delete legacy/final history still alert, including denied calls.
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource       = ["backup.amazonaws.com"]
          eventName         = ["DeleteRecoveryPoint"]
          requestParameters = { backupVaultName = ["ejc3-backup", "ejc3-backup-dr", "fcvm-backups", "ejc3-backup-recovery"] }
        }
      },
      {
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "central" {
  rule      = aws_cloudwatch_event_rule.findings.name
  target_id = "central-security-alerts"
  arn       = var.central_event_bus_arn
  role_arn  = var.forwarding_role_arn
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
  dead_letter_config { arn = aws_sqs_queue.delivery_failures.arn }
  depends_on = [aws_sqs_queue_policy.delivery_failures]
}

# A DLQ must be in its rule's Region. The central observer reads counts only;
# failed security events are retained for recovery, never consumed automatically.
resource "aws_sqs_queue" "delivery_failures" {
  name                      = "security-findings-delivery-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = { Managed = "terraform", Purpose = "security-delivery" }
}

resource "aws_sqs_queue_policy" "delivery_failures" {
  queue_url = aws_sqs_queue.delivery_failures.url
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.delivery_failures.arn
        Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.findings.arn } }
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.delivery_failures.arn
        Condition = { Bool = { "aws:SecureTransport" = "false", "aws:PrincipalIsAWSService" = "false" } }
      }
    ]
  })
}

# Posture checks run where durable workloads/data currently exist. GuardDuty and
# Access Analyzer above still cover every enabled region. A new workload region
# must add posture coverage in the root module when its infrastructure is added.
resource "aws_iam_role" "config" {
  count = var.posture_enabled ? 1 : 0
  name  = "security-config-${data.aws_region.current.name}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.posture_enabled ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_delivery" {
  count = var.posture_enabled ? 1 : 0
  name  = "audit-delivery"
  role  = aws_iam_role.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource = var.audit_bucket_arn
      },
      {
        Effect    = "Allow"
        Action    = "s3:PutObject"
        Resource  = "${var.audit_bucket_arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "security" {
  count    = var.posture_enabled ? 1 : 0
  name     = "security"
  role_arn = aws_iam_role.config[0].arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = var.record_global_iam
  }
  recording_mode {
    recording_frequency = "CONTINUOUS"
    recording_mode_override {
      description         = "Bound runner churn cost; instance and volume posture can lag by up to 24 hours"
      recording_frequency = "DAILY"
      resource_types      = ["AWS::EC2::Instance", "AWS::EC2::NetworkInterface", "AWS::EC2::Volume"]
    }
  }
  depends_on = [aws_iam_role_policy_attachment.config, aws_iam_role_policy.config_delivery]
}

resource "aws_config_delivery_channel" "security" {
  count          = var.posture_enabled ? 1 : 0
  name           = "security"
  s3_bucket_name = var.audit_bucket_name
  s3_key_prefix  = "config"
  snapshot_delivery_properties { delivery_frequency = "TwentyFour_Hours" }
  depends_on = [aws_config_configuration_recorder.security]
}

resource "aws_config_configuration_recorder_status" "security" {
  count      = var.posture_enabled ? 1 : 0
  name       = aws_config_configuration_recorder.security[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.security]
}

resource "aws_securityhub_account" "security" {
  count                     = var.posture_enabled ? 1 : 0
  enable_default_standards  = false
  auto_enable_controls      = true
  control_finding_generator = "SECURITY_CONTROL"
  depends_on                = [aws_config_configuration_recorder_status.security]
}

resource "aws_securityhub_standards_subscription" "foundational" {
  count         = var.posture_enabled ? 1 : 0
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.security]
}

# Standard OS/package and Lambda dependency scans, without the separately priced
# Lambda code scan, ECR scanning, or GuardDuty runtime/malware agents.
resource "aws_inspector2_enabler" "security" {
  count          = var.posture_enabled ? 1 : 0
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "LAMBDA"]
}
