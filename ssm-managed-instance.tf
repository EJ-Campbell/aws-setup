# Additive shared policy: preserve SSM agent/session connectivity without the
# AWS-managed core policy's account-wide GetParameter/GetParameters permission.
# Workloads receive any needed parameter grant separately and by exact resource.
resource "aws_iam_policy" "ssm_managed_instance" {
  name        = "dev-ssm-managed-instance"
  description = "SSM managed-instance connectivity without account-wide parameter access"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManagedInstanceOperations"
        Effect = "Allow"
        Action = [
          "ssm:DescribeAssociation",
          "ssm:GetDeployablePatchSnapshotForInstance",
          "ssm:GetDocument",
          "ssm:DescribeDocument",
          "ssm:GetManifest",
          "ssm:ListAssociations",
          "ssm:ListInstanceAssociations",
          "ssm:PutInventory",
          "ssm:PutComplianceItems",
          "ssm:PutConfigurePackageResult",
          "ssm:UpdateAssociationStatus",
          "ssm:UpdateInstanceAssociationStatus",
          "ssm:UpdateInstanceInformation",
        ]
        Resource = "*"
      },
      {
        Sid    = "SessionChannels"
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel",
        ]
        Resource = "*"
      },
      {
        Sid    = "AgentMessages"
        Effect = "Allow"
        Action = [
          "ec2messages:AcknowledgeMessage",
          "ec2messages:DeleteMessage",
          "ec2messages:FailMessage",
          "ec2messages:GetEndpoint",
          "ec2messages:GetMessages",
          "ec2messages:SendReply",
        ]
        Resource = "*"
      },
    ]
  })
}
