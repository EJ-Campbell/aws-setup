# Temporary, non-credential fixtures for the live runner IAM cutover on 2026-09-07.
# Run only GetParameter --query Parameter.Name using each runner's own EC2 role:
# its own fixture must succeed and its peer's must fail with AccessDenied.
# Repeat after removing the broad managed SSM grant, then delete these fixtures
# through a reviewed Terraform plan. Never use them as registration credentials.
resource "aws_ssm_parameter" "runner_iam_canary" {
  for_each = {
    first  = "arn:aws:ec2:us-west-1:928413605543:instance/i-0be53bfb530ed9362"
    second = "arn:aws:ec2:us-west-1:928413605543:instance/i-0f5cfc58a90969611"
  }
  name  = "/github-runner/bootstrap/security-canary-20260907-${each.key}"
  type  = "SecureString"
  value = "security-canary-not-a-credential"
  tags = {
    InstanceArn = each.value
    Purpose     = "temporary-runner-iam-boundary-test"
    RemoveAfter = "2026-09-07"
  }
}
