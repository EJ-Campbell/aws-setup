# AWS Account Info
output "account_info" {
  description = "AWS Account information"
  value = {
    account_id = data.aws_caller_identity.current.account_id
    region     = var.aws_region
  }
}
