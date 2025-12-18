# Remote state backend - S3 + DynamoDB
# This allows CI runs to share Terraform state

terraform {
  backend "s3" {
    bucket         = "ejc3-aws-infra-tfstate-928413605543"
    key            = "terraform.tfstate"
    region         = "us-west-1"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}
