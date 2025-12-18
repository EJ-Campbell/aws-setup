output "cluster_endpoint" {
  description = "Aurora cluster endpoint (write)"
  value       = aws_rds_cluster.aurora.endpoint
}

output "cluster_reader_endpoint" {
  description = "Aurora cluster reader endpoint (read-only)"
  value       = aws_rds_cluster.aurora.reader_endpoint
}

output "db_address" {
  description = "Database address (without port)"
  value       = aws_rds_cluster.aurora.endpoint
}

output "db_port" {
  description = "Database port"
  value       = aws_rds_cluster.aurora.port
}

output "db_name" {
  description = "Database name"
  value       = aws_rds_cluster.aurora.database_name
}

output "db_username" {
  description = "Database username"
  value       = aws_rds_cluster.aurora.master_username
  sensitive   = true
}

output "db_password" {
  description = "Database password (auto-generated)"
  value       = random_password.db_password.result
  sensitive   = true
}

output "connection_string" {
  description = "MySQL connection string"
  value       = "mysql -h ${aws_rds_cluster.aurora.endpoint} -P ${aws_rds_cluster.aurora.port} -u ${aws_rds_cluster.aurora.master_username} -p ${aws_rds_cluster.aurora.database_name}"
  sensitive   = true
}

output "iam_policy_arn" {
  description = "ARN of the IAM policy for RDS IAM authentication"
  value       = aws_iam_policy.rds_connect.arn
}

output "iam_connect_instructions" {
  description = "Instructions for IAM authentication setup"
  value       = <<-EOT
    To use IAM authentication:
    1. Attach the policy to your IAM user/role:
       aws iam attach-user-policy --user-name YOUR_USER --policy-arn ${aws_iam_policy.rds_connect.arn}
       OR
       aws iam attach-role-policy --role-name YOUR_ROLE --policy-arn ${aws_iam_policy.rds_connect.arn}

    2. Create a database user for IAM auth (connect with password first):
       CREATE USER 'iamuser'@'%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
       GRANT ALL PRIVILEGES ON *.* TO 'iamuser'@'%';
       FLUSH PRIVILEGES;

    3. Connect using IAM token:
       make connect-iam
  EOT
}

output "auto_pause_config" {
  description = "Auto-pause configuration details"
  value = {
    min_capacity        = aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].min_capacity
    max_capacity        = aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].max_capacity
    auto_pause_enabled  = aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].min_capacity == 0
    seconds_until_pause = aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].min_capacity == 0 ? aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].seconds_until_auto_pause : null
    pause_delay_minutes = aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].min_capacity == 0 ? aws_rds_cluster.aurora.serverlessv2_scaling_configuration[0].seconds_until_auto_pause / 60 : null
  }
}

# Auto Scaling Group Outputs
output "asg_name" {
  description = "Auto Scaling Group name"
  value       = var.enable_dev_instance ? aws_autoscaling_group.buckman[0].name : null
}

output "asg_desired_capacity" {
  description = "ASG desired capacity"
  value       = var.enable_dev_instance ? aws_autoscaling_group.buckman[0].desired_capacity : null
}

output "asg_min_size" {
  description = "ASG minimum size"
  value       = var.enable_dev_instance ? aws_autoscaling_group.buckman[0].min_size : null
}

output "asg_max_size" {
  description = "ASG maximum size"
  value       = var.enable_dev_instance ? aws_autoscaling_group.buckman[0].max_size : null
}

output "launch_template_id" {
  description = "Launch Template ID"
  value       = var.enable_dev_instance ? aws_launch_template.buckman[0].id : null
}

output "launch_template_latest_version" {
  description = "Latest version of Launch Template"
  value       = var.enable_dev_instance ? aws_launch_template.buckman[0].latest_version : null
}

output "instance_refresh_command" {
  description = "Command to trigger manual instance refresh"
  value       = var.enable_dev_instance ? "aws autoscaling start-instance-refresh --auto-scaling-group-name ${aws_autoscaling_group.buckman[0].name} --region ${var.aws_region}" : null
}

# SSM Parameter Store Outputs
output "ssm_runner_image_tag_parameter" {
  description = "SSM parameter name for runner image tag"
  value       = aws_ssm_parameter.runner_image_tag.name
}

output "ssm_version_server_image_tag_parameter" {
  description = "SSM parameter name for version-server image tag"
  value       = aws_ssm_parameter.version_server_image_tag.name
}

output "current_runner_image_tag" {
  description = "Current runner image tag from Parameter Store"
  value       = aws_ssm_parameter.runner_image_tag.value
  sensitive   = true
}

output "current_version_server_image_tag" {
  description = "Current version-server image tag from Parameter Store"
  value       = aws_ssm_parameter.version_server_image_tag.value
  sensitive   = true
}

# ALB Outputs
output "alb_dns_name" {
  description = "ALB DNS name for accessing the application"
  value       = var.enable_dev_instance ? aws_lb.main[0].dns_name : null
}

output "alb_url" {
  description = "Full ALB URL"
  value       = var.enable_dev_instance ? "http://${aws_lb.main[0].dns_name}" : null
}

output "alb_zone_id" {
  description = "ALB zone ID for Route53 records"
  value       = var.enable_dev_instance ? aws_lb.main[0].zone_id : null
}

# ECR Outputs
output "ecr_repository_url" {
  description = "ECR repository URL for all demos"
  value       = aws_ecr_repository.demos.repository_url
}

output "ecr_buckman_runner_url" {
  description = "ECR repository URL for buckman-runner"
  value       = aws_ecr_repository.buckman_runner.repository_url
}

output "ecr_buckman_version_server_url" {
  description = "ECR repository URL for buckman-version-server"
  value       = aws_ecr_repository.buckman_version_server.repository_url
}
