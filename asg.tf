# Auto Scaling Group for Buckman Infrastructure
# Provides zero-downtime rolling deployments with instance refresh

resource "aws_autoscaling_group" "buckman" {
  count = var.enable_dev_instance ? 1 : 0
  name  = "buckman-asg"

  # Capacity configuration
  desired_capacity = 2
  min_size         = 2
  max_size         = 2

  # High availability across multiple AZs
  vpc_zone_identifier = [
    aws_subnet.subnet_a.id,
    aws_subnet.subnet_b.id
  ]

  # Launch Template configuration
  launch_template {
    id      = aws_launch_template.buckman[0].id
    version = "$Latest" # Always use latest version for new instances
  }

  # ALB Integration
  target_group_arns = [aws_lb_target_group.proxy[0].arn]

  # Health checks
  health_check_type         = "ELB" # Use ALB health checks
  health_check_grace_period = 300   # 5 minutes for instance bootstrap
  default_cooldown          = 60    # 1 minute between scaling actions
  wait_for_capacity_timeout = "10m" # Wait up to 10 minutes for instances

  # Instance refresh configuration (zero-downtime deployments)
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50  # Keep at least 50% healthy during refresh
      instance_warmup        = 300 # 5 minutes warmup before health checks

      # Checkpoints for gradual rollout (optional but recommended)
      checkpoint_percentages = [50]
      checkpoint_delay       = 60 # Wait 1 minute at 50% checkpoint
    }

    triggers = ["tag"] # Trigger refresh when tags change
  }

  # Termination policies (which instances to replace first)
  termination_policies = [
    "OldestLaunchTemplate", # Replace instances with old launch template first
    "OldestInstance",       # Then oldest instance by creation time
    "Default"               # Then AWS default behavior
  ]

  # Metrics for scaling (even though we don't auto-scale, good for monitoring)
  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupMaxSize",
    "GroupMinSize",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances"
  ]

  # Protect instances from scale-in (we control replacements via instance refresh)
  protect_from_scale_in = false

  # Tags propagated to instances (in addition to launch template tags)
  tag {
    key                 = "ManagedBy"
    value               = "ASG"
    propagate_at_launch = true
  }

  tag {
    key                 = "DeploymentMethod"
    value               = "instance-refresh"
    propagate_at_launch = true
  }

  # Lifecycle hooks (optional, for future graceful shutdown improvements)
  # lifecycle {
  #   ignore_changes = [desired_capacity] # If using auto-scaling in future
  # }

  # Wait for instances to be healthy before considering creation complete
  wait_for_elb_capacity = 2

  # Force delete ASG even if instances are running (for easier Terraform destroy)
  force_delete = true

  # Dependencies - ensure resources exist before creating ASG
  depends_on = [
    aws_lb_target_group.proxy,
    aws_launch_template.buckman,
    aws_iam_instance_profile.dev
  ]
}

# Auto Scaling Policy - CPU-based (optional, currently not auto-scaling)
# Uncomment if you want auto-scaling in the future
# resource "aws_autoscaling_policy" "cpu_target" {
#   count                  = var.enable_dev_instance ? 1 : 0
#   name                   = "${var.project_name}-cpu-target-policy"
#   autoscaling_group_name = aws_autoscaling_group.buckman[0].name
#   policy_type            = "TargetTrackingScaling"
#
#   target_tracking_configuration {
#     predefined_metric_specification {
#       predefined_metric_type = "ASGAverageCPUUtilization"
#     }
#     target_value = 70.0 # Target 70% CPU utilization
#   }
# }

# CloudWatch Alarms for ASG health monitoring
resource "aws_cloudwatch_metric_alarm" "asg_unhealthy_instances" {
  count               = var.enable_dev_instance ? 1 : 0
  alarm_name          = "${var.project_name}-asg-unhealthy-instances"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Average"
  threshold           = 2 # Alert if less than 2 healthy instances
  alarm_description   = "Alert when ASG has less than 2 healthy instances"
  treat_missing_data  = "breaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.buckman[0].name
  }
}
