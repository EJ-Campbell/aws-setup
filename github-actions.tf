# GitHub Actions OIDC for Terraform drift detection

# OIDC Provider for GitHub Actions
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# IAM Role for GitHub Actions
resource "aws_iam_role" "github_actions_terraform" {
  name = "github-actions-terraform"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # Allow both aws and fcvm repos (firepod was renamed to fcvm)
          # Pinned to main for ejc3/aws: its only workflow is the scheduled drift run, so a
          # branch has no reason to assume this role. ejc3/fcvm keeps the wildcard because
          # its AMI build uses workflow_dispatch, which may legitimately run from a branch.
          "token.actions.githubusercontent.com:sub" = ["repo:ejc3/aws:ref:refs/heads/main", "repo:ejc3/fcvm:*"]
        }
      }
    }]
  })
}

# Policy for drift detection and AMI builds
resource "aws_iam_role_policy" "github_actions_terraform" {
  name = "github-actions-policy"
  role = aws_iam_role.github_actions_terraform.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "iam:Get*",
          "iam:List*",
          "s3:Get*",
          "s3:List*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "rds:Describe*",
          "lambda:Get*",
          "lambda:List*",
          "apigateway:GET",
          "budgets:View*",
          "budgets:Describe*",
          "budgets:List*",
          "ses:Get*",
          "ses:List*",
          "ssm:GetParameter*",
          "ssm:DescribeParameters",
          "ssm:ListTagsForResource",
          "backup:Describe*",
          "backup:Get*",
          "backup:List*",
          "events:Describe*",
          "events:List*",
          "sns:Get*",
          "sns:List*",
          "sms-voice:Describe*"
        ]
        Resource = "*"
      },
      {
        # Named the real bucket. This pattern matched NOTHING: the backend bucket is
        # `ejc3-terraform-state` (see the backend block in main.tf), not
        # `aws-infrastructure-*-tf-state`. State access worked only because the ReadOnly
        # statement above grants s3:Get*/s3:List* on "*" -- so this statement read like it
        # was doing the scoping while contributing nothing, and tightening the broad grant
        # would have broken `terraform init` with a confusing AccessDenied.
        Sid    = "TerraformState"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::ejc3-terraform-state",
          "arn:aws:s3:::ejc3-terraform-state/*"
        ]
      },
      {
        Sid    = "TerraformLock"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem"
        ]
        Resource = "arn:aws:dynamodb:us-west-1:928413605543:table/ejc3-terraform-locks"
      },
      # THIS ROLE IS NOT READ-ONLY, despite what the drift-only workflow suggests. The
      # statements below exist for ejc3/fcvm's .github/workflows/build-runner-ami.yml,
      # which runs scripts/build-ami.sh: it launches a builder instance, snapshots it into
      # a runner AMI, and terminates it. Say so plainly here rather than let "CI can only
      # plan" survive as folklore -- ejc3/aws's own workflow really is plan-only, so the
      # write capability is invisible from this repo alone.
      #
      # The reach is worth understanding before extending it: the trust policy admits
      # `repo:ejc3/fcvm:*` (any ref, not just main), and build-ami.sh launches with
      # `--iam-instance-profile Name=jumpbox-admin-profile`. So this role can start an
      # instance that IS an admin. The conditions below keep that path pointed at AMI
      # builds instead of leaving it open-ended.
      {
        Sid    = "AMIBuilderLaunch"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateImage",
          "ec2:RegisterImage",
          "ec2:DeregisterImage"
        ]
        # Deliberately unconditioned. RunInstances authorises every resource it creates --
        # volumes, ENIs, the security group and subnet it references -- and build-ami.sh
        # tags only the instance, so an aws:RequestTag condition here would deny volume
        # creation and break the build. Narrowing this needs the script to tag every
        # created resource type first; tracked rather than guessed at.
        Resource = "*"
      },
      # CreateTags is split out from the launch statement because leaving it unrestricted
      # made the lifecycle scoping below decorative: the role could rename ANY instance --
      # a dev box, a runner -- to `ami-builder-temp` and then satisfy the terminate
      # condition. A tag-based guard is only as strong as who can write the tag.
      #
      # build-ami.sh does need to tag after launch (BuildStatus as the build progresses,
      # KernelVersion, and the AMI's own Name), so a blanket ec2:CreateAction restriction
      # would break it. The split below follows what the script actually does: `Name` on an
      # INSTANCE only at RunInstances; anything else afterwards; `Name` on an image freely.
      {
        Sid      = "AMIBuilderTagAtLaunch"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringEquals = {
            # Only as part of the RunInstances call itself, i.e. --tag-specifications on
            # an instance this role is creating. Never on one that already exists.
            "ec2:CreateAction" = "RunInstances"
          }
        }
      },
      {
        Sid      = "AMIBuilderTagProgress"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          # BuildStatus and KernelVersion on the running builder: allowed. `Name` on an
          # existing instance: denied, which is what keeps the terminate condition honest.
          "ForAllValues:StringNotEquals" = {
            "aws:TagKeys" = ["Name"]
          }
        }
      },
      {
        # Images and their snapshots. build-ami.sh names the finished AMI, and nothing
        # about that can reach a running instance, so `Name` is unrestricted here.
        Sid      = "AMIBuilderTagImage"
        Effect   = "Allow"
        Action   = "ec2:CreateTags"
        Resource = ["arn:aws:ec2:*::image/*", "arn:aws:ec2:*::snapshot/*"]
      },
      {
        # Stop/terminate ARE scoped: build-ami.sh only ever stops or terminates instances
        # it launched with Name=ami-builder-temp, including its orphan sweep, which
        # filters on exactly that tag. Combined with the tagging split above -- where only
        # RunInstances can put that Name on an instance -- this cannot reach a dev box or
        # a runner.
        Sid    = "AMIBuilderLifecycle"
        Effect = "Allow"
        Action = [
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Name" = "ami-builder-temp"
          }
        }
      },
      {
        # Constrained to EC2. Without this, the grant is "hand the admin role to any
        # service that accepts one"; with it, the only thing this role can do with
        # jumpbox_admin is launch an instance carrying it -- which is what the AMI build
        # needs and nothing more.
        Sid      = "PassRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.jumpbox_admin[0].arn
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      },
      {
        Sid    = "CodeArtifact"
        Effect = "Allow"
        Action = [
          "codeartifact:GetAuthorizationToken",
          "codeartifact:GetRepositoryEndpoint",
          "codeartifact:ReadFromRepository",
          "codeartifact:PublishPackageVersion",
          "codeartifact:PutPackageMetadata",
          "codeartifact:DescribePackageVersion",
          "codeartifact:ListPackageVersions",
          "codeartifact:ListPackages",
          "codeartifact:DeletePackageVersions"
        ]
        Resource = "*"
      },
      {
        Sid      = "CodeArtifactToken"
        Effect   = "Allow"
        Action   = "sts:GetServiceBearerToken"
        Resource = "*"
        Condition = {
          StringEquals = {
            "sts:AWSServiceName" = "codeartifact.amazonaws.com"
          }
        }
      }
    ]
  })
}
