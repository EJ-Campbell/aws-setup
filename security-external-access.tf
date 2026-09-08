# Free external-access findings only: one account-zone analyzer per enabled region.
# Reuse security-regions.tf routing. No paid internal/unused analyzer, custom policy
# checks, archive rule, workload permission change, or notification pipeline.
# Explicitly own the two required service roles before regional analyzers start.

resource "aws_iam_service_linked_role" "access_analyzer_main" {
  aws_service_name = "access-analyzer.amazonaws.com"
}

resource "aws_iam_service_linked_role" "access_analyzer_staging" {
  provider         = aws.staging
  aws_service_name = "access-analyzer.amazonaws.com"
}

resource "aws_accessanalyzer_analyzer" "external_main_ap_northeast_1" {
  provider      = aws.security_main_ap_northeast_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_ap_northeast_2" {
  provider      = aws.security_main_ap_northeast_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_ap_northeast_3" {
  provider      = aws.security_main_ap_northeast_3
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_ap_south_1" {
  provider      = aws.security_main_ap_south_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_ap_southeast_1" {
  provider      = aws.security_main_ap_southeast_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_ap_southeast_2" {
  provider      = aws.security_main_ap_southeast_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_ca_central_1" {
  provider      = aws.security_main_ca_central_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_eu_central_1" {
  provider      = aws.security_main_eu_central_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_eu_north_1" {
  provider      = aws.security_main_eu_north_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_eu_west_1" {
  provider      = aws.security_main_eu_west_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_eu_west_2" {
  provider      = aws.security_main_eu_west_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_eu_west_3" {
  provider      = aws.security_main_eu_west_3
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_sa_east_1" {
  provider      = aws.security_main_sa_east_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_us_east_1" {
  provider      = aws.dr
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_us_east_2" {
  provider      = aws.security_main_us_east_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_us_west_1" {
  provider      = aws
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_main_us_west_2" {
  provider      = aws.west2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_main]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ap_northeast_1" {
  provider      = aws.security_staging_ap_northeast_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ap_northeast_2" {
  provider      = aws.security_staging_ap_northeast_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ap_northeast_3" {
  provider      = aws.security_staging_ap_northeast_3
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ap_south_1" {
  provider      = aws.security_staging_ap_south_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ap_southeast_1" {
  provider      = aws.security_staging_ap_southeast_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ap_southeast_2" {
  provider      = aws.security_staging_ap_southeast_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_ca_central_1" {
  provider      = aws.security_staging_ca_central_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_eu_central_1" {
  provider      = aws.security_staging_eu_central_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_eu_north_1" {
  provider      = aws.security_staging_eu_north_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_eu_west_1" {
  provider      = aws.security_staging_eu_west_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_eu_west_2" {
  provider      = aws.security_staging_eu_west_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_eu_west_3" {
  provider      = aws.security_staging_eu_west_3
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_sa_east_1" {
  provider      = aws.security_staging_sa_east_1
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_us_east_1" {
  provider      = aws.staging_dr
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_us_east_2" {
  provider      = aws.security_staging_us_east_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_us_west_1" {
  provider      = aws.staging
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}

resource "aws_accessanalyzer_analyzer" "external_staging_us_west_2" {
  provider      = aws.security_staging_us_west_2
  analyzer_name = "security-external-access"
  type          = "ACCOUNT"
  tags          = { Managed = "terraform" }
  depends_on    = [aws_iam_service_linked_role.access_analyzer_staging]
}
