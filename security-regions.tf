# Shared provider routing for security controls in both accounts' 17 enabled regions.
# Reuse existing west1/west2/east1 aliases; these definitions create no resources.
# If another region is enabled, explicitly extend both account module sets.

provider "aws" {
  alias  = "security_main_ap_northeast_1"
  region = "ap-northeast-1"
}

provider "aws" {
  alias  = "security_main_ap_northeast_2"
  region = "ap-northeast-2"
}

provider "aws" {
  alias  = "security_main_ap_northeast_3"
  region = "ap-northeast-3"
}

provider "aws" {
  alias  = "security_main_ap_south_1"
  region = "ap-south-1"
}

provider "aws" {
  alias  = "security_main_ap_southeast_1"
  region = "ap-southeast-1"
}

provider "aws" {
  alias  = "security_main_ap_southeast_2"
  region = "ap-southeast-2"
}

provider "aws" {
  alias  = "security_main_ca_central_1"
  region = "ca-central-1"
}

provider "aws" {
  alias  = "security_main_eu_central_1"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "security_main_eu_north_1"
  region = "eu-north-1"
}

provider "aws" {
  alias  = "security_main_eu_west_1"
  region = "eu-west-1"
}

provider "aws" {
  alias  = "security_main_eu_west_2"
  region = "eu-west-2"
}

provider "aws" {
  alias  = "security_main_eu_west_3"
  region = "eu-west-3"
}

provider "aws" {
  alias  = "security_main_sa_east_1"
  region = "sa-east-1"
}

provider "aws" {
  alias  = "security_main_us_east_2"
  region = "us-east-2"
}

provider "aws" {
  alias  = "security_staging_ap_northeast_1"
  region = "ap-northeast-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_ap_northeast_2"
  region = "ap-northeast-2"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_ap_northeast_3"
  region = "ap-northeast-3"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_ap_south_1"
  region = "ap-south-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_ap_southeast_1"
  region = "ap-southeast-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_ap_southeast_2"
  region = "ap-southeast-2"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_ca_central_1"
  region = "ca-central-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_eu_central_1"
  region = "eu-central-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_eu_north_1"
  region = "eu-north-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_eu_west_1"
  region = "eu-west-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_eu_west_2"
  region = "eu-west-2"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_eu_west_3"
  region = "eu-west-3"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_sa_east_1"
  region = "sa-east-1"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_us_east_2"
  region = "us-east-2"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}

provider "aws" {
  alias  = "security_staging_us_west_2"
  region = "us-west-2"
  assume_role {
    role_arn = "arn:aws:iam::${aws_organizations_account.dev_staging[0].id}:role/OrganizationAccountAccessRole"
  }
}
