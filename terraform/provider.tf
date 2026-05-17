terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    s3         = "http://192.168.100.20:4566"
    dynamodb   = "http://192.168.100.20:4566"
    iam        = "http://192.168.100.20:4566"
    sts        = "http://192.168.100.20:4566"
    cloudtrail = "http://192.168.100.20:4566"
  }
}
