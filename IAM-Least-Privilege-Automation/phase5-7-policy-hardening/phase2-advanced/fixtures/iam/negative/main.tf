terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.60.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

data "aws_iam_policy_document" "wildcard_policy" {
  statement {
    effect = "Allow"

    actions = [
      "*"
    ]

    resources = [
      "*"
    ]
  }
}

resource "aws_iam_policy" "wildcard_policy" {
  name   = "aegis-phase2-wildcard-policy"
  policy = data.aws_iam_policy_document.wildcard_policy.json
}
