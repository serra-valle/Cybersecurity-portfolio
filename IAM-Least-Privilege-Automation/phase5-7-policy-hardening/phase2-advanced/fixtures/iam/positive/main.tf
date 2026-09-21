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

data "aws_iam_policy_document" "least_privilege" {
  statement {
    effect = "Allow"

    actions = [
      "s3:GetObject"
    ]

    resources = [
      "arn:aws:s3:::aegis-example-bucket/*"
    ]
  }
}

resource "aws_iam_policy" "least_privilege" {
  name   = "aegis-phase2-least-privilege"
  policy = data.aws_iam_policy_document.least_privilege.json
}
