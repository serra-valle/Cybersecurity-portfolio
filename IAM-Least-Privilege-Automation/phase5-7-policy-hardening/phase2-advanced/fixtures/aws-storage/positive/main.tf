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

resource "aws_s3_bucket" "secure" {
  bucket = "aegis-phase2-secure-storage"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "secure" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true

  tags = {
    Name = "aegis-phase2-secure-ebs"
  }
}

resource "aws_db_instance" "secure" {
  identifier                  = "aegis-phase2-secure-rds"
  allocated_storage           = 20
  engine                      = "mysql"
  instance_class              = "db.t3.micro"
  username                    = "aegisadmin"
  manage_master_user_password = true
  storage_encrypted           = true
  skip_final_snapshot         = true
}
