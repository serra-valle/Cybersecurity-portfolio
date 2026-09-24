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

resource "aws_s3_bucket" "insecure" {
  bucket = "aegis-phase2-insecure-storage"
}

resource "aws_s3_bucket_public_access_block" "insecure" {
  bucket = aws_s3_bucket.insecure.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_ebs_volume" "insecure" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false

  tags = {
    Name = "aegis-phase2-insecure-ebs"
  }
}

resource "aws_db_instance" "insecure" {
  identifier                  = "aegis-phase2-insecure-rds"
  allocated_storage           = 20
  engine                      = "mysql"
  instance_class              = "db.t3.micro"
  username                    = "aegisadmin"
  manage_master_user_password = true
  storage_encrypted           = false
  skip_final_snapshot         = true
}
