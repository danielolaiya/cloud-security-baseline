# -------------------------------------------------------
# AWS Security Baseline — CIS AWS Foundations Level 2
# -------------------------------------------------------
# this module was born out of a compliance audit that flagged
# 47 findings across our AWS accounts. rather than fixing them
# manually account by account we codified everything here so
# any new account gets the baseline automatically on day one.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  backend "s3" {
    bucket         = "platform-terraform-state"
    key            = "security-baseline/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "terraform"
      Repository  = "cloud-security-baseline"
      Environment = var.environment
    }
  }
}

# 14 character minimum is the CIS requirement.
# we use a password manager anyway so nobody types these manually.
resource "aws_iam_account_password_policy" "baseline" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
  hard_expiry                    = false
}

# nuclear option — blocks public access at account level.
# we had an incident where a developer accidentally made a bucket
# public while testing. this control would have caught it immediately.
resource "aws_s3_account_public_access_block" "baseline" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# multi-region trail is non-negotiable. we had a finding where
# someone was spinning up resources in ap-southeast-1 that we
# had zero visibility into because our trail was single region.
resource "aws_cloudtrail" "baseline" {
  name                          = "${var.environment}-baseline-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = "${var.environment}-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# GuardDuty caught a compromised access key within 20 minutes.
# without it we would not have known until the monthly billing spike.
resource "aws_guardduty_detector" "baseline" {
  enable = true

  datasources {
    s3_logs { enable = true }
    kubernetes {
      audit_logs { enable = true }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }
}

resource "aws_securityhub_account" "baseline" {}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.baseline]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
