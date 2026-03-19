# AWS Cloud Security Baseline

Automated security baseline for AWS environments implementing CIS AWS Foundations Benchmark Level 2 controls through infrastructure as code. Built for regulated environments requiring continuous compliance validation.

## Overview

Manual security configuration does not scale. This repository codifies security controls into Terraform and AWS Config rules so every new account automatically inherits the baseline.

**Control coverage:** CIS AWS Foundations Benchmark v1.5, NIST SP 800-53, SOC 2 Type II

## What it does

- Enforces IAM password policy (CIS 1.8-1.11)
- Blocks all S3 public access at account level (CIS 2.3)
- Enables multi-region CloudTrail with KMS encryption (CIS 2.1)
- Enables GuardDuty with S3, Kubernetes, and malware protection (CIS 3.x)
- Enables Security Hub with CIS and AWS Foundational standards

## Author

**Daniel Olaiya** — DevOps Engineer
olaiyadaniel00@gmail.com
