terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # No backend configured here on purpose — this is a starting point
  # for a real environment to fill in (S3+DynamoDB state locking, or
  # Terraform Cloud), not a decision this module should make silently.
}

provider "aws" {
  region = var.aws_region
}
