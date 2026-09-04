variable "aws_region" {
  description = "AWS region to deploy the dev environment's IAM roles into. IAM is global, but the provider still needs a region for API calls."
  type        = string
  default     = "us-east-1"
}

variable "remediation_executor_trust_principal_arns" {
  description = "See modules/iam's variable of the same name. Left empty by default: this dev environment stands up the roles, it does not yet wire a real remediation-approval workflow's role ARN to assume CerberusRemediationExecutorRole."
  type        = list(string)
  default     = []
}
