# dev environment — IAM roles only.
#
# Deliberately scoped to just the iam module (see
# docs/adr/0011-deployment-profiles.md for why): no API Gateway, Lambda,
# SQS, DynamoDB, Fargate, KMS, or EventBridge yet. Those need a real,
# testable compute/data workload behind them (the cerberus-api/worker/mcp
# Go binaries are still Sprint 4 stubs — see deploy/docker/*.Dockerfile)
# and this project's convention throughout has been to not stand up
# untested infrastructure for code that doesn't exist yet.
module "iam" {
  source = "../../modules/iam"

  name_prefix                               = "cerberus-dev"
  remediation_executor_trust_principal_arns = var.remediation_executor_trust_principal_arns

  tags = {
    Project     = "cerberus"
    Environment = "dev"
    ManagedBy   = "terraform"
  }
}
