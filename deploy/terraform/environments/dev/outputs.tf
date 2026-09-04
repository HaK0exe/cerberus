output "role_arns" {
  description = "Every Cerberus IAM role this environment defines, for wiring into a future ECS task definition / Lambda config module."
  value = {
    web_scanner          = module.iam.web_scanner_role_arn
    git_scanner          = module.iam.git_scanner_role_arn
    api                  = module.iam.api_role_arn
    finding_writer       = module.iam.finding_writer_role_arn
    audit                = module.iam.audit_role_arn
    remediation_planner  = module.iam.remediation_planner_role_arn
    remediation_executor = module.iam.remediation_executor_role_arn
  }
}
