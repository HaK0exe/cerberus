output "web_scanner_role_arn" {
  value = aws_iam_role.web_scanner.arn
}

output "git_scanner_role_arn" {
  value = aws_iam_role.git_scanner.arn
}

output "api_role_arn" {
  value = aws_iam_role.api.arn
}

output "finding_writer_role_arn" {
  value = aws_iam_role.finding_writer.arn
}

output "audit_role_arn" {
  value = aws_iam_role.audit.arn
}

output "remediation_planner_role_arn" {
  value = aws_iam_role.remediation_planner.arn
}

output "remediation_executor_role_arn" {
  value = aws_iam_role.remediation_executor.arn
}
