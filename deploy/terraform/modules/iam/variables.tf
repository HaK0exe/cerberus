variable "name_prefix" {
  description = "Prefix applied to every role/policy name, so multiple environments (dev/prod) can coexist in one account without collision."
  type        = string
  default     = "cerberus"
}

variable "tags" {
  description = "Tags applied to every resource this module creates."
  type        = map(string)
  default     = {}
}

variable "remediation_executor_trust_principal_arns" {
  description = <<-EOT
    ARNs allowed to assume CerberusRemediationExecutorRole (typically the
    ECS task role or Lambda execution role running the remediation
    executor workload — see internal/remediation/aws.Executor). Left
    empty by default so the module never ships a role nobody has scoped
    a trust policy for; environments/dev supplies this explicitly.
  EOT
  type        = list(string)
  default     = []
}

variable "remediation_executor_key_resource_arns" {
  description = <<-EOT
    Resource ARN pattern(s) CerberusRemediationExecutorRole's
    iam:UpdateAccessKey permission is scoped to (e.g.
    "arn:aws:iam::<account-id>:user/*" narrowed further by a
    aws:ResourceTag condition in a real environment). IAM does not
    support scoping UpdateAccessKey to "only access keys Cerberus
    itself flagged" — that authorization decision is made in Go, by
    internal/remediation's Planner/Executor and the policy engine,
    before this role's credentials are ever used (see
    docs/adr/0010-remediation-v2.md and docs/adr/0011-deployment-profiles.md
    for the split between what Terraform can enforce and what the
    application enforces). This variable only bounds the AWS-account
    blast radius if the role's credentials were ever misused directly.
  EOT
  type        = list(string)
  default     = ["*"]
}
