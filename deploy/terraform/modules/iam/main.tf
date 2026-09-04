# Cerberus IAM role separation module.
#
# This is the Terraform-level enforcement of docs/adr/0003-remediation-separation.md:
# scanner != remediator. Each role below is a SEPARATE aws_iam_role with
# its own trust policy and, where a policy is attached at all, the
# narrowest permission set that role's Go component actually needs
# (see the cited internal/* package for what each role backs).
#
# What this module can and cannot guarantee:
#   - It CAN guarantee, structurally, that CerberusWebScannerRole and
#     CerberusGitScannerRole carry zero IAM/cloud-mutating permissions
#     today, because no policy is attached to them below. Terraform
#     has no "this role may never gain an iam:* permission in the
#     future" runtime check (that would need a policy-as-code gate
#     like terraform-compliance or Sentinel evaluated in CI — not
#     added in this slice, see docs/adr/0011-deployment-profiles.md).
#     The guarantee here is "nothing is attached today, and a reviewer
#     changing that has to touch this file" — process, not automation.
#   - It CAN guarantee, via an explicit Deny statement (which no
#     Allow anywhere, including a future one, can override), that
#     CerberusRemediationExecutorRole can never call iam:DeleteAccessKey,
#     iam:CreateAccessKey, iam:DeleteUser, or iam:CreateUser — the
#     disable-before-delete boundary from internal/remediation/aws.Executor
#     (docs/adr/0010-remediation-v2.md) enforced at the AWS API layer,
#     not just in Go.

data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# CerberusRemediationExecutorRole is trusted by an explicit allowlist of
# principal ARNs (e.g. the remediation planner/approval workflow's own
# role), never a blanket AWS service principal — this is the one role
# in the account that can flip a compromised access key to Inactive,
# so who can even attempt to assume it is deliberately narrow. An empty
# allowlist (the module's default) produces a role nothing can assume,
# which is the safe default until an environment explicitly wires a
# principal in.
data "aws_iam_policy_document" "remediation_executor_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = length(var.remediation_executor_trust_principal_arns) > 0 ? var.remediation_executor_trust_principal_arns : ["arn:aws:iam::000000000000:role/nobody"]
    }
  }
}

# --- Data plane: scanners. Zero IAM/cloud-mutating permissions. -------

resource "aws_iam_role" "web_scanner" {
  name               = "${var.name_prefix}-CerberusWebScannerRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
  # No aws_iam_role_policy / policy attachment below, deliberately —
  # see internal/scanner/web and docs/adr/0003. This role backs the
  # Fargate task running the web/JS scanner (not Lambda: the spec
  # explicitly rules out forcing a headless-browser/Chromium workload
  # into Lambda when Fargate is the better fit).
}

resource "aws_iam_role" "git_scanner" {
  name               = "${var.name_prefix}-CerberusGitScannerRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
  # No policy attached — same reasoning as web_scanner. Backs
  # internal/scanner/git's Fargate task (git history can be large;
  # same "don't force it into Lambda" reasoning applies).
}

# --- Control plane: API, finding ingestion, audit. ---------------------
# No policy attached yet in this slice — these will get narrow,
# resource-scoped DynamoDB/S3 permissions once deploy/terraform/modules/dynamodb
# and /s3 exist (see docs/deployment/cloud.md for what's still planned).
# Defining the role now, with the right trust boundary and name, is
# what lets other modules attach policies to it later without ever
# needing scanners or the remediation executor to share it.

resource "aws_iam_role" "api" {
  name               = "${var.name_prefix}-CerberusAPIRole"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role" "finding_writer" {
  name               = "${var.name_prefix}-CerberusFindingWriterRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

resource "aws_iam_role" "audit" {
  name               = "${var.name_prefix}-CerberusAuditRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

# --- Remediation plane. -------------------------------------------------

# CerberusRemediationPlannerRole backs internal/remediation.DefaultPlanner
# (Phase K), which is side-effect-free by construction: it only calls
# internal/risk.Assess and a PolicyEngine, never an AWS API. This role
# therefore gets NO policy at all, on purpose — a Planner that somehow
# tried to call AWS would fail with AccessDenied, which is the correct
# outcome, not a bug to work around.
resource "aws_iam_role" "remediation_planner" {
  name               = "${var.name_prefix}-CerberusRemediationPlannerRole"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

# CerberusRemediationExecutorRole backs internal/remediation/aws.Executor
# (Phase K). It gets exactly the two IAM read/write calls that
# Executor's IAMClient interface needs (UpdateAccessKey, ListAccessKeys
# — the real AWS API a ListAccessKeys-backed GetAccessKeyStatus
# implementation would call to read live key status) and an explicit,
# unconditional Deny on the destructive/creation actions this role must
# never be able to perform, matching Executor's disable-before-delete
# design.
resource "aws_iam_role" "remediation_executor" {
  name               = "${var.name_prefix}-CerberusRemediationExecutorRole"
  assume_role_policy = data.aws_iam_policy_document.remediation_executor_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "remediation_executor_permissions" {
  statement {
    sid       = "DisableCompromisedAccessKeys"
    effect    = "Allow"
    actions   = ["iam:UpdateAccessKey"]
    resources = var.remediation_executor_key_resource_arns
  }

  statement {
    sid    = "ReadAccessKeyStatusForVerification"
    effect = "Allow"
    # ListAccessKeys is the real AWS API a GetAccessKeyStatus-shaped
    # IAMClient method (see internal/remediation/aws.IAMClient) reads
    # Status from — IAM has no narrower "read one key's status" call.
    actions   = ["iam:ListAccessKeys"]
    resources = var.remediation_executor_key_resource_arns
  }

  # Deny wins over any Allow, from this policy or any other attached
  # to this role, present or future — this is the durable,
  # AWS-API-enforced mirror of internal/remediation/aws.Executor never
  # implementing a delete path (docs/adr/0010-remediation-v2.md). No
  # IAM identity/credential-creation action is granted either: this
  # role revokes, it never provisions.
  statement {
    sid    = "NeverDeleteOrCreateIAMIdentities"
    effect = "Deny"
    actions = [
      "iam:DeleteAccessKey",
      "iam:CreateAccessKey",
      "iam:CreateUser",
      "iam:DeleteUser",
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:PutUserPolicy",
      "iam:AttachUserPolicy",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediation_executor" {
  name   = "${var.name_prefix}-remediation-executor-disable-only"
  role   = aws_iam_role.remediation_executor.id
  policy = data.aws_iam_policy_document.remediation_executor_permissions.json
}
