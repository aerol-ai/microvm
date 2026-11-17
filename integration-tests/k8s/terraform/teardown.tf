# The run's teardown timer: a Lambda (lambda/teardown.py) that AWS itself
# calls at var.teardown_at, so a dead laptop or a lost session cannot leave
# the machines running. EventBridge Scheduler calls it three times: at the
# TTL (compute: Karpenter's rights and machines, the node groups, the load
# balancers), and 30 and 60 minutes later (the cluster, once its node groups
# are gone). eks-bank.sh scale adds a fourth, one-time schedule of its own
# for the 60-worker time box (phase scale-cap). Only with var.teardown_at.

locals {
  teardown = var.teardown_at != ""
  # Scheduler's at() takes local time without a zone; the schedules say UTC.
  teardown_t = local.teardown ? trimsuffix(var.teardown_at, "Z") : ""
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "teardown" {
  count              = local.teardown ? 1 : 0
  name               = "${var.name}-teardown"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# The ARNs are written out, not read from the cluster: the cluster depends
# on this policy and the schedules (main.tf), so a destroy removes the
# cluster before the timer that would remove it.
data "aws_iam_policy_document" "teardown" {
  statement {
    sid     = "Cluster"
    actions = ["eks:ListNodegroups", "eks:DescribeNodegroup", "eks:DeleteNodegroup", "eks:DescribeCluster", "eks:DeleteCluster"]
    resources = [
      "arn:aws:eks:${var.region}:${data.aws_caller_identity.this.account_id}:cluster/${var.name}",
      "arn:aws:eks:${var.region}:${data.aws_caller_identity.this.account_id}:nodegroup/${var.name}/*/*",
    ]
  }
  statement {
    sid       = "Read"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTags"]
    resources = ["*"]
  }
  # Only this run's volumes, unattached: the ones its claims left.
  statement {
    sid       = "Volumes"
    actions   = ["ec2:DeleteVolume"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/aerol:run"
      values   = [var.name]
    }
  }
  # Only this run's machines: Karpenter's carry aerol:run (its EC2NodeClass).
  statement {
    sid       = "Terminate"
    actions   = ["ec2:TerminateInstances"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/aerol:run"
      values   = [var.name]
    }
  }
  statement {
    sid       = "LoadBalancers"
    actions   = ["elasticloadbalancing:DeleteLoadBalancer"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/elbv2.k8s.aws/cluster"
      values   = [var.name]
    }
  }
  statement {
    sid       = "StopKarpenter"
    actions   = ["iam:ListRolePolicies", "iam:DeleteRolePolicy"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.this.account_id}:role/${var.name}-karpenter"]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.this.account_id}:log-group:/aws/lambda/${var.name}-teardown*"]
  }
}

resource "aws_iam_role_policy" "teardown" {
  count  = local.teardown ? 1 : 0
  name   = "teardown"
  role   = aws_iam_role.teardown[0].id
  policy = data.aws_iam_policy_document.teardown.json
}

data "archive_file" "teardown" {
  count       = local.teardown ? 1 : 0
  type        = "zip"
  source_file = "${path.module}/lambda/teardown.py"
  # The run's own state folder (git-ignored), not the module's.
  output_path = "${path.module}/../.state/${var.name}/teardown.zip"
}

# Its log group, made here so it carries the run's tags (one the Lambda
# made itself would carry none, and reap.sh could not tell it is the run's).
resource "aws_cloudwatch_log_group" "teardown" {
  count             = local.teardown ? 1 : 0
  name              = "/aws/lambda/${var.name}-teardown"
  retention_in_days = 7
}

resource "aws_lambda_function" "teardown" {
  count            = local.teardown ? 1 : 0
  depends_on       = [aws_cloudwatch_log_group.teardown]
  function_name    = "${var.name}-teardown"
  role             = aws_iam_role.teardown[0].arn
  runtime          = "python3.12"
  handler          = "teardown.handler"
  filename         = data.archive_file.teardown[0].output_path
  source_code_hash = data.archive_file.teardown[0].output_base64sha256
  timeout          = 900
  environment {
    variables = {
      CLUSTER        = var.name
      KARPENTER_ROLE = var.karpenter ? "${var.name}-karpenter" : ""
      # This run's TTL: what it ends must carry it too, so an older run's
      # leftovers of the same name are not this run's to touch.
      TTL = var.ttl
    }
  }
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  count              = local.teardown ? 1 : 0
  name               = "${var.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  count = local.teardown ? 1 : 0
  name  = "invoke-teardown"
  role  = aws_iam_role.scheduler[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "lambda:InvokeFunction", Resource = aws_lambda_function.teardown[0].arn }]
  })
}

resource "aws_scheduler_schedule" "teardown" {
  for_each = local.teardown ? {
    compute   = { at = local.teardown_t, phase = "compute" }
    cluster   = { at = trimsuffix(timeadd(var.teardown_at, "30m"), "Z"), phase = "cluster" }
    cluster-2 = { at = trimsuffix(timeadd(var.teardown_at, "60m"), "Z"), phase = "cluster" }
  } : {}
  name                         = "${var.name}-teardown-${each.key}"
  schedule_expression          = "at(${each.value.at})"
  schedule_expression_timezone = "UTC"
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_lambda_function.teardown[0].arn
    role_arn = aws_iam_role.scheduler[0].arn
    input    = jsonencode({ phase = each.value.phase })
    retry_policy {
      maximum_retry_attempts       = 3
      maximum_event_age_in_seconds = 3600
    }
  }
}
