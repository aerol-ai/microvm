###############################################################################
# Audit export S3 sink (plans/integration-test-security.md §5.4)
#
# Gated on var.audit_export_enabled so nothing exists for a deployment that did
# not ask for it. Separate from the bootstrap bundle bucket on purpose: that one
# holds join material every node can READ, this one holds audit evidence nodes
# only ever WRITE, and mixing the two would hand a joiner read access to the
# fleet's audit trail.
###############################################################################

resource "random_id" "audit_suffix" {
  count       = var.audit_export_enabled ? 1 : 0
  byte_length = 3
}

resource "aws_s3_bucket" "audit" {
  count = var.audit_export_enabled ? 1 : 0

  bucket = "${var.cluster_name}-audit-${random_id.audit_suffix[0].hex}"
  # Scenario evidence is read back by the suite during the run and worthless
  # after it, so teardown must not be blocked by objects the run itself wrote.
  force_destroy = true

  tags = merge(var.extra_tags, { Name = "${var.cluster_name}-audit" })
}

resource "aws_s3_bucket_public_access_block" "audit" {
  count = var.audit_export_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.audit[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  count = var.audit_export_enabled ? 1 : 0

  bucket = aws_s3_bucket.audit[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 3-day expiry: a belt-and-braces backstop for the case where force_destroy
# never runs because a scenario leaked (see the two-pass teardown note in
# TODOS.md). Without it, leaked audit objects accumulate indefinitely.
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  count = var.audit_export_enabled ? 1 : 0

  bucket = aws_s3_bucket.audit[0].id
  rule {
    id     = "expire-itest-audit"
    status = "Enabled"
    filter {}
    expiration { days = 3 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

# PutObject only. Nodes ship evidence and must never be able to read the
# fleet's audit trail back, or delete their own records to cover a compromise —
# which is the entire point of shipping evidence OFF the node.
data "aws_iam_policy_document" "audit_export" {
  count = var.audit_export_enabled ? 1 : 0

  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit[0].arn}/*"]
  }
}

resource "aws_iam_role_policy" "audit_export_seed" {
  count = var.audit_export_enabled ? 1 : 0

  name   = "${var.cluster_name}-audit-export"
  role   = aws_iam_role.seed.id
  policy = data.aws_iam_policy_document.audit_export[0].json
}

resource "aws_iam_role_policy" "audit_export_joiner" {
  count = var.audit_export_enabled ? 1 : 0

  name   = "${var.cluster_name}-audit-export"
  role   = aws_iam_role.joiner.id
  policy = data.aws_iam_policy_document.audit_export[0].json
}
