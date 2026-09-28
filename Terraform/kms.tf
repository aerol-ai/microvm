###############################################################################
# Cluster secret provider: real AWS KMS (plans/integration-test-security.md §5.3)
#
# Gated on var.secret_kms_enabled, so nothing here exists for a deployment that
# did not ask for it and a production render is unchanged.
###############################################################################

resource "aws_kms_key" "secrets" {
  count = var.secret_kms_enabled ? 1 : 0

  description = "AerolVM cluster secret provider CMK for ${var.cluster_name}"
  # Short window: these are throwaway scenario keys, and 7 days is the AWS
  # minimum. A longer window would leave a month of orphaned keys behind after
  # every destroyed scenario.
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(var.extra_tags, { Name = "${var.cluster_name}-secrets" })
}

resource "aws_kms_alias" "secrets" {
  count = var.secret_kms_enabled ? 1 : 0

  name          = "alias/${var.cluster_name}-secrets"
  target_key_id = aws_kms_key.secrets[0].key_id
}

# Encrypt/Decrypt/DescribeKey only — the daemon envelope-encrypts with this CMK
# and never manages it. No kms:CreateKey, no kms:ScheduleKeyDeletion, and no
# GenerateDataKey* beyond what Encrypt/Decrypt need, so a compromised node
# cannot destroy the key that protects every other node's secrets.
data "aws_iam_policy_document" "secret_kms" {
  count = var.secret_kms_enabled ? 1 : 0

  statement {
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.secrets[0].arn]
  }
}

resource "aws_iam_role_policy" "secret_kms_seed" {
  count = var.secret_kms_enabled ? 1 : 0

  name   = "${var.cluster_name}-secret-kms"
  role   = aws_iam_role.seed.id
  policy = data.aws_iam_policy_document.secret_kms[0].json
}

resource "aws_iam_role_policy" "secret_kms_joiner" {
  count = var.secret_kms_enabled ? 1 : 0

  name   = "${var.cluster_name}-secret-kms"
  role   = aws_iam_role.joiner.id
  policy = data.aws_iam_policy_document.secret_kms[0].json
}
