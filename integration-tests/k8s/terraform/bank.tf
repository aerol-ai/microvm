# The bank drills on EKS (../eks-bank.sh): enterprise mode's audit store,
# reached through IRSA, and the AWS Load Balancer Controller's role for the
# internal NLB. Only with var.bank_drills. Everything here carries the
# aerol:* tags (main.tf's default_tags), so reap.sh finds what a dead run
# left.

data "aws_caller_identity" "this" {}

locals {
  oidc_host = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
  # The chart's node service account (audit.credentials.serviceAccount,
  # <release>-node) in the two namespaces nodes run in.
  audit_subjects = [for ns in ["aerolvm-system", "aerolvm-workers"] : "system:serviceaccount:${ns}:aerolvm-node"]
}

# IRSA: the cluster's OIDC issuer as an IAM identity provider. EKS Pod
# Identity would work too; the bank preset documents IRSA, so the run uses it.
resource "aws_iam_openid_connect_provider" "eks" {
  count          = var.bank_drills ? 1 : 0
  url            = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "audit_assume" {
  count = var.bank_drills ? 1 : 0
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks[0].arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    # The node service accounts only: no other pod of the cluster gets it.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = local.audit_subjects
    }
  }
}

resource "aws_iam_role" "audit" {
  count              = var.bank_drills ? 1 : 0
  name               = "${var.name}-audit"
  assume_role_policy = data.aws_iam_policy_document.audit_assume[0].json
}

# The witness bucket. GOVERNANCE, not COMPLIANCE: a COMPLIANCE version can
# be removed by nobody until its retention ends, so the bucket would outlive
# the run by var.audit_lock_days. Under GOVERNANCE the node role still
# cannot remove a head (it has no bypass right, and the witness's boot
# canary proves it), while the teardown, with s3:BypassGovernanceRetention,
# empties and deletes the bucket at once (eks-bank.sh down, reap.sh).
resource "aws_s3_bucket" "witness" {
  count               = var.bank_drills ? 1 : 0
  bucket              = "${var.name}-witness-${data.aws_caller_identity.this.account_id}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "witness" {
  count  = var.bank_drills ? 1 : 0
  bucket = aws_s3_bucket.witness[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "witness" {
  count  = var.bank_drills ? 1 : 0
  bucket = aws_s3_bucket.witness[0].id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      # The witness refuses a bucket that locks heads for less than the
      # nodes' audit retention (SB_SECRET_AUDIT_RETENTION_DAYS, 30).
      days = var.audit_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.witness]
}

# Noncurrent versions go once their lock is over: a backstop if every
# teardown failed, so a forgotten bucket empties itself.
resource "aws_s3_bucket_lifecycle_configuration" "witness" {
  count  = var.bank_drills ? 1 : 0
  bucket = aws_s3_bucket.witness[0].id
  rule {
    id     = "expire-old-heads"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = var.audit_lock_days + 1 }
    expiration { days = var.audit_lock_days + 1 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  depends_on = [aws_s3_bucket_versioning.witness]
}

resource "aws_s3_bucket" "export" {
  count  = var.bank_drills ? 1 : 0
  bucket = "${var.name}-export-${data.aws_caller_identity.this.account_id}"
  # No lock on the export bucket: destroy may empty it.
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "audit" {
  for_each                = var.bank_drills ? { witness = aws_s3_bucket.witness[0].id, export = aws_s3_bucket.export[0].id } : {}
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# The node role's rights: the ones docs/enterprise/enterprise-mode.mdx lists
# for the witness, PutObject on the export bucket, and every way to remove
# or unlock a head denied.
data "aws_iam_policy_document" "audit" {
  count = var.bank_drills ? 1 : 0
  statement {
    sid       = "WitnessObjects"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.witness[0].arn}/*"]
  }
  statement {
    sid       = "WitnessBucket"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration"]
    resources = [aws_s3_bucket.witness[0].arn]
  }
  statement {
    sid       = "WitnessDenyErase"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:BypassGovernanceRetention"]
    resources = ["${aws_s3_bucket.witness[0].arn}/*"]
  }
  statement {
    sid       = "WitnessDenyBucketChanges"
    effect    = "Deny"
    actions   = ["s3:PutBucketObjectLockConfiguration", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration", "s3:PutBucketPolicy"]
    resources = [aws_s3_bucket.witness[0].arn]
  }
  statement {
    sid       = "Export"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.export[0].arn}/*"]
  }
}

resource "aws_iam_role_policy" "audit" {
  count  = var.bank_drills ? 1 : 0
  name   = "audit-store"
  role   = aws_iam_role.audit[0].id
  policy = data.aws_iam_policy_document.audit[0].json
}

# The AWS Load Balancer Controller, for the gateways' internal NLB with IP
# targets (values-bank-eks.yaml's annotations). Its policy is the one the
# controller publishes for v3.6.2 (lb-controller-iam-policy.json, sha256 in
# eks-bank.sh). It gets its role through EKS Pod Identity.
resource "aws_iam_role" "lb_controller" {
  count              = var.bank_drills ? 1 : 0
  name               = "${var.name}-lb-controller"
  assume_role_policy = data.aws_iam_policy_document.karpenter_assume.json
}

resource "aws_iam_role_policy" "lb_controller" {
  count  = var.bank_drills ? 1 : 0
  name   = "aws-load-balancer-controller"
  role   = aws_iam_role.lb_controller[0].id
  policy = file("${path.module}/lb-controller-iam-policy.json")
}

resource "aws_eks_pod_identity_association" "lb_controller" {
  count           = var.bank_drills ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  namespace       = "kube-system"
  service_account = "aws-load-balancer-controller"
  role_arn        = aws_iam_role.lb_controller[0].arn
  depends_on      = [aws_eks_addon.pod_identity]
}
