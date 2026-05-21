###############################################################################
# Bootstrap artifact bucket.
#
# The seed node uploads two objects: gossip-key.txt + aerolvm-tls-bundle.tar.gz.
# Every joiner polls until they appear, downloads them, runs cluster-join.sh.
# Bucket is private, SSE-encrypted, and (by default) force_destroy on tear-down.
###############################################################################

resource "random_id" "bundle_suffix" {
  byte_length = 3
}

resource "aws_s3_bucket" "bundle" {
  bucket        = local.bundle_bucket_name
  force_destroy = var.bundle_bucket_force_destroy
}

resource "aws_s3_bucket_public_access_block" "bundle" {
  bucket                  = aws_s3_bucket.bundle.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bundle" {
  bucket = aws_s3_bucket.bundle.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "bundle" {
  bucket = aws_s3_bucket.bundle.id
  versioning_configuration {
    status = "Disabled"
  }
}

###############################################################################
# Instance profile + role.
#
# Two policies are attached:
#   - seed_rw : Put + Get on bundle/* (only attached to the seed instance)
#   - joiner_r: Get on bundle/* (attached to every other instance)
# Both share the same execution role; the diff is which inline policy each
# instance profile picks up.
###############################################################################

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "seed" {
  name               = "${var.cluster_name}-seed"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role" "joiner" {
  name               = "${var.cluster_name}-joiner"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

data "aws_iam_policy_document" "seed_rw" {
  statement {
    actions   = ["s3:PutObject", "s3:GetObject", "s3:HeadObject"]
    resources = ["${aws_s3_bucket.bundle.arn}/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.bundle.arn]
  }
}

data "aws_iam_policy_document" "joiner_r" {
  statement {
    actions   = ["s3:GetObject", "s3:HeadObject"]
    resources = ["${aws_s3_bucket.bundle.arn}/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.bundle.arn]
  }
}

resource "aws_iam_role_policy" "seed_rw" {
  name   = "${var.cluster_name}-seed-rw"
  role   = aws_iam_role.seed.id
  policy = data.aws_iam_policy_document.seed_rw.json
}

resource "aws_iam_role_policy" "joiner_r" {
  name   = "${var.cluster_name}-joiner-r"
  role   = aws_iam_role.joiner.id
  policy = data.aws_iam_policy_document.joiner_r.json
}

resource "aws_iam_instance_profile" "seed" {
  name = "${var.cluster_name}-seed"
  role = aws_iam_role.seed.name
}

resource "aws_iam_instance_profile" "joiner" {
  name = "${var.cluster_name}-joiner"
  role = aws_iam_role.joiner.name
}

###############################################################################
# Optional: shared Caddy cert storage bucket.
#
# Off by default. When enabled in managed mode, Terraform owns the bucket so
# every ingress node has IAM-granted R/W and never needs static access keys.
# In BYO mode (existing bucket, R2, MinIO) we just attach an IAM policy
# against the supplied bucket ARN so the daemon's default credential chain
# resolves automatically when the operator's bucket lives in this same AWS
# account; for cross-account / non-AWS buckets the operator passes static
# keys via var.caddy_shared_cert_storage and we skip the IAM attachment.
#
# Versioning is ON so an accidental delete of a renewed cert is recoverable.
# force_destroy is OFF — `terraform destroy` should not silently wipe long-
# lived TLS material the way the one-shot bundle bucket can be.
###############################################################################

resource "aws_s3_bucket" "caddy_certs" {
  count = local.caddy_storage_s3_managed ? 1 : 0

  bucket        = local.caddy_certs_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "caddy_certs" {
  count = local.caddy_storage_s3_managed ? 1 : 0

  bucket                  = aws_s3_bucket.caddy_certs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "caddy_certs" {
  count = local.caddy_storage_s3_managed ? 1 : 0

  bucket = aws_s3_bucket.caddy_certs[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "caddy_certs" {
  count = local.caddy_storage_s3_managed ? 1 : 0

  bucket = aws_s3_bucket.caddy_certs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# IAM grants: every node may renew (certmagic picks one via the distributed
# lock). Attach to both seed and joiner roles for managed mode AND for byo
# mode when no static creds were supplied (which is the "bucket is in the
# same AWS account" case — easiest setup, no key handling).
locals {
  caddy_certs_bucket_arn = (
    local.caddy_storage_s3_managed
    ? (length(aws_s3_bucket.caddy_certs) > 0 ? aws_s3_bucket.caddy_certs[0].arn : "")
    : (var.caddy_shared_cert_storage.bucket != "" ? "arn:aws:s3:::${var.caddy_shared_cert_storage.bucket}" : "")
  )

  # Don't reference local.caddy_certs_bucket_arn here — it depends on the
  # managed bucket's arn, which is unknown until apply on the first run and
  # makes `count` on the data source/policies below unplannable. The arn is
  # non-empty exactly when (managed mode) OR (byo mode with bucket set), so
  # check the inputs directly — both are known at plan time.
  caddy_certs_attach_iam = (
    var.caddy_shared_cert_storage.enabled
    && var.caddy_shared_cert_storage.access_key == ""
    && (local.caddy_storage_s3_managed || var.caddy_shared_cert_storage.bucket != "")
  )
}

data "aws_iam_policy_document" "caddy_certs_rw" {
  count = local.caddy_certs_attach_iam ? 1 : 0

  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:HeadObject",
    ]
    resources = ["${local.caddy_certs_bucket_arn}/${var.caddy_shared_cert_storage.prefix}/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = [local.caddy_certs_bucket_arn]
  }
}

resource "aws_iam_role_policy" "caddy_certs_seed_rw" {
  count = local.caddy_certs_attach_iam ? 1 : 0

  name   = "${var.cluster_name}-caddy-certs-rw"
  role   = aws_iam_role.seed.id
  policy = data.aws_iam_policy_document.caddy_certs_rw[0].json
}

resource "aws_iam_role_policy" "caddy_certs_joiner_rw" {
  count = local.caddy_certs_attach_iam ? 1 : 0

  name   = "${var.cluster_name}-caddy-certs-rw"
  role   = aws_iam_role.joiner.id
  policy = data.aws_iam_policy_document.caddy_certs_rw[0].json
}
