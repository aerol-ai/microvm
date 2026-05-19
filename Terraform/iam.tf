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
