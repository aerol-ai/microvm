###############################################################################
# Audit witness: S3 Object Lock bucket (plans/open-audit-witness.md, Phase 3)
#
# Gated on var.audit_witness_enabled so nothing exists for a deployment that
# did not ask for it. The witness keeps each node's audit hash-chain heads OFF
# the node, in versions that Object Lock forbids anyone from changing or
# deleting until the lock ends. That is the whole claim: a node that later
# turns hostile cannot rewrite the history its earlier heads vouch for.
#
# Its own bucket, never a prefix in the audit-export bucket: export objects are
# overwritten on re-send (the key IS the batch id) and expire, and a bucket's
# Object Lock default applies to every object in it. Mixing the two would
# either lock export batches or unlock heads.
#
# SB_NODE_ID needs no wiring here. cluster-init.sh / cluster-join.sh already
# write SB_NODE_ID=<cluster_name>-<node> into cluster.env, so every
# Terraform-provisioned node has a unique id that can never be "standalone",
# which is what sandboxd requires once a witness backend is set (D3).
###############################################################################

locals {
  # The daemon refuses to boot when the bucket's default lock is shorter than
  # SB_SECRET_AUDIT_RETENTION_DAYS (boot check 3: a head must outlive the
  # local records it vouches for). Resolve the effective value per node the
  # way the bootstrap renders it (a node's sandboxd_env over
  # extra_sandboxd_env, else the daemon default of 30) so a mismatch fails
  # here at plan time instead of as a crash loop on every node.
  audit_witness_retention_days = [
    for _, n in var.nodes :
    try(tonumber(merge(var.extra_sandboxd_env, n.sandboxd_env)["SB_SECRET_AUDIT_RETENTION_DAYS"]), 30)
  ]
}

resource "random_id" "witness_suffix" {
  count       = var.audit_witness_enabled ? 1 : 0
  byte_length = 3
}

resource "aws_s3_bucket" "witness" {
  count = var.audit_witness_enabled ? 1 : 0

  bucket = "${var.cluster_name}-witness-${random_id.witness_suffix[0].hex}"
  # On from creation, so there is never a moment when an object in this bucket
  # can be written unlocked. Changing it later forces a new bucket.
  object_lock_enabled = true

  # No force_destroy, on purpose. A COMPLIANCE-locked version cannot be
  # deleted by anyone, the AWS account root included, until its lock ends, so
  # `terraform destroy` fails on this bucket until then; pretending otherwise
  # would hide that the evidence outlives the cluster. A GOVERNANCE bucket
  # (trials, integration runs) must be emptied first by a principal holding
  # s3:BypassGovernanceRetention that sends the bypass header, e.g.
  # `aws s3api delete-objects --bypass-governance-retention` over every
  # version; the integration harness does that before destroy (Phase 4, D13).
  force_destroy = false

  tags = merge(var.extra_tags, { Name = "${var.cluster_name}-witness" })

  lifecycle {
    precondition {
      condition     = alltrue([for d in local.audit_witness_retention_days : var.witness_lock_days >= d])
      error_message = "witness_lock_days is shorter than SB_SECRET_AUDIT_RETENTION_DAYS on at least one node (30 unless extra_sandboxd_env or a node's sandboxd_env sets it). sandboxd refuses to boot when a witnessed head can expire before the records it vouches for. Raise witness_lock_days or lower SB_SECRET_AUDIT_RETENTION_DAYS."
    }
  }
}

resource "aws_s3_bucket_public_access_block" "witness" {
  count = var.audit_witness_enabled ? 1 : 0

  bucket                  = aws_s3_bucket.witness[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "witness" {
  count = var.audit_witness_enabled ? 1 : 0

  bucket = aws_s3_bucket.witness[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Object Lock already implies versioning, but the daemon's first boot check is
# GetBucketVersioning == Enabled, so state it rather than rely on the side
# effect.
resource "aws_s3_bucket_versioning" "witness" {
  count = var.audit_witness_enabled ? 1 : 0

  bucket = aws_s3_bucket.witness[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

# The default retention rule is what locks every head the moment it is written;
# the daemon never sets per-object retention (its role is denied
# s3:PutObjectRetention), and refuses to boot on a bucket without this rule.
resource "aws_s3_bucket_object_lock_configuration" "witness" {
  count = var.audit_witness_enabled ? 1 : 0

  bucket = aws_s3_bucket.witness[0].id
  rule {
    default_retention {
      mode = var.witness_lock_mode
      days = var.witness_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.witness]
}

# Cost control only. Every ship adds a version, so without this the bucket
# grows forever. NONCURRENT versions expire once the lock period is over (S3
# never expires a version that is still locked), and the current version of
# each day's key is never expired, so the newest head per node per day always
# survives. noncurrent_days counts from when a version was superseded, which is
# always after it was written, so it can never undercut the lock.
resource "aws_s3_bucket_lifecycle_configuration" "witness" {
  count = var.audit_witness_enabled ? 1 : 0

  bucket = aws_s3_bucket.witness[0].id
  rule {
    id     = "expire-noncurrent-witness-heads"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.witness_lock_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.witness]
}

# Node role. Every grant is the minimum the witness needs, and every erasing or
# reconfiguring action is denied outright, so that even a later Allow added to
# the role for something else cannot hand a node a way to hide its own heads.
data "aws_iam_policy_document" "audit_witness" {
  count = var.audit_witness_enabled ? 1 : 0

  # Ship a head (PutObject), read the latest one back (GetObject), and walk a
  # key's versions when today's key has no current version (GetObjectVersion).
  # The boot canary and missing-key probe live under the same prefix.
  statement {
    sid       = "WitnessObjects"
    actions   = ["s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.witness[0].arn}/${var.audit_witness_prefix}*"]
  }

  # ListObjectVersions finds the newest day after downtime across UTC
  # midnight. It must be the versions listing: ListObjectsV2 hides a key whose
  # newest version is a delete marker, which is exactly the tamper to catch.
  statement {
    sid       = "WitnessListVersions"
    actions   = ["s3:ListBucketVersions"]
    resources = [aws_s3_bucket.witness[0].arn]
  }

  # Not optional (D19). Without s3:ListBucket, S3 answers a GET for a missing
  # key with 403 instead of 404 NoSuchKey, so a first boot on an empty bucket,
  # and any boot after downtime across UTC midnight, would fail. The daemon's
  # missing-key probe refuses to boot, naming s3:ListBucket, if this grant does
  # not produce a 404.
  #
  # Deliberately unconditioned. A GetObject request carries no s3:prefix key,
  # so a grant limited by an s3:prefix condition would not count when S3
  # decides between 404 and 403, and the probe would refuse every boot. The
  # bucket holds nothing but witness objects, and the node can already read
  # every head under the prefix, so listing it reveals nothing more.
  statement {
    sid       = "WitnessListBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.witness[0].arn]
  }

  # Boot checks 1 and 2: refuse a bucket that is not really WORM.
  statement {
    sid = "WitnessBucketChecks"
    actions = [
      "s3:GetBucketVersioning",
      "s3:GetBucketObjectLockConfiguration",
    ]
    resources = [aws_s3_bucket.witness[0].arn]
  }

  # DeleteObject would let a node lay a delete marker over its newest head;
  # the rest would shorten or bypass a lock. The boot canary's delete (sent
  # with the bypass header, the way an attacker would) expects this denial.
  statement {
    sid    = "WitnessDenyErase"
    effect = "Deny"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:PutObjectRetention",
      "s3:PutObjectLegalHold",
      "s3:BypassGovernanceRetention",
    ]
    resources = ["${aws_s3_bucket.witness[0].arn}/*"]
  }

  # Any of these would let a node weaken the bucket itself: drop the default
  # lock, suspend versioning, expire current versions, or grant itself more.
  statement {
    sid    = "WitnessDenyReconfigure"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
      "s3:PutBucketPolicy",
    ]
    resources = [aws_s3_bucket.witness[0].arn]
  }
}

# Both roles get the same grant: every node writes its own heads. The roles are
# shared across nodes, so node A can write a version into node B's key. It
# cannot erase B's history (the lock stops that), and B's next tick raises
# SandboxdAuditWitnessForeignHead. Confining each node to its own key needs the
# writer's AWS identity in the key, a v2 layout change (D8, TODOS.md);
# attribute such a write with CloudTrail S3 data events on this bucket.
resource "aws_iam_role_policy" "audit_witness_seed" {
  count = var.audit_witness_enabled ? 1 : 0

  name   = "${var.cluster_name}-audit-witness"
  role   = aws_iam_role.seed.id
  policy = data.aws_iam_policy_document.audit_witness[0].json
}

resource "aws_iam_role_policy" "audit_witness_joiner" {
  count = var.audit_witness_enabled ? 1 : 0

  name   = "${var.cluster_name}-audit-witness"
  role   = aws_iam_role.joiner.id
  policy = data.aws_iam_policy_document.audit_witness[0].json
}

# Auditor read-only policy (D22). Created, never attached: whoever runs
# `aerolvm audit verify` is a person or a CI role outside this cluster, and
# attaching it to anything here would be guessing. It can read every head and
# every version, plus the export batches, and can change nothing, so handing it
# to an outside auditor does not hand them a way to alter the evidence.
data "aws_iam_policy_document" "audit_witness_auditor" {
  count = var.audit_witness_enabled && var.audit_witness_auditor_policy_enabled ? 1 : 0

  statement {
    sid       = "WitnessList"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [aws_s3_bucket.witness[0].arn]
  }

  statement {
    sid       = "WitnessRead"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.witness[0].arn}/*"]
  }

  # The verifier links every witnessed head through the exported records, so it
  # needs the export too. Only when Terraform owns that bucket; a webhook or bus
  # export is saved by its receiver and passed with --export-dir instead.
  dynamic "statement" {
    for_each = var.audit_export_enabled ? [1] : []
    content {
      sid       = "ExportList"
      actions   = ["s3:ListBucket"]
      resources = [aws_s3_bucket.audit[0].arn]
    }
  }

  dynamic "statement" {
    for_each = var.audit_export_enabled ? [1] : []
    content {
      sid       = "ExportRead"
      actions   = ["s3:GetObject"]
      resources = ["${aws_s3_bucket.audit[0].arn}/*"]
    }
  }
}

resource "aws_iam_policy" "audit_witness_auditor" {
  count = var.audit_witness_enabled && var.audit_witness_auditor_policy_enabled ? 1 : 0

  name        = "${var.cluster_name}-audit-witness-auditor"
  description = "Read-only access to the ${var.cluster_name} audit witness and export buckets, for aerolvm audit verify."
  policy      = data.aws_iam_policy_document.audit_witness_auditor[0].json

  tags = merge(var.extra_tags, { Name = "${var.cluster_name}-audit-witness-auditor" })
}
