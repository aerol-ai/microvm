# Enterprise mode on ONE server, with the stock daemon and an S3 Object Lock
# bucket (plans/open-audit-witness.md, Phase 4, D17). The single-server half
# of "the released sandboxd boots SB_ENTERPRISE_MODE=true given a witness
# bucket"; cluster-3-mixed-secrets-enterprise is the cluster half. It is also
# the release smoke (T24), run once against the published artifact:
#
#   integration-tests/run.sh single-node-secrets-enterprise --version <tag>
#
# What enterprise needs, and where each piece comes from:
#   1. a non-noop controlplane.Witness: audit_witness_enabled creates the
#      Object Lock bucket, grants the node role the witness IAM and sets
#      SB_AUDIT_WITNESS_BACKEND=s3, which pkg/daemon opens at boot.
#   2. an off-node https audit sink: pkg/auditexport refuses the file/stdout
#      backends under enterprise, so the node exports to the receiver.
#   3. SB_NODE_ID that is not "standalone", or the witness refuses to open:
#      cluster-init.sh writes SB_NODE_ID=<cluster_name>-node1 on every
#      Terraform node, this lone seed included, so nothing is set here.
#
# The local secret provider, not KMS: the claim under test is "the free
# download and a bucket", and cluster-3-mixed-secrets-enterprise covers KMS.
cluster_name = "aerolvm-itest-single-node-secrets-enterprise"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = false
}

audit_receiver_enabled = true
audit_export_enabled   = true

# GOVERNANCE for one day (D13), so run.sh's teardown can empty the bucket with
# the bypass header before `terraform destroy`; a COMPLIANCE or longer lock
# would leave a bucket nobody can delete until the lock ends. Production keeps
# the Terraform defaults (COMPLIANCE, 30 days).
audit_witness_enabled = true
witness_lock_mode     = "GOVERNANCE"
witness_lock_days     = 1

extra_sandboxd_env = {
  SB_ENTERPRISE_MODE = "true"
  # The daemon refuses a bucket that locks heads for less time than the local
  # records they vouch for are kept, and enterprise refuses zero, so the
  # one-day lock needs one-day retention (D13).
  SB_SECRET_AUDIT_RETENTION_DAYS = "1"
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
