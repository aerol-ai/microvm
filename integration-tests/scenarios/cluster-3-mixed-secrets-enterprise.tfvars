# S4 — the fail-fast profile end to end (plans/integration-test-security.md
# §6.2 and §6.4a). Enterprise mode changes BOOT behaviour, so it has to be
# proven from a cold boot rather than flipped on a running cluster.
#
# Three constraints, all measured on a live box before this file was written:
#   1. enterprise forces SB_SECRET_AUDIT_EXTERNAL_WITNESS, and pkg/daemon
#      refuses to boot without a non-noop controlplane.Witness. The stock
#      daemon gets one from SB_AUDIT_WITNESS_BACKEND=s3, which
#      audit_witness_enabled sets below along with the Object Lock bucket;
#      the caps file advertises audit-witness so the witness cases run.
#   2. pkg/auditexport REJECTS the file/stdout backends under enterprise
#      ("keeps audit evidence on this node"), so the sink must be off-node.
#   3. the webhook URL must be https — the receiver serves TLS for this.
cluster_name = "aerolvm-itest-cluster-3-mixed-secrets-enterprise"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

secret_kms_enabled     = true
secret_kms_strict_boot = true

# Constraints 2+3: the receiver is the off-node, https sink.
audit_receiver_enabled = true
audit_export_enabled   = true

# The S3 Object Lock witness enterprise mode requires (plans/open-audit-witness.md,
# D13/D17), written by the stock daemon. GOVERNANCE for one day, so run.sh's
# teardown can empty the bucket with the bypass header before
# `terraform destroy`; a COMPLIANCE or longer lock would leave a bucket nobody
# can delete until the lock ends.
audit_witness_enabled = true
witness_lock_mode     = "GOVERNANCE"
witness_lock_days     = 1

# D6: S4 is the scenario that provisions the V8-isolate runtime AND its jail,
# so UC-150/163/164 have somewhere to run. §6.2a flagged that no scenario set
# this flag even though §6.1 lists the jail as an axis.
default_with_isolate = true

extra_sandboxd_env = {
  SB_ENTERPRISE_MODE = "true"
  # The jail is the enterprise posture; the chroot-populate blocker that used
  # to force it off is closed (pkg/isolate/chroot.go PrepareJailBase).
  SB_ISOLATE_USE_JAIL = "true"
  # The daemon refuses a witness that locks heads for less time than the
  # local records they vouch for are kept, and enterprise refuses zero, so
  # the one-day lock needs one-day retention (D13).
  SB_SECRET_AUDIT_RETENTION_DAYS = "1"
}

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
