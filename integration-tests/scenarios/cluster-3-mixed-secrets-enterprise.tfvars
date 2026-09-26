# S4 — the fail-fast profile end to end (plans/integration-test-security.md
# §6.2 and §6.4a). Enterprise mode changes BOOT behaviour, so it has to be
# proven from a cold boot rather than flipped on a running cluster.
#
# Four constraints, all measured on a live box before this file was written:
#   1. enterprise forces SB_SECRET_AUDIT_EXTERNAL_WITNESS, and pkg/daemon
#      refuses to boot without a non-noop controlplane.Witness. The caps file
#      advertises audit-witness, which makes run.sh provision the
#      -tags itestwitness daemon.
#   2. pkg/auditexport REJECTS the file/stdout backends under enterprise
#      ("keeps audit evidence on this node"), so the sink must be off-node.
#   3. the webhook URL must be https — the receiver serves TLS for this.
#   4. the witness must be configured from FIRST boot (see the TODOS entry on
#      the standalone-node-id mismatch; retrofitting it fails closed).
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

# D6: S4 is the scenario that provisions the V8-isolate runtime AND its jail,
# so UC-150/163/164 have somewhere to run. §6.2a flagged that no scenario set
# this flag even though §6.1 lists the jail as an axis.
default_with_isolate = true

extra_sandboxd_env = {
  SB_ENTERPRISE_MODE = "true"
  # The jail is the enterprise posture; the chroot-populate blocker that used
  # to force it off is closed (pkg/isolate/chroot.go PrepareJailBase).
  SB_ISOLATE_USE_JAIL = "true"
}

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
