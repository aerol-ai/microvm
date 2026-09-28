# S3 — the KMS provider's OWN use-case set (plans/integration-test-security.md
# §6.2). NOT S2 parity: KMSProvider.Open never checks the envelope recipient
# set (pkg/secrets/kms_provider.go documents `_ = nodeID`), so IAM is the
# entire boundary and S2's recipient-set assertions would be vacuous or false
# here. This scenario asserts the IAM boundary instead.
cluster_name = "aerolvm-itest-cluster-3-mixed-secrets-kms"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

# A REAL CMK (D3): pkg/secrets/fake_kms.go already covers the contract
# offline, so a fake here would prove nothing new. Strict boot on, so a
# provider that cannot round-trip fails the daemon instead of degrading.
secret_kms_enabled     = true
secret_kms_strict_boot = true

audit_receiver_enabled = true
audit_export_enabled   = true

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
