# S2 — the iteration loop (plans/integration-test-security.md §6.2).
# 3× mixed, LOCAL secret provider, real per-node mTLS from the CSR rendezvous,
# audit shipped off-node to the receiver. This is where fan-out, cross-node
# failover open (UC-117), reseal and audit fan-out are proven.
cluster_name = "aerolvm-itest-cluster-3-mixed-secrets"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

# Off-node audit: the receiver runs on the seed and the suite reads results
# back over HTTP instead of SSH.
audit_receiver_enabled = true
audit_export_enabled   = true

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
