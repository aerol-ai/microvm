# Customer key custody against Vault Transit (plans/customer-key-custody.md
# Phase 6). Nothing key-store specific is provisioned here: the suite puts an
# OpenBao dev server (TLS) on the seed and an OpenBao Proxy on every node
# over SSH (keycustody_support_test.go), so the cases start from a plain
# local cluster and run the switch a customer would.
cluster_name = "aerolvm-itest-cluster-3-mixed-secrets-vault"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
