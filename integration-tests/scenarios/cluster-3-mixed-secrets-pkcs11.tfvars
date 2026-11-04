# Customer key custody against PKCS#11 (plans/customer-key-custody.md
# Phase 6). The suite installs SoftHSM2 on every node over SSH and imports
# the SAME AES keys into each token, so copies sealed on one node open on
# another. This proves the code path (helper process, labels, rotation),
# not a network HSM: SoftHSM2 keeps its keys on the node's own disk.
cluster_name = "aerolvm-itest-cluster-3-mixed-secrets-pkcs11"

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
