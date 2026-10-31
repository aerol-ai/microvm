# A fresh cluster with wrapped server-key custody on a REAL AWS KMS key
# (plans/customer-key-custody.md §3, Phase 6): the seed generates the server
# key wrapped, the cred bundle carries only the wrapped file, and joiners
# unwrap it at boot. UC-310 checks no plaintext copy exists anywhere.
cluster_name = "aerolvm-itest-cluster-3-mixed-wrapped-kms"

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
key_custody            = "wrapped"

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
