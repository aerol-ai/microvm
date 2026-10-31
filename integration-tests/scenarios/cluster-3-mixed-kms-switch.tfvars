# The two-step switch from local to AWS KMS (plans/customer-key-custody.md
# §12, eng D22) on a REAL AWS KMS key. The cluster installs sealing with AWS
# KMS (custody file); UC-312 steps every node back to local sealing with the
# AWS settings kept, which is step 1's state, then runs step 2 node by node
# with a failover from a switched node to one not yet switched.
cluster_name = "aerolvm-itest-cluster-3-mixed-kms-switch"

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

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}
