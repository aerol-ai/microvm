# cluster-3-mixed-bench — the latency arm for UC-165/166 (§7 group L, T16).
#
# Identical topology to cluster-3-mixed-secrets so the comparison is apples to
# apples; the ONLY difference is that it advertises `benchmark` and carries no
# security profile. D5: the baseline is main-built binaries via
# `build.sh --ref main`, not "the same scenario with security off", because
# the security defaults are already on in the branch.
cluster_name = "aerolvm-itest-cluster-3-mixed-bench"

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
