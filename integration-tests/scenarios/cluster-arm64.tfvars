# All-arm64 3× mixed cluster integration scenario.
cluster_name = "aerolvm-itest-cluster-arm64"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type    = "c7g.metal"
default_volume_size_gb   = 80
default_with_firecracker = true

caddy_shared_cert_storage = {
  enabled = true
}

firecracker = {}

nodes = {
  node1 = { role = "mixed", seed = true, arch = "arm64", spot = false }
  node2 = { role = "mixed", arch = "arm64", spot = false }
  node3 = { role = "mixed", arch = "arm64", spot = false }
}
