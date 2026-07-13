# Single-node containerd-engine soak: same shape as single-node, but
# SB_CONTAINER_ENGINE=containerd via the containerd-engine capability
# (plans/containerd-engine.md Phase 5). Runs UC-99..102 + the normal docker
# UCs against the native containerd driver.
#
# AWS access is inherited from config/terraform.tfvars via run.sh.
cluster_name = "aerolvm-itest-single-node-containerd"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = false
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
