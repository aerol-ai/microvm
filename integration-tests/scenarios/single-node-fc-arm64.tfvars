# Single-node arm64 Firecracker integration scenario: one mixed Graviton metal
# worker with Firecracker enabled. Parity target for UC-24/47-50 on arm64.
#
# AWS access is inherited from config/terraform.tfvars (chained first by run.sh).
cluster_name = "aerolvm-itest-single-node-fc-arm64"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "c7g.metal"
default_volume_size_gb = 80
default_with_firecracker = true

caddy_shared_cert_storage = {
  enabled = false
}

firecracker = {
  # Leave *_url empty when the AMI already ships aarch64 firecracker/jailer/vmlinux
  # artifacts at the matching *_path defaults. Set kernel_url when staging a
  # custom aarch64 vmlinux built with CONFIG_VMGENID=y.
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    arch = "arm64"
    spot = false
  }
}
