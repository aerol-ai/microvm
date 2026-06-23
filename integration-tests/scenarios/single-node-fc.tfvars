# Single-node x86 Firecracker integration scenario: one mixed bare-metal worker
# with Firecracker enabled. The lowest-cost way to exercise the firecracker
# use cases (UC-24/47-50) in isolation — i.e. without standing up the full
# 8-node cluster-hetero just to reach its single worker-fc node. arm64 parity
# lives in single-node-fc-arm64.tfvars.
#
# Firecracker needs /dev/kvm, so this must be a bare-metal instance (c5.metal).
# On-Demand only (spot = false): the bare-metal box alone exceeds the account
# Spot vCPU quota (MaxSpotInstanceCountExceeded), matching cluster-hetero's
# worker-fc reasoning.
#
# AWS access (aws_profile, aws_region, ssh_key_name, ...) is inherited from the
# operator's config/terraform.tfvars, which run.sh chains as the first
# -var-file.
cluster_name = "aerolvm-itest-single-node-fc"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type    = "c5.metal"
default_volume_size_gb   = 80
default_with_firecracker = true

# A single node has nothing to share certs WITH; disable the prod-inherited
# managed S3 cert bucket so the run doesn't create one.
caddy_shared_cert_storage = {
  enabled = false
}

firecracker = {
  # Empty *_url + auto_install_artifacts (default true) pulls arch-matched
  # upstream firecracker/jailer/vmlinux on first boot — no custom staging needed.
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = false
  }
}
