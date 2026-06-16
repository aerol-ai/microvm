# Cluster (heterogeneous, 8 nodes) integration scenario: dedicated roles so
# each runtime + the control/ingress split is exercised independently.
#
#   3× server  (t3.small)   — Raft voters only, no sandboxes, no public traffic
#   1× ingress (t3.small)   — route table + Caddy, no sandbox compute
#   4× worker  (t3.medium / *.metal):
#       worker-docker  — docker runtime
#       worker-gvisor  — gVisor (runsc; no KVM needed)
#       worker-wasm    — WASM runtime (enabled via config overlay)
#       worker-fc      — Firecracker; needs /dev/kvm → bare-metal (c5.metal)
#
# Cost control is by instance sizing (servers/ingress are t3.small). Every node
# runs On-Demand (spot = false): the bare-metal firecracker box alone exceeds the
# account Spot vCPU quota (MaxSpotInstanceCountExceeded), and spot reclaim of any
# node mid-run makes the multi-node convergence flaky. The modest extra cost buys
# a deterministic 8-node bring-up.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh).
cluster_name = "aerolvm-itest-cluster-hetero"

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
  server-1  = { role = "server", seed = true, instance_type = "t3.small", volume_size_gb = 20, spot = false }
  server-2  = { role = "server", instance_type = "t3.small", volume_size_gb = 20, spot = false }
  server-3  = { role = "server", instance_type = "t3.small", volume_size_gb = 20, spot = false }
  ingress-1 = { role = "ingress", instance_type = "t3.small", volume_size_gb = 20, spot = false }

  worker-docker = { role = "worker", instance_type = "t3.medium", spot = false }
  worker-gvisor = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-wasm   = { role = "worker", instance_type = "t3.medium", spot = false }

  # Firecracker needs KVM → bare metal. On-Demand like the rest (spot = false).
  worker-fc = { role = "worker", instance_type = "c5.metal", volume_size_gb = 80, with_firecracker = true, spot = false }
}
