# Cluster (heterogeneous, 8 nodes) integration scenario: multi-runtime workers
# so placement and failover can choose among peers that advertise the same
# runtimes instead of one dedicated box per runtime.
#
#   3× server  (t3.small)   — Raft voters only, no sandboxes, no public traffic
#   1× ingress (t3.small)   — route table + Caddy, no sandbox compute
#   4× worker  (t3.medium / c5.metal), each carrying multiple runtimes:
#       worker-x/y/w — docker + gVisor + WASM (WASM enabled via cluster overlay)
#       worker-z     — docker + gVisor + WASM + Firecracker (KVM bare metal)
#
# Failover/disruptive tests kill worker-x and expect recreate-policy sandboxes
# to land on worker-y or worker-z (worker-w is an extra placement peer). Firecracker create UCs are skipped
# here (caps.yml omits the firecracker capability) — see single-node-fc and
# cluster-arm64 for live FC coverage.
#
# Cost control is by instance sizing (servers/ingress are t3.small). Every node
# runs On-Demand (spot = false): the bare-metal firecracker box alone exceeds the
# account Spot vCPU quota (MaxSpotInstanceCountExceeded), and spot reclaim of any
# node mid-run makes the multi-node convergence flaky.
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

  # docker + gVisor + WASM (wasm runtime enabled fleet-wide when scenario caps wasm).
  worker-x = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-y = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-w = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }

  # All runtimes including Firecracker (KVM). FC UCs are not exercised in this
  # scenario — worker-z exists for failover targets and future FC tests.
  worker-z = { role = "worker", instance_type = "c5.metal", volume_size_gb = 80, with_firecracker = true, with_gvisor = true, spot = false }
}
