# Cluster (heterogeneous, 8 nodes) WITHOUT the bare-metal worker: the
# cluster-hetero topology and runtimes with worker-z a t3.medium instead of a
# c5.metal, so everything but Firecracker runs for ~8 x t3.medium on-demand.
#
#   3x server  (t3.medium)  — Raft voters only, no sandboxes, no public traffic
#   1x ingress (t3.medium)  — route table + Caddy, no sandbox compute
#   4x worker  (t3.medium)  — docker + gVisor + WASM each
#
# On-demand, as on cluster-hetero: a spot reclaim mid-run makes the
# multi-node convergence flaky. AWS access is inherited from
# config/terraform.tfvars (chained first by run.sh).
cluster_name = "aerolvm-itest-cluster-hetero-lite"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

# Serve the remote MCP endpoint at /mcp on every node (UC-178, capability
# remote-mcp). Here the API domain lands on ingress-1, which can never own a
# sandbox, so every remote tool call is forwarded to its owning worker.
extra_sandboxd_env = {
  SB_MCP_ENABLED = "true"
}

nodes = {
  server-1  = { role = "server", seed = true, instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-2  = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-3  = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  ingress-1 = { role = "ingress", instance_type = "t3.medium", volume_size_gb = 20, spot = false }

  # docker + gVisor + WASM (wasm runtime enabled fleet-wide when scenario caps wasm).
  worker-x = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-y = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-w = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }

  # worker-z is a t3.medium here, not the c5.metal: no Firecracker.
  worker-z = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
}
