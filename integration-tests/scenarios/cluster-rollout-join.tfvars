# The rollout gate on one-line joins (plans/kubectl-style-cluster-ops.md §8):
# cluster-rollout's 8-node shape, but every node joins with the one-line
# installer and Terraform's token per role (one_line_join), so worker and
# ingress nodes never hold the operator PAT. They hold its hash, and call
# their peers with their node certs alone. UC-690..693 check that; the node
# verb, delete, rollout and CLI-upgrade cases run here to show the cluster
# works without the PAT on those nodes. Its own name, because the harness
# keys Terraform state by scenario name.
#
#   3x server  (t3.medium)  — Raft voters only; join with the 24h server token
#   1x ingress (t3.medium)  — the API domain lands here; no PAT
#   4x worker  (t3.medium)  — docker + gVisor + WASM each; no PAT
#
# On-demand, as on cluster-hetero: a spot reclaim mid-run makes the
# multi-node convergence flaky. AWS access is inherited from
# config/terraform.tfvars (chained first by run.sh).
cluster_name = "aerolvm-itest-cluster-rollout-join"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

one_line_join = true

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
