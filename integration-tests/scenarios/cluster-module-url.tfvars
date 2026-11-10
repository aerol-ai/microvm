# Terraform used by URL (plans/kubectl-style-cluster-ops.md §7, §9 Phase 5
# row). run.sh gives this scenario a root of its own whose module block
# fetches Terraform/ by git URL (the module-url capability;
# prepare_module_root), and leaves one_line_join to the module's default, so
# every node joins with one line and a token per role. Small, on-demand:
#
#   server-1 (seed, server,ingress) — the API domain lands here
#   server-2, server-3 (server)     — Raft voters; the 24h server token
#   worker-1 (worker)               — the never-expiring worker token
#   spare-1  (blank)                — plain Ubuntu; UC-687 joins it with the
#                                     line `aerolvm join-command` prints
cluster_name = "aerolvm-itest-cluster-module-url"

extra_tags = {
  itest = "true"
  ttl   = "3"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 30

nodes = {
  server-1 = { role = "server,ingress", seed = true, instance_type = "t3.medium", spot = false }
  server-2 = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-3 = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  worker-1 = { role = "worker", instance_type = "t3.medium", spot = false }
  spare-1  = { role = "worker", blank = true, instance_type = "t3.medium", spot = false }
}
