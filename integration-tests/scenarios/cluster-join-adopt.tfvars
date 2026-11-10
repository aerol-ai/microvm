# The adopt half of the Phase 2 gate (plans/kubectl-style-cluster-ops.md
# §4.4): provisioned on an old release with the old scripts (two-pass join,
# the seed's CSR loop), moved to this build, adopted, then grown by one
# machine with a one-line join. Run through adopt-gate.sh:
#
#   integration-tests/run.sh cluster-join-adopt --adopt-from v0.6.11
#
#   server-1 (seed, server,ingress) — the API domain lands here
#   server-2, server-3 (server)     — adopt fetches the CA key from the seed
#   worker-1 (worker)
#   spare-1  (blank)                — plain Ubuntu; the one-line join target
cluster_name = "aerolvm-itest-cluster-join-adopt"

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
