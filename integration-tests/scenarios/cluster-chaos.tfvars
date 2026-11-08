# cluster-chaos: the cluster-correctness fault scenario
# (plans/cluster-correctness-and-create-latency.md §3.2, UC-470..UC-479,
# `make integration-cluster-chaos`).
#
#   3x server  (t3.medium)  Raft voters only: no sandboxes, no public traffic
#   3x worker  (t3.medium)  containerd engine, sandboxes only, no Raft state
#   1x ingress (t3.medium)  Caddy + route table; the API domain lands here
#
# Role-separated on purpose: "partition the owner from the servers with an
# ingress on its side" (UC-470) can only be expressed when owner, voters and
# ingress are different machines. On a 3x mixed cluster every node is all
# three at once.
#
# Three workers, not two: the mass-failover case (UC-478) needs two survivors
# for the leader to spread one dead worker's sandboxes over, and the create
# storm (UC-473, 200 creates at 0.25 CPU) needs about three workers' budget
# (18 CPU each on a t3.medium: 2 cores x 0.9 x 10 overprovision).
#
# t3.medium everywhere: the smallest size any scenario has run sandboxd on.
# t3.small servers would save about $0.06/h and are unproven (bootstrap,
# Caddy and a Raft log on 2 GiB).
#
# On-demand, not spot: a spot reclaim in the middle of a partition is a fault
# this scenario did not inject, and it would be reported as one it did.
#
# Cost: 7 x t3.medium on-demand = 7 x $0.0416/h = $0.29/h (us-east-1), plus
# 4 x 40 GiB + 4 x 20 GiB gp3 (~$0.02/h). A full run (bring-up, the ten
# chaos cases, teardown) is about 1.5 to 2 hours, so about $0.45 to $0.65.
cluster_name = "aerolvm-itest-cluster-chaos"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

extra_sandboxd_env = {
  # Several cases wait out two reconcile intervals before they call a state
  # converged (I6). The 5-minute default would make that 10 minutes per case;
  # 60 s keeps the run near an hour. Reconcile then runs more often, which can
  # only surface a reconcile-driven resurrection sooner, never hide one. The
  # cases read the interval off a node, so their bounds follow this value.
  SB_RECONCILE_INTERVAL = "60s"
}

nodes = {
  server-1  = { role = "server", seed = true, volume_size_gb = 20, spot = false }
  server-2  = { role = "server", volume_size_gb = 20, spot = false }
  server-3  = { role = "server", volume_size_gb = 20, spot = false }
  ingress-1 = { role = "ingress", volume_size_gb = 20, spot = false }
  worker-1  = { role = "worker", spot = false }
  worker-2  = { role = "worker", spot = false }
  worker-3  = { role = "worker", spot = false }
}
