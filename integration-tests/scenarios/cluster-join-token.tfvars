# One-line joins (plans/kubectl-style-cluster-ops.md §9 Phase 2 row): every
# node starts as blank Ubuntu and joins with the one-line installer and
# Terraform's token per role (Terraform one_line_join), with no S3 hand-off,
# no CSR loop and no scp. Sized like cluster-hetero-lite, smaller:
#
#   3x server  (t3.medium)  — Raft voters; join with the 24h server token
#   1x ingress (t3.medium)  — the API domain lands here; the never-expiring ingress token
#   2x worker  (t3.medium)  — the never-expiring worker token
#
# Node certs last 10 minutes (SB_CLUSTER_NODE_CERT_TTL) so UC-623 sees them
# renew during the run. On-demand, as on cluster-hetero-lite.
cluster_name = "aerolvm-itest-cluster-join-token"

extra_tags = {
  itest = "true"
  ttl   = "3"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 30

one_line_join = true

extra_sandboxd_env = {
  SB_CLUSTER_NODE_CERT_TTL = "10m"
}

nodes = {
  server-1  = { role = "server", seed = true, instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-2  = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-3  = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  ingress-1 = { role = "ingress", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  worker-1  = { role = "worker", instance_type = "t3.medium", spot = false }
  worker-2  = { role = "worker", instance_type = "t3.medium", spot = false }
  # Plain Ubuntu with nothing installed: UC-694 makes it a server added
  # late, through a joined server's own bootstrap and a fresh token, as
  # node_join_tokens would.
  spare-server = { role = "server", blank = true, instance_type = "t3.medium", volume_size_gb = 20, spot = false }
}
