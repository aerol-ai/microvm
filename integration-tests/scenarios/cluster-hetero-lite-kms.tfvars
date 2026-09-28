# cluster-hetero-lite-kms — plans/integration-test-security.md §6.2 (T18).
# cluster-hetero-secrets-kms WITHOUT the c5.metal. Same 8-member role-separated topology
# (3 server / 1 ingress / 4 worker), same security profile; worker-z is a
# t3.medium instead of a c5.metal, so Firecracker is the only thing this run
# cannot cover. ~8 x t3.medium on-demand, well under $1/h — cheap enough to
# run after every internal/cluster change. The metal run is cluster-hetero-secrets-kms (T19).
#
# On-demand, not spot, for the same reason as the flagship: a spot reclaim
# mid-run makes multi-node convergence flaky.
cluster_name = "aerolvm-itest-cluster-hetero-lite-kms"

extra_tags = {
  itest = "true"
  ttl   = "6"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = true
}

secret_kms_enabled     = true
secret_kms_strict_boot = true

audit_receiver_enabled = true
audit_export_enabled   = true

extra_sandboxd_env = {
  SB_ENTERPRISE_MODE = "true"
}

nodes = {
  server-1  = { role = "server", seed = true, instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-2  = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  server-3  = { role = "server", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  ingress-1 = { role = "ingress", instance_type = "t3.medium", volume_size_gb = 20, spot = false }
  worker-x = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-y = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-w = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
  worker-z = { role = "worker", instance_type = "t3.medium", with_gvisor = true, spot = false }
}
