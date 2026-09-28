# cluster-hetero-secrets-kms — plans/integration-test-security.md §6.2.
# Pre-merge only. The one run that proves the shipped enterprise+KMS posture.
#
# Reuses cluster-hetero's node map VERBATIM, including spot = false: a spot
# reclaim mid-run makes multi-node convergence flaky (seen on a t3 single-node
# run), and the c5.metal worker exceeds the spot vCPU quota. Only the security
# profile is overlaid.
cluster_name = "aerolvm-itest-cluster-hetero-secrets-kms"

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
  worker-z = { role = "worker", instance_type = "c5.metal", volume_size_gb = 80, with_firecracker = true, with_gvisor = true, spot = false }
}
