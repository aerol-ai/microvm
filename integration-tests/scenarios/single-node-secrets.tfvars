# S1 — the cheapest security gate (plans/integration-test-security.md §6.2).
# One mixed node, local secret provider, enterprise OFF, audit exported to a
# file. Runs first: if S1 is red the cluster scenarios are not worth paying for.
cluster_name = "aerolvm-itest-single-node-secrets"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = false
}

# file is legal here ONLY because enterprise is off: pkg/auditexport rejects
# the on-node backends under SB_ENTERPRISE_MODE ("keeps audit evidence on this
# node"). S4/S6 therefore use the receiver instead.
audit_export_backend = "file"

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
