# cluster-3-mixed with SB_INGRESS_PROXY_ROUTING on every node
# (plans/ingress-proxy-routing.md T10). Same three mixed spot t3 boxes as
# cluster-3-mixed, so the whole suite runs against the static-route data path:
# Caddy holds static routes only, sandboxd answers "where" over loopback DNS,
# and raw TCP host ports are kernel-DNATed. UC-171..173 are the gate.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-routing"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

# Three mixed nodes share Caddy cert storage so any ingress can serve the
# wildcard cert without re-issuing (and burning the LE budget).
caddy_shared_cert_storage = {
  enabled = true
}

nodes = {
  node1 = { role = "mixed", seed = true, spot = true }
  node2 = { role = "mixed", spot = true }
  node3 = { role = "mixed", spot = true }
}

# install.sh --ingress-proxy-routing on every node: writes
# SB_INGRESS_PROXY_ROUTING=true and the ~rt.internal resolver routing domain.
default_ingress_proxy_routing = true
