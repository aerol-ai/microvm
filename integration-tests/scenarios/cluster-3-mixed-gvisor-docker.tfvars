# Cluster (3× mixed) gVisor-on-dockerd scenario: identical topology to
# cluster-3-mixed-gvisor (three Raft voter + worker + ingress nodes,
# default_with_gvisor=true) but pinned to the docker engine via the
# docker-engine capability in its caps.yml. Exists so the gvisor benchmark has
# an engine A/B: runtime "gvisor" served by dockerd's daemon.json runsc
# registration here vs the native containerd driver's io.containerd.runsc.v1
# shim in cluster-3-mixed-gvisor. No shim stopgap needed — the released
# install.sh already registers runsc with dockerd.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-gvisor-docker"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40
default_with_gvisor    = true

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
