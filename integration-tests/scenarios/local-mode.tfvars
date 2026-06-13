# Local-mode integration scenario: one throwaway Linux box running
# `install.sh --local` (no Caddy, no DNS). The suite reaches it via an SSH
# local port-forward to http://localhost:21212 (see run.sh).
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-local-mode"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

# No domain / no Caddy in local-mode — disable the prod-inherited cert bucket.
caddy_shared_cert_storage = {
  enabled = false
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
