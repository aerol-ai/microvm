# Single-node integration scenario: one mixed node with a public domain + TLS.
#
# AWS access (aws_profile, aws_region, ssh_key_name, ...) is INHERITED from the
# operator's config/terraform.tfvars, which run.sh chains as the first
# -var-file. This file is chained second and overrides only the prod-specific
# bits below (topology, identity, tags, cert storage, volume). Ops + secrets
# come from the runtime-generated config overlay (run.sh) + config/secrets.yml.
cluster_name = "aerolvm-itest-single-node"

# Override prod's extra_tags entirely (a map override replaces it). The itest
# marker is required by the safety tripwire; ttl drives scripts/integration-reap.sh.
extra_tags = {
  itest = "true"
  ttl   = "4" # hours; reaper terminates older instances
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40 # override prod's 128 — throwaway box, keep cost down

# A single node has nothing to share certs WITH; disable the prod-inherited
# managed S3 cert bucket so the run doesn't create one. Cluster scenarios re-enable it.
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
