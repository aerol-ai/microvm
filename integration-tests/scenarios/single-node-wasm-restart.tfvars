# Single node with every in-process runtime on: WASM (run.sh's wasm overlay
# and staged modules, as in single-node-wasm) and the V8 isolate (workerd,
# default_with_isolate, as in single-node-isolate-jail, jail on: the shipped
# default). A copy of single-node-wasm-isolate under its own name, so its
# Terraform state is its own: the gate that WASM and isolate sandboxes keep
# running across `systemctl restart sandboxd` and a node upgrade (UC-677,
# UC-678, UC-700..703). Both runtimes on one node, and a restart that costs
# nothing else.
#
# AWS access (aws_profile, aws_region, ssh_key_name, ...) is INHERITED from the
# operator's config/terraform.tfvars, which run.sh chains as the first
# -var-file. This file overrides only the prod-specific bits below.
cluster_name = "aerolvm-itest-single-node-wasm-restart"

# The itest marker is required by the safety tripwire; ttl drives
# scripts/integration-reap.sh.
extra_tags = {
  itest = "true"
  ttl   = "4" # hours; reaper terminates older instances
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40 # throwaway box, keep cost down

# workerd (SHA-256-pinned) and SB_ENABLE_ISOLATE=true at bootstrap. The jail
# stays on: T14 measures the default, then turns it off on the node itself.
default_with_isolate = true

# A single node has nothing to share certs with.
caddy_shared_cert_storage = {
  enabled = false
}

# Named credentials (avm_ tokens) for `aerolvm get/describe/delete tokens`.
extra_sandboxd_env = {
  SB_IDENTITY_ENABLED = "true"
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
