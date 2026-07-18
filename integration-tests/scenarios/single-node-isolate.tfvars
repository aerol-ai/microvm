# Single-node V8-isolate (workerd) integration scenario: one mixed node with a
# public domain + TLS and the isolate runtime installed at bootstrap. Topology is
# identical to single-node.tfvars / single-node-wasm.tfvars; the only difference
# is default_with_isolate = true, which Terraform threads into install.sh's
# --with-isolate flag (downloads the SHA-256-pinned workerd release to
# /usr/local/bin/workerd and writes SB_ENABLE_ISOLATE=true). Unlike wasm there
# is NO run.sh config-overlay flip and no node-side module staging — the isolate
# runtime is entirely provisioning-driven (same shape as gvisor's
# default_with_gvisor), and its JS bundles are uploaded by the UCs over the API.
#
# A single "mixed" node is both ingress and worker, so IsWorker() is true and
# supportedRuntimesForConfig advertises "isolate" (EnableIsolate && IsWorker) —
# without that, admission would reject every isolate create with
# ErrNoPlacementTarget (the gvisor UC-87 class of bug). isolate runs in-process
# via workerd (host-mediated, no KVM / bare metal), so the cheap t3.medium
# suffices.
#
# AWS access (aws_profile, aws_region, ssh_key_name, ...) is INHERITED from the
# operator's config/terraform.tfvars, which run.sh chains as the first
# -var-file. This file is chained second and overrides only the prod-specific
# bits below. Ops + secrets come from the runtime config overlay (run.sh) +
# config/secrets.yml.
cluster_name = "aerolvm-itest-single-node-isolate"

# Override prod's extra_tags entirely (a map override replaces it). The itest
# marker is required by the safety tripwire; ttl drives scripts/integration-reap.sh.
extra_tags = {
  itest = "true"
  ttl   = "4" # hours; reaper terminates older instances
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40 # override prod's 128 — throwaway box, keep cost down

# Install Cloudflare workerd (SHA-256-pinned) + SB_ENABLE_ISOLATE=true on the
# node at bootstrap. This is the isolate analog of default_with_gvisor=true.
default_with_isolate = true

# A single node has nothing to share certs WITH; disable the prod-inherited
# managed S3 cert bucket so the run doesn't create one. Cluster scenarios re-enable it.
caddy_shared_cert_storage = {
  enabled = false
}

# extra_user_data runs AFTER install.sh writes the env + starts sandboxd, so it
# is the append-and-restart hook (same one the wasm/gvisor scenarios use). We
# turn the isolate jail OFF for the test: SB_ISOLATE_USE_JAIL defaults to true,
# but the jail's chroot is not yet populated with the workerd binary (the
# chroot-populate step is the tracked "full jail realization" follow-up in
# plans/isolate-runtime.md). With the jail on, workerd is exec'd inside an empty
# chroot and every create fails with "fork/exec /usr/local/bin/workerd: no such
# file or directory" — even though the binary is installed on the host and health
# reports isolate:ok. Jail-off is how the runtime is currently deployable end to
# end (it is what the manual live validation used), and it is orthogonal to the
# per-sandbox egress attribution UC-104 proves. A jail-ON isolate scenario is a
# follow-up gated on the chroot-populate work.
nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
    extra_user_data = <<-EOT
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
}
