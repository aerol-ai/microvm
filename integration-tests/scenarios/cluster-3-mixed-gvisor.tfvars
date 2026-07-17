# Cluster (3× mixed) gVisor integration scenario: three nodes, each a Raft voter +
# worker + ingress, with gVisor (runsc) enabled on every node. Topology mirrors
# cluster-3-mixed.tfvars except default_with_gvisor=true so any mixed node can
# place gvisor sandboxes. Exercises cluster formation, leader election,
# placement, forwarding, and the shared Caddy cert store — all on cheap spot t3
# boxes.
#
# Engine: containerd (the harness default — no docker-engine cap), so runtime
# "gvisor" is served by the native containerd driver via the
# io.containerd.runsc.v1 shim. The docker-engine A/B twin is
# cluster-3-mixed-gvisor-docker.tfvars.
#
# AWS access (profile, region, ssh_key_name) is inherited from
# config/terraform.tfvars (chained first by run.sh). This file overrides only
# the prod-specific bits below.
cluster_name = "aerolvm-itest-cluster-3-mixed-gvisor"

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

# STOPGAP until a release ships the install.sh that bundles the shim: nodes
# fetch install.sh from releases/latest, and the released --with-gvisor only
# installs runsc + the dockerd daemon.json registration. The containerd engine
# needs containerd-shim-runsc-v1 on PATH (io.containerd.runsc.v1 resolves to
# that binary), so install it via extra_user_data — same download + SHA-512
# pattern install.sh now uses (scripts/install.sh install_runsc_shim). Runs
# after install.sh during cloud-init; no containerd restart needed (shims are
# resolved per-container launch). tfvars are literal-only, hence the per-node
# repetition. Drop this block once releases/latest carries the fix.
nodes = {
  node1 = {
    role            = "mixed", seed = true, spot = true
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
    EOT
  }
  node2 = {
    role            = "mixed", spot = true
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
    EOT
  }
  node3 = {
    role            = "mixed", spot = true
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
    EOT
  }
}
