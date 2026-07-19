# Everyday investor-grade benchmark + live Grafana wall (Phase 0).
# Topology: 3× t3.large mixed on-demand (containerd + gVisor + WASM resident +
# isolate jail-off) + obs1 provisioned outside the nodes map when
# deploy_obs=true (run.sh sets that when caps advertise `observability`).
#
# On-demand (not spot): this scenario's job is a clean UC + short sim pass for
# screenshots; a spot reclaim would surface as spurious failures.
# t3.large (not medium): WASM resident host + isolate warm pool + gVisor need
# the RAM headroom (same lesson as cluster-3-mixed-wasm).
#
# No Firecracker — needs bare metal; reserved for hetero (T7 unresolved).
# Headline latency numbers must NOT be sourced from this t3 topology (CM-4);
# mixed validates connectivity + UC coverage only.
#
# AWS access inherited from config/terraform.tfvars (chained first by run.sh).
cluster_name = "aerolvm-itest-cluster-mixed-benchmark-with-obs"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.large"
default_volume_size_gb = 40
default_with_gvisor    = true
default_with_isolate   = true

# Obs node (Terraform/obs.tf). run.sh also passes -var deploy_obs=true when the
# scenario caps advertise observability; keep the default false so other
# scenarios never pay for it.
deploy_obs         = true
obs_instance_type  = "t3.medium"

caddy_shared_cert_storage = {
  enabled = true
}

# Per-node: WASM resident host + isolate jail-off + gVisor shim (until releases
# ship install.sh that bundles containerd-shim-runsc-v1). SB_HOST_RUNTIMES is
# written by install.sh --with-gvisor; isolate is appended by the daemon when
# EnableIsolate is on. tfvars are literal-only, hence the repetition.
nodes = {
  node1 = {
    role            = "mixed", seed = true, spot = false
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node2 = {
    role            = "mixed", spot = false
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node3 = {
    role            = "mixed", spot = false
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
}
