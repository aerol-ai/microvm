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

# Per-node: WASM resident host + isolate jail-off. install.sh --with-gvisor
# installs runsc and containerd-shim-runsc-v1 and writes SB_HOST_RUNTIMES;
# isolate is appended by the daemon when EnableIsolate is on. tfvars are
# literal-only, hence the repetition.
#
# Warm pools for best-case latency: WASM (resident+pool) and isolate pools are
# on by default; the containerd warm TASK pool is enabled here (seeded with the
# bench image alpine:3.20) so container creates adopt a ready task. The netns
# (network) pool is already on by default (containerd.native_netns_pool_enabled).
# NOTE: warm slots hold capacity, so UC-95 density is measured with the pool
# resident (Perf-1 -p 1 keeps sims off the density window).
nodes = {
  node1 = {
    role            = "mixed", seed = true, spot = false
    extra_user_data = <<-EOT
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_ENABLED=true' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_IMAGES=alpine:3.20' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_DEPTH=8' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_REFILL_INTERVAL=2s' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node2 = {
    role            = "mixed", spot = false
    extra_user_data = <<-EOT
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_ENABLED=true' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_IMAGES=alpine:3.20' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_DEPTH=8' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_REFILL_INTERVAL=2s' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  node3 = {
    role            = "mixed", spot = false
    extra_user_data = <<-EOT
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_ENABLED=true' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_IMAGES=alpine:3.20' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_DEPTH=8' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      echo 'SB_CONTAINERD_POOL_REFILL_INTERVAL=2s' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
}
