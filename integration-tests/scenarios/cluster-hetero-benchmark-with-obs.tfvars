# Flagship investor soak — T7 RESOLVED 2026-07-19.
#
# CM-4: headline create-latency / density numbers require comparable metal-class
# hardware for all five runtimes. Decision:
#   - 5× c5.metal workers (one per runtime: containerd, gVisor, WASM, isolate, FC)
#   - 2× m6i.large ingress (HA ingress story; not a create-path headline source)
#   - 3× t3.medium Raft servers (no sandboxes; burstable is fine)
#   - 1× m6i.large obs1 (outside nodes map via deploy_obs)
# Ballpark us-east-1 on-demand: ~$21/hr → ~$63–84 for a 3–4h soak (plus egress).
# No optional 12th arm64 metal (static expected_members).
#
# Mixed (t3) remains connectivity/UC validation only — never a headline source.
cluster_name = "aerolvm-itest-cluster-hetero-benchmark-with-obs"

extra_tags = {
  itest = "true"
  ttl   = "8"
}

default_instance_type  = "m6i.large"
default_volume_size_gb = 40
default_with_gvisor    = false
default_with_isolate   = false

deploy_obs        = true
obs_instance_type = "m6i.large"

caddy_shared_cert_storage = {
  enabled = true
}

nodes = {
  server-1 = {
    role = "server", seed = true, spot = false
    instance_type = "t3.medium", volume_size_gb = 20
    volume_iops = 8000, volume_throughput = 250
  }
  server-2 = {
    role = "server", spot = false
    instance_type = "t3.medium", volume_size_gb = 20
    volume_iops = 8000, volume_throughput = 250
  }
  server-3 = {
    role = "server", spot = false
    instance_type = "t3.medium", volume_size_gb = 20
    volume_iops = 8000, volume_throughput = 250
  }

  ingress-1 = { role = "ingress", spot = false, instance_type = "m6i.large" }
  ingress-2 = { role = "ingress", spot = false, instance_type = "m6i.large" }

  # Density + containerd headline target (write-hot SQLite owner). Enables the
  # containerd warm TASK pool seeded with the bench image (alpine:3.20) so
  # container creates adopt a ready task instead of paying engine create+start —
  # best-case latency. The netns (network) pool is already on by default
  # (config/cluster.yml containerd.native_netns_pool_enabled: true).
  worker-c = {
    role = "worker", spot = false
    instance_type = "c5.metal", volume_size_gb = 80
    volume_iops = 8000, volume_throughput = 250
    extra_user_data = <<-EOT
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=false' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null || true
      echo 'SB_CONTAINERD_POOL_ENABLED=true' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null || true
      echo 'SB_CONTAINERD_POOL_IMAGES=alpine:3.20' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null || true
      sudo systemctl restart sandboxd || true
    EOT
  }

  worker-g = {
    role = "worker", spot = false
    instance_type = "c5.metal", volume_size_gb = 80
    with_gvisor = true
    extra_user_data = <<-EOT
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1 -o /tmp/runsc-shim
      curl -fsSL https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/containerd-shim-runsc-v1.sha512 -o /tmp/runsc-shim.sha512
      (cd /tmp && awk '{print $1"  runsc-shim"}' runsc-shim.sha512 > runsc-shim.check && sha512sum -c runsc-shim.check)
      sudo install -m 0755 /tmp/runsc-shim /usr/local/bin/containerd-shim-runsc-v1
      sudo systemctl restart sandboxd || true
    EOT
  }

  worker-w = {
    role = "worker", spot = false
    instance_type = "c5.metal", volume_size_gb = 80
    extra_user_data = <<-EOT
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }

  worker-i = {
    role = "worker", spot = false
    instance_type = "c5.metal", volume_size_gb = 80
    with_isolate = true
    extra_user_data = <<-EOT
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }

  worker-f = {
    role = "worker", spot = false
    instance_type = "c5.metal", volume_size_gb = 80
    with_firecracker = true
  }
}
