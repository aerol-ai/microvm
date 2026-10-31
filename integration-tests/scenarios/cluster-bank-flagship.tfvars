# Bank-readiness flagship: the heterogeneous production shape within a
# 16-server / 2-bare-metal budget. 3 Raft servers and 2 ingress nodes on
# steady (non-burstable) instances, two bare-metal workers that each run
# Firecracker, gVisor and runc (so Firecracker has a failover peer), and one
# worker each for the containerd warm pool, WASM and V8 isolates, plus the
# observability node. 11 servers; with m5zn.metal workers it fits 116 vCPUs.
# Switch to c5.metal through .tf/cluster-bank-flagship/override.tfvars when
# the vCPU quota allows.
cluster_name = "aerolvm-itest-cluster-bank-flagship"
extra_tags = {
  itest = "true"
  ttl   = "12"
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
  server-1  = { role = "server", seed = true, spot = false, instance_type = "m6i.large", volume_size_gb = 30 }
  server-2  = { role = "server", spot = false, instance_type = "m6i.large", volume_size_gb = 30 }
  server-3  = { role = "server", spot = false, instance_type = "m6i.large", volume_size_gb = 30 }
  ingress-1 = { role = "ingress", spot = false, instance_type = "m6i.large" }
  ingress-2 = { role = "ingress", spot = false, instance_type = "m6i.large" }
  worker-m1 = {
    role = "worker", spot = false
    instance_type = "m5zn.metal", volume_size_gb = 200
    volume_iops = 8000, volume_throughput = 500
    with_firecracker = true, with_gvisor = true
  }
  worker-m2 = {
    role = "worker", spot = false
    instance_type = "m5zn.metal", volume_size_gb = 200
    volume_iops = 8000, volume_throughput = 500
    with_firecracker = true, with_gvisor = true
  }
  worker-c = {
    role = "worker", spot = false
    instance_type = "m6i.xlarge", volume_size_gb = 80
    extra_user_data = <<-EOT
      echo 'SB_CONTAINERD_POOL_ENABLED=true' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null || true
      echo 'SB_CONTAINERD_POOL_IMAGES=alpine:3.20' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null || true
      echo 'SB_CONTAINERD_POOL_DEPTH=8' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null || true
      sudo systemctl restart sandboxd || true
    EOT
  }
  worker-w = {
    role = "worker", spot = false
    instance_type = "m6i.large"
    extra_user_data = <<-EOT
      echo 'SB_WASM_RESIDENT_HOST_ENABLED=true' | sudo tee -a /etc/sandboxd/cluster.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
  worker-i = {
    role = "worker", spot = false
    instance_type = "m6i.large"
    with_isolate = true
    extra_user_data = <<-EOT
      echo 'SB_ISOLATE_USE_JAIL=false' | sudo tee -a /etc/sandboxd/sandboxd.env >/dev/null
      sudo systemctl restart sandboxd
    EOT
  }
}
