# Privilege mode split on VMs (config/cluster.yml privilege_mode,
# plans/security-gaps-m1-m4.md M1 PR 10).
#
# The root helper now runs every runtime a VM node can have: V8 isolates and
# Firecracker (#1423), Firecracker snapshots, its warm VM pool and disk images
# (#1426, #1432), the containerd warm pool and gVisor moves (#1428), and WASM
# with its warm pool and checkpoints (#1430). install.sh --privilege-mode split
# takes --with-isolate and --with-firecracker (#1431). So split takes them all
# here too. What is left is a short list of settings split cannot run with:
# split_problems names each one that is set, and validate_cluster_ops
# (locals.tf) fails the plan with that list, before any node is touched.
#
# These locals live in a file of their own so a test can load it, unchanged,
# into a fixture module (integration-tests/safety/terraform_privilege_mode_test.go).
# It reads only local.containerd_cfg, local.container_engine, local.wasm_cfg,
# local.nodes_resolved, var.one_line_join and var.firecracker.
locals {
  split_mode      = local.containerd_cfg.privilege_mode == "split"
  any_firecracker = anytrue([for name, n in local.nodes_resolved : n.with_firecracker])

  # The guest kernel. The root helper links it into every VM's jail and
  # refuses a kernel in a folder sandboxd's user writes, which in split owns
  # /var/lib/sandboxd. So split moves the single default to where
  # install.sh --privilege-mode split puts it, a folder only root writes. A
  # path the operator chose stays as it is; split_problems refuses one in
  # sandboxd's folders.
  firecracker_kernel_path = (
    local.split_mode && var.firecracker.kernel_path == "/var/lib/sandboxd/firecracker/vmlinux"
    ? "/usr/local/lib/aerolvm-firecracker/vmlinux"
    : var.firecracker.kernel_path
  )

  # The jailer's user. Unset is uid and gid 1000 in single, as before. In
  # split the bootstrap writes no SB_JAILER_UID or SB_JAILER_GID, so the
  # sandboxd-jailer user that install.sh --with-firecracker makes runs the
  # VMs: it owns nothing and cannot log in. Uid 1000 is the `ubuntu` login
  # user on Ubuntu images, which has sudo. A value set in tfvars is kept.
  firecracker_jailer_uid = var.firecracker.jailer_uid != null ? var.firecracker.jailer_uid : (local.split_mode ? null : 1000)
  firecracker_jailer_gid = var.firecracker.jailer_gid != null ? var.firecracker.jailer_gid : (local.split_mode ? null : 1000)

  # sandboxd's own folders in split: the only ones its unit lets it write
  # (install.sh split_sandboxd_unit: ReadWritePaths=/var/lib/sandboxd, and
  # RuntimeDirectory /run/sandboxd), besides the jailer's /srv/jailer.
  split_agent_dirs = ["/var/lib/sandboxd", "/run/sandboxd"]
  # The folders sandboxd writes for the runtimes this cluster turns on.
  split_runtime_dirs = concat(
    local.any_firecracker ? [var.firecracker.run_dir, var.firecracker.templates_dir] : [],
    local.wasm_cfg.enabled == "true" ? compact([local.wasm_cfg.modules_dir, local.wasm_cfg.cache_dir]) : [],
  )

  split_problems = local.split_mode ? compact([
    local.container_engine == "containerd" ? "" : "container_engine must be containerd: Docker's socket is as good as root, and nothing checks what is sent to it.",
    var.one_line_join ? "" : "one_line_join must be true: only that bootstrap passes install.sh --privilege-mode split.",
    local.containerd_cfg.native_netns_pool_enabled == "true" ? "" : "containerd.native_netns_pool_enabled must be true: the root helper makes every sandbox's network namespace for that pool.",
    (!local.any_firecracker || var.firecracker.use_jailer) ? "" : "firecracker.use_jailer must be true: the root helper runs every VM through the jailer.",
    (!local.any_firecracker || var.firecracker.jailer_chroot_base == "/srv/jailer") ? "" : "firecracker.jailer_chroot_base must be /srv/jailer: install.sh --privilege-mode split lets sandboxd write there and in no other jailer folder.",
    (!local.any_firecracker || !anytrue([for a in local.split_agent_dirs : startswith(local.firecracker_kernel_path, "${a}/")])) ? "" : "firecracker.kernel_path must not be in /var/lib/sandboxd or /run/sandboxd: the root helper refuses a kernel in a folder sandboxd writes.",
    alltrue([for d in local.split_runtime_dirs : anytrue([for a in local.split_agent_dirs : d == a || startswith(d, "${a}/")])]) ? "" : "firecracker.run_dir, firecracker.templates_dir, wasm.modules_dir and wasm.cache_dir must be in /var/lib/sandboxd or /run/sandboxd: sandboxd writes them, and in split it may write nowhere else.",
  ]) : []
}
