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
# local.nodes_resolved, var.one_line_join, var.firecracker and
# var.extra_sandboxd_env.
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

  # mkfs.ext4, which the root helper runs. Single keeps its default,
  # /sbin/mkfs.ext4. On Ubuntu, Debian and Amazon Linux 2023 /sbin is a link
  # to /usr/sbin, and the helper follows no link in a folder
  # (internal/rootd checkRootBinaryFile), so split names /usr/sbin/mkfs.ext4:
  # a file on Amazon Linux, and on Ubuntu and Debian a link to mke2fs beside
  # it, which the helper takes (a program's last name may be a link).
  # A path the operator chose stays as it is; split_problems refuses one
  # under a folder that is a link.
  firecracker_mkfs_bin = (
    local.split_mode && var.firecracker.mkfs_bin == "/sbin/mkfs.ext4"
    ? "/usr/sbin/mkfs.ext4"
    : var.firecracker.mkfs_bin
  )

  # The jailer's user. Unset is uid and gid 1000 in single, as before. In
  # split the bootstrap writes no SB_JAILER_UID or SB_JAILER_GID, so the VMs
  # run as a user of their own, sandboxd-jailer, which install.sh
  # --with-firecracker makes. A value set in tfvars is kept.
  firecracker_jailer_uid = var.firecracker.jailer_uid != null ? var.firecracker.jailer_uid : (local.split_mode ? null : 1000)
  firecracker_jailer_gid = var.firecracker.jailer_gid != null ? var.firecracker.jailer_gid : (local.split_mode ? null : 1000)

  # The folders sandboxd's user owns in split: what `aerolvm-rootd
  # agent-folders` hands it at each start (internal/rootd
  # AgentFoldersFromEnv), with sandboxd's defaults, moved by any node's
  # sandboxd_env, plus the folder its unit makes for the egress gateway's
  # lookups. Root never writes in them, and nothing root runs or links may sit
  # in them: sandboxd's user can swap any name there for a link.
  split_envs = [for name, n in local.nodes_resolved : merge(var.extra_sandboxd_env, n.sandboxd_env)]
  split_agent_dirs = distinct(concat(
    ["/var/lib/sandboxd", "/run/sandboxd", "/run/aerolvm-procid", "/etc/sandboxd/tls", "/etc/sandboxd/cluster-ca"],
    flatten([for env in local.split_envs : compact(concat(
      [for k in ["SB_MOUNTS_ROOT", "SB_MOUNTS_CRED_DIR", "SB_CONTAINERD_RUN_DIR", "SB_RAFT_DATA_DIR", "SB_RAFT_WAL_DIR", "SB_CLUSTER_TLS_DIR", "SB_CLUSTER_CA_DIR"] :
      trimsuffix(lookup(env, k, ""), "/")],
      [lookup(env, "SB_DB_PATH", "") == "" ? "" : dirname(lookup(env, "SB_DB_PATH", ""))],
    ))]),
  ))
  # Files root runs or links into every VM's jail, on a Firecracker cluster:
  # the jailer and firecracker (the helper runs the jailer), the guest kernel,
  # mkfs.ext4 and, when set, ip (the helper runs both).
  split_root_files = local.any_firecracker ? compact([
    var.firecracker.jailer_path, var.firecracker.binary_path, local.firecracker_kernel_path,
    local.firecracker_mkfs_bin, var.firecracker.ip_binary,
  ]) : []
  # The top folders a merged /usr makes links into /usr. Terraform cannot see
  # the node, so it refuses these by name, as the helper's own path rule does
  # (internal/rootd CheckRootProgramPath); the helper also checks each file
  # on the node at start.
  split_merged_usr_links = ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"]
  # Folders sandboxd writes for the runtimes this cluster turns on. Its split
  # unit lets it write in /var/lib/sandboxd and /run/sandboxd for data
  # (install.sh split_sandboxd_unit), and nowhere else.
  split_runtime_dirs = concat(
    local.any_firecracker ? [var.firecracker.run_dir, var.firecracker.templates_dir] : [],
    local.wasm_cfg.enabled == "true" ? compact([local.wasm_cfg.modules_dir, local.wasm_cfg.cache_dir]) : [],
  )
  # Every path above, and the jailer's chroot base, must be clean and
  # absolute: no "..", ".", "//" or relative path, which would make the
  # folder checks above say nothing.
  split_checked_paths = concat(
    local.split_root_files, local.split_runtime_dirs,
    local.any_firecracker ? [var.firecracker.jailer_chroot_base] : [],
  )

  split_problems = local.split_mode ? compact([
    local.container_engine == "containerd" ? "" : "container_engine must be containerd: Docker's socket is as good as root, and nothing checks what is sent to it.",
    var.one_line_join ? "" : "one_line_join must be true: only that bootstrap passes install.sh --privilege-mode split.",
    local.containerd_cfg.native_netns_pool_enabled == "true" ? "" : "containerd.native_netns_pool_enabled must be true: the root helper makes every sandbox's network namespace for that pool.",
    alltrue([for p in local.split_checked_paths : !can(regex("^[^/]|//|(^|/)[.][.]?(/|$)", p))]) ? "" : "firecracker and wasm paths must be clean absolute paths, with no \"..\", \".\" or \"//\": the checks below compare them as written.",
    (!local.any_firecracker || var.firecracker.use_jailer) ? "" : "firecracker.use_jailer must be true: the root helper runs every VM through the jailer.",
    (!local.any_firecracker || var.firecracker.jailer_chroot_base == "/srv/jailer") ? "" : "firecracker.jailer_chroot_base must be /srv/jailer: install.sh --privilege-mode split lets sandboxd write there and in no other jailer folder.",
    alltrue([for f in local.split_root_files : !anytrue([for a in local.split_agent_dirs : startswith(f, "${a}/")])]) ? "" : "firecracker.kernel_path, binary_path, jailer_path, mkfs_bin and ip_binary must not be in a folder sandboxd owns (${join(", ", local.split_agent_dirs)}): root runs or links them, and sandboxd could swap them.",
    alltrue([for f in local.split_root_files : !anytrue([for l in local.split_merged_usr_links : startswith(f, "${l}/")])]) ? "" : "firecracker.kernel_path, binary_path, jailer_path, mkfs_bin and ip_binary must not be under ${join(", ", local.split_merged_usr_links)}: on Ubuntu, Debian and Amazon Linux 2023 those are links into /usr, and the root helper follows no link in a folder. Name each by the path `readlink -f` prints for it on a node.",
    alltrue([for d in local.split_runtime_dirs : anytrue([for a in ["/var/lib/sandboxd", "/run/sandboxd"] : d == a || startswith(d, "${a}/")])]) ? "" : "firecracker.run_dir, firecracker.templates_dir, wasm.modules_dir and wasm.cache_dir must be in /var/lib/sandboxd or /run/sandboxd: sandboxd writes them, and in split it may write nowhere else.",
  ]) : []
}
