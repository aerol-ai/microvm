locals {
  # Operational env vars come from the shared SoT file that Ansible also
  # reads (../config/cluster.yml). Both tools render identical SB_* values
  # into /etc/sandboxd/cluster.env so day-0 (terraform apply) and day-2
  # (ansible-playbook configure-ops.yml) can't drift. Tool-specific concerns
  # — cluster topology, cloud creds — stay in terraform.tfvars.
  # config_dir resolves to the override when set, else the repo's ../config.
  # Centralised so both the cluster.yml and secrets.yml reads use one source.
  config_dir  = var.config_dir != "" ? var.config_dir : "${path.module}/../config"
  cluster_ops = yamldecode(file("${local.config_dir}/cluster.yml"))

  # Cluster SECRETS (shared SB_PAT_TOKEN + AOCR wrap key + cluster PAT) live
  # in the parallel SoT file ../config/secrets.yml. Gitignored; operators
  # bootstrap with `cp config/secrets.example.yml config/secrets.yml`.
  # sensitive() marks the whole decoded tree so values stay redacted in plan
  # / apply output and propagate through any references into resource args.
  cluster_secrets = sensitive(yamldecode(file("${local.config_dir}/secrets.yml")))

  # Shared cluster-identity values that both Terraform (day-0 cloud-init +
  # DNS records) and Ansible (day-2 rotation) read from the SoT. Lifted into
  # named locals so the rest of the .tf files don't sprinkle
  # local.cluster_ops.ingress.* / local.cluster_secrets.cluster.* everywhere.
  domain_name = local.cluster_ops.ingress.domain_name
  acme_email  = local.cluster_ops.ingress.acme_email
  # Custom domains require a public domain (the daemon refuses to boot with
  # SB_ENABLE_CUSTOM_DOMAINS=true and no SB_DOMAIN). AND with domain presence so
  # the no-domain local-mode scenario — which still inherits the shared config's
  # enable flag — emits false instead of a boot-breaking true.
  enable_custom_domains          = try(local.cluster_ops.ingress.enable_custom_domains, false) && local.domain_name != ""
  custom_domain_txt_prefix       = local.cluster_ops.ingress.custom_domain_txt_prefix
  custom_domain_txt_value_prefix = local.cluster_ops.ingress.custom_domain_txt_value_prefix
  pat_token                      = local.cluster_secrets.cluster.pat_token

  # Cloudflare provider credential. Lives in config/secrets.yml under
  # cloudflare.api_token (NOT in config/terraform.tfvars) so the rule
  # "non-secret config in cluster.yml / terraform.tfvars, secrets in
  # secrets.yml" holds uniformly. providers.tf reads this local; if the value
  # is empty the precondition below fails at plan time.
  cloudflare_api_token = local.cluster_secrets.cloudflare.api_token

  # Normalise each node entry with its effective values (per-node overrides
  # win, then var.default_*). Doing this once here keeps nodes.tf / dns.tf
  # readable.
  #
  # node_arch derives CPU architecture from an explicit nodes[*].arch field
  # or from the instance type (Graviton families use a 'g' size token).
  graviton_instance_re = "([a-z][0-9]+g|a1|t4g)\\."

  derived_node_arch = {
    for name, n in var.nodes : name => (
      can(regex(local.graviton_instance_re, coalesce(n.instance_type, var.default_instance_type))) ? "arm64" : "amd64"
    )
  }

  node_arch = {
    for name, n in var.nodes : name => coalesce(try(n.arch, null), local.derived_node_arch[name])
  }

  nodes_resolved = {
    for name, n in var.nodes : name => {
      name              = name
      role              = n.role
      seed              = n.seed
      instance_type     = coalesce(n.instance_type, var.default_instance_type)
      volume_size_gb    = coalesce(n.volume_size_gb, var.default_volume_size_gb)
      volume_type       = coalesce(n.volume_type, var.default_volume_type)
      volume_iops       = coalesce(n.volume_iops, var.default_volume_iops)
      volume_throughput = coalesce(n.volume_throughput, var.default_volume_throughput)
      arch              = local.node_arch[name]
      ami_id = coalesce(
        n.ami_id,
        local.node_arch[name] == "arm64" ? data.aws_ami.ubuntu_arm64.id : (
          var.ami_id != "" ? var.ami_id : data.aws_ami.ubuntu_amd64.id
        )
      )
      # bool defaults need explicit null handling — coalesce treats `false` as
      # a real value, but optional() without a default returns null.
      with_firecracker = n.with_firecracker == null ? var.default_with_firecracker : n.with_firecracker
      with_gvisor      = n.with_gvisor == null ? var.default_with_gvisor : n.with_gvisor
      with_nvidia_gpu  = n.with_nvidia_gpu == null ? var.default_with_nvidia_gpu : n.with_nvidia_gpu
      with_amd_gpu     = n.with_amd_gpu == null ? var.default_with_amd_gpu : n.with_amd_gpu
      idle_timeout_min = n.idle_timeout_min == null ? var.default_idle_timeout_min : n.idle_timeout_min
      extra_user_data  = n.extra_user_data
      tags             = n.tags
      spot             = n.spot
    }
  }

  seed_name = one([for name, n in var.nodes : name if n.seed])

  # Node names whose role set contains "ingress" (pure ingress, edge, or
  # server,ingress). "mixed" expands to server,worker,ingress so it counts too.
  ingress_node_names = sort([
    for name, n in local.nodes_resolved : name
    if contains(split(",", replace(n.role, " ", "")), "ingress") ||
    n.role == "mixed"
  ])

  has_public_ingress = length(local.ingress_node_names) > 0

  # SSH key resolution. Three modes:
  #   1. var.ssh_key_name set        → use existing keypair, don't create one
  #   2. var.ssh_public_key set      → upload that material
  #   3. var.ssh_public_key_path set → upload contents of that file
  # The file() call is gated so terraform doesn't fail when mode 1 is used
  # and the default ssh_public_key_path doesn't exist on this machine.
  manage_keypair = var.ssh_key_name == ""

  ssh_public_key_material = (
    !local.manage_keypair ? "" :
    var.ssh_public_key != "" ? var.ssh_public_key :
    file(pathexpand(var.ssh_public_key_path))
  )

  effective_key_name = (
    local.manage_keypair ? aws_key_pair.this[0].key_name : var.ssh_key_name
  )

  # Stable bucket name (lowercase, region-scoped, 6-char suffix).
  bundle_bucket_name = format(
    "%s-bundle-%s",
    substr(lower(replace(var.cluster_name, "/[^a-z0-9-]/", "-")), 0, 40),
    random_id.bundle_suffix.hex,
  )

  # Caddy shared cert storage — resolved config that bootstrap.sh.tftpl
  # consumes regardless of mode. In managed mode, fields point at TF-created
  # resources; in byo mode, fields come straight from the user's tfvars. The
  # template never needs to branch on mode this way.
  caddy_storage_s3_enabled = var.caddy_shared_cert_storage.enabled
  caddy_storage_s3_managed = (
    var.caddy_shared_cert_storage.enabled
    && var.caddy_shared_cert_storage.mode == "managed"
  )
  caddy_certs_bucket_name = format(
    "%s-caddy-certs-%s",
    substr(lower(replace(var.cluster_name, "/[^a-z0-9-]/", "-")), 0, 40),
    random_id.bundle_suffix.hex,
  )
  caddy_storage_s3 = {
    enabled  = var.caddy_shared_cert_storage.enabled
    bucket   = local.caddy_storage_s3_managed ? local.caddy_certs_bucket_name : var.caddy_shared_cert_storage.bucket
    region   = local.caddy_storage_s3_managed ? var.aws_region : var.caddy_shared_cert_storage.region
    endpoint = var.caddy_shared_cert_storage.endpoint
    prefix   = var.caddy_shared_cert_storage.prefix
    # In managed mode the EC2 instance role grants the bucket, so we leave
    # static creds empty (the AWS SDK default chain picks up the role).
    # BYO mode passes whatever the operator supplied.
    access_key = local.caddy_storage_s3_managed ? "" : var.caddy_shared_cert_storage.access_key
    secret_key = local.caddy_storage_s3_managed ? "" : var.caddy_shared_cert_storage.secret_key
    encryption_key = (
      local.caddy_storage_s3_managed
      ? (length(random_id.caddy_storage_s3_encryption_key) > 0 ? random_id.caddy_storage_s3_encryption_key[0].b64_std : "")
      : var.caddy_shared_cert_storage.encryption_key
    )
  }

  # Platform volumes are operator-backed named volumes. The integration overlay
  # enables them without naming a bucket; in that case use this scenario's
  # force-destroyed bundle bucket under a separate prefix so live volume bytes
  # disappear with the test infrastructure.
  platform_volumes_cfg = {
    enabled             = try(local.cluster_ops.platform_volumes.enabled, false) ? "true" : "false"
    backend             = try(local.cluster_ops.platform_volumes.backend, "s3")
    max_per_tenant      = try(local.cluster_ops.platform_volumes.max_per_tenant, 0)
    reclaim_interval    = try(local.cluster_ops.platform_volumes.reclaim_interval, "5m")
    reclaim_mount_root  = try(local.cluster_ops.platform_volumes.reclaim_mount_root, "/var/lib/aerolvm/volume-reclaim")
    reclaim_concurrency = try(local.cluster_ops.platform_volumes.reclaim_concurrency, 8)
    s3_bucket = (
      try(local.cluster_ops.platform_volumes.s3_bucket, "") != ""
      ? local.cluster_ops.platform_volumes.s3_bucket
      : aws_s3_bucket.bundle.bucket
    )
    s3_prefix            = try(local.cluster_ops.platform_volumes.s3_prefix, "volumes")
    s3_region            = try(local.cluster_ops.platform_volumes.s3_region, "") != "" ? local.cluster_ops.platform_volumes.s3_region : var.aws_region
    s3_endpoint          = try(local.cluster_ops.platform_volumes.s3_endpoint, "")
    s3_access_key_id     = try(local.cluster_ops.platform_volumes.s3_access_key_id, "")
    s3_secret_access_key = try(local.cluster_ops.platform_volumes.s3_secret_access_key, "")
    nfs_server           = try(local.cluster_ops.platform_volumes.nfs_server, "")
    nfs_export           = try(local.cluster_ops.platform_volumes.nfs_export, "")
    nfs_options          = try(local.cluster_ops.platform_volumes.nfs_options, "")
  }

  # AOCR (Phase 4 F17-F21) — resolved view for bootstrap.sh.tftpl. Non-secret
  # config (mirror host, upstreams, auto-import toggle, cluster_id, ...)
  # comes from the shared SoT in config/cluster.yml; secrets (wrap key,
  # cluster PAT) come from the parallel SoT config/secrets.yml. Terraform
  # delivers both via cloud-init. enabled is derived: any non-empty mirror
  # host OR auto-import on is enough to activate the AOCR template section.
  aocr_enabled = (
    local.cluster_ops.mirror.host != ""
    || local.cluster_ops.auto_import.enabled
  )
  aocr = {
    enabled             = local.aocr_enabled
    mirror_host         = local.aocr_enabled ? local.cluster_ops.mirror.host : ""
    mirror_push_host    = local.aocr_enabled ? local.cluster_ops.mirror.push_host : ""
    mirror_upstreams    = local.aocr_enabled ? local.cluster_ops.mirror.upstreams : ""
    upstream_wrap_key   = local.aocr_enabled ? local.cluster_secrets.aocr.upstream_wrap_key : ""
    auto_import_enabled = local.aocr_enabled && local.cluster_ops.auto_import.enabled
    hooks_url           = local.aocr_enabled ? local.cluster_ops.auto_import.hooks_url : ""
    cluster_id          = local.aocr_enabled ? local.cluster_ops.auto_import.cluster_id : ""
    cluster_pat         = local.aocr_enabled ? local.cluster_secrets.aocr.cluster_pat : ""
    retention_suffix    = local.aocr_enabled ? local.cluster_ops.auto_import.retention_suffix : "--idle-90d"
    request_timeout     = local.aocr_enabled ? local.cluster_ops.auto_import.request_timeout : "15s"
    reconcile_interval  = local.aocr_enabled ? local.cluster_ops.auto_import.reconcile_interval : "5m"
    max_in_flight       = local.aocr_enabled ? local.cluster_ops.auto_import.max_in_flight : 4

    # Snapshot distribution (push sandbox snapshots + firecracker templates to
    # AOCR). Gated on aocr being enabled AND a push_host being set — without a
    # write vhost there is nowhere to push, so the daemon would refuse to boot
    # with the feature on. try() keeps older config/cluster.yml files (no
    # mirror.snapshot_push_* keys) valid by defaulting the feature off.
    snapshot_push_enabled = (
      local.aocr_enabled
      && local.cluster_ops.mirror.push_host != ""
      && try(local.cluster_ops.mirror.snapshot_push_enabled, false)
    )
    snapshot_push_reconcile_interval = try(local.cluster_ops.mirror.snapshot_push_reconcile_interval, "5m")
    snapshot_push_max_in_flight      = try(local.cluster_ops.mirror.snapshot_push_max_in_flight, 2)
    snapshot_push_tag_suffix         = try(local.cluster_ops.mirror.snapshot_push_tag_suffix, "")
  }

  # Fleet control plane (optional managed integration) — resolved view for
  # bootstrap.sh.tftpl. Non-secret config (enable toggle, endpoint, contract
  # refresh) comes from config/cluster.yml; the fleet token is a secret that
  # lives under a SEPARATE top-level key in config/secrets.yml (fleet.token)
  # so loading it never clobbers the cluster.yml fleet_control_plane block.
  # Everything else the integration needs is fetched from the managed contract
  # API at runtime, so nothing else is templated here.
  fleet_enabled = local.cluster_ops.fleet_control_plane.enabled
  fleet = {
    enabled          = local.fleet_enabled
    endpoint         = local.fleet_enabled ? local.cluster_ops.fleet_control_plane.endpoint : ""
    token            = local.fleet_enabled ? local.cluster_secrets.fleet.token : ""
    contract_refresh = local.fleet_enabled ? local.cluster_ops.fleet_control_plane.contract_refresh : "5m"
  }

  # WASM runtime + module distribution. standard_modules is flattened into the
  # SB_WASM_STANDARD_MODULES "alias=alias.wasm,..." reserved-keyword contract so
  # Terraform and Ansible render identical env on every node. try() keeps older
  # cluster.yml files (no wasm: block) working.
  wasm_cfg = {
    enabled            = try(local.cluster_ops.wasm.enabled, false) ? "true" : "false"
    modules_dir        = try(local.cluster_ops.wasm.modules_dir, "/var/lib/sandboxd/wasm/modules")
    cache_dir          = try(local.cluster_ops.wasm.cache_dir, "")
    pool_enabled       = try(local.cluster_ops.wasm.pool.enabled, true) ? "true" : "false"
    pool_depth_default = tostring(try(local.cluster_ops.wasm.pool.depth_default, 2))
    registry_allowlist = try(local.cluster_ops.wasm.registry_allowlist, "")
    pull_timeout       = try(local.cluster_ops.wasm.pull_timeout, "60s")
    push_host          = try(local.cluster_ops.wasm.push_host, "")
    registry_username  = try(local.cluster_ops.wasm.registry_username, "")
    registry_pat_path  = try(local.cluster_ops.wasm.registry_pat_path, "")
    standard_modules   = join(",", [for m in try(local.cluster_ops.wasm.standard_modules, []) : "${m.alias}=${m.alias}.wasm"])
  }

  # Docker warm container pool (park + adopt). Mirrors wasm_cfg: values come
  # from config/cluster.yml's docker.pool block, try() keeps older cluster.yml
  # files (no docker: block) working with the same defaults config.go uses.
  docker_pool_cfg = {
    enabled         = try(local.cluster_ops.docker.pool.enabled, false) ? "true" : "false"
    depth           = tostring(try(local.cluster_ops.docker.pool.depth, 2))
    images          = join(",", try(local.cluster_ops.docker.pool.images, []))
    max_images      = tostring(try(local.cluster_ops.docker.pool.max_images, 8))
    idle_ttl        = try(local.cluster_ops.docker.pool.idle_ttl, "15m")
    refill_interval = try(local.cluster_ops.docker.pool.refill_interval, "5s")
  }

  # Homogeneous per-arch clusters (D5): one GOARCH for snapshot tagging and
  # Firecracker upstream artifact selection. The precondition on
  # validate_cluster_ops enforces a single distinct arch across nodes.
  cluster_arch_values = distinct([for _, arch in local.node_arch : arch])
  cluster_arch        = length(local.cluster_arch_values) == 1 ? local.cluster_arch_values[0] : "mixed"

  firecracker_upstream_arch = local.cluster_arch == "arm64" ? "aarch64" : "x86_64"
}

# Plan-time validation of values that come from local.cluster_ops. Terraform
# does not allow `validation {}` blocks on locals directly, so we hang the
# preconditions off a free terraform_data resource (no apply-time side
# effects). All four mirror what var.aocr's validation blocks did before
# config/cluster.yml became the source of those fields.
resource "terraform_data" "validate_cluster_ops" {
  lifecycle {
    precondition {
      condition     = length(distinct([for name, arch in local.node_arch : arch])) == 1
      error_message = "All nodes in a cluster must share one CPU architecture; mixed x86/arm64 clusters are unsupported (see plans/arm64-firecracker-hosts.md)."
    }

    precondition {
      condition = alltrue([
        for name, n in var.nodes :
        try(n.arch, null) == null || local.node_arch[name] == local.derived_node_arch[name]
      ])
      error_message = "nodes[*].arch must match the node's instance_type-derived CPU architecture; do not pair Graviton instances with arch=\"amd64\" or x86 instances with arch=\"arm64\"."
    }

    precondition {
      condition = (
        !local.cluster_ops.auto_import.enabled
        || (
          local.cluster_ops.auto_import.hooks_url != ""
          && local.cluster_ops.auto_import.cluster_id != ""
          && local.cluster_secrets.aocr.cluster_pat != ""
        )
      )
      error_message = "When auto_import.enabled = true in config/cluster.yml, auto_import.hooks_url, auto_import.cluster_id, and aocr.cluster_pat in config/secrets.yml are all required (sandboxd refuses to boot otherwise)."
    }

    precondition {
      condition = (
        local.cluster_ops.auto_import.cluster_id == ""
        || can(regex("^[A-Za-z0-9_-]{1,64}$", local.cluster_ops.auto_import.cluster_id))
      )
      error_message = "auto_import.cluster_id must match ^[A-Za-z0-9_-]{1,64}$ (matches AOCR ImportAPI validation)."
    }

    # Snapshot push needs a write vhost (mirror.push_host) plus the cluster
    # identity it reuses for auth (cluster_id + the cluster PAT secret).
    # sandboxd refuses to boot with SB_SNAPSHOT_PUSH_ENABLED=true and these
    # unset, so fail at plan time rather than after cloud-init.
    precondition {
      condition = (
        !try(local.cluster_ops.mirror.snapshot_push_enabled, false)
        || (
          local.cluster_ops.mirror.push_host != ""
          && local.cluster_ops.auto_import.cluster_id != ""
          && local.cluster_secrets.aocr.cluster_pat != ""
        )
      )
      error_message = "When mirror.snapshot_push_enabled = true in config/cluster.yml, mirror.push_host, auto_import.cluster_id, and aocr.cluster_pat in config/secrets.yml are all required (sandboxd refuses to boot otherwise)."
    }

    precondition {
      condition = (
        local.cluster_ops.auto_import.retention_suffix == ""
        || can(regex("^--[a-z0-9]+(-[a-z0-9]+)*$", local.cluster_ops.auto_import.retention_suffix))
      )
      error_message = "auto_import.retention_suffix must start with '--' followed by lowercase alphanumerics, e.g. '--idle-90d'."
    }

    precondition {
      condition = (
        can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.otel.metrics_interval))
        && can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.image_pull.failure_backoff))
        && can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.image_build_gc.interval))
        && can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.image_build_gc.ttl))
        && can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.auto_import.request_timeout))
        && can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.auto_import.reconcile_interval))
      )
      error_message = "Duration fields in config/cluster.yml must be Go durations such as 30s, 10m, 1h."
    }

    precondition {
      condition = (
        local.cluster_ops.otel.traces_sample_ratio >= 0
        && local.cluster_ops.otel.traces_sample_ratio <= 1
      )
      error_message = "otel.traces_sample_ratio must be between 0 and 1."
    }

    precondition {
      condition     = local.cluster_ops.image_pull.max_concurrent >= 0
      error_message = "image_pull.max_concurrent must be >= 0."
    }

    precondition {
      condition     = local.cluster_ops.auto_import.max_in_flight >= 1
      error_message = "auto_import.max_in_flight must be >= 1."
    }

    precondition {
      condition     = local.pat_token != ""
      error_message = "cluster.pat_token in config/secrets.yml must be set (shared SB_PAT_TOKEN used by every node for operator/SDK API auth)."
    }

    precondition {
      condition     = local.cloudflare_api_token != ""
      error_message = "cloudflare.api_token in config/secrets.yml must be set (Cloudflare token with Zone:DNS:Edit on the target zone; reused for Let's Encrypt DNS-01)."
    }

    precondition {
      condition = (
        !local.cluster_ops.fleet_control_plane.enabled
        || (
          local.cluster_ops.fleet_control_plane.endpoint != ""
          && local.cluster_secrets.fleet.token != ""
        )
      )
      error_message = "When fleet_control_plane.enabled = true in config/cluster.yml, fleet_control_plane.endpoint and fleet.token in config/secrets.yml are both required (sandboxd refuses to boot otherwise)."
    }

    precondition {
      condition = (
        !local.cluster_ops.fleet_control_plane.enabled
        || can(regex("^https?://", local.cluster_ops.fleet_control_plane.endpoint))
      )
      error_message = "fleet_control_plane.endpoint must be an absolute http(s) URL."
    }

    precondition {
      condition     = can(regex("^[0-9]+(ns|us|ms|s|m|h)$", local.cluster_ops.fleet_control_plane.contract_refresh))
      error_message = "fleet_control_plane.contract_refresh must be a Go duration such as 30s, 5m, 1h."
    }
  }
}

# certmagic-s3 encrypts cert+private-key bytes with this 32-byte key before
# uploading. Every node MUST present the same value or readers can't decrypt
# what the issuing node wrote. Managed mode auto-generates and threads it via
# user_data; BYO mode uses var.caddy_shared_cert_storage.encryption_key
# directly (and this resource is suppressed).
#
# random_id with byte_length = 32 gives us a true 32-byte secret; b64_std
# emits the same base64 format an operator would produce by hand with
# `openssl rand -base64 32`.
resource "random_id" "caddy_storage_s3_encryption_key" {
  count = local.caddy_storage_s3_managed && var.caddy_shared_cert_storage.encryption_key == "" ? 1 : 0

  byte_length = 32
}
