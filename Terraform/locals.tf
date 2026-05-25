locals {
  # Operational env vars come from the shared SoT file that Ansible also
  # reads (../config/cluster.yml). Both tools render identical SB_* values
  # into /etc/sandboxd/cluster.env so day-0 (terraform apply) and day-2
  # (ansible-playbook configure-ops.yml) can't drift. Tool-specific concerns
  # — cluster topology, cloud creds — stay in terraform.tfvars.
  cluster_ops = yamldecode(file("${path.module}/../config/cluster.yml"))

  # Cluster SECRETS (shared SB_PAT_TOKEN + AOCR wrap key + cluster PAT) live
  # in the parallel SoT file ../config/secrets.yml. Gitignored; operators
  # bootstrap with `cp config/secrets.example.yml config/secrets.yml`.
  # sensitive() marks the whole decoded tree so values stay redacted in plan
  # / apply output and propagate through any references into resource args.
  cluster_secrets = sensitive(yamldecode(file("${path.module}/../config/secrets.yml")))

  # Shared cluster-identity values that both Terraform (day-0 cloud-init +
  # DNS records) and Ansible (day-2 rotation) read from the SoT. Lifted into
  # named locals so the rest of the .tf files don't sprinkle
  # local.cluster_ops.ingress.* / local.cluster_secrets.cluster.* everywhere.
  domain_name = local.cluster_ops.ingress.domain_name
  acme_email  = local.cluster_ops.ingress.acme_email
  pat_token   = local.cluster_secrets.cluster.pat_token

  # Normalise each node entry with its effective values (per-node overrides
  # win, then var.default_*). Doing this once here keeps nodes.tf / dns.tf
  # readable.
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
      ami_id            = coalesce(n.ami_id, var.ami_id, data.aws_ami.ubuntu.id)
      # bool defaults need explicit null handling — coalesce treats `false` as
      # a real value, but optional() without a default returns null.
      with_gvisor      = n.with_gvisor == null ? var.default_with_gvisor : n.with_gvisor
      with_nvidia_gpu  = n.with_nvidia_gpu == null ? var.default_with_nvidia_gpu : n.with_nvidia_gpu
      with_amd_gpu     = n.with_amd_gpu == null ? var.default_with_amd_gpu : n.with_amd_gpu
      idle_timeout_min = n.idle_timeout_min == null ? var.default_idle_timeout_min : n.idle_timeout_min
      extra_user_data  = n.extra_user_data
      tags             = n.tags
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
  }
}

# Plan-time validation of values that come from local.cluster_ops. Terraform
# does not allow `validation {}` blocks on locals directly, so we hang the
# preconditions off a free terraform_data resource (no apply-time side
# effects). All four mirror what var.aocr's validation blocks did before
# config/cluster.yml became the source of those fields.
resource "terraform_data" "validate_cluster_ops" {
  lifecycle {
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
