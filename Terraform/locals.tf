locals {
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
