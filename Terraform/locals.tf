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
      extra_user_data   = n.extra_user_data
      tags              = n.tags
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
}
