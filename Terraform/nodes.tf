###############################################################################
# Seed first, joiners second.
#
# Seed and joiners are separate resources so the joiners can depend_on the
# seed (the joiner user_data references seed_private_ip and waits on S3
# objects the seed creates). Splitting also makes the dependency graph
# obvious in `terraform plan`.
###############################################################################

locals {
  seed_node    = local.nodes_resolved[local.seed_name]
  joiner_nodes = { for n, v in local.nodes_resolved : n => v if n != local.seed_name }
}

resource "aws_instance" "seed" {
  ami                         = local.seed_node.ami_id
  instance_type               = local.seed_node.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.node.id]
  key_name                    = local.effective_key_name
  iam_instance_profile        = aws_iam_instance_profile.seed.name
  associate_public_ip_address = true

  root_block_device {
    volume_size           = local.seed_node.volume_size_gb
    volume_type           = local.seed_node.volume_type
    iops                  = contains(["gp3", "io1", "io2"], local.seed_node.volume_type) ? local.seed_node.volume_iops : null
    throughput            = local.seed_node.volume_type == "gp3" ? local.seed_node.volume_throughput : null
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_name               = local.seed_node.name
    role                    = local.seed_node.role
    is_seed                 = true
    domain                  = var.domain_name
    pat_token               = var.pat_token
    cloudflare_api_token    = var.cloudflare_api_token
    with_gvisor             = local.seed_node.with_gvisor
    with_nvidia_gpu         = local.seed_node.with_nvidia_gpu
    with_amd_gpu            = local.seed_node.with_amd_gpu
    idle_timeout_min        = local.seed_node.idle_timeout_min
    bundle_bucket           = aws_s3_bucket.bundle.bucket
    aws_region              = var.aws_region
    seed_private_ip         = ""
    install_script_url      = var.install_script_url
    cluster_init_script_url = var.cluster_init_script_url
    cluster_join_script_url = var.cluster_join_script_url
    seed_wait_max_seconds   = var.seed_wait_max_seconds
    extra_user_data         = local.seed_node.extra_user_data
  })

  tags = merge(
    {
      Name    = "${var.cluster_name}-${local.seed_node.name}"
      Role    = local.seed_node.role
      Seed    = "true"
      Cluster = var.cluster_name
    },
    local.seed_node.tags,
  )

  lifecycle {
    ignore_changes = [ami] # don't recycle a running cluster member on AMI refresh
  }
}

resource "aws_instance" "joiner" {
  for_each = local.joiner_nodes

  ami                         = each.value.ami_id
  instance_type               = each.value.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.node.id]
  key_name                    = local.effective_key_name
  iam_instance_profile        = aws_iam_instance_profile.joiner.name
  associate_public_ip_address = true

  root_block_device {
    volume_size           = each.value.volume_size_gb
    volume_type           = each.value.volume_type
    iops                  = contains(["gp3", "io1", "io2"], each.value.volume_type) ? each.value.volume_iops : null
    throughput            = each.value.volume_type == "gp3" ? each.value.volume_throughput : null
    delete_on_termination = true
    encrypted             = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_name               = each.value.name
    role                    = each.value.role
    is_seed                 = false
    domain                  = var.domain_name
    pat_token               = var.pat_token
    cloudflare_api_token    = var.cloudflare_api_token
    with_gvisor             = each.value.with_gvisor
    with_nvidia_gpu         = each.value.with_nvidia_gpu
    with_amd_gpu            = each.value.with_amd_gpu
    idle_timeout_min        = each.value.idle_timeout_min
    bundle_bucket           = aws_s3_bucket.bundle.bucket
    aws_region              = var.aws_region
    seed_private_ip         = aws_instance.seed.private_ip
    install_script_url      = var.install_script_url
    cluster_init_script_url = var.cluster_init_script_url
    cluster_join_script_url = var.cluster_join_script_url
    seed_wait_max_seconds   = var.seed_wait_max_seconds
    extra_user_data         = each.value.extra_user_data
  })

  depends_on = [aws_instance.seed]

  tags = merge(
    {
      Name    = "${var.cluster_name}-${each.value.name}"
      Role    = each.value.role
      Seed    = "false"
      Cluster = var.cluster_name
    },
    each.value.tags,
  )

  lifecycle {
    ignore_changes = [ami]
  }
}

# Convenience: every node, keyed by name, for downstream resources (dns, outputs).
locals {
  all_instances = merge(
    { (local.seed_name) = aws_instance.seed },
    { for n, inst in aws_instance.joiner : n => inst },
  )
}
