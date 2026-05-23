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

  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_name                  = "${var.cluster_name}-${local.seed_node.name}"
    role                       = local.seed_node.role
    is_seed                    = true
    domain                     = var.domain_name
    pat_token                  = var.pat_token
    cloudflare_api_token       = var.cloudflare_api_token
    acme_email                 = var.acme_email
    with_gvisor                = local.seed_node.with_gvisor
    with_nvidia_gpu            = local.seed_node.with_nvidia_gpu
    with_amd_gpu               = local.seed_node.with_amd_gpu
    idle_timeout_min           = local.seed_node.idle_timeout_min
    bundle_bucket              = aws_s3_bucket.bundle.bucket
    aws_region                 = var.aws_region
    seed_private_ip            = ""
    install_script_url         = var.install_script_url
    cluster_init_script_url    = var.cluster_init_script_url
    cluster_join_script_url    = var.cluster_join_script_url
    seed_wait_max_seconds      = var.seed_wait_max_seconds
    otel_metrics_enabled       = var.otel_metrics_enabled || var.otel_metrics_endpoint != ""
    otel_metrics_endpoint      = var.otel_metrics_endpoint
    otel_metrics_interval      = var.otel_metrics_interval
    otel_traces_enabled        = var.otel_traces_enabled || var.otel_traces_endpoint != ""
    otel_traces_endpoint       = var.otel_traces_endpoint
    otel_traces_sample_ratio   = var.otel_traces_sample_ratio
    otel_service_name          = var.otel_service_name
    image_pull_max_concurrent  = var.image_pull_max_concurrent
    image_pull_failure_backoff = var.image_pull_failure_backoff
    extra_user_data            = local.seed_node.extra_user_data
    # Shared S3-backed Caddy cert storage — see local.caddy_storage_s3.
    caddy_storage_s3_enabled        = local.caddy_storage_s3.enabled
    caddy_storage_s3_bucket         = local.caddy_storage_s3.bucket
    caddy_storage_s3_region         = local.caddy_storage_s3.region
    caddy_storage_s3_endpoint       = local.caddy_storage_s3.endpoint
    caddy_storage_s3_prefix         = local.caddy_storage_s3.prefix
    caddy_storage_s3_access_key     = local.caddy_storage_s3.access_key
    caddy_storage_s3_secret_key     = local.caddy_storage_s3.secret_key
    caddy_storage_s3_encryption_key = local.caddy_storage_s3.encryption_key
    # AOCR mirror + auto-import (Phase 4 F17-F21) — see local.aocr.
    aocr_enabled             = local.aocr.enabled
    aocr_mirror_host         = local.aocr.mirror_host
    aocr_mirror_push_host    = local.aocr.mirror_push_host
    aocr_mirror_upstreams    = local.aocr.mirror_upstreams
    aocr_upstream_wrap_key   = local.aocr.upstream_wrap_key
    aocr_auto_import_enabled = local.aocr.auto_import_enabled
    aocr_hooks_url           = local.aocr.hooks_url
    aocr_cluster_id          = local.aocr.cluster_id
    aocr_cluster_pat         = local.aocr.cluster_pat
    aocr_retention_suffix    = local.aocr.retention_suffix
    aocr_request_timeout     = local.aocr.request_timeout
    aocr_reconcile_interval  = local.aocr.reconcile_interval
    aocr_max_in_flight       = local.aocr.max_in_flight
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

  user_data_replace_on_change = true

  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_name                  = "${var.cluster_name}-${each.value.name}"
    role                       = each.value.role
    is_seed                    = false
    domain                     = var.domain_name
    pat_token                  = var.pat_token
    cloudflare_api_token       = var.cloudflare_api_token
    acme_email                 = var.acme_email
    with_gvisor                = each.value.with_gvisor
    with_nvidia_gpu            = each.value.with_nvidia_gpu
    with_amd_gpu               = each.value.with_amd_gpu
    idle_timeout_min           = each.value.idle_timeout_min
    bundle_bucket              = aws_s3_bucket.bundle.bucket
    aws_region                 = var.aws_region
    seed_private_ip            = aws_instance.seed.private_ip
    install_script_url         = var.install_script_url
    cluster_init_script_url    = var.cluster_init_script_url
    cluster_join_script_url    = var.cluster_join_script_url
    seed_wait_max_seconds      = var.seed_wait_max_seconds
    otel_metrics_enabled       = var.otel_metrics_enabled || var.otel_metrics_endpoint != ""
    otel_metrics_endpoint      = var.otel_metrics_endpoint
    otel_metrics_interval      = var.otel_metrics_interval
    otel_traces_enabled        = var.otel_traces_enabled || var.otel_traces_endpoint != ""
    otel_traces_endpoint       = var.otel_traces_endpoint
    otel_traces_sample_ratio   = var.otel_traces_sample_ratio
    otel_service_name          = var.otel_service_name
    image_pull_max_concurrent  = var.image_pull_max_concurrent
    image_pull_failure_backoff = var.image_pull_failure_backoff
    extra_user_data            = each.value.extra_user_data
    # Shared S3-backed Caddy cert storage — see local.caddy_storage_s3.
    caddy_storage_s3_enabled        = local.caddy_storage_s3.enabled
    caddy_storage_s3_bucket         = local.caddy_storage_s3.bucket
    caddy_storage_s3_region         = local.caddy_storage_s3.region
    caddy_storage_s3_endpoint       = local.caddy_storage_s3.endpoint
    caddy_storage_s3_prefix         = local.caddy_storage_s3.prefix
    caddy_storage_s3_access_key     = local.caddy_storage_s3.access_key
    caddy_storage_s3_secret_key     = local.caddy_storage_s3.secret_key
    caddy_storage_s3_encryption_key = local.caddy_storage_s3.encryption_key
    # AOCR mirror + auto-import (Phase 4 F17-F21) — see local.aocr.
    aocr_enabled             = local.aocr.enabled
    aocr_mirror_host         = local.aocr.mirror_host
    aocr_mirror_push_host    = local.aocr.mirror_push_host
    aocr_mirror_upstreams    = local.aocr.mirror_upstreams
    aocr_upstream_wrap_key   = local.aocr.upstream_wrap_key
    aocr_auto_import_enabled = local.aocr.auto_import_enabled
    aocr_hooks_url           = local.aocr.hooks_url
    aocr_cluster_id          = local.aocr.cluster_id
    aocr_cluster_pat         = local.aocr.cluster_pat
    aocr_retention_suffix    = local.aocr.retention_suffix
    aocr_request_timeout     = local.aocr.request_timeout
    aocr_reconcile_interval  = local.aocr.reconcile_interval
    aocr_max_in_flight       = local.aocr.max_in_flight
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
