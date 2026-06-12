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
    node_name                                = "${var.cluster_name}-${local.seed_node.name}"
    role                                     = local.seed_node.role
    is_seed                                  = true
    domain                                   = local.domain_name
    custom_domain_txt_prefix                 = local.custom_domain_txt_prefix
    custom_domain_txt_value_prefix           = local.custom_domain_txt_value_prefix
    pat_token                                = local.pat_token
    cloudflare_api_token                     = local.cloudflare_api_token
    acme_email                               = local.acme_email
    with_firecracker                         = local.seed_node.with_firecracker
    with_gvisor                              = local.seed_node.with_gvisor
    with_nvidia_gpu                          = local.seed_node.with_nvidia_gpu
    with_amd_gpu                             = local.seed_node.with_amd_gpu
    idle_timeout_min                         = local.seed_node.idle_timeout_min
    firecracker_binary_url                   = var.firecracker.binary_url
    firecracker_jailer_url                   = var.firecracker.jailer_url
    firecracker_kernel_url                   = var.firecracker.kernel_url
    firecracker_kernel_config_url            = var.firecracker.kernel_config_url
    firecracker_binary_path                  = var.firecracker.binary_path
    firecracker_jailer_path                  = var.firecracker.jailer_path
    firecracker_kernel_path                  = var.firecracker.kernel_path
    firecracker_run_dir                      = var.firecracker.run_dir
    firecracker_templates_dir                = var.firecracker.templates_dir
    firecracker_use_jailer                   = var.firecracker.use_jailer
    firecracker_jailer_chroot_base           = var.firecracker.jailer_chroot_base
    firecracker_jailer_uid                   = var.firecracker.jailer_uid
    firecracker_jailer_gid                   = var.firecracker.jailer_gid
    firecracker_tap_base_cidr                = var.firecracker.tap_base_cidr
    firecracker_tap_pool_size                = var.firecracker.tap_pool_size
    firecracker_skopeo_bin                   = var.firecracker.skopeo_bin
    firecracker_umoci_bin                    = var.firecracker.umoci_bin
    firecracker_mkfs_bin                     = var.firecracker.mkfs_bin
    firecracker_ip_binary                    = var.firecracker.ip_binary
    firecracker_template_gc_enabled          = var.firecracker.template_gc_enabled
    firecracker_template_gc_interval         = var.firecracker.template_gc_interval
    firecracker_template_gc_ttl              = var.firecracker.template_gc_ttl
    firecracker_snapshot_enabled             = var.firecracker.snapshot_enabled
    firecracker_template_build_timeout       = var.firecracker.template_build_timeout
    firecracker_template_rotation_interval   = var.firecracker.template_rotation_interval
    firecracker_template_max_age             = var.firecracker.template_max_age
    firecracker_template_memory_mb           = var.firecracker.template_memory_mb
    firecracker_template_vcpu                = var.firecracker.template_vcpu
    firecracker_snapshot_verify_on_load      = var.firecracker.snapshot_verify_on_load
    firecracker_overlay_enabled              = var.firecracker.overlay_enabled
    firecracker_overlay_mkfs                 = var.firecracker.overlay_mkfs
    firecracker_snapshot_post_resume_timeout = var.firecracker.snapshot_post_resume_timeout
    firecracker_vmm_pool_enabled             = var.firecracker.vmm_pool_enabled
    firecracker_vmm_pool_depth_default       = var.firecracker.vmm_pool_depth_default
    firecracker_vmm_pool_gc_interval         = var.firecracker.vmm_pool_gc_interval
    firecracker_vmm_pool_gc_ttl              = var.firecracker.vmm_pool_gc_ttl
    firecracker_vmm_pool_refill_interval     = var.firecracker.vmm_pool_refill_interval
    firecracker_rss_sampler_interval         = var.firecracker.rss_sampler_interval
    firecracker_rss_watermark_ratio          = var.firecracker.rss_watermark_ratio
    bundle_bucket                            = aws_s3_bucket.bundle.bucket
    aws_region                               = var.aws_region
    seed_private_ip                          = ""
    install_script_url                       = var.install_script_url
    cluster_init_script_url                  = var.cluster_init_script_url
    cluster_join_script_url                  = var.cluster_join_script_url
    seed_wait_max_seconds                    = var.seed_wait_max_seconds
    otel_metrics_enabled                     = local.cluster_ops.otel.metrics_enabled || local.cluster_ops.otel.metrics_endpoint != ""
    otel_metrics_endpoint                    = local.cluster_ops.otel.metrics_endpoint
    otel_metrics_interval                    = local.cluster_ops.otel.metrics_interval
    otel_traces_enabled                      = local.cluster_ops.otel.traces_enabled || local.cluster_ops.otel.traces_endpoint != ""
    otel_traces_endpoint                     = local.cluster_ops.otel.traces_endpoint
    otel_traces_sample_ratio                 = local.cluster_ops.otel.traces_sample_ratio
    otel_service_name                        = local.cluster_ops.otel.service_name
    image_pull_max_concurrent                = local.cluster_ops.image_pull.max_concurrent
    image_pull_failure_backoff               = local.cluster_ops.image_pull.failure_backoff
    image_gc_whitelist                       = join(",", local.cluster_ops.image_gc.whitelist)
    image_build_gc_enabled                   = local.cluster_ops.image_build_gc.enabled
    image_build_gc_interval                  = local.cluster_ops.image_build_gc.interval
    image_build_gc_ttl                       = local.cluster_ops.image_build_gc.ttl
    extra_user_data                          = local.seed_node.extra_user_data
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

    fleet_enabled          = local.fleet.enabled
    fleet_endpoint         = local.fleet.endpoint
    fleet_token            = local.fleet.token
    fleet_contract_refresh = local.fleet.contract_refresh
    wasm_cfg               = local.wasm_cfg
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
    node_name                                = "${var.cluster_name}-${each.value.name}"
    role                                     = each.value.role
    is_seed                                  = false
    domain                                   = local.domain_name
    custom_domain_txt_prefix                 = local.custom_domain_txt_prefix
    custom_domain_txt_value_prefix           = local.custom_domain_txt_value_prefix
    pat_token                                = local.pat_token
    cloudflare_api_token                     = local.cloudflare_api_token
    acme_email                               = local.acme_email
    with_firecracker                         = each.value.with_firecracker
    with_gvisor                              = each.value.with_gvisor
    with_nvidia_gpu                          = each.value.with_nvidia_gpu
    with_amd_gpu                             = each.value.with_amd_gpu
    idle_timeout_min                         = each.value.idle_timeout_min
    firecracker_binary_url                   = var.firecracker.binary_url
    firecracker_jailer_url                   = var.firecracker.jailer_url
    firecracker_kernel_url                   = var.firecracker.kernel_url
    firecracker_kernel_config_url            = var.firecracker.kernel_config_url
    firecracker_binary_path                  = var.firecracker.binary_path
    firecracker_jailer_path                  = var.firecracker.jailer_path
    firecracker_kernel_path                  = var.firecracker.kernel_path
    firecracker_run_dir                      = var.firecracker.run_dir
    firecracker_templates_dir                = var.firecracker.templates_dir
    firecracker_use_jailer                   = var.firecracker.use_jailer
    firecracker_jailer_chroot_base           = var.firecracker.jailer_chroot_base
    firecracker_jailer_uid                   = var.firecracker.jailer_uid
    firecracker_jailer_gid                   = var.firecracker.jailer_gid
    firecracker_tap_base_cidr                = var.firecracker.tap_base_cidr
    firecracker_tap_pool_size                = var.firecracker.tap_pool_size
    firecracker_skopeo_bin                   = var.firecracker.skopeo_bin
    firecracker_umoci_bin                    = var.firecracker.umoci_bin
    firecracker_mkfs_bin                     = var.firecracker.mkfs_bin
    firecracker_ip_binary                    = var.firecracker.ip_binary
    firecracker_template_gc_enabled          = var.firecracker.template_gc_enabled
    firecracker_template_gc_interval         = var.firecracker.template_gc_interval
    firecracker_template_gc_ttl              = var.firecracker.template_gc_ttl
    firecracker_snapshot_enabled             = var.firecracker.snapshot_enabled
    firecracker_template_build_timeout       = var.firecracker.template_build_timeout
    firecracker_template_rotation_interval   = var.firecracker.template_rotation_interval
    firecracker_template_max_age             = var.firecracker.template_max_age
    firecracker_template_memory_mb           = var.firecracker.template_memory_mb
    firecracker_template_vcpu                = var.firecracker.template_vcpu
    firecracker_snapshot_verify_on_load      = var.firecracker.snapshot_verify_on_load
    firecracker_overlay_enabled              = var.firecracker.overlay_enabled
    firecracker_overlay_mkfs                 = var.firecracker.overlay_mkfs
    firecracker_snapshot_post_resume_timeout = var.firecracker.snapshot_post_resume_timeout
    firecracker_vmm_pool_enabled             = var.firecracker.vmm_pool_enabled
    firecracker_vmm_pool_depth_default       = var.firecracker.vmm_pool_depth_default
    firecracker_vmm_pool_gc_interval         = var.firecracker.vmm_pool_gc_interval
    firecracker_vmm_pool_gc_ttl              = var.firecracker.vmm_pool_gc_ttl
    firecracker_vmm_pool_refill_interval     = var.firecracker.vmm_pool_refill_interval
    firecracker_rss_sampler_interval         = var.firecracker.rss_sampler_interval
    firecracker_rss_watermark_ratio          = var.firecracker.rss_watermark_ratio
    bundle_bucket                            = aws_s3_bucket.bundle.bucket
    aws_region                               = var.aws_region
    seed_private_ip                          = aws_instance.seed.private_ip
    install_script_url                       = var.install_script_url
    cluster_init_script_url                  = var.cluster_init_script_url
    cluster_join_script_url                  = var.cluster_join_script_url
    seed_wait_max_seconds                    = var.seed_wait_max_seconds
    otel_metrics_enabled                     = local.cluster_ops.otel.metrics_enabled || local.cluster_ops.otel.metrics_endpoint != ""
    otel_metrics_endpoint                    = local.cluster_ops.otel.metrics_endpoint
    otel_metrics_interval                    = local.cluster_ops.otel.metrics_interval
    otel_traces_enabled                      = local.cluster_ops.otel.traces_enabled || local.cluster_ops.otel.traces_endpoint != ""
    otel_traces_endpoint                     = local.cluster_ops.otel.traces_endpoint
    otel_traces_sample_ratio                 = local.cluster_ops.otel.traces_sample_ratio
    otel_service_name                        = local.cluster_ops.otel.service_name
    image_pull_max_concurrent                = local.cluster_ops.image_pull.max_concurrent
    image_pull_failure_backoff               = local.cluster_ops.image_pull.failure_backoff
    image_gc_whitelist                       = join(",", local.cluster_ops.image_gc.whitelist)
    image_build_gc_enabled                   = local.cluster_ops.image_build_gc.enabled
    image_build_gc_interval                  = local.cluster_ops.image_build_gc.interval
    image_build_gc_ttl                       = local.cluster_ops.image_build_gc.ttl
    extra_user_data                          = each.value.extra_user_data
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

    fleet_enabled          = local.fleet.enabled
    fleet_endpoint         = local.fleet.endpoint
    fleet_token            = local.fleet.token
    fleet_contract_refresh = local.fleet.contract_refresh
    wasm_cfg               = local.wasm_cfg
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
