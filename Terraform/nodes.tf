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

  # Spot is opt-in per node. The dynamic block emits ZERO blocks when spot is
  # false, so an on-demand (prod) node renders byte-identical to before this
  # field existed — `terraform plan` shows no diff. one-time + terminate means
  # a reclaimed integration node is gone, not stopped (ephemeral test intent).
  dynamic "instance_market_options" {
    # force_on_demand flips ONLY firecracker (bare-metal) nodes off spot —
    # *.metal spot capacity is thin and a reclaim mid-run is disruptive, so the
    # operator can opt the expensive node into on-demand without losing spot on
    # the cheap t3 workers. Defaults false, so prod stays byte-identical.
    for_each = local.seed_node.spot && !(var.force_on_demand && local.seed_node.with_firecracker) ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        spot_instance_type             = "one-time"
        instance_interruption_behavior = "terminate"
      }
    }
  }

  user_data_replace_on_change = true

  # gzip+base64 the rendered bootstrap. Firecracker nodes render a much larger
  # script (the full SB_FIRECRACKER_* env block) that blows past EC2's 16 KiB
  # user_data ceiling as plain text. cloud-init transparently decompresses
  # gzipped user-data, so we hand it the compressed form and the 16 KiB limit
  # then applies to the (far smaller) compressed payload.
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_name                                = "${var.cluster_name}-${local.seed_node.name}"
    role                                     = local.seed_node.role
    is_seed                                  = true
    domain                                   = local.domain_name
    enable_custom_domains                    = local.enable_custom_domains
    custom_domain_txt_prefix                 = local.custom_domain_txt_prefix
    custom_domain_txt_value_prefix           = local.custom_domain_txt_value_prefix
    pat_token                                = local.pat_token
    cloudflare_api_token                     = local.cloudflare_api_token
    acme_email                               = local.acme_email
    with_firecracker                         = local.seed_node.with_firecracker
    with_gvisor                              = local.seed_node.with_gvisor
    with_isolate                             = local.seed_node.with_isolate
    with_nvidia_gpu                          = local.seed_node.with_nvidia_gpu
    with_amd_gpu                             = local.seed_node.with_amd_gpu
    idle_timeout_min                         = local.seed_node.idle_timeout_min
    firecracker_binary_url                   = var.firecracker.binary_url
    firecracker_jailer_url                   = var.firecracker.jailer_url
    firecracker_kernel_url                   = var.firecracker.kernel_url
    firecracker_kernel_config_url            = var.firecracker.kernel_config_url
    firecracker_auto_install                 = var.firecracker.auto_install_artifacts
    firecracker_version                      = var.firecracker.version
    firecracker_upstream_arch                = local.firecracker_upstream_arch
    firecracker_kernel_ci_version            = var.firecracker.kernel_ci_version
    firecracker_kernel_version               = var.firecracker.kernel_version
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
    caddy_binary_url                         = var.caddy_binary_url
    cluster_init_script_url                  = var.cluster_init_script_url
    cluster_join_script_url                  = var.cluster_join_script_url
    cluster_sign_node_script_url             = var.cluster_sign_node_script_url
    sandboxd_url                             = var.sandboxd_url
    toolboxd_url                             = var.toolboxd_url
    checksums_url                            = var.checksums_url
    joiner_role_unique_id                    = aws_iam_role.joiner.unique_id
    secret_kms_key_arn                       = var.secret_kms_enabled ? aws_kms_key.secrets[0].arn : ""
    secret_kms_strict_boot                   = var.secret_kms_strict_boot
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
    sandboxd_env                             = merge(var.extra_sandboxd_env, local.seed_node.sandboxd_env)
    shard_aware_ingress                      = var.shard_aware_ingress
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
    aocr_enabled                          = local.aocr.enabled
    aocr_mirror_host                      = local.aocr.mirror_host
    aocr_mirror_push_host                 = local.aocr.mirror_push_host
    aocr_mirror_upstreams                 = local.aocr.mirror_upstreams
    aocr_upstream_wrap_key                = local.aocr.upstream_wrap_key
    aocr_auto_import_enabled              = local.aocr.auto_import_enabled
    aocr_hooks_url                        = local.aocr.hooks_url
    aocr_cluster_id                       = local.aocr.cluster_id
    aocr_cluster_pat                      = local.aocr.cluster_pat
    ssh_host_key_pem                      = var.ssh_host_key_pem
    aocr_retention_suffix                 = local.aocr.retention_suffix
    aocr_request_timeout                  = local.aocr.request_timeout
    aocr_reconcile_interval               = local.aocr.reconcile_interval
    aocr_max_in_flight                    = local.aocr.max_in_flight
    aocr_snapshot_push_enabled            = local.aocr.snapshot_push_enabled
    aocr_snapshot_push_reconcile_interval = local.aocr.snapshot_push_reconcile_interval
    aocr_snapshot_push_max_in_flight      = local.aocr.snapshot_push_max_in_flight
    aocr_snapshot_push_tag_suffix         = local.aocr.snapshot_push_tag_suffix

    fleet_enabled          = local.fleet.enabled
    fleet_endpoint         = local.fleet.endpoint
    fleet_token            = local.fleet.token
    fleet_contract_refresh = local.fleet.contract_refresh
    wasm_cfg               = local.wasm_cfg
    docker_pool_cfg        = local.docker_pool_cfg
    docker_netns_pool_cfg  = local.docker_netns_pool_cfg
    container_engine       = local.container_engine
    containerd_cfg         = local.containerd_cfg
    platform_volumes_cfg   = local.platform_volumes_cfg
  }))

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

    # Mirror the daemon's topology gate (cluster.MaxReplicatedIngressRouteNodes)
    # at plan time: above 10 ingress-capable nodes each ingress node holds only
    # its share of the public route table, and sandboxd refuses to boot (or,
    # open-source, to mark ingress ready) unless the operator declares a
    # shard-aware router with shard_aware_ingress. Failing here is cheaper
    # than provisioning 100 nodes the daemon rejects. Mirrored in
    # Terraform/validate/ingress.go.
    precondition {
      condition     = length(local.ingress_node_names) <= 10 || var.shard_aware_ingress
      error_message = "More than 10 ingress-capable nodes (ingress, a hybrid containing it, or mixed) need a shard-aware router in front of the tier (GET /v1/cluster/ingress-route/{id}); set shard_aware_ingress = true only once that router is in place. See setup/runbooks/cluster-ingress-topology.md."
    }
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

  # See the seed resource for the rationale: zero blocks when spot=false keeps
  # on-demand (prod) joiners diff-free.
  dynamic "instance_market_options" {
    # See the seed block: force_on_demand pulls firecracker nodes off spot only.
    for_each = each.value.spot && !(var.force_on_demand && each.value.with_firecracker) ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        spot_instance_type             = "one-time"
        instance_interruption_behavior = "terminate"
      }
    }
  }

  user_data_replace_on_change = true

  # gzip+base64: see the seed resource above. Firecracker joiners (worker-fc in
  # cluster-hetero) render the largest scripts and exceed the 16 KiB plain-text
  # user_data limit; cloud-init decompresses gzipped user-data transparently.
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_name                                = "${var.cluster_name}-${each.value.name}"
    role                                     = each.value.role
    is_seed                                  = false
    domain                                   = local.domain_name
    enable_custom_domains                    = local.enable_custom_domains
    custom_domain_txt_prefix                 = local.custom_domain_txt_prefix
    custom_domain_txt_value_prefix           = local.custom_domain_txt_value_prefix
    pat_token                                = local.pat_token
    cloudflare_api_token                     = local.cloudflare_api_token
    acme_email                               = local.acme_email
    with_firecracker                         = each.value.with_firecracker
    with_gvisor                              = each.value.with_gvisor
    with_isolate                             = each.value.with_isolate
    with_nvidia_gpu                          = each.value.with_nvidia_gpu
    with_amd_gpu                             = each.value.with_amd_gpu
    idle_timeout_min                         = each.value.idle_timeout_min
    firecracker_binary_url                   = var.firecracker.binary_url
    firecracker_jailer_url                   = var.firecracker.jailer_url
    firecracker_kernel_url                   = var.firecracker.kernel_url
    firecracker_kernel_config_url            = var.firecracker.kernel_config_url
    firecracker_auto_install                 = var.firecracker.auto_install_artifacts
    firecracker_version                      = var.firecracker.version
    firecracker_upstream_arch                = local.firecracker_upstream_arch
    firecracker_kernel_ci_version            = var.firecracker.kernel_ci_version
    firecracker_kernel_version               = var.firecracker.kernel_version
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
    caddy_binary_url                         = var.caddy_binary_url
    cluster_init_script_url                  = var.cluster_init_script_url
    cluster_join_script_url                  = var.cluster_join_script_url
    cluster_sign_node_script_url             = var.cluster_sign_node_script_url
    sandboxd_url                             = var.sandboxd_url
    toolboxd_url                             = var.toolboxd_url
    checksums_url                            = var.checksums_url
    joiner_role_unique_id                    = aws_iam_role.joiner.unique_id
    secret_kms_key_arn                       = var.secret_kms_enabled ? aws_kms_key.secrets[0].arn : ""
    secret_kms_strict_boot                   = var.secret_kms_strict_boot
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
    sandboxd_env                             = merge(var.extra_sandboxd_env, each.value.sandboxd_env)
    shard_aware_ingress                      = var.shard_aware_ingress
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
    aocr_enabled                          = local.aocr.enabled
    aocr_mirror_host                      = local.aocr.mirror_host
    aocr_mirror_push_host                 = local.aocr.mirror_push_host
    aocr_mirror_upstreams                 = local.aocr.mirror_upstreams
    aocr_upstream_wrap_key                = local.aocr.upstream_wrap_key
    aocr_auto_import_enabled              = local.aocr.auto_import_enabled
    aocr_hooks_url                        = local.aocr.hooks_url
    aocr_cluster_id                       = local.aocr.cluster_id
    aocr_cluster_pat                      = local.aocr.cluster_pat
    ssh_host_key_pem                      = var.ssh_host_key_pem
    aocr_retention_suffix                 = local.aocr.retention_suffix
    aocr_request_timeout                  = local.aocr.request_timeout
    aocr_reconcile_interval               = local.aocr.reconcile_interval
    aocr_max_in_flight                    = local.aocr.max_in_flight
    aocr_snapshot_push_enabled            = local.aocr.snapshot_push_enabled
    aocr_snapshot_push_reconcile_interval = local.aocr.snapshot_push_reconcile_interval
    aocr_snapshot_push_max_in_flight      = local.aocr.snapshot_push_max_in_flight
    aocr_snapshot_push_tag_suffix         = local.aocr.snapshot_push_tag_suffix

    fleet_enabled          = local.fleet.enabled
    fleet_endpoint         = local.fleet.endpoint
    fleet_token            = local.fleet.token
    fleet_contract_refresh = local.fleet.contract_refresh
    wasm_cfg               = local.wasm_cfg
    docker_pool_cfg        = local.docker_pool_cfg
    docker_netns_pool_cfg  = local.docker_netns_pool_cfg
    container_engine       = local.container_engine
    containerd_cfg         = local.containerd_cfg
    platform_volumes_cfg   = local.platform_volumes_cfg
  }))

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

  # Joiners bootstrap against the seed private IP. If the seed is replaced, the
  # joiners need a planned replacement too instead of a provider-discovered
  # user_data replacement during apply.
  lifecycle {
    ignore_changes       = [ami]
    replace_triggered_by = [aws_instance.seed]
  }
}

# Authoritative caller-identity -> node-id mapping for the CSR signing
# rendezvous (templates/bootstrap.sh.tftpl).
#
# This object is what makes the rendezvous safe. cluster-sign-node.sh stamps
# `DNS:node:<id>` straight from its --node-id flag and never inspects the CSR,
# so the seed must learn a joiner's identity from something the joiner cannot
# influence. A joiner's IAM grant only lets it write under csr/${aws:userid}/,
# and ${aws:userid} for EC2 instance-profile credentials is
# "<role-unique-id>:<instance-id>" — assigned by AWS, not chosen by the
# instance. The seed reads the CSR's prefix, looks up nodes/<that prefix>
# here, and signs the name TERRAFORM recorded.
#
# Joiners can read this (joiner_r grants GetObject on the whole bucket) but
# cannot write it: their PutObject is scoped to csr/${aws:userid}/*.
resource "aws_s3_object" "joiner_identity" {
  for_each = local.joiner_nodes

  bucket = aws_s3_bucket.bundle.bucket
  key    = "nodes/${aws_iam_role.joiner.unique_id}:${aws_instance.joiner[each.key].id}"
  # Must match the --node-id the joiner is told to use, which is the same
  # node_name the template renders into its cluster-join invocation.
  content                = "${var.cluster_name}-${each.value.name}"
  content_type           = "text/plain"
  server_side_encryption = "AES256"
}

# Convenience: every node, keyed by name, for downstream resources (dns, outputs).
locals {
  all_instances = merge(
    { (local.seed_name) = aws_instance.seed },
    { for n, inst in aws_instance.joiner : n => inst },
  )
}
