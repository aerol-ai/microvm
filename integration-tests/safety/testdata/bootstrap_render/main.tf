# Fixture for TestBootstrapTemplateRenders (../../bootstrap_render_test.go).
#
# Renders Terraform/templates/bootstrap.sh.tftpl for BOTH the seed and the
# joiner branch so the generated bash can be syntax-checked. Nothing else
# validates that ~460-line script: `terraform validate` only proves the
# template parses, and a real apply is the first thing that would run it — on
# an EC2 box, inside cloud-init, where a typo surfaces as a silently
# half-bootstrapped node.
#
# The values are deliberately meaningless; only TYPES matter (a %{ if } needs a
# bool, arithmetic needs a number). __TEMPLATE__ is replaced by the test.
#
# When you add a variable to the templatefile call in Terraform/nodes.tf, add
# it here too — templatefile fails on a missing variable, so the test will tell
# you exactly which one.

locals {
  base = {
    node_name = "x"
    role = "x"
    is_seed = false
    domain = "x"
    enable_custom_domains = false
    custom_domain_txt_prefix = "x"
    custom_domain_txt_value_prefix = "x"
    pat_token = "x"
    cloudflare_api_token = "x"
    acme_email = "x"
    with_firecracker = false
    with_gvisor = false
    with_isolate = false
    with_nvidia_gpu = false
    with_amd_gpu = false
    idle_timeout_min = 30
    firecracker_binary_url = "x"
    firecracker_jailer_url = "x"
    firecracker_kernel_url = "x"
    firecracker_kernel_config_url = "x"
    firecracker_auto_install = false
    firecracker_version = "x"
    firecracker_upstream_arch = "x"
    firecracker_kernel_ci_version = "x"
    firecracker_kernel_version = "x"
    firecracker_binary_path = "x"
    firecracker_jailer_path = "x"
    firecracker_kernel_path = "x"
    firecracker_run_dir = "x"
    firecracker_templates_dir = "x"
    firecracker_use_jailer = false
    firecracker_jailer_chroot_base = "x"
    firecracker_jailer_uid = 30
    firecracker_jailer_gid = 30
    firecracker_tap_base_cidr = "x"
    firecracker_tap_pool_size = 30
    firecracker_skopeo_bin = "x"
    firecracker_umoci_bin = "x"
    firecracker_mkfs_bin = "x"
    firecracker_ip_binary = "x"
    firecracker_template_gc_enabled = false
    firecracker_template_gc_interval = "x"
    firecracker_template_gc_ttl = "x"
    firecracker_snapshot_enabled = false
    firecracker_template_build_timeout = "x"
    firecracker_template_rotation_interval = "x"
    firecracker_template_max_age = "x"
    firecracker_template_memory_mb = 30
    firecracker_template_vcpu = 30
    firecracker_snapshot_verify_on_load = false
    firecracker_overlay_enabled = false
    firecracker_overlay_mkfs = "x"
    firecracker_snapshot_post_resume_timeout = "x"
    firecracker_vmm_pool_enabled = false
    firecracker_vmm_pool_depth_default = 30
    firecracker_vmm_pool_gc_interval = "x"
    firecracker_vmm_pool_gc_ttl = "x"
    firecracker_vmm_pool_refill_interval = "x"
    firecracker_rss_sampler_interval = "x"
    firecracker_rss_watermark_ratio = 30
    bundle_bucket = "x"
    aws_region = "x"
    seed_private_ip = "x"
    install_script_url = "x"
    caddy_binary_url = "x"
    cluster_init_script_url = "x"
    cluster_join_script_url = "x"
    cluster_sign_node_script_url = "x"
    sandboxd_url = "x"
    toolboxd_url = "x"
    checksums_url = "x"
    joiner_role_unique_id = "x"
    seed_wait_max_seconds = 30
    otel_metrics_enabled = false
    otel_metrics_endpoint = false
    otel_metrics_interval = false
    otel_traces_enabled = false
    otel_traces_endpoint = false
    otel_traces_sample_ratio = false
    otel_service_name = false
    image_pull_max_concurrent = 30
    image_pull_failure_backoff = "x"
    image_gc_whitelist = "x"
    image_build_gc_enabled = false
    image_build_gc_interval = "x"
    image_build_gc_ttl = "x"
    extra_user_data = "x"
    sandboxd_env           = { SB_ENTERPRISE_MODE = "true", SB_AUDIT_EXPORT_MODE = "file" }
    secret_kms_key_arn     = ""
    secret_kms_strict_boot = true
    shard_aware_ingress = false
    caddy_storage_s3_enabled = false
    caddy_storage_s3_bucket = "x"
    caddy_storage_s3_region = "x"
    caddy_storage_s3_endpoint = "x"
    caddy_storage_s3_prefix = "x"
    caddy_storage_s3_access_key = "x"
    caddy_storage_s3_secret_key = "x"
    caddy_storage_s3_encryption_key = "x"
    aocr_enabled = false
    aocr_mirror_host = "x"
    aocr_mirror_push_host = "x"
    aocr_mirror_upstreams = "x"
    aocr_upstream_wrap_key = "x"
    aocr_auto_import_enabled = false
    aocr_hooks_url = "x"
    aocr_cluster_id = "x"
    aocr_cluster_pat = "x"
    ssh_host_key_pem = "x"
    aocr_retention_suffix = "x"
    aocr_request_timeout = "x"
    aocr_reconcile_interval = "x"
    aocr_max_in_flight = 30
    aocr_snapshot_push_enabled = false
    aocr_snapshot_push_reconcile_interval = "x"
    aocr_snapshot_push_max_in_flight = 30
    aocr_snapshot_push_tag_suffix = "x"
    fleet_enabled = false
    fleet_endpoint = "x"
    fleet_token = "x"
    fleet_contract_refresh = "x"
    wasm_cfg = { enabled = "x", cache_dir = "x", modules_dir = "x", pool_depth_default = "x", pool_enabled = "x", pull_timeout = "x", push_host = "x", registry_allowlist = "x", registry_pat_path = "x", registry_username = "x", standard_modules = "x" }
    docker_pool_cfg = { enabled = "x", depth = "x", images = "x", max_images = "x", idle_ttl = "x", refill_interval = "x" }
    docker_netns_pool_cfg = { enabled = "x", depth = "x", pause_image = "x", refill_interval = "x" }
    container_engine = "x"
    containerd_cfg = { socket = "x", namespace = "x", cni_plugin_dir = "x", native_netns_pool_enabled = "x" }
    platform_volumes_cfg = { enabled = "x", backend = "x", max_per_tenant = "x", nfs_export = "x", nfs_options = "x", nfs_server = "x", reclaim_concurrency = "x", reclaim_interval = "x", reclaim_mount_root = "x", s3_access_key_id = "x", s3_bucket = "x", s3_endpoint = "x", s3_prefix = "x", s3_region = "x", s3_secret_access_key = "x" }
  }
}
output "seed"   { value = templatefile("__TEMPLATE__", merge(local.base, { is_seed = true })) }
output "joiner" { value = templatefile("__TEMPLATE__", merge(local.base, { is_seed = false })) }

# Same joiner, but with the KMS secret provider turned on, so the conditional
# block and its interaction with the sandboxd_env override layer are both
# covered.
output "joiner_kms" {
  value = templatefile("__TEMPLATE__", merge(local.base, {
    is_seed            = false
    secret_kms_key_arn = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
    sandboxd_env = {
      SB_ENTERPRISE_MODE = "true"
      # Proves the override layering: this must WIN over the KMS block's value
      # because extra_sandboxd_env is rendered last and systemd's
      # EnvironmentFile takes the last assignment.
      SB_SECRET_PROVIDER_STRICT_BOOT = "false"
    }
  }))
}
