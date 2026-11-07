# The root module a repo checkout runs: scripts/terraform.sh and the
# integration harness (integration-tests/run.sh). It calls the module in
# Terraform/ by path and passes every variable through, so a tfvars file
# written for the old layout (Terraform/ as the root) works unchanged.
#
# Outside a checkout, use the module by URL instead; see
# Terraform/examples/from-url/.
module "aerolvm" {
  source = "../"

  cluster_name                         = var.cluster_name
  aws_region                           = var.aws_region
  config_dir                           = var.config_dir
  aws_profile                          = var.aws_profile
  aws_shared_credentials_files         = var.aws_shared_credentials_files
  extra_tags                           = var.extra_tags
  vpc_cidr                             = var.vpc_cidr
  subnet_cidr                          = var.subnet_cidr
  availability_zone                    = var.availability_zone
  admin_allowed_cidrs                  = var.admin_allowed_cidrs
  allow_admin_from_anywhere            = var.allow_admin_from_anywhere
  public_http_ports                    = var.public_http_ports
  l4_port_range                        = var.l4_port_range
  ssh_gateway_port                     = var.ssh_gateway_port
  api_load_balancer                    = var.api_load_balancer
  api_lb_health_check_port             = var.api_lb_health_check_port
  ssh_host_key_pem                     = var.ssh_host_key_pem
  cluster_internal_tcp_ports           = var.cluster_internal_tcp_ports
  cluster_internal_udp_ports           = var.cluster_internal_udp_ports
  ssh_key_name                         = var.ssh_key_name
  ssh_public_key                       = var.ssh_public_key
  ssh_public_key_path                  = var.ssh_public_key_path
  ami_id                               = var.ami_id
  default_instance_type                = var.default_instance_type
  default_volume_size_gb               = var.default_volume_size_gb
  default_volume_type                  = var.default_volume_type
  default_volume_iops                  = var.default_volume_iops
  default_volume_throughput            = var.default_volume_throughput
  shard_aware_ingress                  = var.shard_aware_ingress
  nodes                                = var.nodes
  force_on_demand                      = var.force_on_demand
  default_with_firecracker             = var.default_with_firecracker
  default_with_gvisor                  = var.default_with_gvisor
  default_with_isolate                 = var.default_with_isolate
  default_ingress_proxy_routing        = var.default_ingress_proxy_routing
  default_with_nvidia_gpu              = var.default_with_nvidia_gpu
  default_with_amd_gpu                 = var.default_with_amd_gpu
  default_idle_timeout_min             = var.default_idle_timeout_min
  firecracker                          = var.firecracker
  deploy_obs                           = var.deploy_obs
  obs_instance_type                    = var.obs_instance_type
  obs_prometheus_volume_size_gb        = var.obs_prometheus_volume_size_gb
  cloudflare_zone_id                   = var.cloudflare_zone_id
  create_wildcard_record               = var.create_wildcard_record
  cloudflare_proxied                   = var.cloudflare_proxied
  cloudflare_record_ttl                = var.cloudflare_record_ttl
  install_script_url                   = var.install_script_url
  caddy_binary_url                     = var.caddy_binary_url
  download_mirror                      = var.download_mirror
  secret_kms_enabled                   = var.secret_kms_enabled
  key_custody                          = var.key_custody
  secret_kms_strict_boot               = var.secret_kms_strict_boot
  audit_export_enabled                 = var.audit_export_enabled
  audit_export_backend                 = var.audit_export_backend
  audit_export_file_path               = var.audit_export_file_path
  audit_witness_enabled                = var.audit_witness_enabled
  audit_witness_prefix                 = var.audit_witness_prefix
  witness_lock_mode                    = var.witness_lock_mode
  witness_lock_days                    = var.witness_lock_days
  audit_witness_auditor_policy_enabled = var.audit_witness_auditor_policy_enabled
  audit_receiver_enabled               = var.audit_receiver_enabled
  audit_receiver_port                  = var.audit_receiver_port
  audit_receiver_url                   = var.audit_receiver_url
  identity_issuer_enabled              = var.identity_issuer_enabled
  extra_sandboxd_env                   = var.extra_sandboxd_env
  pat_scope                            = var.pat_scope
  l4_proxy_protocol                    = var.l4_proxy_protocol
  sandboxd_url                         = var.sandboxd_url
  toolboxd_url                         = var.toolboxd_url
  checksums_url                        = var.checksums_url
  cluster_init_script_url              = var.cluster_init_script_url
  cluster_join_script_url              = var.cluster_join_script_url
  cluster_sign_node_script_url         = var.cluster_sign_node_script_url
  bundle_bucket_force_destroy          = var.bundle_bucket_force_destroy
  caddy_certs_bucket_force_destroy     = var.caddy_certs_bucket_force_destroy
  seed_wait_max_seconds                = var.seed_wait_max_seconds
  caddy_shared_cert_storage            = var.caddy_shared_cert_storage
  one_line_join                        = var.one_line_join
}
