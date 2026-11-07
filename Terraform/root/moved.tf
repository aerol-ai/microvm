# State written while Terraform/ was the root module lives at the top
# level (aws_instance.seed). The same objects now live inside
# module.aerolvm. These blocks move them on the next plan, so a cluster
# built from a checkout before the move keeps every machine: nothing is
# destroyed or made again. A moved block with no state behind it does
# nothing, so a new cluster is not affected.
#
# Moving from a checkout to the module by URL in your own root: copy this
# file next to your module block and change module.aerolvm to its name.

moved {
  from = random_id.audit_suffix
  to   = module.aerolvm.random_id.audit_suffix
}

moved {
  from = aws_s3_bucket.audit
  to   = module.aerolvm.aws_s3_bucket.audit
}

moved {
  from = aws_s3_bucket_public_access_block.audit
  to   = module.aerolvm.aws_s3_bucket_public_access_block.audit
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.audit
  to   = module.aerolvm.aws_s3_bucket_server_side_encryption_configuration.audit
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.audit
  to   = module.aerolvm.aws_s3_bucket_lifecycle_configuration.audit
}

moved {
  from = aws_iam_role_policy.audit_export_seed
  to   = module.aerolvm.aws_iam_role_policy.audit_export_seed
}

moved {
  from = aws_iam_role_policy.audit_export_joiner
  to   = module.aerolvm.aws_iam_role_policy.audit_export_joiner
}

moved {
  from = random_password.audit_receiver_token
  to   = module.aerolvm.random_password.audit_receiver_token
}

moved {
  from = random_password.audit_receiver_hmac
  to   = module.aerolvm.random_password.audit_receiver_hmac
}

moved {
  from = tls_private_key.audit_receiver
  to   = module.aerolvm.tls_private_key.audit_receiver
}

moved {
  from = tls_self_signed_cert.audit_receiver
  to   = module.aerolvm.tls_self_signed_cert.audit_receiver
}

moved {
  from = aws_security_group_rule.audit_receiver
  to   = module.aerolvm.aws_security_group_rule.audit_receiver
}

moved {
  from = random_id.witness_suffix
  to   = module.aerolvm.random_id.witness_suffix
}

moved {
  from = aws_s3_bucket.witness
  to   = module.aerolvm.aws_s3_bucket.witness
}

moved {
  from = aws_s3_bucket_public_access_block.witness
  to   = module.aerolvm.aws_s3_bucket_public_access_block.witness
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.witness
  to   = module.aerolvm.aws_s3_bucket_server_side_encryption_configuration.witness
}

moved {
  from = aws_s3_bucket_versioning.witness
  to   = module.aerolvm.aws_s3_bucket_versioning.witness
}

moved {
  from = aws_s3_bucket_object_lock_configuration.witness
  to   = module.aerolvm.aws_s3_bucket_object_lock_configuration.witness
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.witness
  to   = module.aerolvm.aws_s3_bucket_lifecycle_configuration.witness
}

moved {
  from = aws_iam_role_policy.audit_witness_seed
  to   = module.aerolvm.aws_iam_role_policy.audit_witness_seed
}

moved {
  from = aws_iam_role_policy.audit_witness_joiner
  to   = module.aerolvm.aws_iam_role_policy.audit_witness_joiner
}

moved {
  from = aws_iam_policy.audit_witness_auditor
  to   = module.aerolvm.aws_iam_policy.audit_witness_auditor
}

moved {
  from = cloudflare_record.apex
  to   = module.aerolvm.cloudflare_record.apex
}

moved {
  from = cloudflare_record.wildcard
  to   = module.aerolvm.cloudflare_record.wildcard
}

moved {
  from = cloudflare_record.l4_direct
  to   = module.aerolvm.cloudflare_record.l4_direct
}

moved {
  from = random_id.bundle_suffix
  to   = module.aerolvm.random_id.bundle_suffix
}

moved {
  from = aws_s3_bucket.bundle
  to   = module.aerolvm.aws_s3_bucket.bundle
}

moved {
  from = aws_s3_bucket_public_access_block.bundle
  to   = module.aerolvm.aws_s3_bucket_public_access_block.bundle
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.bundle
  to   = module.aerolvm.aws_s3_bucket_server_side_encryption_configuration.bundle
}

moved {
  from = aws_s3_bucket_versioning.bundle
  to   = module.aerolvm.aws_s3_bucket_versioning.bundle
}

moved {
  from = aws_iam_role.seed
  to   = module.aerolvm.aws_iam_role.seed
}

moved {
  from = aws_iam_role.joiner
  to   = module.aerolvm.aws_iam_role.joiner
}

moved {
  from = aws_iam_role_policy.seed_rw
  to   = module.aerolvm.aws_iam_role_policy.seed_rw
}

moved {
  from = aws_iam_role_policy.joiner_r
  to   = module.aerolvm.aws_iam_role_policy.joiner_r
}

moved {
  from = aws_iam_role_policy.platform_volumes_seed_rw
  to   = module.aerolvm.aws_iam_role_policy.platform_volumes_seed_rw
}

moved {
  from = aws_iam_role_policy.platform_volumes_joiner_rw
  to   = module.aerolvm.aws_iam_role_policy.platform_volumes_joiner_rw
}

moved {
  from = aws_iam_instance_profile.seed
  to   = module.aerolvm.aws_iam_instance_profile.seed
}

moved {
  from = aws_iam_instance_profile.joiner
  to   = module.aerolvm.aws_iam_instance_profile.joiner
}

moved {
  from = aws_s3_bucket.caddy_certs
  to   = module.aerolvm.aws_s3_bucket.caddy_certs
}

moved {
  from = aws_s3_bucket_public_access_block.caddy_certs
  to   = module.aerolvm.aws_s3_bucket_public_access_block.caddy_certs
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.caddy_certs
  to   = module.aerolvm.aws_s3_bucket_server_side_encryption_configuration.caddy_certs
}

moved {
  from = aws_s3_bucket_versioning.caddy_certs
  to   = module.aerolvm.aws_s3_bucket_versioning.caddy_certs
}

moved {
  from = aws_iam_role_policy.caddy_certs_seed_rw
  to   = module.aerolvm.aws_iam_role_policy.caddy_certs_seed_rw
}

moved {
  from = aws_iam_role_policy.caddy_certs_joiner_rw
  to   = module.aerolvm.aws_iam_role_policy.caddy_certs_joiner_rw
}

moved {
  from = random_string.join_token_id
  to   = module.aerolvm.random_string.join_token_id
}

moved {
  from = random_password.join_token_secret
  to   = module.aerolvm.random_password.join_token_secret
}

moved {
  from = aws_kms_key.secrets
  to   = module.aerolvm.aws_kms_key.secrets
}

moved {
  from = aws_kms_alias.secrets
  to   = module.aerolvm.aws_kms_alias.secrets
}

moved {
  from = aws_iam_role_policy.secret_kms_seed
  to   = module.aerolvm.aws_iam_role_policy.secret_kms_seed
}

moved {
  from = aws_iam_role_policy.secret_kms_joiner
  to   = module.aerolvm.aws_iam_role_policy.secret_kms_joiner
}

moved {
  from = aws_eip.api_lb
  to   = module.aerolvm.aws_eip.api_lb
}

moved {
  from = aws_security_group.api_lb
  to   = module.aerolvm.aws_security_group.api_lb
}

moved {
  from = aws_security_group_rule.api_lb_listener
  to   = module.aerolvm.aws_security_group_rule.api_lb_listener
}

moved {
  from = aws_security_group_rule.api_lb_to_nodes
  to   = module.aerolvm.aws_security_group_rule.api_lb_to_nodes
}

moved {
  from = aws_security_group_rule.node_lb_health
  to   = module.aerolvm.aws_security_group_rule.node_lb_health
}

moved {
  from = aws_lb.api
  to   = module.aerolvm.aws_lb.api
}

moved {
  from = aws_lb_target_group.api
  to   = module.aerolvm.aws_lb_target_group.api
}

moved {
  from = aws_lb_listener.api
  to   = module.aerolvm.aws_lb_listener.api
}

moved {
  from = aws_lb_target_group_attachment.api
  to   = module.aerolvm.aws_lb_target_group_attachment.api
}

moved {
  from = terraform_data.validate_cluster_ops
  to   = module.aerolvm.terraform_data.validate_cluster_ops
}

moved {
  from = random_id.caddy_storage_s3_encryption_key
  to   = module.aerolvm.random_id.caddy_storage_s3_encryption_key
}

moved {
  from = aws_vpc.this
  to   = module.aerolvm.aws_vpc.this
}

moved {
  from = aws_internet_gateway.this
  to   = module.aerolvm.aws_internet_gateway.this
}

moved {
  from = aws_subnet.public
  to   = module.aerolvm.aws_subnet.public
}

moved {
  from = aws_route_table.public
  to   = module.aerolvm.aws_route_table.public
}

moved {
  from = aws_route_table_association.public
  to   = module.aerolvm.aws_route_table_association.public
}

moved {
  from = aws_key_pair.this
  to   = module.aerolvm.aws_key_pair.this
}

moved {
  from = aws_security_group.node
  to   = module.aerolvm.aws_security_group.node
}

moved {
  from = aws_security_group_rule.egress_all
  to   = module.aerolvm.aws_security_group_rule.egress_all
}

moved {
  from = aws_security_group_rule.admin_ssh
  to   = module.aerolvm.aws_security_group_rule.admin_ssh
}

moved {
  from = aws_security_group_rule.admin_api
  to   = module.aerolvm.aws_security_group_rule.admin_api
}

moved {
  from = aws_security_group_rule.vpc_api
  to   = module.aerolvm.aws_security_group_rule.vpc_api
}

moved {
  from = aws_security_group_rule.cluster_internal_tcp
  to   = module.aerolvm.aws_security_group_rule.cluster_internal_tcp
}

moved {
  from = aws_security_group.join
  to   = module.aerolvm.aws_security_group.join
}

moved {
  from = aws_security_group_rule.join_port
  to   = module.aerolvm.aws_security_group_rule.join_port
}

moved {
  from = aws_security_group_rule.cluster_internal_udp
  to   = module.aerolvm.aws_security_group_rule.cluster_internal_udp
}

moved {
  from = aws_security_group_rule.public_http
  to   = module.aerolvm.aws_security_group_rule.public_http
}

moved {
  from = aws_security_group_rule.public_l4_pool
  to   = module.aerolvm.aws_security_group_rule.public_l4_pool
}

moved {
  from = aws_security_group_rule.public_ssh_gateway
  to   = module.aerolvm.aws_security_group_rule.public_ssh_gateway
}

moved {
  from = aws_instance.seed
  to   = module.aerolvm.aws_instance.seed
}

moved {
  from = aws_instance.joiner
  to   = module.aerolvm.aws_instance.joiner
}

moved {
  from = aws_s3_object.joiner_identity
  to   = module.aerolvm.aws_s3_object.joiner_identity
}

moved {
  from = random_password.grafana_admin
  to   = module.aerolvm.random_password.grafana_admin
}

moved {
  from = aws_security_group.obs
  to   = module.aerolvm.aws_security_group.obs
}

moved {
  from = aws_security_group_rule.obs_egress_all
  to   = module.aerolvm.aws_security_group_rule.obs_egress_all
}

moved {
  from = aws_security_group_rule.obs_grafana
  to   = module.aerolvm.aws_security_group_rule.obs_grafana
}

moved {
  from = aws_security_group_rule.obs_ssh
  to   = module.aerolvm.aws_security_group_rule.obs_ssh
}

moved {
  from = aws_security_group_rule.obs_pushgateway
  to   = module.aerolvm.aws_security_group_rule.obs_pushgateway
}

moved {
  from = aws_security_group_rule.node_metrics_from_obs
  to   = module.aerolvm.aws_security_group_rule.node_metrics_from_obs
}

moved {
  from = aws_iam_role.obs
  to   = module.aerolvm.aws_iam_role.obs
}

moved {
  from = aws_iam_instance_profile.obs
  to   = module.aerolvm.aws_iam_instance_profile.obs
}

moved {
  from = aws_ebs_volume.obs_prometheus
  to   = module.aerolvm.aws_ebs_volume.obs_prometheus
}

moved {
  from = aws_instance.obs
  to   = module.aerolvm.aws_instance.obs
}

moved {
  from = aws_volume_attachment.obs_prometheus
  to   = module.aerolvm.aws_volume_attachment.obs_prometheus
}
