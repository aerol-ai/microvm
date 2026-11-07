# Every module output, under the same name, so `terraform output` reads
# the same here as it did when Terraform/ was the root.

output "audit_receiver" {
  value     = module.aerolvm.audit_receiver
  sensitive = true
}

output "cluster_name" {
  value = module.aerolvm.cluster_name
}

output "seed_node" {
  value = module.aerolvm.seed_node
}

output "nodes" {
  value = module.aerolvm.nodes
}

output "ingress_public_ips" {
  value = module.aerolvm.ingress_public_ips
}

output "ingress_hostname" {
  value = module.aerolvm.ingress_hostname
}

output "api_load_balancer" {
  value = module.aerolvm.api_load_balancer
}

output "api_base_url" {
  value = module.aerolvm.api_base_url
}

output "integration_targets" {
  value = module.aerolvm.integration_targets
}

output "grafana_url" {
  value = module.aerolvm.grafana_url
}

output "pushgateway_url" {
  value = module.aerolvm.pushgateway_url
}

output "grafana_admin_password" {
  value     = module.aerolvm.grafana_admin_password
  sensitive = true
}

output "bundle_bucket" {
  value = module.aerolvm.bundle_bucket
}

output "audit_witness_bucket" {
  value = module.aerolvm.audit_witness_bucket
}

output "audit_witness_prefix" {
  value = module.aerolvm.audit_witness_prefix
}

output "audit_witness_auditor_policy_arn" {
  value = module.aerolvm.audit_witness_auditor_policy_arn
}

output "audit_export_bucket" {
  value = module.aerolvm.audit_export_bucket
}

output "audit_export_prefix" {
  value = module.aerolvm.audit_export_prefix
}

output "caddy_certs_bucket" {
  value = module.aerolvm.caddy_certs_bucket
}

output "caddy_certs_encryption_key" {
  value     = module.aerolvm.caddy_certs_encryption_key
  sensitive = true
}

output "ssh_command_seed" {
  value = module.aerolvm.ssh_command_seed
}

output "verify_cluster_command" {
  value = module.aerolvm.verify_cluster_command
}

output "prometheus_scrape_targets" {
  value = module.aerolvm.prometheus_scrape_targets
}

output "grafana_dashboard_file" {
  value = module.aerolvm.grafana_dashboard_file
}

output "prometheus_alert_rules_file" {
  value = module.aerolvm.prometheus_alert_rules_file
}

output "alertmanager_example_file" {
  value = module.aerolvm.alertmanager_example_file
}

output "operational_runbooks_dir" {
  value = module.aerolvm.operational_runbooks_dir
}
