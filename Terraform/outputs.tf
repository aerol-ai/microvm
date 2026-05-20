output "cluster_name" {
  value = var.cluster_name
}

output "seed_node" {
  description = "Name of the bootstrap (seed) node."
  value       = local.seed_name
}

output "nodes" {
  description = "Per-node summary: role, public IP, private IP, instance type."
  value = {
    for n, inst in local.all_instances : n => {
      role          = local.nodes_resolved[n].role
      seed          = n == local.seed_name
      instance_type = local.nodes_resolved[n].instance_type
      public_ip     = inst.public_ip
      private_ip    = inst.private_ip
      instance_id   = inst.id
    }
  }
}

output "ingress_public_ips" {
  description = "Public IPs of every node whose role set contains \"ingress\". These are pointed at <domain_name> + wildcard in Cloudflare."
  value       = [for n in local.ingress_node_names : local.all_instances[n].public_ip]
}

output "ingress_hostname" {
  value = var.domain_name
}

output "bundle_bucket" {
  description = "S3 bucket used to ferry the gossip key + TLS bundle from seed to joiners. Safe to leave empty after the cluster forms."
  value       = aws_s3_bucket.bundle.bucket
}

output "ssh_command_seed" {
  description = "Convenience SSH command to the seed (uses default Ubuntu user)."
  value       = "ssh ubuntu@${aws_instance.seed.public_ip}"
}

output "verify_cluster_command" {
  description = "Run this from any node (after bootstrap) to confirm membership."
  value       = "curl -s -H 'Authorization: Bearer <PAT>' http://127.0.0.1:21212/v1/cluster/members | jq ."
}

output "prometheus_scrape_targets" {
  description = "Private-IP sandboxd API targets for Prometheus scraping with metrics_path=/v1/metrics and bearer_token=<PAT>."
  value       = [for n, inst in local.all_instances : "${inst.private_ip}:21212"]
}

output "grafana_dashboard_file" {
  description = "Repo-local dashboard JSON to import into Grafana."
  value       = "setup/grafana/sandboxd-slo-dashboard.json"
}

output "prometheus_alert_rules_file" {
  description = "Repo-local Prometheus alert rule file for sandboxd SLOs."
  value       = "setup/prometheus/sandboxd-alerts.yml"
}

output "alertmanager_example_file" {
  description = "Repo-local Alertmanager example route/receiver config."
  value       = "setup/alertmanager/sandboxd-alertmanager-example.yml"
}
