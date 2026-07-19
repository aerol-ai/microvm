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
  value = local.domain_name
}

# api_base_url is the single endpoint the integration harness points its SDK at.
# Domain mode → https://<domain> (Caddy serves the control-plane API there).
# No public ingress (e.g. a pure local-mode box) → empty; the harness falls
# back to an SSH-tunnelled http://localhost:21212.
output "api_base_url" {
  description = "Base URL for the control-plane API. https://<domain> in domain mode, empty in local-mode (no domain) where the harness tunnels to localhost:21212."
  value       = local.has_domain ? "https://${local.domain_name}" : ""
}

# Machine-readable target descriptor so run.sh doesn't have to parse the human
# `nodes` output. Mirrors what the harness needs: where to talk, which node is
# which, and the leased domain.
output "integration_targets" {
  description = "Structured targets for the integration harness: base URL, ingress IP, domain, and per-node role/IPs."
  value = {
    base_url   = local.has_domain ? "https://${local.domain_name}" : ""
    domain     = local.domain_name
    ingress_ip = local.has_public_ingress ? local.all_instances[local.ingress_node_names[0]].public_ip : ""
    seed_ip    = aws_instance.seed.public_ip
    nodes = [
      for n, inst in local.all_instances : {
        name        = n
        role        = local.nodes_resolved[n].role
        seed        = n == local.seed_name
        public_ip   = inst.public_ip
        private_ip  = inst.private_ip
        instance_id = inst.id
        spot        = local.nodes_resolved[n].spot
      }
    ]
    grafana_url     = var.deploy_obs ? "http://${aws_instance.obs[0].public_ip}:3000" : ""
    pushgateway_url = var.deploy_obs ? "http://${aws_instance.obs[0].private_ip}:9091" : ""
    obs_public_ip   = var.deploy_obs ? aws_instance.obs[0].public_ip : ""
    obs_private_ip  = var.deploy_obs ? aws_instance.obs[0].private_ip : ""
  }
}

output "grafana_url" {
  description = "Grafana UI URL on the dedicated obs node. Empty when deploy_obs=false."
  value       = var.deploy_obs ? "http://${aws_instance.obs[0].public_ip}:3000" : ""
}

output "pushgateway_url" {
  description = "Pushgateway base URL (VPC-private). Empty when deploy_obs=false."
  value       = var.deploy_obs ? "http://${aws_instance.obs[0].private_ip}:9091" : ""
}

output "grafana_admin_password" {
  description = "Grafana admin password for the obs node. SAVE for login — integration-test clusters only."
  value       = var.deploy_obs ? random_password.grafana_admin[0].result : ""
  sensitive   = true
}

output "bundle_bucket" {
  description = "S3 bucket used to ferry the gossip key + TLS bundle from seed to joiners. Safe to leave empty after the cluster forms."
  value       = aws_s3_bucket.bundle.bucket
}

output "caddy_certs_bucket" {
  description = "Shared Caddy cert storage bucket name. Empty when shared storage is disabled. In BYO mode this echoes the operator-supplied bucket."
  value       = local.caddy_storage_s3.enabled ? local.caddy_storage_s3.bucket : ""
}

output "caddy_certs_encryption_key" {
  description = "Encryption key used by certmagic-s3 to protect cert bytes at rest in S3. SAVE THIS — losing it means the bucket's stored certs become unreadable. Re-export with `terraform output -raw caddy_certs_encryption_key`."
  value       = local.caddy_storage_s3.encryption_key
  sensitive   = true
}

output "ssh_command_seed" {
  description = "Convenience SSH command to the seed (uses default Ubuntu user)."
  value       = "ssh ubuntu@${aws_instance.seed.public_ip}"
}

output "verify_cluster_command" {
  description = "Run this from any node (after bootstrap) to confirm membership."
  # nonsensitive() so the PAT is interpolated into the copy-pasteable command
  # rather than redacted to <sensitive>. This deliberately prints the real token
  # in plan/apply output — acceptable only because these are throwaway
  # integration-test clusters whose PAT is rotated/destroyed with the infra.
  value     = "curl -s -H 'Authorization: Bearer ${nonsensitive(local.pat_token)}' http://127.0.0.1:21212/v1/cluster/members | jq ."
  sensitive = false
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

output "operational_runbooks_dir" {
  description = "Repo-local operator runbooks for restore, lost quorum, image-pull storms, and SLO breaches."
  value       = "setup/runbooks"
}
