output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "region" {
  value = var.region
}

output "zones" {
  value = local.zones
}

output "node_role_name" {
  value = aws_iam_role.node.name
}

# The registry the cell's images go to: <account>.dkr.ecr.<region>.amazonaws.com/<name>.
output "ecr_registry" {
  value = length(var.ecr_repos) == 0 ? "" : trimsuffix(aws_ecr_repository.dev[var.ecr_repos[0]].repository_url, "/${var.ecr_repos[0]}")
}
