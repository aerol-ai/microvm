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
