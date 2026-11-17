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

# The bank drills (bank.tf, teardown.tf); empty without them.
output "audit_role_arn" {
  value = var.bank_drills ? aws_iam_role.audit[0].arn : ""
}

output "witness_bucket" {
  value = var.bank_drills ? aws_s3_bucket.witness[0].bucket : ""
}

output "export_bucket" {
  value = var.bank_drills ? aws_s3_bucket.export[0].bucket : ""
}

output "vpc_id" {
  value = aws_vpc.this.id
}

output "teardown_lambda_arn" {
  value = local.teardown ? aws_lambda_function.teardown[0].arn : ""
}

output "scheduler_role_arn" {
  value = local.teardown ? aws_iam_role.scheduler[0].arn : ""
}
