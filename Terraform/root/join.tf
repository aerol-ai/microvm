# The module joins nodes with one line by default (Terraform/join.tf). This
# root keeps the old join as its default instead, because it is what a
# checkout has always run: a cluster built from it before the move has user
# data from the old join, and new user data replaces every machine. So a
# `git pull` and `scripts/terraform.sh apply` leaves that cluster as it is.
#
# For a new cluster from a checkout, set one_line_join = true in
# config/terraform.tfvars. Never flip it on a running cluster.
variable "one_line_join" {
  description = "Join nodes with one line and a token per role (true), or the old S3 bundle hand-off and CSR loop (false, the default here so a cluster built from this checkout keeps its machines). Changing it on a running cluster replaces every node."
  type        = bool
  default     = false
}
