###############################################################################
# One-line joins (plans/kubectl-style-cluster-ops.md §7, CEO D13).
#
# With one_line_join = true, nodes join with the line `aerolvm join-command`
# prints, run through the installer:
#
#   seed:    install.sh ... init --token worker=<t>:0 --token ingress=<t>:0 --token server=<t>:24h
#   others:  install.sh ... join https://<seed>:7003 --token <their role's token>
#
# instead of the S3 bundle hand-off and the seed's CSR signing loop. The
# servers sign every cert themselves, so nothing is copied between nodes.
#
# Terraform makes one token per role, shaped <6 chars>.<32 chars> of
# [a-z0-9] (kubeadm's shape, longer). Worker and ingress tokens are
# reusable and never expire, so a scale-out weeks later still joins; the
# server token is reusable for 24 hours, enough for the first servers.
# Servers added later get a fresh one from `aerolvm join-command --role
# server`. The tokens live in Terraform state and in user data, like the
# PAT does already. Off by default, so every existing deployment renders
# byte for byte as before.
###############################################################################

variable "one_line_join" {
  description = "Join nodes with `install.sh ... join <seed>:7003 --token <t>` (one token per role, made here) instead of the S3 bundle hand-off and the seed's CSR loop. Needs a release with `sandboxd join` (v0.6.12 or later)."
  type        = bool
  default     = false
}

locals {
  join_roles = var.one_line_join ? toset(["server", "worker", "ingress"]) : toset([])

  # The join role each node's token must carry: any role set with server
  # (or mixed) is a server; else worker beats ingress (the same rule as
  # sandboxd's joinRoleOf).
  node_join_role = {
    for name, n in local.nodes_resolved : name => (
      n.role == "mixed" || contains(split(",", replace(n.role, " ", "")), "server") ? "server" :
      contains(split(",", replace(n.role, " ", "")), "worker") ? "worker" : "ingress"
    )
  }
}

resource "random_string" "join_token_id" {
  for_each = local.join_roles
  length   = 6
  upper    = false
  special  = false
}

resource "random_password" "join_token_secret" {
  for_each = local.join_roles
  length   = 32
  upper    = false
  special  = false
}

locals {
  join_tokens = {
    for role in ["server", "worker", "ingress"] : role => (
      var.one_line_join ? "${random_string.join_token_id[role].result}.${random_password.join_token_secret[role].result}" : ""
    )
  }
}
