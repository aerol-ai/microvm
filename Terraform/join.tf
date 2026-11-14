###############################################################################
# One-line joins (plans/kubectl-style-cluster-ops.md §7, CEO D13).
#
# This is how the module joins nodes. Each node runs the line that
# `aerolvm join-command` prints, through the installer:
#
#   seed:    install.sh ... init --token worker=<t>:0 --token ingress=<t>:0 --token server=<t>:24h
#   others:  install.sh ... join https://<seed>:7003 --token <their role's token>
#
# The servers sign every cert themselves, so nothing is copied between nodes.
#
# Terraform makes one token per role, shaped <6 chars>.<32 chars> of
# [a-z0-9] (kubeadm's shape, longer). Worker and ingress tokens are
# reusable and never expire, so a scale-out weeks later still joins; the
# server token is reusable for 24 hours, enough for the first servers.
# Servers added later get a fresh one from `aerolvm join-command --role
# server`. The tokens live in Terraform state and in user data, like the
# PAT does already. A join token makes a node, and a node gets the
# cluster's keys, so keep the state as safe as the PAT.
#
# one_line_join = false is the old way: an S3 bundle hand-off and a CSR
# signing loop on the seed, run by cluster-init.sh and cluster-join.sh. It
# stays for one release so a cluster built that way keeps its nodes:
# switching changes every node's user data, and a user data change replaces
# the machine. It goes when those scripts leave the release.
###############################################################################

variable "one_line_join" {
  description = "Join nodes with `install.sh ... init|join` and one token per role, made here (the default). false is the old S3 bundle hand-off and the seed's CSR loop, kept for one release for clusters built that way: changing it replaces every node. Needs a release with `sandboxd join` (v0.7.0 or later). A cluster with no domain can't join this way (install.sh --local never joins): set it to false there."
  type        = bool
  default     = true
  # A root that passes null gets the default, not a null the template can't
  # branch on.
  nullable = false
}

# A warning, not an error: a cluster built the old way keeps working, but
# its operator should hear that the path is going away.
check "old_join_mode" {
  assert {
    condition     = var.one_line_join
    error_message = "one_line_join = false joins nodes the old way (an S3 bundle hand-off and a CSR loop on the seed, through cluster-init.sh and cluster-join.sh). It is deprecated and goes away when those scripts leave the release. New clusters: leave one_line_join at its default, true. A running cluster can't switch in place: new user data replaces every node."
  }
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

  # The operator PAT a joiner's user data carries. A one-line worker or
  # ingress joiner gets none: the join answer brings the PAT's hash and the
  # node calls its peers with its cert alone, so a leaked worker or ingress
  # token (it sits in that user data) yields no admin credential. Servers
  # still get the PAT, and the old two-pass join needs it on every node.
  node_pat_token = {
    for name, role in local.node_join_role : name => (var.one_line_join && role != "server" ? "" : local.pat_token)
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
