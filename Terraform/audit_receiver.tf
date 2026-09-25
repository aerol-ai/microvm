###############################################################################
# Audit receiver fixture (plans/integration-test-security.md §6.4)
#
# Runs on the SEED. §6.4 puts it on the ingress node for hetero; the seed is
# the only node every topology has, and joiners already know its private IP
# from the bootstrap rendezvous, so seed-hosting works for every scenario
# without a second discovery mechanism.
###############################################################################

# Generated, never hardcoded in a scenario file: these authenticate audit
# evidence, and a shared constant in a committed tfvars would be a credential
# in git that every scenario reuses.
resource "random_password" "audit_receiver_token" {
  count   = var.audit_receiver_enabled ? 1 : 0
  length  = 40
  special = false
}

resource "random_password" "audit_receiver_hmac" {
  count   = var.audit_receiver_enabled ? 1 : 0
  length  = 48
  special = false
}

# VPC-internal only. The receiver holds the fleet's audit evidence and has no
# TLS and no real authz beyond a bearer token, so it must never be reachable
# from admin_allowed_cidrs, let alone the internet.
resource "aws_security_group_rule" "audit_receiver" {
  count = var.audit_receiver_enabled ? 1 : 0

  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = var.audit_receiver_port
  to_port           = var.audit_receiver_port
  cidr_blocks       = [var.vpc_cidr]
  description       = "Audit receiver fixture (VPC-internal)"
}

locals {
  # Joiners reach the receiver over the seed's private IP; the seed itself uses
  # loopback, which also means the seed keeps exporting if the SG rule is ever
  # wrong — a failure that would otherwise look like "export is broken" rather
  # than "joiners cannot reach the receiver".
  audit_receiver_seed_endpoint = var.audit_receiver_enabled ? "http://127.0.0.1:${var.audit_receiver_port}" : ""
  audit_receiver_token_value   = var.audit_receiver_enabled ? random_password.audit_receiver_token[0].result : ""
  audit_receiver_hmac_value    = var.audit_receiver_enabled ? random_password.audit_receiver_hmac[0].result : ""
}

output "audit_receiver" {
  description = "Coordinates the integration suite needs to read the receiver back."
  value = var.audit_receiver_enabled ? {
    port  = var.audit_receiver_port
    token = random_password.audit_receiver_token[0].result
    # Reachable from the suite only via SSH to the seed; not exposed publicly.
    probe_path = "/_probe"
    chaos_path = "/_chaos/fail"
  } : null
  sensitive = true
}
