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

# TLS for the receiver.
#
# Enterprise mode REJECTS a plain-http webhook URL ("audit export webhook URL
# must use https when SB_ENTERPRISE_MODE=true"), so S4/S6 cannot use the
# receiver at all without this.
#
# WHY A DNS ALIAS INSTEAD OF THE SEED'S IP: joiners reach the receiver at the
# seed's private IP, but putting that IP in the certificate would make the
# cert depend on aws_instance.seed — and the seed's own user_data has to
# CONTAIN the cert, which is a dependency cycle. A fixed name every node maps
# in /etc/hosts (seed -> 127.0.0.1, joiner -> seed private IP) breaks it: the
# SAN is known at plan time and depends on nothing.
#
# Self-signed and used directly as the trust anchor — nodes get this same PEM
# as SB_AUDIT_EXPORT_WEBHOOK_CA_FILE. A separate CA would buy nothing for one
# throwaway endpoint.
resource "tls_private_key" "audit_receiver" {
  count       = var.audit_receiver_enabled ? 1 : 0
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "audit_receiver" {
  count = var.audit_receiver_enabled ? 1 : 0

  private_key_pem = tls_private_key.audit_receiver[0].private_key_pem
  subject {
    common_name  = local.audit_receiver_host
    organization = "AerolVM integration fixture"
  }
  dns_names             = [local.audit_receiver_host, "localhost"]
  ip_addresses          = ["127.0.0.1"]
  validity_period_hours = 24 * 30
  allowed_uses          = ["key_encipherment", "digital_signature", "server_auth"]
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
  # One name every node resolves through /etc/hosts: the seed to loopback, a
  # joiner to the seed's private IP. Using a name rather than an address is
  # what lets one certificate serve both without depending on the instance.
  audit_receiver_host = "aerol-audit-receiver"

  # https, not http — enterprise rejects a plain-http webhook URL, and one
  # scheme everywhere keeps enterprise and non-enterprise on the same path.
  audit_receiver_endpoint_url = var.audit_receiver_enabled ? "https://${local.audit_receiver_host}:${var.audit_receiver_port}" : ""
  audit_receiver_token_value  = var.audit_receiver_enabled ? random_password.audit_receiver_token[0].result : ""
  audit_receiver_hmac_value   = var.audit_receiver_enabled ? random_password.audit_receiver_hmac[0].result : ""
  audit_receiver_cert_pem     = var.audit_receiver_enabled ? tls_self_signed_cert.audit_receiver[0].cert_pem : ""
  audit_receiver_key_pem      = var.audit_receiver_enabled ? tls_private_key.audit_receiver[0].private_key_pem : ""
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
