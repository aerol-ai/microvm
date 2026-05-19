###############################################################################
# Cloudflare DNS for the cluster's public ingress.
#
# One A record per ingress-bearing node points at <domain_name>; an optional
# wildcard *.<domain_name> repeats the same set. DNS round-robin gives basic
# failover; for true LB use Cloudflare Spectrum / an NLB and point a single
# A record at it instead (set var.nodes' ingress count appropriately and skip
# this file by clearing var.cloudflare_zone_id... actually the records are
# required-input gated, so just supply a dummy zone if you wire your own LB).
###############################################################################

locals {
  ingress_ip_by_node = {
    for n in local.ingress_node_names :
    n => local.all_instances[n].public_ip
  }
}

resource "cloudflare_record" "apex" {
  for_each = local.ingress_ip_by_node

  zone_id = var.cloudflare_zone_id
  name    = var.domain_name
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} ingress (${each.key})"
}

resource "cloudflare_record" "wildcard" {
  for_each = var.create_wildcard_record ? local.ingress_ip_by_node : {}

  zone_id = var.cloudflare_zone_id
  name    = "*.${var.domain_name}"
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} wildcard ingress (${each.key})"
}
