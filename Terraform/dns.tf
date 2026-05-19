###############################################################################
# Cloudflare DNS for the cluster's public ingress.
#
# One A record per ingress-bearing node points at <domain_name>; an optional
# wildcard *.<domain_name> repeats the same set. DNS round-robin gives basic
# failover; for true LB use Cloudflare Spectrum / an NLB and point a single
# A record at it instead.
#
# Zone resolution: var.cloudflare_zone_id wins if set. Otherwise we derive the
# zone name from var.domain_name by stripping the first label
# ("cluster.example.com" -> "example.com") and look it up via the Cloudflare
# API. This requires Zone:Read on the API token in addition to Zone:DNS:Edit.
# Multi-label TLDs (co.uk, com.au, ...) are not handled — pass
# cloudflare_zone_id explicitly in that case.
###############################################################################

locals {
  ingress_ip_by_node = {
    for n in local.ingress_node_names :
    n => local.all_instances[n].public_ip
  }

  # Strip the leftmost label to get the zone for subdomain inputs.
  # "cluster.example.com" -> "example.com"; "example.com" -> "example.com".
  domain_labels         = split(".", var.domain_name)
  derived_zone_name     = length(local.domain_labels) > 2 ? join(".", slice(local.domain_labels, 1, length(local.domain_labels))) : var.domain_name
  resolve_zone_from_api = var.cloudflare_zone_id == ""
}

data "cloudflare_zones" "lookup" {
  count = local.resolve_zone_from_api ? 1 : 0

  filter {
    name = local.derived_zone_name
  }
}

locals {
  effective_zone_id = (
    local.resolve_zone_from_api
    ? one(data.cloudflare_zones.lookup[0].zones).id
    : var.cloudflare_zone_id
  )
}

resource "cloudflare_record" "apex" {
  for_each = local.ingress_ip_by_node

  zone_id = local.effective_zone_id
  name    = var.domain_name
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} ingress (${each.key})"
}

resource "cloudflare_record" "wildcard" {
  for_each = var.create_wildcard_record ? local.ingress_ip_by_node : {}

  zone_id = local.effective_zone_id
  name    = "*.${var.domain_name}"
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} wildcard ingress (${each.key})"
}
