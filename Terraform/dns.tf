###############################################################################
# Cloudflare DNS for the cluster's public ingress.
#
# One A record per ingress-bearing node points at <domain_name>; an optional
# wildcard *.<domain_name> repeats the same set. DNS round-robin gives basic
# failover; for true LB use Cloudflare Spectrum / an NLB and point a single
# A record at it instead.
#
# Zone resolution: var.cloudflare_zone_id wins if set. Otherwise we derive the
# zone name from cluster.yml's ingress.domain_name by stripping the first
# label ("cluster.example.com" -> "example.com") and look it up via the
# Cloudflare API. This requires Zone:Read on the API token in addition to
# Zone:DNS:Edit. Multi-label TLDs (co.uk, com.au, ...) are not handled —
# pass cloudflare_zone_id explicitly in that case.
###############################################################################

locals {
  ingress_ip_by_node = {
    for n in local.ingress_node_names :
    n => local.all_instances[n].public_ip
  }

  # Strip the leftmost label to get the zone for subdomain inputs.
  # "cluster.example.com" -> "example.com"; "example.com" -> "example.com".
  domain_labels         = split(".", local.domain_name)
  derived_zone_name     = length(local.domain_labels) > 2 ? join(".", slice(local.domain_labels, 1, length(local.domain_labels))) : local.domain_name
  resolve_zone_from_api = var.cloudflare_zone_id == ""

  # No domain => no public DNS. The integration harness's local-mode scenario
  # runs install.sh --local (no Caddy, localhost API) and must create ZERO
  # Cloudflare records and skip the zone lookup entirely. Prod/cluster always
  # set a domain, so has_domain is true there and every resource below renders
  # exactly as before — a zero-diff change for prod.
  has_domain = local.domain_name != ""
}

data "cloudflare_zones" "lookup" {
  count = local.has_domain && local.resolve_zone_from_api ? 1 : 0

  filter {
    name = local.derived_zone_name
  }
}

locals {
  effective_zone_id = (
    local.resolve_zone_from_api
    ? (length(data.cloudflare_zones.lookup) > 0 ? one(data.cloudflare_zones.lookup[0].zones).id : "")
    : var.cloudflare_zone_id
  )
}

resource "cloudflare_record" "apex" {
  for_each = local.has_domain ? local.ingress_ip_by_node : {}

  zone_id = local.effective_zone_id
  name    = local.domain_name
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} ingress (${each.key})"
}

resource "cloudflare_record" "wildcard" {
  for_each = local.has_domain && var.create_wildcard_record ? local.ingress_ip_by_node : {}

  zone_id = local.effective_zone_id
  name    = "*.${local.domain_name}"
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} wildcard ingress (${each.key})"
}
