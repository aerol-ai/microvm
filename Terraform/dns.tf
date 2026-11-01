###############################################################################
# Cloudflare DNS for the cluster's public ingress.
#
# api_load_balancer = "none": one A record per ingress-bearing node points at
# <domain_name>, and an optional wildcard *.<domain_name> repeats the same
# set. DNS round-robin gives basic failover only: a node whose sandboxd is
# down still answers the handshakes, so its share of clients get 502.
#
# api_load_balancer = "nlb": <domain_name> and the wildcard get ONE A record,
# the load balancer's Elastic IP (load_balancer.tf), and tcp.<domain_name>
# keeps one A record per ingress node for the raw-TCP port pool, which an NLB
# cannot carry. A records, not a CNAME to the balancer's DNS name: Cloudflare
# refuses a CNAME on a name that still has A records, so a switch would have
# to delete them first and leave the name unresolvable in between, and
# resolvers would cache that for the zone's negative TTL. A records for the
# same name coexist, so the switch has no gap in either direction.
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

  # What <domain_name> and its wildcard point at. With the balancer off this
  # is ingress_ip_by_node itself, so the records, their keys and their
  # comments are exactly what they were: an existing deployment plans no
  # change.
  ingress_dns_targets = local.api_lb_enabled ? { lb = aws_eip.api_lb[0].public_ip } : local.ingress_ip_by_node
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
  for_each = local.has_domain ? local.ingress_dns_targets : {}

  zone_id = local.effective_zone_id
  name    = local.domain_name
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} ingress (${each.key})"
}

resource "cloudflare_record" "wildcard" {
  for_each = local.has_domain && var.create_wildcard_record ? local.ingress_dns_targets : {}

  zone_id = local.effective_zone_id
  name    = "*.${local.domain_name}"
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = var.cloudflare_proxied
  comment = "AerolVM ${var.cluster_name} wildcard ingress (${each.key})"
}

# Raw-TCP exposures behind the load balancer: tcp://tcp.<domain_name>:<port>
# reaches the ingress nodes directly, as tcp://<domain_name>:<port> did
# before. Never proxied: Cloudflare's proxy does not carry raw TCP. An
# explicit name wins over the wildcard, so it does not resolve to the
# balancer.
resource "cloudflare_record" "l4_direct" {
  for_each = local.l4_direct_host != "" ? local.ingress_ip_by_node : {}

  zone_id = local.effective_zone_id
  name    = local.l4_direct_host
  type    = "A"
  content = each.value
  ttl     = var.cloudflare_record_ttl
  proxied = false
  comment = "AerolVM ${var.cluster_name} raw TCP, direct to ingress (${each.key})"
}
