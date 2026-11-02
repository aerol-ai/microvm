###############################################################################
# Health-checked load balancer in front of the ingress nodes
# (api_load_balancer = "nlb"). Nothing here exists with the default "none".
#
# Why: with DNS round-robin, a node whose sandboxd is down but whose Caddy is
# up still completes the TCP and TLS handshakes, so a client that DNS sends
# there gets 502 and never tries the next A record. One daemon restart on an
# ingress node failed about 1/N of API calls in the bank-readiness live test.
# A load balancer that health-checks each node stops sending it new
# connections instead.
#
# Why an NLB, in TCP passthrough:
#   - Caddy keeps terminating TLS with the DNS-01 wildcard certificates, and
#     caddy-l4 keeps routing sandbox TLS ports by SNI on :443. An ALB would
#     terminate TLS itself and could not carry raw TLS passthrough.
#   - Instance targets with client IP preservation hand Caddy the real client
#     address, exactly as a direct connection does. The audit log, the 401
#     limiter and SB_PAT_SCOPE all key on it; with preservation off, every
#     client would look like the balancer.
#   - Routing Caddy to peer daemons instead is not an option: a peer's :21212
#     treats the caller as a cluster peer, so internet traffic forwarded there
#     would carry the operator token's host scope.
#
# What rides the balancer and what stays direct:
#   - public_http_ports (80, 443) and ssh_gateway_port: one TCP listener each.
#     443 carries the API, every sandbox web URL and every TLS-SNI port. 80
#     is carried so a client sees exactly what the node answers there today.
#     The SSH gateway runs inside sandboxd, so it goes down with the daemon
#     and gains the most.
#   - The raw-TCP host-port pool (l4_port_range, 1,001 ports) stays direct: an
#     NLB has at most 50 listeners, not adjustable. Its addresses move to
#     tcp.<domain> (dns.tf), one A record per ingress node, and every node
#     advertises that name (SB_L4_PUBLIC_HOST). Those connections are relayed
#     by caddy-l4 without sandboxd, so a daemon outage does not break them.
#   - Admin SSH (22) and the API port (21212) are not public and stay so.
#
# Nodes keep their public IPs (the subnet has no NAT gateway) and their
# world-open web rules: with client IP preservation the node sees the
# client's address, not the balancer's, so a security group cannot tell
# balancer traffic from a direct connection. Only DNS stops pointing at them.
###############################################################################

locals {
  api_lb_enabled = var.api_load_balancer == "nlb"

  # Listener ports, as strings for for_each keys.
  api_lb_ports = local.api_lb_enabled ? toset(concat(
    [for p in var.public_http_ports : tostring(p)],
    [tostring(var.ssh_gateway_port)],
  )) : toset([])

  # One target per (listener port, ingress node). Keys stay stable when a
  # node or a port is added, so neither replaces the other attachments.
  api_lb_targets = {
    for pair in setproduct(local.api_lb_ports, local.ingress_node_names) :
    "${pair[0]}/${pair[1]}" => { port = pair[0], node = pair[1] }
  }

  # Raw-TCP exposures are advertised under this name while the domain points
  # at the balancer. "" with the balancer off: the daemon keeps the domain.
  # nodes.tf hands it to EVERY node as SB_L4_PUBLIC_HOST (a sandbox's owner
  # composes its URL, and owners are workers), and the health port to the
  # ingress nodes only; with the balancer off both render nothing, so an
  # existing cluster's user data, and its instances, do not change.
  l4_direct_host = local.api_lb_enabled && local.has_domain ? "tcp.${local.domain_name}" : ""

  # Load balancer and target group names are capped at 32 characters and
  # must be unique in the account and region. The hash keeps two clusters
  # whose names share their first 18 characters apart (every
  # aerolvm-itest-cluster-3-mixed-* scenario does).
  api_lb_name_stub = trim(substr(replace(lower(var.cluster_name), "/[^a-z0-9-]/", "-"), 0, 18), "-")
  api_lb_name_base = "${local.api_lb_name_stub}-${substr(sha1(var.cluster_name), 0, 6)}"

  # Ports a node already listens on; the health listener must avoid them or
  # Caddy fails to start and takes the API with it.
  api_lb_reserved_ports = concat(
    [2019, 8443, 21212, 21215, 53053, var.ssh_gateway_port],
    var.public_http_ports,
    var.cluster_internal_tcp_ports,
  )
}

# A fixed address for <domain>: the A records point here, so the switch from
# per-node records needs no CNAME (Cloudflare refuses a CNAME next to the A
# records it replaces, which would leave the name briefly unresolvable), and
# a customer can allowlist one IP.
resource "aws_eip" "api_lb" {
  count  = local.api_lb_enabled ? 1 : 0
  domain = "vpc"
  tags   = { Name = "${var.cluster_name}-api-lb" }
}

resource "aws_security_group" "api_lb" {
  count       = local.api_lb_enabled ? 1 : 0
  name        = "${var.cluster_name}-api-lb"
  description = "AerolVM ingress load balancer"
  vpc_id      = aws_vpc.this.id
  tags        = { Name = "${var.cluster_name}-api-lb" }
}

resource "aws_security_group_rule" "api_lb_listener" {
  for_each          = local.api_lb_ports
  type              = "ingress"
  security_group_id = aws_security_group.api_lb[0].id
  protocol          = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Public TCP ${each.key} through the load balancer"
}

# The balancer's outbound rules govern what it may send to the targets: the
# client connections on the listener ports and its own health checks.
resource "aws_security_group_rule" "api_lb_to_nodes" {
  for_each                 = local.api_lb_enabled ? toset(concat(tolist(local.api_lb_ports), [tostring(var.api_lb_health_check_port)])) : toset([])
  type                     = "egress"
  security_group_id        = aws_security_group.api_lb[0].id
  protocol                 = "tcp"
  from_port                = tonumber(each.key)
  to_port                  = tonumber(each.key)
  source_security_group_id = aws_security_group.node.id
  description              = "To the ingress nodes on TCP ${each.key}"
}

# The health listener is plain HTTP and only for the balancer: its health
# checks come from the balancer's own addresses, so the node can admit them
# by the balancer's security group and nothing else. admin_allowed_cidrs is
# untouched.
resource "aws_security_group_rule" "node_lb_health" {
  count                    = local.api_lb_enabled ? 1 : 0
  type                     = "ingress"
  security_group_id        = aws_security_group.node.id
  protocol                 = "tcp"
  from_port                = var.api_lb_health_check_port
  to_port                  = var.api_lb_health_check_port
  source_security_group_id = aws_security_group.api_lb[0].id
  description              = "Load balancer health check (Caddy /health listener), from the balancer only"
}

resource "aws_lb" "api" {
  count              = local.api_lb_enabled ? 1 : 0
  name               = "${local.api_lb_name_base}-nlb"
  internal           = false
  load_balancer_type = "network"
  security_groups    = [aws_security_group.api_lb[0].id]
  # One subnet today, so this changes nothing yet. On, every balancer
  # address can reach every ingress node if a second zone is ever added;
  # instance targets keep the client address either way.
  enable_cross_zone_load_balancing = true

  subnet_mapping {
    subnet_id     = aws_subnet.public.id
    allocation_id = aws_eip.api_lb[0].id
  }

  tags = { Name = "${var.cluster_name}-api-lb" }

  lifecycle {
    precondition {
      condition     = local.has_domain && local.has_public_ingress
      error_message = "api_load_balancer = \"nlb\" needs a domain (config/cluster.yml ingress.domain_name) and at least one ingress-capable node: the balancer fronts the ingress nodes' Caddy, which serves the domain."
    }
    precondition {
      condition = (
        !contains(local.api_lb_reserved_ports, var.api_lb_health_check_port)
        && (var.api_lb_health_check_port < var.l4_port_range.start || var.api_lb_health_check_port > var.l4_port_range.end)
      )
      error_message = "api_lb_health_check_port collides with a port the nodes already use (a public or SSH gateway port, the API, Caddy, cluster ports or the raw-TCP pool). Pick another."
    }
  }
}

resource "aws_lb_target_group" "api" {
  for_each    = local.api_lb_ports
  name        = "${local.api_lb_name_base}-${each.key}"
  port        = tonumber(each.key)
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = aws_vpc.this.id

  # Caddy, and through it sandboxd's audit records and limiters, must see the
  # client's address. The default for instance targets, written down so a
  # change to it is a visible decision.
  preserve_client_ip = "true"

  # The probe answers 502 unless caddy-l4 on :443, the HTTPS API site and
  # sandboxd all work. Two failures 5 s apart take a node out: about 10 s,
  # under 20 s with a probe's phase and the balancer's propagation. Two
  # passes bring it back. The timeout is below the interval, as the API
  # requires, and well above a healthy answer (milliseconds on loopback).
  # Every listener's group shares this probe: the daemon behind it also runs
  # the SSH gateway, and a node is either in rotation or not.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(var.api_lb_health_check_port)
    path                = "/health"
    matcher             = "200"
    interval            = 5
    timeout             = 4
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  # A node leaving rotation stops getting NEW connections. Connections it
  # already holds are left alone: sandbox traffic that caddy-l4 relays does
  # not pass through sandboxd and keeps working while the daemon restarts,
  # so resetting it would turn a daemon blip into cut sandbox sessions.
  target_health_state {
    enable_unhealthy_connection_termination = false
  }

  tags = { Name = "${var.cluster_name}-api-${each.key}" }
}

resource "aws_lb_listener" "api" {
  for_each          = local.api_lb_ports
  load_balancer_arn = aws_lb.api[0].arn
  port              = tonumber(each.key)
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api[each.key].arn
  }
}

resource "aws_lb_target_group_attachment" "api" {
  for_each         = local.api_lb_targets
  target_group_arn = aws_lb_target_group.api[each.value.port].arn
  target_id        = local.all_instances[each.value.node].id
  port             = tonumber(each.value.port)
}

# What the integration harness and operators need to find the balancer.
# null with the balancer off.
locals {
  api_lb_summary = local.api_lb_enabled ? {
    ip                = aws_eip.api_lb[0].public_ip
    dns_name          = aws_lb.api[0].dns_name
    l4_host           = local.l4_direct_host
    health_check_port = var.api_lb_health_check_port
    target_group_arns = { for port, tg in aws_lb_target_group.api : port => tg.arn }
  } : null
}
