data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.cluster_name}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.cluster_name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone != "" ? var.availability_zone : data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = { Name = "${var.cluster_name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.cluster_name}-public" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

###############################################################################
# SSH key pair: reuse an existing one if ssh_key_name is set, otherwise upload.
###############################################################################

resource "aws_key_pair" "this" {
  count      = var.ssh_key_name == "" ? 1 : 0
  key_name   = "${var.cluster_name}-key"
  public_key = local.ssh_public_key_material
}

###############################################################################
# Security group. One SG keeps wiring simple; rules below gate by source:
#   - admin (SSH 22, operator API 21212) → var.admin_allowed_cidrs
#   - cluster-internal (7000/7001/7002)  → vpc_cidr
#   - public ingress (80/443 by default) → 0.0.0.0/0, only attached to nodes
#                                          whose role set contains "ingress"
###############################################################################

resource "aws_security_group" "node" {
  name        = "${var.cluster_name}-node"
  description = "AerolVM cluster node SG"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.cluster_name}-node" }
}

resource "aws_security_group_rule" "egress_all" {
  type              = "egress"
  security_group_id = aws_security_group.node.id
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "All egress"
}

resource "aws_security_group_rule" "admin_ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = var.admin_allowed_cidrs
  description       = "SSH from admin CIDRs"
}

resource "aws_security_group_rule" "admin_api" {
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = 21212
  to_port           = 21212
  cidr_blocks       = var.admin_allowed_cidrs
  description       = "Operator + SDK API from admin CIDRs"
}

resource "aws_security_group_rule" "cluster_internal_tcp" {
  for_each          = toset([for p in var.cluster_internal_tcp_ports : tostring(p)])
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
  cidr_blocks       = [var.vpc_cidr]
  description       = "Cluster-internal TCP ${each.key} (raft / gossip / mTLS)"
}

resource "aws_security_group_rule" "cluster_internal_udp" {
  for_each          = toset([for p in var.cluster_internal_udp_ports : tostring(p)])
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "udp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
  cidr_blocks       = [var.vpc_cidr]
  description       = "Cluster-internal UDP ${each.key} (SWIM gossip)"
}

# Public HTTP/HTTPS — opened on every node SG, but only ingress-bearing nodes
# actually answer. Keeping the rule global avoids a second SG; if you want
# strict isolation set var.public_http_ports = [] and add your own SG.
resource "aws_security_group_rule" "public_http" {
  for_each          = local.has_public_ingress ? toset([for p in var.public_http_ports : tostring(p)]) : toset([])
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = tonumber(each.key)
  to_port           = tonumber(each.key)
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Public ingress TCP ${each.key}"
}

# Raw-TCP (L4) sandbox exposures allocate a host port from this pool and serve
# it directly on the ingress node, so the whole range must be publicly reachable.
# Keep var.l4_port_range in sync with SB_L4_PORT_RANGE_START/END on the daemon.
resource "aws_security_group_rule" "public_l4_pool" {
  count             = local.has_public_ingress ? 1 : 0
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = var.l4_port_range.start
  to_port           = var.l4_port_range.end
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Public raw-TCP (L4) exposure pool ${var.l4_port_range.start}-${var.l4_port_range.end}"
}

# Per-sandbox SSH gateway. Distinct from admin SSH (22): this is the public
# Ed25519-keyed gateway clients reach to shell into their sandbox. Keep
# var.ssh_gateway_port in sync with SB_SSH_LISTEN_ADDR on the daemon.
resource "aws_security_group_rule" "public_ssh_gateway" {
  count             = local.has_public_ingress ? 1 : 0
  type              = "ingress"
  security_group_id = aws_security_group.node.id
  protocol          = "tcp"
  from_port         = var.ssh_gateway_port
  to_port           = var.ssh_gateway_port
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "Public per-sandbox SSH gateway ${var.ssh_gateway_port}"
}
