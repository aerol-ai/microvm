# A throwaway EKS cluster for the Kubernetes v2 Phase 0 spikes
# (plans/kubernetes-v2-phase0.md). Nothing here is production shape: one
# region, two zones, public subnets and no NAT gateway, because a spike runs
# for an hour or two and a NAT gateway would be most of its cost.
#
# Every resource carries the aerol:* tags through default_tags, so the EKS
# reaper (../reap.sh) can find and remove anything a crashed run left behind.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      "aerol:purpose" = "k8s-phase0"
      "aerol:owner"   = "itest"
      "aerol:ttl"     = var.ttl
      "aerol:run"     = var.name
    }
  }
}

data "aws_availability_zones" "up" {
  state = "available"
  # EKS will not put a control plane in use1-az3. The zones are also cut to
  # those that offer the worker type (below), so the node group always fits.
  exclude_zone_ids = ["use1-az3"]
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_ec2_instance_type_offerings" "worker" {
  location_type = "availability-zone"
  filter {
    name   = "instance-type"
    values = [var.worker_instance_type]
  }
}

locals {
  # Two zones that both offer the worker type, in a stable order.
  zones = slice(sort(tolist(setintersection(
    toset(data.aws_availability_zones.up.names),
    toset(data.aws_ec2_instance_type_offerings.worker.locations),
  ))), 0, 2)
}

resource "aws_vpc" "this" {
  cidr_block           = "10.80.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.zones[count.index]
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 4, count.index)
  map_public_ip_on_launch = true
  tags = {
    Name                                = "${var.name}-${local.zones[count.index]}"
    "kubernetes.io/cluster/${var.name}" = "shared"
    "kubernetes.io/role/elb"            = "1"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = { Name = var.name }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- IAM ---------------------------------------------------------------

data "aws_iam_policy_document" "eks_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    # SSM, so a spike can read a node's kernel and cgroup tree without SSH keys.
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ])
  role       = aws_iam_role.node.name
  policy_arn = each.value
}

# --- EKS ---------------------------------------------------------------

resource "aws_eks_cluster" "this" {
  name     = var.name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  vpc_config {
    subnet_ids              = aws_subnet.public[*].id
    endpoint_public_access  = true
    endpoint_private_access = true
    public_access_cidrs     = var.api_allowed_cidrs
  }

  depends_on = [aws_iam_role_policy_attachment.cluster]
}

# One small untainted node for the system add-ons (CoreDNS), so the worker
# node can carry the worker taint and hold nothing but the worker pod.
resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = aws_subnet.public[*].id
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = ["t3.medium"]
  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }
  depends_on = [aws_iam_role_policy_attachment.node]
}

resource "aws_eks_node_group" "worker" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "worker-${lower(replace(var.worker_ami_type, "_", "-"))}"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = aws_subnet.public[*].id
  ami_type        = var.worker_ami_type
  instance_types  = [var.worker_instance_type]
  disk_size       = var.worker_disk_gib
  labels          = { "aerolvm.io/pool" = "phase0" }
  taint {
    key    = "aerolvm.io/worker"
    value  = "true"
    effect = "NO_SCHEDULE"
  }
  scaling_config {
    desired_size = var.worker_count
    min_size     = var.worker_count
    max_size     = var.worker_count
  }
  depends_on = [aws_iam_role_policy_attachment.node]
}
