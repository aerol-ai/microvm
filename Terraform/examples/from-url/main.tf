# An AerolVM cluster on AWS from the module, used by URL. No checkout of the
# repo is needed: copy this folder, fill in config/, then
#
#   terraform init
#   terraform apply
#
# What you need next to this file:
#   config/cluster.yml   your cluster settings (the one here is a start)
#   config/secrets.yml   copy config/secrets.example.yml and fill it in
#
# Nodes join with one line: the seed runs `sandboxd init` with one join
# token per role, made by the module, and every other node runs
# `sandboxd join` with its role's token. Worker and ingress tokens never
# expire, so adding a worker to `nodes` later still joins. Add a server later
# with a fresh token from `aerolvm join-command --role server`.
#
# The join tokens are in the Terraform state. A join token can make a node,
# and a node gets the cluster's keys, so keep the state as safe as the
# cluster's admin token: an encrypted backend with tight access.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }

  # Keep the state somewhere safe and shared. For S3:
  #
  # backend "s3" {
  #   bucket       = "my-terraform-state"
  #   key          = "aerolvm/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

variable "aws_region" {
  description = "AWS region for the cluster."
  type        = string
  default     = "us-east-1"
}

variable "admin_allowed_cidrs" {
  description = "Your office or VPN ranges. Only these reach SSH and the API from outside the VPC."
  type        = list(string)
}

variable "ssh_key_name" {
  description = "An EC2 key pair that already exists in the region, for SSH to the nodes."
  type        = string
}

locals {
  cluster_name = "aerolvm"
  config_dir   = "${path.module}/config"
  secrets      = sensitive(yamldecode(file("${local.config_dir}/secrets.yml")))
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = local.cluster_name
      ManagedBy = "terraform"
    }
  }
}

provider "cloudflare" {
  api_token = local.secrets.cloudflare.api_token
}

module "aerolvm" {
  # Pin a release tag. Upgrade the cluster's software with
  # `aerolvm upgrade apply`, not by changing this ref: a new ref can change
  # user data, and new user data replaces the machines.
  source = "git::https://github.com/aerol-ai/microvm//Terraform?ref=v0.7.0"

  cluster_name        = local.cluster_name
  aws_region          = var.aws_region
  config_dir          = local.config_dir
  admin_allowed_cidrs = var.admin_allowed_cidrs
  ssh_key_name        = var.ssh_key_name

  default_instance_type = "t3.large"

  nodes = {
    server-1  = { role = "server", seed = true }
    server-2  = { role = "server" }
    server-3  = { role = "server" }
    ingress-1 = { role = "ingress" }
    worker-1  = { role = "worker", instance_type = "c6i.xlarge", volume_size_gb = 200 }
    worker-2  = { role = "worker", instance_type = "c6i.xlarge", volume_size_gb = 200 }
  }
}

output "api_base_url" {
  value = module.aerolvm.api_base_url
}

output "nodes" {
  value = module.aerolvm.nodes
}

output "ssh_command_seed" {
  value = module.aerolvm.ssh_command_seed
}
