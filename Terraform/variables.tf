###############################################################################
# Cluster identity
###############################################################################

variable "cluster_name" {
  description = "Logical cluster name. Used to namespace AWS resources and the Cloudflare DNS records."
  type        = string
  default     = "aerolvm"
}

variable "pat_token" {
  description = "Shared SB_PAT_TOKEN used by every node. Same value flows to install.sh and is consumed by cluster forwarding."
  type        = string
  sensitive   = true
}

###############################################################################
# AWS credentials / region
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy the cluster into."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Optional AWS shared-credentials profile name. Empty to use the default chain (env vars, instance role, etc)."
  type        = string
  default     = ""
}

variable "aws_shared_credentials_files" {
  description = "Optional explicit shared-credentials file paths. Empty list to use the default."
  type        = list(string)
  default     = []
}

variable "extra_tags" {
  description = "Additional default tags applied to every AWS resource."
  type        = map(string)
  default     = {}
}

###############################################################################
# Networking
###############################################################################

variable "vpc_cidr" {
  description = "CIDR for the new VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR for the single public subnet that hosts cluster nodes."
  type        = string
  default     = "10.42.1.0/24"
}

variable "availability_zone" {
  description = "AZ for the subnet. Empty string picks the first AZ in the region."
  type        = string
  default     = ""
}

variable "admin_allowed_cidrs" {
  description = "CIDRs allowed to reach SSH (22) and the operator/SDK API (21212)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "public_http_ports" {
  description = "Public TCP ports opened on ingress-bearing nodes. Defaults to 80/443."
  type        = list(number)
  default     = [80, 443]
}

variable "cluster_internal_tcp_ports" {
  description = "Cluster-internal TCP ports (raft / gossip-tcp / internal-mtls). Restricted to the VPC CIDR."
  type        = list(number)
  default     = [7000, 7001, 7002]
}

variable "cluster_internal_udp_ports" {
  description = "Cluster-internal UDP ports (SWIM gossip). Restricted to the VPC CIDR."
  type        = list(number)
  default     = [7001]
}

###############################################################################
# SSH key
###############################################################################

variable "ssh_key_name" {
  description = "Name of an existing EC2 key pair to use. Leave empty to upload ssh_public_key / ssh_public_key_path as a new key pair."
  type        = string
  default     = ""
}

variable "ssh_public_key" {
  description = "SSH public key material. Used only when ssh_key_name is empty AND ssh_public_key_path is empty."
  type        = string
  default     = ""
}

variable "ssh_public_key_path" {
  description = "Path to an SSH public key file. Used only when ssh_key_name is empty."
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

###############################################################################
# AMI / instance defaults
###############################################################################

variable "ami_id" {
  description = "AMI ID for every node. Empty string auto-resolves the latest Canonical Ubuntu 22.04 LTS amd64 in the region."
  type        = string
  default     = ""
}

variable "default_instance_type" {
  description = "Instance type used for any node that does not override it."
  type        = string
  default     = "t3.medium"
}

variable "default_volume_size_gb" {
  description = "Root EBS volume size (GiB) used for any node that does not override it."
  type        = number
  default     = 64
}

variable "default_volume_type" {
  description = "Root EBS volume type (gp3, gp2, io2, ...)."
  type        = string
  default     = "gp3"
}

variable "default_volume_iops" {
  description = "Root EBS volume IOPS for gp3/io2. Ignored for gp2."
  type        = number
  default     = 3000
}

variable "default_volume_throughput" {
  description = "Root EBS volume throughput (MiB/s) for gp3. Ignored otherwise."
  type        = number
  default     = 125
}

###############################################################################
# Cluster topology
#
# Roles recognised by AerolVM (see docs/cluster-setup-step-by-step.mdx):
#   - "server"          : Raft voter, no sandboxes, no public traffic
#   - "worker"          : owns sandboxes, never votes
#   - "ingress"         : holds public route table, never votes, no sandboxes
#   - "worker,ingress"  : edge node (sandboxes + ingress, non-voter)
#   - "server,worker"   : voter + sandboxes
#   - "server,ingress"  : voter + public traffic
#   - "mixed"           : equivalent to "server,worker,ingress" (the 3-node default)
#
# Exactly one node must set seed = true.
###############################################################################

variable "nodes" {
  description = <<-EOT
    Map of node-name => node config. Each entry supports:
      role             (string,  default "mixed")
      seed             (bool,    default false; exactly one node must be true)
      instance_type    (string,  default var.default_instance_type)
      volume_size_gb   (number,  default var.default_volume_size_gb)
      volume_type      (string,  default var.default_volume_type)
      volume_iops      (number,  default var.default_volume_iops)
      volume_throughput(number,  default var.default_volume_throughput)
      ami_id           (string,  default var.ami_id resolved to Ubuntu 22.04)
      with_gvisor      (bool,    default var.default_with_gvisor)
      with_nvidia_gpu  (bool,    default var.default_with_nvidia_gpu)
      with_amd_gpu     (bool,    default var.default_with_amd_gpu)
      idle_timeout_min (number,  default var.default_idle_timeout_min; 0 disables)
      extra_user_data  (string,  default ""; appended to bootstrap.sh)
      tags             (map(string), default {})
  EOT
  type = map(object({
    role              = optional(string, "mixed")
    seed              = optional(bool, false)
    instance_type     = optional(string)
    volume_size_gb    = optional(number)
    volume_type       = optional(string)
    volume_iops       = optional(number)
    volume_throughput = optional(number)
    ami_id            = optional(string)
    with_gvisor       = optional(bool)
    with_nvidia_gpu   = optional(bool)
    with_amd_gpu      = optional(bool)
    idle_timeout_min  = optional(number)
    extra_user_data   = optional(string, "")
    tags              = optional(map(string), {})
  }))
  default = {
    node1 = { role = "mixed", seed = true }
    node2 = { role = "mixed" }
    node3 = { role = "mixed" }
  }

  validation {
    condition     = length([for k, v in var.nodes : k if try(v.seed, false)]) == 1
    error_message = "Exactly one node in var.nodes must have seed = true."
  }

  # Mirror cluster-init.sh + cluster-join.sh validate_node_role(): every role
  # token must be in {server, worker, ingress, mixed}, and "mixed" cannot be
  # combined with other tokens. Catches typos at plan-time instead of at
  # cloud-init time on the instance.
  validation {
    condition = alltrue([
      for k, v in var.nodes : alltrue([
        for tok in split(",", replace(coalesce(v.role, "mixed"), " ", "")) :
        contains(["server", "worker", "ingress", "mixed"], tok)
      ])
    ])
    error_message = "Each node's role must be a comma-separated set of {server, worker, ingress, mixed}. Examples: \"mixed\", \"server\", \"worker,ingress\"."
  }

  validation {
    condition = alltrue([
      for k, v in var.nodes :
      length(split(",", replace(coalesce(v.role, "mixed"), " ", ""))) == 1 ||
      !contains(split(",", replace(coalesce(v.role, "mixed"), " ", "")), "mixed")
    ])
    error_message = "\"mixed\" is shorthand for server,worker,ingress and cannot be combined with other tokens."
  }

  # cluster-init.sh refuses to bootstrap a fresh cluster from a node whose role
  # set lacks "server"/"mixed". Catching it here avoids a failed cloud-init.
  validation {
    condition = alltrue([
      for k, v in var.nodes :
      !try(v.seed, false) ||
      contains(
        split(",", replace(coalesce(v.role, "mixed"), " ", "")),
        "server",
      ) ||
      coalesce(v.role, "mixed") == "mixed"
    ])
    error_message = "The seed node's role must contain \"server\" or equal \"mixed\" (cluster-init.sh refuses to bootstrap from a pure worker/ingress node)."
  }
}

###############################################################################
# Install.sh feature defaults (per-node overrides live in var.nodes)
###############################################################################

variable "default_with_gvisor" {
  description = "Install gVisor runsc and register it as an alternative OCI runtime. Per-node override via nodes[*].with_gvisor."
  type        = bool
  default     = false
}

variable "default_with_nvidia_gpu" {
  description = "Install nvidia-container-toolkit and configure Docker for NVIDIA GPUs. Host must already have NVIDIA drivers."
  type        = bool
  default     = false
}

variable "default_with_amd_gpu" {
  description = "Install AMD ROCm so containers can access AMD GPUs via /dev/kfd and /dev/dri. x86_64 only."
  type        = bool
  default     = false
}

variable "default_idle_timeout_min" {
  description = "Idle auto-stop timeout in minutes for sandboxes (install.sh --idle-timeout-min). 0 disables."
  type        = number
  default     = 0
}

###############################################################################
# Cloudflare DNS
###############################################################################

variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone:DNS:Edit on the target zone."
  type        = string
  sensitive   = true
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for the apex domain (the 'region key' shown on the zone overview page). Leave empty to auto-resolve from domain_name (requires Zone:Read on the API token)."
  type        = string
  default     = ""
}

variable "domain_name" {
  description = "Hostname advertised as the cluster ingress. Both an A record (this name) and a wildcard *.<name> are created and pointed at every ingress-bearing node's public IP."
  type        = string
}

variable "create_wildcard_record" {
  description = "Whether to create a wildcard *.<domain_name> A record alongside the apex."
  type        = bool
  default     = true
}

variable "cloudflare_proxied" {
  description = "Whether the Cloudflare DNS records should be orange-clouded (proxied). Set false for raw TCP ingress / non-HTTP."
  type        = bool
  default     = false
}

variable "cloudflare_record_ttl" {
  description = "TTL for the A records. 1 == automatic (required when proxied)."
  type        = number
  default     = 1
}

###############################################################################
# Bootstrap behavior
###############################################################################

variable "install_script_url" {
  description = "URL of the single-node install.sh."
  type        = string
  default     = "https://github.com/aerol-ai/microvm/releases/latest/download/install.sh"
}

variable "cluster_init_script_url" {
  description = "URL of cluster-init.sh."
  type        = string
  default     = "https://github.com/aerol-ai/microvm/releases/latest/download/cluster-init.sh"
}

variable "cluster_join_script_url" {
  description = "URL of cluster-join.sh."
  type        = string
  default     = "https://github.com/aerol-ai/microvm/releases/latest/download/cluster-join.sh"
}

variable "bundle_bucket_force_destroy" {
  description = "Whether `terraform destroy` may delete the bundle S3 bucket even if it still has objects."
  type        = bool
  default     = true
}

variable "seed_wait_max_seconds" {
  description = "How long a joiner will poll S3 for the seed's gossip key + TLS bundle before giving up."
  type        = number
  default     = 1800
}
