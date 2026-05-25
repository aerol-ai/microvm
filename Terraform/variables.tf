###############################################################################
# Cluster identity
###############################################################################

variable "cluster_name" {
  description = "Logical cluster name. Used to namespace AWS resources and the Cloudflare DNS records."
  type        = string
  default     = "aerolvm"
}

# pat_token has moved to ../config/secrets.yml as cluster.pat_token. It's a
# cluster-wide secret (every node uses the same value), so the shared SoT
# pattern applies — Ansible can roll a rotated value into /etc/sandboxd at
# day-2 from the same file. See locals.tf:pat_token.

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
# Observability and operational hardening
###############################################################################

# Observability, image-pull controls, image-GC, mirror/auto-import config —
# everything except secrets — lives in ../config/cluster.yml. That file is
# the single source of truth both Terraform and Ansible read from, so
# day-0 (terraform apply) and day-2 (configure-ops.yml) cannot drift.
# See locals.tf:cluster_ops and resource.terraform_data.validate_cluster_ops.

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

# domain_name and acme_email have moved to ../config/cluster.yml under the
# ingress: section. Both feed into Caddy / DNS / sandboxd at runtime, so
# Ansible reading from the same source lets day-2 reconfig stay in sync with
# day-0 provisioning. See locals.tf:domain_name and locals.tf:acme_email.

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

variable "caddy_certs_bucket_force_destroy" {
  description = "Whether `terraform destroy` may delete the managed Caddy cert S3 bucket even if it still has object versions."
  type        = bool
  default     = false
}

variable "seed_wait_max_seconds" {
  description = "How long a joiner will poll S3 for the seed's gossip key + TLS bundle before giving up."
  type        = number
  default     = 1800
}

variable "caddy_shared_cert_storage" {
  description = <<-EOT
    Shared S3-backed Caddy cert storage. Lets every ingress node read the
    wildcard cert issued by one node, sidestepping Let's Encrypt rate
    limits when the cluster has 10+ ingress-bearing nodes. Disabled by
    default; each node issues its own cert when off (the existing
    behaviour, fine up to a handful of nodes).

    mode = "managed": Terraform creates a dedicated S3 bucket + IAM
                      grants, and generates the encryption_key
                      automatically (stored in TF state).
    mode = "byo":     Operator supplies bucket / region / encryption_key
                      (and optional creds for non-EC2-instance-role auth).
                      Useful when the bucket already exists, lives in
                      another account, or is Cloudflare R2 / MinIO.

    encryption_key must be a base64-encoded 32-byte secret and identical
    on every node. Losing it makes existing stored certs unreadable.
    See setup/multi-node-cert-sharing.md.
  EOT
  type = object({
    enabled        = bool
    mode           = optional(string, "managed")
    bucket         = optional(string, "")
    region         = optional(string, "")
    endpoint       = optional(string, "")
    prefix         = optional(string, "caddy")
    access_key     = optional(string, "")
    secret_key     = optional(string, "")
    encryption_key = optional(string, "")
  })
  default = {
    enabled = false
  }

  validation {
    condition     = !var.caddy_shared_cert_storage.enabled || contains(["managed", "byo"], var.caddy_shared_cert_storage.mode)
    error_message = "caddy_shared_cert_storage.mode must be either \"managed\" or \"byo\"."
  }

  validation {
    condition = (
      !var.caddy_shared_cert_storage.enabled
      || var.caddy_shared_cert_storage.mode != "byo"
      || (
        var.caddy_shared_cert_storage.bucket != ""
        && var.caddy_shared_cert_storage.region != ""
        && var.caddy_shared_cert_storage.encryption_key != ""
      )
    )
    error_message = "When caddy_shared_cert_storage.mode = \"byo\", bucket, region, and encryption_key are all required."
  }
}

###############################################################################
# AOCR (Aerol OCI Registry) — Authenticated mirror + auto-import (Phase 4 F17-F21)
#
# All AOCR config has moved out of variables.tf:
#   - Non-secret knobs (mirror host, upstreams, auto_import toggle, cluster_id,
#     hooks_url, retention/timeout) live in ../config/cluster.yml.
#   - Secrets (upstream_wrap_key, cluster_pat) live in ../config/secrets.yml.
# Both files are read at the top of locals.tf and Ansible's configure-ops.yml,
# so day-0 (terraform apply) and day-2 (ansible-playbook) cannot drift.
# See sandbox-library/AUTHENTICATED_MIRROR.md for the full operator reference.
###############################################################################
