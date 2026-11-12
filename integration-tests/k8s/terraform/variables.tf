variable "name" {
  description = "Cluster name, also the aerol:run tag. Unique per run."
  type        = string
}

variable "ttl" {
  description = "RFC 3339 time after which the reaper may delete this run's resources."
  type        = string
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "kubernetes_version" {
  # 1.36 is the first release where user namespaces are stable (spike S9).
  type    = string
  default = "1.36"
}

variable "worker_instance_type" {
  type    = string
  default = "m7i.xlarge"
}

variable "worker_ami_type" {
  description = "AL2023_x86_64_STANDARD or BOTTLEROCKET_x86_64."
  type        = string
  default     = "AL2023_x86_64_STANDARD"
}

variable "worker_count" {
  type    = number
  default = 1
}

variable "worker_disk_gib" {
  type    = number
  default = 60
}

variable "api_allowed_cidrs" {
  description = "Who may reach the cluster's API endpoint. run.sh passes this machine's address."
  type        = list(string)
}

variable "worker_release_version" {
  description = "The worker node group's AMI release (e.g. 1.36.5-20261031). Empty takes the latest. S5 starts one behind so it can upgrade."
  type        = string
  default     = ""
}

variable "karpenter" {
  description = "Add what Karpenter needs (spike S5): its controller's role through EKS Pod Identity. cluster.sh installs the chart."
  type        = bool
  default     = false
}

# --- The Phase 2 cell (cell.sh): three zones, servers and gateways on the
# system nodes, workers whose machines keep IMDS out of pods' reach. The
# defaults keep the Phase 0 shape. ---------------------------------------

variable "zone_count" {
  description = "Zones to spread subnets and node groups over (2 for the spikes, 3 for the cell)."
  type        = number
  default     = 2
}

variable "system_count" {
  description = "System nodes: CoreDNS for the spikes; the cell also puts its servers, gateways and operator there."
  type        = number
  default     = 1
}

variable "system_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "worker_imds_hop_limit" {
  description = "IMDS hop limit on worker machines, with IMDSv2 required; 0 keeps the node group's default. The cell sets 1, which aerolvm k8s verify checks (C24)."
  type        = number
  default     = 0
}

variable "ebs_csi" {
  description = "Add the EBS CSI driver, for the cell's server disks."
  type        = bool
  default     = false
}

variable "ecr_repos" {
  description = "ECR repositories for images built inside the cluster (the cell's dev images). Deleted with the cluster, images and all."
  type        = list(string)
  default     = []
}

variable "network_policy" {
  description = "Manage the VPC CNI add-on with network policy turned on, so the chart's NetworkPolicies are enforced (the cell). Off, they are ignored."
  type        = bool
  default     = false
}
