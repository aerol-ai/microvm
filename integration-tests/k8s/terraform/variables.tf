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
