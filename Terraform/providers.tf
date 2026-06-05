provider "aws" {
  region                   = var.aws_region
  profile                  = var.aws_profile != "" ? var.aws_profile : null
  shared_credentials_files = length(var.aws_shared_credentials_files) > 0 ? var.aws_shared_credentials_files : null

  default_tags {
    tags = merge(
      {
        Project   = var.cluster_name
        ManagedBy = "terraform"
      },
      var.extra_tags,
    )
  }
}

provider "cloudflare" {
  # Pulled from config/secrets.yml (cloudflare.api_token) via locals.tf —
  # not from config/terraform.tfvars. Keeps every cluster secret in one
  # gitignored file alongside cluster.pat_token, aocr.*, and fleet.token.
  api_token = local.cloudflare_api_token
}
