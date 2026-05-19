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
  api_token = var.cloudflare_api_token
}
