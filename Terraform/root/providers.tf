# Provider settings belong to the root module: a module that configures its
# own providers can't be used with count, for_each or depends_on. The values
# are the ones the module used to set for itself, so every resource keeps
# the same tags.
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
  # From config/secrets.yml (cloudflare.api_token), the same file the module
  # reads, so every cluster secret stays in one gitignored file.
  api_token = local.cloudflare_api_token
}

locals {
  config_dir           = var.config_dir != "" ? var.config_dir : "${path.module}/../../config"
  cloudflare_api_token = sensitive(yamldecode(file("${local.config_dir}/secrets.yml")).cloudflare.api_token)
}
