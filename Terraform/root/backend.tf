# Only a root module may name a backend, so this lives here and not in the
# module (Terraform/), which is used by URL. The bucket and key are the ones
# this checkout has always used, so `scripts/terraform.sh` keeps the same
# state. The integration harness points the key elsewhere with
# -backend-config.
terraform {
  backend "s3" {
    bucket       = "aerol-terraform-state-923107117704"
    key          = "prod/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
