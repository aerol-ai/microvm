terraform {
  backend "s3" {
    bucket       = "aerol-terraform-state-923107117704"
    key          = "prod/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
