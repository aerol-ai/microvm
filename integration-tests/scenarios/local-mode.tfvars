# Local-mode integration scenario: one mixed node installed with --local
# because the caps file omits `domain`. The harness opens an SSH tunnel to the
# API on localhost:21212 and runs the same Docker + platform-volume UCs.
#
# AWS access (aws_profile, aws_region, ssh_key_name, ...) is inherited from the
# operator's config/terraform.tfvars, which run.sh chains as the first
# -var-file.
cluster_name = "aerolvm-itest-local-mode"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

# No public Caddy/TLS in local mode, so there is no cert storage to share.
caddy_shared_cert_storage = {
  enabled = false
}

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
