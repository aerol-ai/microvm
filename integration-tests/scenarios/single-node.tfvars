# Single-node integration scenario: one mixed node with public domain + TLS.
# This is the lowest-cost public deployment shape and runs the Docker,
# networking, custom-domain-gated, and platform-volume UCs.
#
# AWS access (aws_profile, aws_region, ssh_key_name, ...) is inherited from the
# operator's config/terraform.tfvars, which run.sh chains as the first
# -var-file.
cluster_name = "aerolvm-itest-single-node"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

# A single node has nothing to share certs WITH; disable the prod-inherited
# managed S3 cert bucket so the run doesn't create one. Cluster scenarios re-enable it.
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
