# A single node installed with wrapped server-key custody on a REAL AWS KMS
# key (plans/customer-key-custody.md §3): Terraform key_custody = "wrapped"
# reaches install.sh --key-custody wrapped. UC-315 checks no plaintext key
# exists and that the node reopens its sealed values after a restart.
cluster_name = "aerolvm-itest-single-node-wrapped-kms"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

caddy_shared_cert_storage = {
  enabled = false
}

secret_kms_enabled     = true
secret_kms_strict_boot = true
key_custody            = "wrapped"

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    spot = true
  }
}
