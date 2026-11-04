# A single node installed with wrapped server-key custody on a REAL AWS KMS
# key (plans/customer-key-custody.md §3): Terraform key_custody = "wrapped"
# reaches install.sh --key-custody wrapped. UC-315 checks no plaintext key
# exists and that the node reopens its sealed values after a restart. UC-316
# replaces the node's root disk and restores a backup onto the fresh install.
cluster_name = "aerolvm-itest-single-node-wrapped-kms"

extra_tags = {
  itest = "true"
  ttl   = "4"
}

default_instance_type  = "t3.medium"
default_volume_size_gb = 40

# Shared: UC-316's fresh disk runs the bootstrap again, and a second
# certificate for the same names in one run would spend Let's Encrypt's
# weekly duplicate-certificate allowance.
caddy_shared_cert_storage = {
  enabled = true
}

secret_kms_enabled     = true
secret_kms_strict_boot = true
key_custody            = "wrapped"

nodes = {
  node1 = {
    role = "mixed"
    seed = true
    # On demand: UC-316 replaces its root volume.
    spot = false
  }
}
