# Multi-Node Cert Sharing (S3-backed Caddy storage)

Opt-in feature for clusters with **10+ ingress-bearing nodes**. Lets one node
issue and renew the wildcard cert via Let's Encrypt while every other node
reads the same cert from S3 — sidestepping the rate limits that bite when
many independent Caddys race for the same `*.<domain>` cert.

When to pick this:

- You run a cluster with 10 or more ingress nodes (`role` containing
  `ingress`, `edge`, or `mixed`).
- You've hit (or are close to hitting) Let's Encrypt's
  5-duplicate-certificates-per-week or 50-certificates-per-week-per-
  registered-domain limits.
- You want one ACME issuance per cluster, not N.

When **not** to pick this:

- Single-node deployment ([`single-node.md`](./single-node.md)) — no
  contention exists.
- Small clusters (≤5 ingress nodes). The independent-issuance model in
  [`cluster.md`](./cluster.md) is simpler and fits inside the rate limits.
- Cluster does not use a wildcard cert. Shared storage only matters when
  there is a wildcard to share.

This feature does NOT change SDK behaviour, sandbox URL shape, or the wire
protocol. End users see no difference.

---

## How it works

```
+----------------+      DNS-01 once per renewal   +----------------+
| 1 winning node | -----------------------------> | Let's Encrypt  |
+----------------+ <----------------------------- +----------------+
        |          cert + private key
        |
        | PUT (AES-256-encrypted)
        v
+-----------------------------+
| S3 bucket (TF-mgmt or BYO)  | <-- distributed lock during ACME
+-----------------------------+
        ^
        | GET (every Caddy reads at boot + on cache miss)
        |
+----------------+ +----------------+ +----------------+
| ingress node 1 | | ingress node 2 | | ingress node N |
+----------------+ +----------------+ +----------------+
```

Locking and leader election are handled by `certmagic-s3` using S3
conditional writes — there is no orchestration code on the AerolVM side.

The bucket holds two cert objects (`<domain>` and `*.<domain>`) plus
account-key metadata. Cert files are tiny (~5 KB each); S3 storage and
request costs are negligible.

---

## Two modes

### Managed mode (Terraform creates the bucket)

The default when you flip `enabled = true`. Terraform owns the bucket, the
IAM grants, and auto-generates the encryption key.

In `terraform.tfvars`:

```hcl
caddy_shared_cert_storage = {
  enabled = true
}
```

Then `terraform apply`. Outputs you should grab and store securely:

```bash
terraform output caddy_certs_bucket
terraform output -raw caddy_certs_encryption_key  # SAVE THIS
```

The encryption key lives in Terraform state. Copy it into your secrets
manager (1Password, AWS Secrets Manager, Vault) — losing it makes existing
stored certs unrecoverable.

### BYO mode (you bring an existing bucket)

Use when:

- The bucket already exists.
- You want it in a different AWS account.
- You want to use a non-AWS S3-compatible store (Cloudflare R2, MinIO,
  Backblaze B2).

In `terraform.tfvars`:

```hcl
caddy_shared_cert_storage = {
  enabled        = true
  mode           = "byo"
  bucket         = "my-caddy-certs"
  region         = "us-east-1"
  encryption_key = "<base64 of 32 random bytes>"   # generate once
}
```

Generate the encryption key once for the whole cluster:

```bash
openssl rand -base64 32
```

If the bucket is **in the same AWS account** and your EC2 instance role
can already reach it, leave `access_key` / `secret_key` empty —
Terraform attaches an IAM policy granting the cluster's instance roles
R/W on the prefix.

If the bucket is **elsewhere** (cross-account, R2, MinIO), supply static
keys:

```hcl
caddy_shared_cert_storage = {
  enabled        = true
  mode           = "byo"
  bucket         = "my-caddy-certs"
  region         = "auto"
  endpoint       = "https://<account-id>.r2.cloudflarestorage.com"
  access_key     = "<r2-access-key-id>"
  secret_key     = "<r2-secret-access-key>"
  encryption_key = "<base64 of 32 random bytes>"
}
```

---

## Required S3 bucket policy (BYO mode)

When you supply your own bucket, grant the nodes' principals the following
operations on the prefix you chose (default `caddy/`):

| Action | Resource |
|---|---|
| `s3:GetObject` | `<bucket-arn>/<prefix>/*` |
| `s3:PutObject` | `<bucket-arn>/<prefix>/*` |
| `s3:DeleteObject` | `<bucket-arn>/<prefix>/*` |
| `s3:HeadObject` | `<bucket-arn>/<prefix>/*` |
| `s3:ListBucket` | `<bucket-arn>` |

For an existing-bucket-in-same-account setup with TF doing the IAM, you
don't need to write a bucket policy — Terraform attaches the policy to the
cluster's instance roles.

For R2 / MinIO, scope the credentials similarly via the provider's own
ACL system.

---

## Without Terraform (bare metal install)

`scripts/install.sh` also accepts the flags directly:

```bash
sudo ./install.sh \
  --domain sandbox.example.com \
  --dns-provider cloudflare \
  --dns-api-token <token> \
  --caddy-storage-s3 \
  --caddy-storage-s3-bucket my-caddy-certs \
  --caddy-storage-s3-region us-east-1 \
  --caddy-storage-s3-encryption-key "$(cat /etc/caddy-shared.key)"
```

Pre-conditions:

- `--domain` and `--dns-provider` are required. Shared storage only
  matters in DNS-01 wildcard mode.
- The encryption key MUST be identical on every node. Generate once,
  distribute via your existing secret-distribution mechanism (e.g.
  cluster bootstrap, configuration management, secrets manager).
- For non-EC2 hosts or buckets that don't honour the AWS default
  credential chain, also pass
  `--caddy-storage-s3-access-key` / `--caddy-storage-s3-secret-key`.
- For non-AWS endpoints, pass `--caddy-storage-s3-endpoint`.

`install.sh --help` lists the full flag set.

---

## Verification

After applying, check from any node:

```bash
sudo journalctl -u caddy --since '5 minutes ago' | grep -E 'storage|certificate'
```

Look for `loaded certificate from storage` on every node except one, which
should show ACME activity for the first issuance. List the bucket:

```bash
aws s3 ls s3://<bucket>/<prefix>/ --recursive
```

You should see exactly one set of cert files, not one per node.

Then try the API endpoint from outside the cluster against each ingress
node's public IP — every node should serve the same valid cert:

```bash
curl --resolve sandbox.example.com:443:<node-ip> https://sandbox.example.com/health
```

---

## Operational notes

### Encryption key loss

The key is the only way to decrypt the cert + private key bytes in S3. If
it's lost:

1. Empty the bucket (or change the `prefix`).
2. Generate a new key, distribute, redeploy.
3. The first node up will re-issue against Let's Encrypt — this counts
   against the weekly cert-issuance ceiling, so don't do it casually.

**Mitigation:** copy `terraform output -raw caddy_certs_encryption_key`
into your secrets manager immediately after the first apply, and treat
it like any other root credential.

### Key rotation

`certmagic-s3` does not support in-place encryption-key rotation. Rotating
means re-issuing certs: empty the prefix, set the new key on every node,
restart Caddy in sequence. Plan around the Let's Encrypt rate limit.

### Renewal storms

With shared storage there is no renewal storm — only the lock holder
performs ACME. Other nodes pick up the rotated cert from S3 on their next
read (certmagic re-reads on cache expiry).

### Toggling the feature on a live cluster

Flipping `enabled = false → true` forces a `user_data_replace_on_change`
recycle of every node. Plan this as a rolling change (or schedule it
during a maintenance window) — Terraform will report the recreate in
the plan.

### Cost

- S3 storage: ~10 KB per cert × 1 cert set per cluster — sub-cent.
- S3 requests: a few PUT/GET operations per renewal cycle, plus one
  GET per Caddy startup per node — also sub-cent at any realistic
  cluster size.

The economic cost of this feature is the operator's time to manage the
encryption key, not the bucket itself.

---

## Reference

- Plugin: [`github.com/ss098/certmagic-s3`](https://github.com/ss098/certmagic-s3)
- install.sh flags: see `scripts/install.sh --help`
- Terraform variable schema: see `Terraform/variables.tf` →
  `caddy_shared_cert_storage`
- Cluster topology / when this becomes necessary:
  [`plans/cluster-criticial-thinking/02-assumptions-challenged.md`](../plans/cluster-criticial-thinking/02-assumptions-challenged.md) §A10
