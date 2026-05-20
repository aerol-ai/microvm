# AerolVM cluster on AWS — Terraform

Spawns a complete AerolVM cluster on EC2 in one `terraform apply`:

- a VPC + public subnet + IGW + security group with the cluster-internal
  ports (`7000/TCP`, `7001/TCP+UDP`, `7002/TCP`) and public ingress
  (`80`, `443`) wired per the rules in
  [`../docs/src/content/docs/cluster-setup-step-by-step.mdx`](../docs/src/content/docs/cluster-setup-step-by-step.mdx),
- N EC2 instances, each sized + roled independently
  (`server`, `worker`, `ingress`, `worker,ingress`, `server,worker`,
  `server,ingress`, or `mixed`),
- an S3 bucket the seed uses to hand its gossip key + TLS bundle to joiners,
- IAM instance profiles that grant only what each role needs on that bucket,
- Cloudflare `A` + wildcard `A` records pointing at every ingress-bearing
  node's public IP.

## Prereqs

- Terraform ≥ 1.5
- AWS credentials (env, profile, or instance role) with EC2 / VPC / IAM / S3
  rights in `aws_region`
- A Cloudflare API token with `Zone:DNS:Edit` on the target zone (add
  `Zone:Read` if you want to skip `cloudflare_zone_id` and let Terraform
  resolve it from `domain_name`)
- An SSH public key (the default reads `~/.ssh/id_rsa.pub`; pass
  `ssh_key_name` to reuse an existing EC2 keypair instead)
- A shared `SB_PAT_TOKEN` value — the same string is installed on every node

## Quick start

```bash
cp terraform.tfvars.example terraform.tfvars
# edit pat_token, cloudflare_*, domain_name, optionally tweak `nodes`
terraform init
terraform apply
```

Outputs include every node's public IP, the seed's SSH command, and the
verify-cluster `curl`. They also include Prometheus scrape targets for
`/v1/metrics` on every node's private API address. Watch one node's bootstrap
with:

```bash
ssh ubuntu@<public-ip> sudo tail -f /var/log/aerolvm-bootstrap.log
```

Once joiners finish (`[bootstrap] complete`), confirm membership from any
node:

```bash
ssh ubuntu@<any-ip> \
  curl -s -H "Authorization: Bearer $SB_PAT_TOKEN" \
       http://127.0.0.1:21212/v1/cluster/members | jq .
```

## Configuring nodes

`var.nodes` is a map. The key is the node's logical name (used in tags + DNS
comments); the value is a config object. Every field except `role` has a
default — set `seed = true` on exactly one entry:

```hcl
nodes = {
  s1 = { role = "server",          seed = true,  instance_type = "t3.small" }
  s2 = { role = "server",                         instance_type = "t3.small" }
  s3 = { role = "server",                         instance_type = "t3.small" }
  w1 = { role = "worker",          instance_type = "c6i.xlarge", volume_size_gb = 500 }
  w2 = { role = "worker",          instance_type = "c6i.xlarge", volume_size_gb = 500 }
  e1 = { role = "worker,ingress",  instance_type = "t3.large"  }
  e2 = { role = "worker,ingress",  instance_type = "t3.large"  }
}
```

Per-node fields:

| Field               | Default                          | Notes                                            |
|---------------------|----------------------------------|--------------------------------------------------|
| `role`              | `"mixed"`                        | `server` / `worker` / `ingress` / `mixed` or csv |
| `seed`              | `false`                          | exactly one node; role must contain `server`     |
| `instance_type`     | `var.default_instance_type`      |                                                  |
| `volume_size_gb`    | `var.default_volume_size_gb`     |                                                  |
| `volume_type`       | `var.default_volume_type`        |                                                  |
| `volume_iops`       | `var.default_volume_iops`        | gp3/io1/io2 only                                 |
| `volume_throughput` | `var.default_volume_throughput`  | gp3 only                                         |
| `ami_id`            | latest Ubuntu 22.04 LTS amd64    |                                                  |
| `with_gvisor`       | `var.default_with_gvisor`        | adds `--with-gvisor` to install.sh               |
| `with_nvidia_gpu`   | `var.default_with_nvidia_gpu`    | adds `--with-nvidia-gpu` (driver must be loaded) |
| `with_amd_gpu`      | `var.default_with_amd_gpu`       | adds `--with-amd-gpu` (x86_64 only)              |
| `idle_timeout_min`  | `var.default_idle_timeout_min`   | sandbox auto-stop minutes; 0 disables            |
| `extra_user_data`   | `""`                             | shell, appended to bootstrap                     |
| `tags`              | `{}`                             |                                                  |

### Role rules (validated at plan time, mirrors `cluster-init.sh` / `cluster-join.sh`)

- Each comma token must be in `{server, worker, ingress, mixed}`.
- `mixed` (shorthand for `server,worker,ingress`) cannot be combined with other tokens.
- The seed node's role must contain `server` or equal `mixed` — `cluster-init.sh` refuses to bootstrap from a pure `worker` / `ingress` / `worker,ingress` node.

## How bootstrap works

Each instance's `user_data` (rendered from
[`templates/bootstrap.sh.tftpl`](./templates/bootstrap.sh.tftpl)) runs in three
phases:

1. **`install.sh`** with `--pat-token <shared> --domain <domain_name>
   --dns-provider cloudflare --dns-api-token <cloudflare_api_token>` so the
   per-node Caddy gets a real wildcard cert via Let's Encrypt DNS-01. Optional
   `--with-gvisor` / `--with-nvidia-gpu` / `--with-amd-gpu` /
   `--idle-timeout-min` are appended from per-node flags. If `domain_name` is
   empty the DNS-01 args are dropped and install.sh falls back to IP/path mode
   with no TLS.
2. **Seed only — `cluster-init.sh`** with `--role <seed-role>
   --ingress-advertise-host <domain_name> --gossip-key <generated>
   --tls-bundle-out /tmp/aerolvm-tls-bundle.tar.gz`. The seed then uploads
   `gossip-key.txt` + `aerolvm-tls-bundle.tar.gz` to the per-cluster S3 bucket.
3. **Every other node — `cluster-join.sh`** polls the S3 bucket
   (`seed_wait_max_seconds`, default 30 min), downloads both artifacts, then
   runs `cluster-join.sh --role <its-role> --ingress-advertise-host
   <domain_name> --gossip-key <…> --peers <seed-private-ip>:7001 --tls-bundle
   /tmp/aerolvm-tls-bundle.tar.gz`.
4. **Operational env** is appended to `/etc/sandboxd/cluster.env` on every
   node: OTEL metrics settings and image-pull storm controls. The bootstrap
   then restarts sandboxd once so those env vars are active immediately.

The S3 bucket is private, SSE-encrypted, and `force_destroy = true` by
default so `terraform destroy` doesn't fail on leftover objects. Flip
`bundle_bucket_force_destroy = false` if you want belt-and-braces.

## Observability and pull-storm controls

Prometheus scraping is always available at `GET /v1/metrics` on each node's
API port. The `prometheus_scrape_targets` output returns private-IP targets
for a Prometheus running inside the VPC:

```hcl
otel_metrics_endpoint = "http://otel-collector.internal:4318/v1/metrics"
otel_metrics_interval = "30s"
otel_service_name     = "sandboxd"

image_pull_max_concurrent  = 4
image_pull_failure_backoff = "30s"
```

The Grafana dashboard JSON to import is
`../setup/grafana/sandboxd-slo-dashboard.json`.

## Cloudflare DNS

`cloudflare_zone_id` is optional. If you leave it empty, Terraform strips the
first label off `domain_name` (so `cluster.example.com` → `example.com`) and
looks the zone up via the Cloudflare API — that requires `Zone:Read` on the
token. Set it explicitly if you'd rather skip the lookup or if the apex is a
multi-label TLD like `co.uk` (the strip-one-label heuristic doesn't handle
those). The value to paste is the "Cloudflare region key" shown on the zone
overview page.

For each ingress-bearing node, two records are created:

- `<domain_name>` → public IP (one record per ingress node, DNS RR)
- `*.<domain_name>` → same set (skip with `create_wildcard_record = false`)

Set `cloudflare_proxied = true` to orange-cloud them. Note: Cloudflare only
proxies HTTP(S); leave it `false` for raw TCP ingress.

## Files

| File                        | Purpose                                   |
|-----------------------------|-------------------------------------------|
| `versions.tf`               | Required providers + Terraform version    |
| `providers.tf`              | AWS + Cloudflare provider config          |
| `variables.tf`              | Every knob, with defaults                 |
| `locals.tf`                 | Node normalisation + ingress derivation   |
| `network.tf`                | VPC, subnet, IGW, SG rules, AMI lookup    |
| `iam.tf`                    | Bundle S3 bucket + seed/joiner profiles   |
| `nodes.tf`                  | Seed `aws_instance` + joiner `for_each`   |
| `dns.tf`                    | Cloudflare A + wildcard records           |
| `outputs.tf`                | Node summary, ingress IPs, SSH help       |
| `templates/bootstrap.sh.tftpl` | Single user_data template (seed/joiner) |
| `terraform.tfvars.example`  | Drop-in starter config                    |

## Tear-down

```bash
terraform destroy
```

This deletes the VPC, instances, security group, IAM profiles, S3 bundle
bucket (force-destroyed), and the Cloudflare records.
