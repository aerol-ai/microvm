# AerolVM cluster on AWS - Terraform

Spawns a complete AerolVM cluster on EC2 in one `scripts/terraform.sh apply`:

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
- A shared `SB_PAT_TOKEN` value - the same string is installed on every node

## Quick start

All cluster configuration lives under `config/` at the repo root. From the
repo root:

```bash
cp config/terraform.tfvars.example config/terraform.tfvars
cp config/secrets.example.yml      config/secrets.yml
# then edit:
#   config/terraform.tfvars  -> AWS placement, instance sizing, node list
#   config/cluster.yml       -> ingress.domain_name, ingress.acme_email, mirror/auto_import/...
#   config/secrets.yml       -> cluster.pat_token, cloudflare.api_token, aocr.*, fleet.token
scripts/terraform.sh init
scripts/terraform.sh apply
```

> **Always invoke via `scripts/terraform.sh`**, not bare `terraform`. The
> wrapper runs `terraform -chdir=Terraform` with
> `-var-file=../config/terraform.tfvars`. Running `terraform` directly from
> `Terraform/` will silently skip the tfvars file (which no longer sits on
> Terraform's auto-load path) and produce an incomplete plan.

### Where each value lives

Three files, one rule: **non-secret day-0+day-2 SoT → `cluster.yml`,
secrets → `secrets.yml`, Terraform-only inputs → `terraform.tfvars`**.

| File | Contents | Tracked? |
|---|---|---|
| `config/terraform.tfvars` | Terraform-only inputs: `aws_region`, `aws_profile`, `ssh_key_name`, `default_*`, `nodes = {...}`, `firecracker = {...}`, `caddy_shared_cert_storage`, `cloudflare_zone_id`, `extra_tags`. | gitignored |
| `config/terraform.tfvars.example` | Drop-in starter for the above. | committed |
| `config/cluster.yml` | Shared non-secret cluster ops env both Terraform (day-0) and Ansible (day-2) read: `ingress.domain_name`, `ingress.acme_email`, `mirror.*`, `auto_import.*`, `fleet_control_plane.*`, `otel.*`, `image_pull.*`, `image_build_gc.*`. | committed |
| `config/secrets.yml` | Shared cluster secrets both Terraform and Ansible read: `cluster.pat_token`, `cloudflare.api_token`, `aocr.upstream_wrap_key`, `aocr.cluster_pat`, `fleet.token`. | gitignored |
| `config/secrets.example.yml` | Empty template for the above. | committed |

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
default - set `seed = true` on exactly one entry:

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
| `with_firecracker`  | `var.default_with_firecracker`   | worker-capable nodes only; writes `SB_ENABLE_FIRECRACKER` and optional host downloads |
| `with_gvisor`       | `var.default_with_gvisor`        | adds `--with-gvisor` to install.sh               |
| `with_nvidia_gpu`   | `var.default_with_nvidia_gpu`    | adds `--with-nvidia-gpu` (driver must be loaded) |
| `with_amd_gpu`      | `var.default_with_amd_gpu`       | adds `--with-amd-gpu` (x86_64 only)              |
| `idle_timeout_min`  | `var.default_idle_timeout_min`   | sandbox auto-stop minutes; 0 disables            |
| `extra_user_data`   | `""`                             | shell, appended to bootstrap                     |
| `tags`              | `{}`                             |                                                  |

### Role rules (validated at plan time, mirrors `cluster-init.sh` / `cluster-join.sh`)

- Each comma token must be in `{server, worker, ingress, mixed}`.
- `mixed` (shorthand for `server,worker,ingress`) cannot be combined with other tokens.
- The seed node's role must contain `server` or equal `mixed` - `cluster-init.sh` refuses to bootstrap from a pure `worker` / `ingress` / `worker,ingress` node.

## How bootstrap works

Each instance's `user_data` (rendered from
[`templates/bootstrap.sh.tftpl`](./templates/bootstrap.sh.tftpl)) runs in three
phases:

1. **`install.sh`** with `--pat-token <shared> --domain <domain_name>
   --dns-provider cloudflare --dns-api-token <cloudflare.api_token>` so the
   per-node Caddy gets a real wildcard cert via Let's Encrypt DNS-01. Optional
   `--with-gvisor` / `--with-nvidia-gpu` / `--with-amd-gpu` /
   `--idle-timeout-min` are appended from per-node flags. If `domain_name` is
   empty the DNS-01 args are dropped and install.sh falls back to IP/path mode
   with no TLS.
2. **Seed only - `cluster-init.sh`** with `--role <seed-role>
   --ingress-advertise-host <domain_name> --gossip-key <generated>
   --tls-bundle-out /tmp/aerolvm-tls-bundle.tar.gz`. The seed then uploads
   `gossip-key.txt` + `aerolvm-tls-bundle.tar.gz` to the per-cluster S3 bucket.
3. **Every other node - `cluster-join.sh`** polls the S3 bucket
   (`seed_wait_max_seconds`, default 30 min), downloads both artifacts, then
   runs `cluster-join.sh --role <its-role> --ingress-advertise-host
   <domain_name> --gossip-key <…> --peers <seed-private-ip>:7001 --tls-bundle
   /tmp/aerolvm-tls-bundle.tar.gz`.
4. **Operational env** is appended to `/etc/sandboxd/cluster.env` on every
   node: OTEL metrics settings and image-pull storm controls. The bootstrap
   then restarts sandboxd once so those env vars are active immediately.

## Onboarding Firecracker nodes

Terraform now exposes Firecracker directly in the node schema instead of
making operators smuggle everything through `extra_user_data`.

> **Host requirements (read this first).** Firecracker is a KVM-only VMM
> and needs `/dev/kvm` on the host. **On AWS that means a bare-metal
> instance type only.** Use `*.metal` SKUs (`c5n.metal`, `m5zn.metal`,
> `c7g.metal`, `i3.metal`, `m5.metal`, `c5.metal`, …). Standard
> `t3`/`m5`/`c5`/`c6i`/`m6i`/`r5` instances are themselves Nitro guests,
> have no `/dev/kvm`, and will fail user-data with a clear remediation
> message at first boot. On GCP, use N1/N2 with
> `--enable-nested-virtualization`. On Azure, Dv3/Ev3+ with nested
> virtualization. Bare metal: enable VT-x / AMD-V in BIOS.
>
> To proceed without Firecracker on incapable hosts, leave
> `default_with_firecracker = false` and set `with_firecracker = true`
> **only** on node entries whose `instance_type` is a bare-metal SKU.

1. Mark worker-capable nodes with `with_firecracker = true`.
2. Fill the `firecracker` object in `config/terraform.tfvars`.
3. Choose one of two bootstrap modes:

- **Artifact-download mode**: set `firecracker.binary_url`, `firecracker.jailer_url`, and `firecracker.kernel_url`. Terraform bootstrap installs `skopeo`, `umoci`, `e2fsprogs`, and `iproute2`, downloads those artifacts, writes the matching `SB_ENABLE_FIRECRACKER` / `SB_FIRECRACKER_*` env vars into `/etc/sandboxd/cluster.env`, and restarts `sandboxd`.
- **Pre-baked AMI mode**: leave the URLs empty and make sure the AMI already has the binaries and kernel at `firecracker.binary_path`, `firecracker.jailer_path`, and `firecracker.kernel_path`.

Example:

```hcl
default_with_firecracker = false

firecracker = {
  binary_url               = "https://example.com/firecracker"
  jailer_url               = "https://example.com/jailer"
  kernel_url               = "https://example.com/vmlinux"
  kernel_path              = "/var/lib/sandboxd/firecracker/vmlinux"
  use_jailer               = true
  tap_base_cidr            = "172.16.0.0/20"
  tap_pool_size            = 256
  vmm_pool_enabled         = true
  vmm_pool_depth_default   = 1
  vmm_pool_refill_interval = "5s"
  vmm_pool_gc_interval     = "5m"
  vmm_pool_gc_ttl          = "1h"
  rss_watermark_ratio      = 0.10
}

nodes = {
  srv1 = { role = "server", seed = true, instance_type = "t3.small" }
  # Firecracker nodes MUST be bare-metal (*.metal) - standard Nitro types
  # (c6i, m6i, c5, m5, t3, ...) do not expose /dev/kvm and bootstrap will
  # hard-fail with a remediation message.
  wrk1 = { role = "worker", with_firecracker = true, instance_type = "c5.metal" }
  wrk2 = { role = "worker", with_firecracker = true, instance_type = "c5.metal" }
}
```

Notes:

- `with_firecracker` is validated at plan time and may only be set on worker-capable nodes (`worker`, `server,worker`, `worker,ingress`, or `mixed`).
- The host default runtime stays Docker; Firecracker is selected per sandbox via `runtime: "firecracker"` or template-backed create calls.
- The bootstrap writes the runtime env only on nodes with `with_firecracker = true`, so server-only and ingress-only nodes keep the old Docker-only shape.

The S3 bucket is private, SSE-encrypted, and `force_destroy = true` by
default so `terraform destroy` doesn't fail on leftover objects. Flip
`bundle_bucket_force_destroy = false` if you want belt-and-braces.

If you enable managed shared cert storage (`caddy_shared_cert_storage = {
enabled = true }` with the default `mode = "managed"`), Terraform creates a
second versioned S3 bucket for Caddy certs. That bucket stays conservative by
default: `caddy_certs_bucket_force_destroy = false`. Set it to `true` before
`terraform destroy` if you want Terraform to purge stored cert object versions
and remove the bucket automatically.

## Observability and pull-storm controls

Prometheus scraping is always available at `GET /v1/metrics` on each node's
API port. The `prometheus_scrape_targets` output returns private-IP targets
for a Prometheus running inside the VPC:

```yaml
# config/cluster.yml
otel:
  metrics_endpoint: "http://otel-collector.internal:4318/v1/metrics"
  metrics_interval: "30s"
  traces_endpoint: "http://otel-collector.internal:4318/v1/traces"
  traces_sample_ratio: 0.05
  service_name: "sandboxd"

image_pull:
  max_concurrent: 4
  failure_backoff: "30s"
```

The repo-local observability artifacts to import are:

- Grafana dashboard: `../setup/grafana/sandboxd-slo-dashboard.json`
- Prometheus alerts: `../setup/prometheus/sandboxd-alerts.yml`
- Alertmanager example: `../setup/alertmanager/sandboxd-alertmanager-example.yml`
- Operational runbooks: `../setup/runbooks/`

## Cloudflare DNS

`cloudflare_zone_id` is optional. If you leave it empty, Terraform strips the
first label off `domain_name` (so `cluster.example.com` → `example.com`) and
looks the zone up via the Cloudflare API - that requires `Zone:Read` on the
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
| `../config/terraform.tfvars.example` | Drop-in starter for `config/terraform.tfvars` (gitignored sibling) |
| `../config/cluster.yml`     | Shared non-secret cluster ops env (Terraform + Ansible) |
| `../config/secrets.example.yml` | Template for `config/secrets.yml` (gitignored sibling) |
| `../scripts/terraform.sh`   | Wrapper - always invoke Terraform via this, not bare `terraform` |

## Connect this cluster to AOCR (mirror + auto-import)

If you operate an [AOCR](https://github.com/aerolai/aocr) deployment alongside
this cluster, you can route every public-registry pull through AOCR's
authenticated mirror - and optionally auto-import each first pull into a
cluster-owned namespace so future failovers are decoupled from the original
upstream credential. The Terraform variable `aocr` (defined in
`variables.tf`) is already plumbed through `locals.tf` → `nodes.tf` → the
node user_data template. Enabling it requires zero code edits - only values.

For the threat model and per-node env-var contract, read
[`../AUTHENTICATED_MIRROR.md`](../AUTHENTICATED_MIRROR.md). For AOCR-side
architecture, read
[`aocr.sh/MIRROR.md`](https://github.com/aerolai/aocr/blob/main/MIRROR.md).
For the full end-to-end deploy + stitch story, read
[`aocr.sh/aocr_aerol_stitch.md`](https://github.com/aerolai/aocr/blob/main/aocr_aerol_stitch.md).

### Step 1 - Pull 4 values from your AOCR side

The AOCR Ansible playbook auto-generates every secret on first deploy. After
you've run it once, the values you need are sitting in `aocr.sh/secrets/`
and `aocr.sh/ansible/inventory/group_vars/all/vars.yml`:

```bash
cd /path/to/aocr.sh

# 1. Mirror host - derived from your aocr_global_domain
#    Default is "mirror." + aocr_global_domain (e.g. mirror.aocr.aerol.ai).
grep aocr_global_domain ansible/inventory/group_vars/all/vars.yml

# 2. Upstream wrap key (base64, 32 bytes) - required for private upstream pulls
cat secrets/upstream_wrap_key

# 3. Internal API token (64-char bearer) - only needed if auto_import_enabled=true
cat secrets/internal_api_token

# 4. Hooks URL - the AOCR root, no trailing slash (e.g. https://aocr.aerol.ai)
```

> **Where does the value actually live?** Each AOCR secret is *either* a
> generated file under `aocr.sh/secrets/` (default on first deploy) *or* an
> inline override in `aocr.sh/ansible/inventory/group_vars/all/secrets.yml`
> (the deploy playbook skips file generation when the override is set). If
> `cat secrets/upstream_wrap_key` errors with "No such file or directory",
> grep `secrets.yml` for the matching `aocr_*` key instead:
>
> ```bash
> cd /path/to/aocr.sh
> # Falls back from inline override → generated file
> aocr_secret() {
>   local s="ansible/inventory/group_vars/all/secrets.yml" v
>   v=$(awk -F'"' -v k="^$1:" '$0 ~ k {print $2; exit}' "$s" 2>/dev/null)
>   if [ -n "$v" ]; then echo "$v"; else cat "secrets/$2"; fi
> }
> aocr_secret aocr_auth_upstream_wrap_key upstream_wrap_key
> aocr_secret aocr_internal_api_token     internal_api_token
> ```
>
> See `aocr.sh/aocr_aerol_stitch.md` § *Resolving AOCR secret values* for
> the full table.

You also pick a **cluster ID** yourself - any string matching
`^[A-Za-z0-9_-]{1,64}$`, e.g. `prod-aerolvm-us-east-1`. AOCR has no
pre-registered list of clusters; this is a label you choose so AOCR can
group your imported tags under `cluster/<your-id>/_imported/...`. Pick once
per cluster and never change it (changing it later orphans previously
imported tags under the old namespace).

### Step 2 - Add the `aocr` block to `config/cluster.yml` + `config/secrets.yml`

> **AOCR no longer lives in `terraform.tfvars`.** Non-secret AOCR config
> (`mirror.host`, `auto_import.*`) sits in `config/cluster.yml` so both
> Terraform and Ansible read it; AOCR secrets (`upstream_wrap_key`,
> `cluster_pat`) sit in `config/secrets.yml`. The example block below shows
> the shape - for the live keys see `config/cluster.yml` and
> `config/secrets.example.yml`.

```hcl
aocr = {
  enabled             = true
  mirror_host         = "mirror.aocr.aerol.ai"
  upstream_wrap_key   = "<paste contents of aocr.sh/secrets/upstream_wrap_key>"

  # Auto-import (F21) - drop these four if you only want the cached mirror.
  auto_import_enabled = true
  hooks_url           = "https://aocr.aerol.ai"
  cluster_id          = "prod-aerolvm-us-east-1"   # pick once, never change
  cluster_pat         = "<paste contents of aocr.sh/secrets/internal_api_token>"
  # retention_suffix  = "--idle-90d"   # default; cluster-imported tags live 90 days idle
}
```

`config/secrets.yml` is loaded through `sensitive(yamldecode(...))` in
`locals.tf`, so `terraform plan/apply` won't print the wrap key or PAT.

### Step 3 - Apply

```bash
scripts/terraform.sh plan    # expect existing nodes to recycle; user_data changed
scripts/terraform.sh apply
```

`nodes.tf` sets `user_data_replace_on_change = true`, so existing EC2
instances **are replaced** when this block changes. New nodes come up with:

1. `/etc/sandboxd/secrets/upstream-wrap.key` written at `0600`.
2. `/etc/sandboxd/secrets/cluster-pat` written at `0600` (when auto-import on).
3. `SB_MIRROR_*` and `SB_AUTO_IMPORT_*` appended to `/etc/sandboxd/cluster.env`.
4. `systemctl restart sandboxd`.

The cluster PAT is **file-sourced** - never an env var, never visible in
`systemctl show sandboxd` or process listings.

### Step 4 - Verify

SSH into any node:

```bash
sudo grep -E '^SB_(MIRROR|AUTO_IMPORT)_' /etc/sandboxd/cluster.env
sudo ls -l /etc/sandboxd/secrets/        # both files 0600 root:root
systemctl is-active sandboxd
```

Then trigger a private pull (via any sandbox) and check AOCR:

```bash
# Mirror cache populated?
curl -sf -H "Authorization: Bearer $(cat aocr.sh/secrets/auth_pat_token)" \
  "https://aocr.aerol.ai/v1/images?limit=20" | jq -r '.images[].repository' | sort -u

# Auto-import landed under your cluster namespace?
curl -sf -H "Authorization: Bearer $(cat aocr.sh/secrets/auth_pat_token)" \
  "https://aocr.aerol.ai/v1/images?limit=200" | jq -r '.images[].repository' \
  | grep "cluster/prod-aerolvm-us-east-1/_imported/"
```

### What each `aocr.*` field means

| Field | Purpose | Where the value comes from |
|---|---|---|
| `enabled` | Master switch. When false, nothing else templates. | You |
| `mirror_host` | Vhost sandboxd rewrites `ghcr.io` / `gcr.io` / `quay.io` / `registry.k8s.io` pulls onto. Docker Hub is intentionally not rewritten. | AOCR side - derived from `aocr_global_domain` |
| `upstream_wrap_key` | Base64 32-byte AES-GCM key. Sandboxd wraps per-pull upstream creds with this; only AOCR's mirror can unwrap. Without it, private upstream pulls 401 at the mirror. | AOCR side - `secrets/upstream_wrap_key` (auto-generated on first AOCR deploy) |
| `mirror_push_host` | Optional. Push vhost (e.g. `aocr.aerol.ai`) so already-pushed refs aren't double-rewritten. Leave empty unless you also push from sandboxes. | AOCR side |
| `mirror_upstreams` | Default `ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s`. Override only if your AOCR exposes different upstream shortnames. | AOCR operator |
| `auto_import_enabled` | Master switch for F21. When true, every successful private pull triggers a re-mount under `cluster/<id>/_imported/...`. | You |
| `hooks_url` | AOCR hooks service root, e.g. `https://aocr.aerol.ai`. Sandboxd appends `/v1/internal/imports`. | AOCR side - same as `aocr_global_domain` |
| `cluster_id` | **A label you choose**, not internal AOCR config. AOCR validates only the format (`^[A-Za-z0-9_-]{1,64}$`) and uses it as a namespace prefix for imported tags. Pick a meaningful per-cluster name like `prod-us-east-1`, `staging`, `dev-suman`. | You |
| `cluster_pat` | Bearer token sandboxd presents on `POST /v1/internal/imports`. Despite the name, this is AOCR's `internal_api_token`, not the UUID-keyed cluster PAT used by `auth/src/clusterPat.ts` (different concept; see `aocr_aerol_stitch.md`). | AOCR side - `secrets/internal_api_token` |
| `retention_suffix` | Suffix appended to imported tags. Drives the reaper's idle-eviction window (see [`aocr.sh/RETENTION.md`](https://github.com/aerolai/aocr/blob/main/RETENTION.md)). | Operator policy |

Everything else (`request_timeout`, `reconcile_interval`, `max_in_flight`)
has a sensible default - only tune if recovery storms or remote latency
warrant it. The full default set lives in `variables.tf`.

### TL;DR

1. AOCR was deployed once; its secrets sit in `aocr.sh/secrets/`.
2. Fill the `mirror.*` + `auto_import.*` blocks in `config/cluster.yml`, and
   the `aocr.upstream_wrap_key` + `aocr.cluster_pat` keys in
   `config/secrets.yml`, with values copied from those files plus an
   `auto_import.cluster_id` you pick.
3. `scripts/terraform.sh apply` - nodes recycle, secrets land at
   `/etc/sandboxd/secrets/`, sandboxd restarts wired to the mirror.
4. Verify with `grep` / `ls` on a node and `curl /v1/images` on AOCR.

## Tear-down

```bash
scripts/terraform.sh destroy
```

This deletes the VPC, instances, security group, IAM profiles, S3 bundle
bucket (force-destroyed), and the Cloudflare records. If managed shared cert
storage is enabled, the cert bucket is only auto-deleted when
`caddy_certs_bucket_force_destroy = true`; otherwise empty it manually first.
