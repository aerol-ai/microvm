# AerolVM cluster on AWS - Terraform

This folder is a Terraform **module**. It builds a whole AerolVM cluster on
EC2 in one `terraform apply`:

- a VPC + public subnet + IGW + security group with the cluster-internal
  ports (`7000/TCP`, `7001/TCP+UDP`, `7002/TCP`, and `7003/TCP` to servers
  for joins) and public ingress (`80`, `443`),
- N EC2 instances, each sized + roled independently
  (`server`, `worker`, `ingress`, `worker,ingress`, `server,worker`,
  `server,ingress`, or `mixed`),
- one join token per role, so every node joins with one line (below),
- Cloudflare `A` + wildcard `A` records pointing at every ingress-bearing
  node's public IP, or, with `api_load_balancer = "nlb"`, at a health-checked
  Network Load Balancer in front of them (see "Load balancer" below).

There are two ways to run it:

| You have | Use | Where |
|---|---|---|
| No copy of the repo (most people) | The module **by URL**, from your own root module | [`examples/from-url/`](./examples/from-url/main.tf) |
| A checkout of this repo | `scripts/terraform.sh`, which runs [`root/`](./root/) | `config/` at the repo root |

## Use the module by URL

You need no clone. Copy [`examples/from-url/`](./examples/from-url/) into
an empty folder, then:

```bash
cp config/secrets.example.yml config/secrets.yml
# edit config/cluster.yml (your domain) and config/secrets.yml (PAT, Cloudflare token)
terraform init
terraform apply -var 'admin_allowed_cidrs=["203.0.113.0/24"]' -var ssh_key_name=my-key
```

The module block in that example is:

```hcl
module "aerolvm" {
  source = "git::https://github.com/aerol-ai/microvm//Terraform?ref=v0.6.12"

  cluster_name        = "aerolvm"
  config_dir          = "${path.module}/config"
  admin_allowed_cidrs = ["203.0.113.0/24"]
  ssh_key_name        = "my-key"

  nodes = {
    server-1 = { role = "server", seed = true }
    server-2 = { role = "server" }
    server-3 = { role = "server" }
    worker-1 = { role = "worker", instance_type = "c6i.xlarge" }
  }
}
```

Your root module configures the `aws` and `cloudflare` providers (the
module does not, so it works with `count` and `for_each`) and picks the
state backend. Every variable in [`variables.tf`](./variables.tf) can be set
in the module block. Pin `ref` to a release tag. Upgrade the software on a
running cluster with `aerolvm upgrade apply`, not by moving `ref`: a new
`ref` may change user data, and new user data replaces the machines.

### How nodes join

By default (`one_line_join = true`) the module makes one join token per
role, shaped `<6>.<32>` of `[a-z0-9]`:

- The seed runs the installer with `init` and registers all three tokens:
  `--token worker=<t>:0 --token ingress=<t>:0 --token server=<t>:24h`.
- Every other node waits for the seed's join port (7003), then runs the
  installer with `join https://<seed>:7003 --token <its role's token>`.
- The worker and ingress tokens never expire, so a worker added to `nodes`
  weeks later still joins. The server token lasts 24 hours; for a server
  added later, make a fresh token with `aerolvm join-command --role server`.

Nothing is copied between nodes: the servers sign every node's certificate.

**Keep the state safe.** The join tokens are in the Terraform state and in
user data, like the admin PAT. A join token can make a node, and a node
receives the cluster's keys. Treat the state like the PAT: an encrypted
backend with tight access.

`one_line_join = false` is the old way (an S3 bundle hand-off and a
certificate-signing loop on the seed, through `cluster-init.sh` and
`cluster-join.sh`). It is deprecated, prints a warning on every plan, and
goes away when those scripts leave the release. A cluster with no domain
still needs it: `install.sh --local` never joins.

## From a checkout of this repo

`scripts/terraform.sh` runs [`root/`](./root/), a root module that calls
this module by path. It keeps this checkout's S3 backend, passes every
variable through, and forwards every output under the same name, so
`config/terraform.tfvars` works as before.

**Already have a cluster built from a checkout?** Run
`scripts/terraform.sh init` once (the working folder moved to
`Terraform/root`), then `scripts/terraform.sh plan`. The moved blocks in
[`root/moved.tf`](./root/moved.tf) move every resource into
`module.aerolvm`; the plan shows `has moved to` lines and nothing to
destroy. `root/` keeps `one_line_join = false` as its default, because your
nodes were built with the old join and changing it replaces every node.
For a **new** cluster from a checkout, set `one_line_join = true` in
`config/terraform.tfvars`.

**Moving to the module by URL** from a checkout cluster: copy
`root/moved.tf` next to your module block (rename `module.aerolvm` if you
named it differently), use the same backend and state key, and set
`one_line_join = false` in the module block. Plan first and check that
nothing is destroyed.

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

## Quick start from a checkout

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
> wrapper runs `terraform -chdir=Terraform/root` with
> `-var-file=<repo>/config/terraform.tfvars`. Running `terraform` directly
> will silently skip the tfvars file (which is not on Terraform's auto-load
> path) and produce an incomplete plan.

### Where each value lives

Three files, one rule: **non-secret day-0+day-2 SoT → `cluster.yml`,
secrets → `secrets.yml`, Terraform-only inputs → `terraform.tfvars`**.

| File | Contents | Tracked? |
|---|---|---|
| `config/terraform.tfvars` | Terraform-only inputs: `aws_region`, `aws_profile`, `ssh_key_name`, `default_*`, `nodes = {...}`, `firecracker = {...}`, `caddy_shared_cert_storage`, `cloudflare_zone_id`, `extra_tags`. | gitignored |
| `config/terraform.tfvars.example` | Drop-in starter for the above. | committed |
| `config/cluster.yml` | Shared non-secret cluster ops env both Terraform (day-0) and Ansible (day-2) read: `ingress.domain_name`, `ingress.acme_email`, `mirror.*`, `auto_import.*`, `fleet_control_plane.*`, `otel.*`, `image_pull.*`, `image_build_gc.*`. | committed |
| `config/secrets.yml` | Shared cluster secrets both Terraform and Ansible read: `cluster.pat_token`, `cluster.metrics_token` (optional read-only Prometheus scrape token; empty scrapes with the PAT), `cloudflare.api_token`, `aocr.upstream_wrap_key`, `aocr.cluster_pat`, `fleet.token`. | gitignored |
| `config/secrets.example.yml` | Empty template for the above. | committed |

Outputs include every node's public IP, the seed's SSH command, and the
verify-cluster `curl`. They also include Prometheus scrape targets for
`/v1/metrics` on every node's private API address. Watch one node's bootstrap
with:

```bash
ssh ubuntu@<public-ip> sudo tail -f /var/log/aerolvm-bootstrap.log
```

Once joiners finish (`[bootstrap] complete`), list the nodes from your
laptop with the `aerolvm` CLI:

```bash
aerolvm login https://<domain_name>
aerolvm get nodes
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
| `ingress_proxy_routing` | `var.default_ingress_proxy_routing` | `null` adds nothing (install.sh's default, on), `true` adds `--ingress-proxy-routing`, `false` adds `--no-ingress-proxy-routing` (see below) |
| `with_nvidia_gpu`   | `var.default_with_nvidia_gpu`    | adds `--with-nvidia-gpu` (driver must be loaded) |
| `with_amd_gpu`      | `var.default_with_amd_gpu`       | adds `--with-amd-gpu` (x86_64 only)              |
| `idle_timeout_min`  | `var.default_idle_timeout_min`   | sandbox auto-stop minutes; 0 disables            |
| `extra_user_data`   | `""`                             | shell, appended to bootstrap                     |
| `tags`              | `{}`                             |                                                  |

**Ingress proxy routing.** An expose or a destroy writes nothing to Caddy, so
it never reloads Caddy and drops new connections
(`plans/ingress-proxy-routing.md`). `default_ingress_proxy_routing` (and each
node's `ingress_proxy_routing`, which wins when set) takes three values:

| Value | install.sh gets | Result |
|---|---|---|
| `null` (default) | no routing flag | install.sh's default: on with a `domain`, off without one (`--local`) |
| `true` | `--ingress-proxy-routing` | on |
| `false` | `--no-ingress-proxy-routing` | off: per-sandbox Caddy routes |

`null` renders exactly the user data the old default `false` rendered, so a
cluster that never set the variable plans no user-data change and no node is replaced
(nodes have `user_data_replace_on_change = true`). Its running nodes keep the
value their install wrote, which was off; nodes created from now on (a new
cluster, a scale-out, a replaced node) come up on. A cluster that wrote
`default_ingress_proxy_routing = false` explicitly now renders
`--no-ingress-proxy-routing`, so its next apply replaces those nodes once;
remove the line to avoid that, or keep it to stay off on every future node.

**Ingress tier size.** Up to 10 ingress-capable nodes (`ingress`, any hybrid
containing it, or `mixed`) work behind the Cloudflare records this module
creates. More than 10 requires a shard-aware router that resolves owners
through `GET /v1/cluster/ingress-route/{id}`, declared with
`shard_aware_ingress = true` (writes `SB_CLUSTER_SHARD_AWARE_INGRESS` on every
node); `terraform plan` refuses a larger tier without it because the daemon
would refuse to boot it. Do not set it with a plain LB in front - see
`setup/runbooks/cluster-ingress-topology.md`.

### Role rules (validated at plan time, mirrors `sandboxd init` / `sandboxd join`)

- Each comma token must be in `{server, worker, ingress, mixed}`.
- `mixed` (shorthand for `server,worker,ingress`) cannot be combined with other tokens.
- The seed node's role must contain `server` or equal `mixed` - `sandboxd init` refuses to start a cluster from a pure `worker` / `ingress` / `worker,ingress` node.
- A node's join token is its role's: any role with `server` (or `mixed`) is a server; else `worker` beats `ingress`.

## How bootstrap works

Each instance's `user_data` (rendered from
[`templates/bootstrap.sh.tftpl`](./templates/bootstrap.sh.tftpl)) runs in three
phases:

1. **`install.sh`** with `--pat-token <shared> --domain <domain_name>
   --dns-provider cloudflare --dns-api-token <cloudflare.api_token>` so the
   per-node Caddy gets a real wildcard cert via Let's Encrypt DNS-01. Optional
   `--with-gvisor` / `--with-nvidia-gpu` / `--with-amd-gpu` /
   `--idle-timeout-min` are appended from per-node flags, and the
   cluster-wide `pat_scope = "host"` and `l4_proxy_protocol = true` add
   `--pat-scope host` (the PAT only from this host and cluster peers, Caddy on
   the public socket; enterprise mode requires it) and `--l4-proxy-protocol`
   (the real client address through Caddy). If `domain_name` is
   empty the DNS-01 args are dropped and install.sh falls back to IP/path mode
   with no TLS.
2. **Seed only - `install.sh ... init`**, which runs `sandboxd init --role
   <seed-role> --node-id <name> --ingress-advertise-host <domain_name>`
   with the three join tokens (see "How nodes join" above). `sandboxd init`
   makes the cluster CA, the gossip key and the server key and starts Raft.
3. **Every other node - `install.sh ... join`**: it waits for the seed's
   join port (`seed_wait_max_seconds`, default 30 min), then runs
   `sandboxd join https://<seed-private-ip>:7003 --token <its role's token>
   --node-id <name> --role <its-role>`, up to three tries (a join is safe to
   run again).
   With `one_line_join = false` (deprecated) steps 2 and 3 are the old
   `cluster-init.sh` / `cluster-join.sh` pair, with an S3 bucket hand-off
   and a signing loop on the seed.
4. **Operational env** is appended to `/etc/sandboxd/cluster.env` on every
   node: OTEL metrics settings and image-pull storm controls. The bootstrap
   then restarts sandboxd once so those env vars are active immediately.

### Download mirror

The bootstrap downloads `install.sh`, the cluster scripts, and on containerd
nodes the CNI plugins and BuildKit (and Firecracker where you turn it on).
Most of these come from GitHub release downloads, and those can fail for
hours while GitHub's status page stays green. That happened on 2026-11-09: a
GitHub `504` on the CNI plugins stopped the bootstrap on two servers and the
ingress of a test cluster.

Set `download_mirror` to give every one of those downloads a fallback:

```hcl
download_mirror = "https://aerolvm-downloads.s3.us-east-1.amazonaws.com"
```

- **What happens.** Each file is tried at its own source first, with a few
  quick retries. If that fails, the same file is fetched from the mirror: AerolVM
  release files from `aerolvm/<tag>/` (the mirror's `aerolvm/latest.txt`
  names the latest release), and the CNI plugins, BuildKit and Firecracker
  from `deps/<project>/<version>/`. A URL the mirror has no copy of (your own
  `install_script_url` server, a presigned bucket URL, the Firecracker CI
  kernel) is downloaded as before.
- **Checks.** The CNI plugins and BuildKit are checked against the SHA-256
  values pinned in `install.sh`, whichever source served them. Firecracker is
  checked against its own `.sha256.txt`, as before.
- **The mirror.** The public one above is filled by `scripts/mirror-sync.sh`
  and by each release (`.github/workflows/release.yml`). You can run your own
  copy of it and point `download_mirror` there.
- **Changing it replaces nodes.** Unset (the default, `null`), the bootstrap
  renders exactly as before, so an existing cluster sees no change. Setting it
  changes every node's `user_data`, so the next `terraform apply` replaces each
  node once (`user_data_replace_on_change`). Plan that like any node
  replacement.
- `install.sh` has its own mirror fallback for what it downloads (sandboxd,
  Caddy and the rest), on by default; see `install.sh --help`
  (`--download-mirror`).

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
3. Choose one of three bootstrap modes:

- **Upstream auto-install (default)**: leave `firecracker.binary_url`, `jailer_url`, and `kernel_url` empty and keep `auto_install_artifacts = true` (default). Bootstrap downloads the arch-matched Firecracker release tarball and the spec.ccfc.min guest kernel for the cluster's homogeneous arch (`x86_64` on amd64 metal, `aarch64` on Graviton). Pins match Ansible `configure-ops.yml` (`version`, `kernel_ci_version`, `kernel_version` are overridable).
- **Custom artifact URLs**: set `firecracker.binary_url`, `firecracker.jailer_url`, and `firecracker.kernel_url` (and optional `kernel_config_url`). Bootstrap curls those instead of upstream.
- **Pre-baked AMI**: set `auto_install_artifacts = false`, leave URLs empty, and ship binaries/kernel at `firecracker.binary_path`, `firecracker.jailer_path`, `firecracker.kernel_path`, and `firecracker.kernel_path + ".config"`.

Example:

```hcl
default_with_firecracker = false

firecracker = {
  binary_url               = "https://example.com/firecracker"
  jailer_url               = "https://example.com/jailer"
  kernel_url               = "https://example.com/vmlinux"
  kernel_config_url        = "https://example.com/vmlinux.config"
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

## Load balancer

`api_load_balancer = "nlb"` (default `"none"`) puts an internet-facing AWS
Network Load Balancer in front of the ingress nodes (`load_balancer.tf`).
DNS round-robin cannot route around a node whose sandboxd is down while its
Caddy is up: the handshakes succeed, so its share of clients get 502 until
the daemon is back. The balancer health-checks every ingress node through
Caddy to sandboxd and drops a failing one in about 10 s.

- TCP passthrough on `public_http_ports` and `ssh_gateway_port`, instance
  targets, client IP preserved: Caddy keeps TLS, caddy-l4 keeps SNI routing,
  and sandboxd's audit records see the real caller.
- Health check: HTTP `GET /health` on `api_lb_health_check_port` (21280),
  served by `install.sh --lb-health-port`, open to the balancer's security
  group only. Every 5 s; out after 2 failures, back after 2 passes.
- `<domain_name>` and `*.<domain_name>` become one A record to the
  balancer's Elastic IP. The raw-TCP pool (`l4_port_range`) cannot ride an
  NLB (50 listeners at most), so `tcp.<domain_name>` keeps one A record per
  ingress node and every node gets `SB_L4_PUBLIC_HOST=tcp.<domain_name>`.
- Choose it when the cluster is created: it changes every node's user data,
  so on a running cluster Terraform replaces the nodes.

`terraform output api_load_balancer` shows the balancer's IP, DNS name,
target groups and the raw-TCP host.

## Files

| File                        | Purpose                                   |
|-----------------------------|-------------------------------------------|
| `versions.tf`               | Required providers + Terraform version    |
| `variables.tf`              | Every knob, with defaults                 |
| `join.tf`                   | `one_line_join` and the join token per role |
| `locals.tf`                 | Node normalisation + ingress derivation   |
| `network.tf`                | VPC, subnet, IGW, SG rules, AMI lookup    |
| `iam.tf`                    | Bundle S3 bucket + seed/joiner profiles   |
| `nodes.tf`                  | Seed `aws_instance` + joiner `for_each`   |
| `root/`                     | The root a checkout runs: backend, providers, the module call, every variable and output passed through, `moved.tf` |
| `examples/from-url/`        | A root that uses the module by URL        |
| `dns.tf`                    | Cloudflare A + wildcard records           |
| `load_balancer.tf`          | Optional NLB in front of ingress (`api_load_balancer`) |
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
scripts/terraform.sh destroy     # from a checkout
terraform destroy                # from your own root (module by URL)
```

This deletes the VPC, instances, security group, IAM profiles, S3 bundle
bucket (force-destroyed), and the Cloudflare records. If managed shared cert
storage is enabled, the cert bucket is only auto-deleted when
`caddy_certs_bucket_force_destroy = true`; otherwise empty it manually first.
