# AerolVM cluster — Ansible

Day-N operations against the cluster that `../Terraform` provisions. Terraform
owns infra (VPC, EC2, SG, DNS); Ansible owns "push a new binary, restart a
service, tail logs across all nodes."

## Prereqs

- Ansible ≥ 2.15 (`pipx install ansible-core` or `brew install ansible`)
- `boto3` + `botocore` reachable from **Ansible's Python** (see install note below)
- AWS credentials in the default chain (env, profile, instance role) with
  `ec2:DescribeInstances` — that's all the inventory plugin needs
- The same SSH private key Terraform installed on the nodes (default:
  `~/.ssh/id_rsa`; change in `ansible.cfg` if you use a different one)

### One-time install

```bash
cd Ansible

# Install Ansible collections this repo depends on.
ansible-galaxy collection install -r requirements.yml

# Install boto3 / botocore for the dynamic EC2 inventory. The right command
# depends on how Ansible itself was installed:
#
#   - pipx (recommended):    pipx inject ansible-core boto3 botocore
#   - brew install ansible:  brew installs them as part of the formula — skip
#   - system pip / venv:     pip install boto3 botocore  (into the SAME env
#                            that owns the `ansible` binary)
#
# If you `pip install boto3` into your base/conda env while Ansible lives in
# a pipx venv, Ansible won't see it and `ansible-inventory --graph` will fail
# with "Failed to import the required Python library (botocore and boto3)".
pipx inject ansible-core boto3 botocore

# Load your SSH key into the agent (per session, no config edit needed).
ssh-add ~/.ssh/your-aws-key.pem

# Point at your cluster (defaults: cluster=aerolvm, region=us-east-1).
export AEROLVM_CLUSTER=aerolvm
export AEROLVM_REGION=us-east-1
export AWS_PROFILE=default            # if you use named profiles
```

Smoke test:

```bash
ansible-inventory --graph        # should list your EC2 nodes grouped by tag
ansible-playbook playbooks/ping.yml
```

## Inventory

`inventory/aws_ec2.yml` is a dynamic inventory plugin — it queries EC2 every
time you run a playbook. It filters by the `Cluster` tag (default `aerolvm`,
matches `var.cluster_name` in Terraform) in `us-east-1`. Override either via
environment variables:

```bash
export AEROLVM_CLUSTER=prod
export AEROLVM_REGION=us-west-2
ansible-inventory --graph
```

You'll get groups for free, derived from the tags Terraform sets:

```
@all:
  |--@aerolvm_role_server:        # Role=server
  |--@aerolvm_role_worker:        # Role=worker
  |--@aerolvm_role_ingress:       # Role=ingress
  |--@aerolvm_role_worker_ingress # Role=worker,ingress (comma → underscore)
  |--@aerolvm_role_mixed:         # Role=mixed
  |--@aerolvm_true:               # Seed=true (exactly one node)
  |--@aerolvm_false:              # Seed=false
```

Target any group with `--limit`:

```bash
ansible-playbook playbooks/update-sandboxd.yml --limit aerolvm_role_worker -e ...
```

## Common playbooks

```bash
# Reachability check (run this first to verify SSH + sudo work):
ansible-playbook playbooks/ping.yml

# Push the LATEST released sandboxd binary across the fleet (most common):
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64

# arm64 / Graviton nodes:
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_arm64

# Pin to a specific release instead of "latest":
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/download/v0.2.2/sandboxd_linux_amd64

# Push a locally-built binary (dev loop):
make -C .. build-sandboxd
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_local_binary=../bin/sandboxd

# Tail recent sandboxd logs from every node:
ansible-playbook playbooks/tail-logs.yml -e lines=200

# Drain a node and wait until it owns zero placements before a Terraform
# role change or instance replacement:
ansible-playbook playbooks/prepare-role-change.yml --limit aerolvm-worker-17

# Configure OTEL/image-pull hardening and deploy backup/recovery,
# node lifecycle, Grafana, Prometheus, Alertmanager, and runbook artifacts:
ansible-playbook playbooks/configure-ops.yml \
  -e sandboxd_otel_metrics_endpoint=http://otel-collector:4318/v1/metrics \
  -e sandboxd_otel_traces_endpoint=http://otel-collector:4318/v1/traces \
  -e sandboxd_backup_enabled=true
```

`update-sandboxd.yml` runs `serial: 1` — one host at a time, with
`any_errors_fatal: true` — so a failed health check on node 1 stops the
rollout before it touches the Raft quorum. Limit to a single non-seed test
node first (use a hostname from `ansible-inventory --graph`, e.g. one that
shows up under `@aerolvm_false`):

```bash
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64 \
  --limit aerolvm-node3
```

Release asset names come from `.github/workflows/release.yml` and follow
`sandboxd_<goos>_<goarch>` — `linux_amd64`, `linux_arm64`, `linux_armv7`,
`linux_armv6`, `linux_386`, `freebsd_amd64`, `darwin_arm64`, etc.

## Per-machine config

`ansible.cfg` is committed — your SSH key path, AWS profile, region, and
cluster name are per-machine and don't belong in it. Use:

- `ssh-add ~/.ssh/<your-key>.pem` for the key (persist on macOS with
  `ssh-add --apple-use-keychain`). Once loaded, `ansible-playbook` picks it
  up via the agent — no `--private-key` flag, no config edit.
- `AEROLVM_CLUSTER`, `AEROLVM_REGION`, `AWS_PROFILE` env vars for cluster
  selection (the dynamic inventory reads these directly).
- `Ansible/ansible.local.cfg` (gitignored) + `ANSIBLE_CONFIG=$PWD/Ansible/ansible.local.cfg`
  if you genuinely need to override `ansible.cfg` settings locally.

## Layout

```
ansible.cfg            # forks, ssh args, default inventory + remote_user
requirements.yml       # collections to install
inventory/
  aws_ec2.yml          # dynamic inventory (EC2 → hosts/groups via tags)
  group_vars/all.yml   # binary path, service name, health URL defaults
                       # (must live next to the inventory; Ansible auto-loads
                       # group_vars only from inventory/ or playbooks/, not
                       # from the repo root)
playbooks/
  ping.yml             # connectivity smoke test
  update-sandboxd.yml  # rolling binary push + restart + healthcheck
  prepare-role-change.yml # drain + wait-empty guard before Terraform role changes
  configure-ops.yml    # OTEL env, image-pull knobs, ops alert/dashboard/runbook files
  tail-logs.yml        # journalctl across the fleet
```

## Connect this cluster to AOCR (mirror + auto-import)

If you operate an [AOCR](https://github.com/aerolai/aocr) deployment alongside
this cluster, you can route every public-registry pull through AOCR's
authenticated mirror — and optionally auto-import each first pull into a
cluster-owned namespace so future failovers are decoupled from the original
upstream credential. The defaults in `inventory/group_vars/all.yml` and the
secret-copy + env-template tasks in `playbooks/configure-ops.yml` are
already in place. Enabling it requires zero code edits — only values and
two secret files on the control node.

Use this path if you bootstrapped nodes with Ansible only, or if you want to
flip the AOCR wiring on existing nodes without recycling EC2 instances
(Terraform's path replaces them).

For the threat model and per-node env-var contract, read
[`../AUTHENTICATED_MIRROR.md`](../AUTHENTICATED_MIRROR.md). For AOCR-side
architecture, read
[`aocr.sh/MIRROR.md`](https://github.com/aerolai/aocr/blob/main/MIRROR.md).
For the full end-to-end deploy + stitch story, read
[`aocr.sh/aocr_aerol_stitch.md`](https://github.com/aerolai/aocr/blob/main/aocr_aerol_stitch.md).

### Step 1 — Pull values from your AOCR side

The AOCR Ansible playbook auto-generates every secret on first deploy. After
you've run it once, the values you need are in `aocr.sh/secrets/` and
`aocr.sh/ansible/inventory/group_vars/all/vars.yml`:

```bash
cd /path/to/aocr.sh

# 1. Mirror host — derived from your aocr_global_domain
#    Default is "mirror." + aocr_global_domain (e.g. mirror.aocr.aerol.ai).
grep aocr_global_domain ansible/inventory/group_vars/all/vars.yml

# 2. Upstream wrap key (base64, 32 bytes) — required for private upstream pulls
cat secrets/upstream_wrap_key

# 3. Internal API token (64-char bearer) — only for auto-import
cat secrets/internal_api_token

# 4. Hooks URL — the AOCR root, no trailing slash (e.g. https://aocr.aerol.ai)
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

You also pick a **cluster ID** yourself — any string matching
`^[A-Za-z0-9_-]{1,64}$`, e.g. `prod-aerolvm-us-east-1`. AOCR has no
pre-registered list of clusters; this is a label you choose so AOCR can
group your imported tags under `cluster/<your-id>/_imported/...`. Pick once
per cluster and never change it (changing it later orphans previously
imported tags under the old namespace).

### Step 2 — Stage the two secret files on the control node

Ansible's secret-copy tasks take a path on the **control node** (your laptop
or whatever box runs `ansible-playbook`) and copy each file to
`/etc/sandboxd/secrets/` on every managed host at `0600`.

```bash
mkdir -p ~/aerol-secrets
chmod 0700 ~/aerol-secrets

# If AOCR generated the secret files, copy them directly:
cp /path/to/aocr.sh/secrets/upstream_wrap_key  ~/aerol-secrets/upstream_wrap_key
cp /path/to/aocr.sh/secrets/internal_api_token ~/aerol-secrets/cluster_pat

# If the values are inline overrides in aocr.sh/ansible/.../secrets.yml,
# use the `aocr_secret` helper from Step 1's note to write the files:
#   aocr_secret aocr_auth_upstream_wrap_key upstream_wrap_key > ~/aerol-secrets/upstream_wrap_key
#   aocr_secret aocr_internal_api_token     internal_api_token > ~/aerol-secrets/cluster_pat

chmod 0600 ~/aerol-secrets/*
```

If your fleet renders these via Vault or another mechanism, leave the
corresponding `*_src` var empty and the play skips the copy.

### Step 3 — Fill in the vars

Either edit `inventory/group_vars/all.yml` for the whole fleet, or create a
group/host-specific file (e.g. `inventory/group_vars/aerolvm_role_worker.yml`)
to scope the change. Either way, set:

```yaml
# Mirror rewrite — required
sandboxd_mirror_host:                  "mirror.aocr.aerol.ai"
sandboxd_upstream_wrap_key_src:        "/home/you/aerol-secrets/upstream_wrap_key"

# Auto-import (F21) — optional; drop these four for cache-only mode
sandboxd_auto_import_enabled:          true
sandboxd_auto_import_hooks_url:        "https://aocr.aerol.ai"
sandboxd_auto_import_cluster_id:       "prod-aerolvm-us-east-1"   # pick once, never change
sandboxd_auto_import_cluster_pat_src:  "/home/you/aerol-secrets/cluster_pat"
# sandboxd_auto_import_retention_suffix: "--idle-90d"   # default
```

### Step 4 — Run configure-ops

```bash
ansible-playbook playbooks/configure-ops.yml
```

For each host the play:

1. Creates `/etc/sandboxd/secrets/` at `0700`.
2. Copies `upstream_wrap_key` → `/etc/sandboxd/secrets/upstream-wrap.key` (`0600`).
3. Copies `cluster_pat` → `/etc/sandboxd/secrets/cluster-pat` (`0600`).
4. Re-renders `/etc/sandboxd/cluster.env` with the `SB_MIRROR_*` / `SB_AUTO_IMPORT_*` lines.
5. Restarts `sandboxd` (gated by `sandboxd_restart_after_ops_config`, default true).

The cluster PAT is **file-sourced** — never an env var, never visible in
`systemctl show sandboxd` or process listings.

### Step 5 — Verify

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

### What each `sandboxd_*` var means

| Var | Purpose | Where the value comes from |
|---|---|---|
| `sandboxd_mirror_host` | Vhost sandboxd rewrites `ghcr.io` / `gcr.io` / `quay.io` / `registry.k8s.io` pulls onto. Empty disables rewrite entirely. Docker Hub is intentionally not rewritten. | AOCR side — derived from `aocr_global_domain` |
| `sandboxd_mirror_push_host` | Optional. Push vhost (e.g. `aocr.aerol.ai`) so already-pushed refs aren't double-rewritten. Leave empty unless sandboxes also push. | AOCR side |
| `sandboxd_mirror_upstreams` | Default `ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s`. Override only if your AOCR exposes different upstream shortnames. | AOCR operator |
| `sandboxd_upstream_wrap_key_src` | Path on the **control node** to the base64 32-byte AES-GCM key. The play copies it to `/etc/sandboxd/secrets/upstream-wrap.key`. Sandboxd wraps per-pull upstream creds with this; only AOCR's mirror can unwrap. Without it, private upstream pulls 401 at the mirror. | AOCR side — `secrets/upstream_wrap_key` (auto-generated on first AOCR deploy) |
| `sandboxd_auto_import_enabled` | Master switch for F21. When true, every successful private pull triggers a re-mount under `cluster/<id>/_imported/...`. | You |
| `sandboxd_auto_import_hooks_url` | AOCR hooks service root, e.g. `https://aocr.aerol.ai`. Sandboxd appends `/v1/internal/imports`. | AOCR side — same as `aocr_global_domain` |
| `sandboxd_auto_import_cluster_id` | **A label you choose**, not internal AOCR config. AOCR validates only the format (`^[A-Za-z0-9_-]{1,64}$`) and uses it as a namespace prefix for imported tags. Pick a meaningful per-cluster name like `prod-us-east-1`, `staging`, `dev-suman`. | You |
| `sandboxd_auto_import_cluster_pat_src` | Path on the **control node** to a file containing the bearer token sandboxd presents on `POST /v1/internal/imports`. Despite the name, this is AOCR's `internal_api_token`, not the UUID-keyed cluster PAT used by `auth/src/clusterPat.ts` (different concept; see `aocr_aerol_stitch.md`). | AOCR side — `secrets/internal_api_token` |
| `sandboxd_auto_import_retention_suffix` | Suffix appended to imported tags. Drives the reaper's idle-eviction window (see [`aocr.sh/RETENTION.md`](https://github.com/aerolai/aocr/blob/main/RETENTION.md)). | Operator policy |

Everything else (`request_timeout`, `reconcile_interval`, `max_in_flight`)
has a sensible default in `inventory/group_vars/all.yml` — only tune if
recovery storms or remote latency warrant it.

### Rotating secrets

- **Wrap key.** Add the new key alongside the old one in AOCR's
  `UPSTREAM_AUTH_WRAP_KEYS` (comma-separated), then overwrite the file at
  `sandboxd_upstream_wrap_key_src` and rerun `configure-ops.yml`. After
  every node has rotated, drop the old key from AOCR.
- **Internal API token / cluster PAT.** Rotate AOCR's `INTERNAL_API_TOKEN`,
  overwrite `sandboxd_auto_import_cluster_pat_src`, and rerun
  `configure-ops.yml`. Auto-imports queued under the old token will fail
  and the local reconciler will retry under the new one.

### TL;DR

1. AOCR was deployed once; its secrets sit in `aocr.sh/secrets/`.
2. Stage `upstream_wrap_key` + `internal_api_token` on the control node.
3. Set the `sandboxd_mirror_*` / `sandboxd_auto_import_*` vars in
   `inventory/group_vars/all.yml` (or a tighter scope).
4. `ansible-playbook playbooks/configure-ops.yml`.
5. Verify with `grep` / `ls` on a node and `curl /v1/images` on AOCR.

## When to use this vs. Terraform

| You want to...                                  | Use         |
|-------------------------------------------------|-------------|
| Add / remove / resize nodes                     | Terraform   |
| Change SG rules, DNS, AMI                       | Terraform   |
| Drain a node before Terraform role changes      | Ansible     |
| Push a new `sandboxd` binary                    | Ansible     |
| Change OTEL/image-pull env on running nodes     | Ansible     |
| Deploy backup/recovery helpers or backup cron   | Ansible     |
| Deploy Grafana/Prometheus/Alertmanager artifacts | Ansible     |
| Deploy operational runbooks                     | Ansible     |
| Restart a service, rotate a PAT, tail logs      | Ansible     |
| Run one-off shell commands across many nodes    | Ansible     |

Terraform's `user_data` only runs at instance launch — it can't update an
already-running node. That's what this folder exists for.
