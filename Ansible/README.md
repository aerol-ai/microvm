# AerolVM cluster - Ansible

Day-N operations against the cluster that `../Terraform` provisions. Terraform
owns infra (VPC, EC2, SG, DNS); Ansible owns "push a new binary, restart a
service, tail logs across all nodes."

## Prereqs

- Ansible ≥ 2.15 (`pipx install ansible-core` or `brew install ansible`)
- `boto3` + `botocore` reachable from **Ansible's Python** (see install note below)
- AWS credentials in the default chain (env, profile, instance role) with
  `ec2:DescribeInstances` - that's all the inventory plugin needs
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
#   - brew install ansible:  brew installs them as part of the formula - skip
#   - system pip / venv:     pip install boto3 botocore  (into the SAME env
#                            that owns the `ansible` binary)
#
# If you `pip install boto3` into your base/conda env while Ansible lives in
# a pipx venv, Ansible won't see it and `ansible-inventory --graph` will fail
# with "Failed to import the required Python library (botocore and boto3)".
pipx inject ansible-core boto3 botocore

# Load your SSH key into the agent (per session, no config edit needed).
ssh-add ~/.ssh/your-aws-key.pem

# Cluster=aerolvm / region=us-east-1 are the built-in defaults - nothing to set.
export AWS_PROFILE=default            # only if you use named profiles
```

Smoke test:

```bash
ansible-inventory --graph        # should list your EC2 nodes grouped by tag
ansible-playbook playbooks/ping.yml
```

## Inventory

`inventory/aws_ec2.yml` is a dynamic inventory plugin - it queries EC2 every
time you run a playbook. It filters by the `Cluster` tag (default `aerolvm`,
matches `var.cluster_name` in Terraform) in `us-east-1`. Those defaults match a
standard deploy, so **you normally set nothing**. Only if your fleet uses a
different cluster name or region, override inline for that one command:

```bash
AEROLVM_CLUSTER=prod AEROLVM_REGION=us-west-2 ansible-inventory --graph
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
# node lifecycle, Grafana, Prometheus, Alertmanager, and runbook artifacts.
# OTEL endpoints, image-pull/GC tuning, mirror host, and auto-import config
# live in ../config/cluster.yml (shared with Terraform) - edit there.
ansible-playbook playbooks/configure-ops.yml \
  -e sandboxd_backup_enabled=true
```

`update-sandboxd.yml` runs `serial: 1` - one host at a time, with
`any_errors_fatal: true` - so a failed health check on node 1 stops the
rollout before it touches the Raft quorum. Limit to a single non-seed test
node first (use a hostname from `ansible-inventory --graph`, e.g. one that
shows up under `@aerolvm_false`):

```bash
ansible-playbook playbooks/update-sandboxd.yml \
  -e sandboxd_remote_url=https://github.com/aerol-ai/microvm/releases/latest/download/sandboxd_linux_amd64 \
  --limit aerolvm-node3
```

Release asset names come from `.github/workflows/release.yml` and follow
`sandboxd_<goos>_<goarch>` - `linux_amd64`, `linux_arm64`, `linux_armv7`,
`linux_armv6`, `linux_386`, `freebsd_amd64`, `darwin_arm64`, etc.

## Per-machine config

`ansible.cfg` is committed - your SSH key path, AWS profile, region, and
cluster name are per-machine and don't belong in it. Use:

- `ssh-add ~/.ssh/<your-key>.pem` for the key (persist on macOS with
  `ssh-add --apple-use-keychain`). Once loaded, `ansible-playbook` picks it
  up via the agent - no `--private-key` flag, no config edit.
- `AWS_PROFILE` env var if you use named profiles. (`AEROLVM_CLUSTER` /
  `AEROLVM_REGION` default to `aerolvm` / `us-east-1` - set them only to override.)
- `Ansible/ansible.local.cfg` (gitignored) + `ANSIBLE_CONFIG=$PWD/Ansible/ansible.local.cfg`
  if you genuinely need to override `ansible.cfg` settings locally.

## Layout

```
ansible.cfg            # forks, ssh args, default inventory + remote_user
requirements.yml       # collections to install
inventory/
  aws_ec2.yml          # dynamic inventory (EC2 → hosts/groups via tags)
  group_vars/
    all/
      defaults.yml     # committed defaults (ships every optional feature OFF)
      local.yml        # GITIGNORED per-operator overrides (auto-loaded
                       # after defaults.yml; later files win alphabetically)
      local.yml.example # copy-to-customize template
                       # (group_vars must live next to the inventory; Ansible
                       # auto-loads from inventory/ or playbooks/, not the
                       # repo root)
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
authenticated mirror - and optionally auto-import each first pull into a
cluster-owned namespace so future failovers are decoupled from the original
upstream credential. The defaults in `inventory/group_vars/all/defaults.yml`
and the secret-copy + env-template tasks in `playbooks/configure-ops.yml`
are already in place. Enabling it requires zero code edits - only values in
a gitignored `local.yml` (no secret files needed if you use the inline-value
mode).

Use this path if you bootstrapped nodes with Ansible only, or if you want to
flip the AOCR wiring on existing nodes without recycling EC2 instances
(Terraform's path replaces them).

For the threat model and per-node env-var contract, read
[`../AUTHENTICATED_MIRROR.md`](../AUTHENTICATED_MIRROR.md). For AOCR-side
architecture, read
[`aocr.sh/MIRROR.md`](https://github.com/aerolai/aocr/blob/main/MIRROR.md).
For the full end-to-end deploy + stitch story, read
[`aocr.sh/aocr_aerol_stitch.md`](https://github.com/aerolai/aocr/blob/main/aocr_aerol_stitch.md).

### Step 1 - Pull values from your AOCR side

The AOCR Ansible playbook auto-generates every secret on first deploy. After
you've run it once, the values you need are in `aocr.sh/secrets/` and
`aocr.sh/ansible/inventory/group_vars/all/vars.yml`:

```bash
cd /path/to/aocr.sh

# 1. Mirror host - derived from your aocr_global_domain
#    Default is "mirror." + aocr_global_domain (e.g. mirror.aocr.aerol.ai).
grep aocr_global_domain ansible/inventory/group_vars/all/vars.yml

# 2. Upstream wrap key (base64, 32 bytes) - required for private upstream pulls
cat secrets/upstream_wrap_key

# 3. Internal API token (64-char bearer) - only for auto-import
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

### Step 2 - Choose how to hand the secrets to the play

Two ways to do this - pick whichever fits your setup. **Inline values** are
simplest for a single operator on a laptop; **control-node files** are how
fleets do it when Vault/SOPS/Secrets Manager renders secrets out-of-band.

**Important: never commit secrets to git.** Edit `inventory/group_vars/all.yml`
and you've edited a tracked file. The clean pattern is a gitignored override
file - convert `all.yml` into a directory: `all/defaults.yml` (committed,
ships everything OFF) plus `all/local.yml` (gitignored, per-operator).
Ansible auto-loads every `*.yml` in `group_vars/all/` **alphabetically, and
later files win**, so the file names matter: `defaults.yml` < `local.yml`,
so `local.yml` overrides `defaults.yml`. If you name the defaults file
something that sorts after `local.yml` (e.g. `main.yml`, `vars.yml`) the
override won't apply.

#### Option A - Inline values (recommended for laptop / single operator)

Set `sandboxd_*_value` directly in your gitignored override file. The play
uses `copy: content:` to write the bytes onto each managed host at `0600`,
and the secret-installing tasks are `no_log: true` so the values don't
land in stdout.

No staging on the control node - skip to Step 3.

#### Option B - Control-node files (fleet / Vault-rendered)

Set `sandboxd_*_src` to a path on the control node (the box that runs
`ansible-playbook`). The play uses `copy: src:` to push that file out:

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

If your fleet renders these via Vault or another mechanism, point `_src`
at whatever path that pipeline writes to.

> If a `*_src` path is set AND the matching `aocr.*` key in
> `config/secrets.yml` is non-empty, the `config/secrets.yml` value wins.
> Leaving both empty skips the copy entirely - sandboxd boots without the
> secret and the corresponding feature is disabled.

### Step 3 - Fill in the vars

Non-secret AOCR config (mirror host, auto-import toggle / hooks_url /
cluster_id, retention/timeouts) lives in the shared `../config/cluster.yml`.
AOCR secret values live in the parallel shared `../config/secrets.yml`
(gitignored - bootstrap with `cp ../config/secrets.example.yml ../config/secrets.yml`).
Edit those two files once; both Terraform (day-0) and Ansible (day-2) read them.

```yaml
# ../config/cluster.yml
mirror:
  host: "mirror.aocr.aerol.ai"
  upstreams: "docker.io=docker,ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s"

auto_import:
  enabled: true
  hooks_url: "https://aocr.aerol.ai"
  cluster_id: "prod-aerolvm-us-east-1"   # pick once, never change
  retention_suffix: "--idle-7d"
```

```yaml
# ../config/secrets.yml  (gitignored - copy from secrets.example.yml)
aocr:
  upstream_wrap_key: "<paste upstream_wrap_key>"
  cluster_pat:       "<paste internal_api_token>"
```

**Optional - control-node file paths (Vault/SOPS workflow):** if your fleet
renders the secrets to files instead, leave the matching keys in
`config/secrets.yml` empty and point at the rendered files from
`group_vars/all/local.yml`:

```yaml
sandboxd_upstream_wrap_key_src:          "/home/you/aerol-secrets/upstream_wrap_key"
sandboxd_auto_import_cluster_pat_src:    "/home/you/aerol-secrets/cluster_pat"
```

### Step 4 - Run configure-ops

```bash
ansible-playbook playbooks/configure-ops.yml
```

For each host the play:

1. Creates `/etc/sandboxd/secrets/` at `0700`.
2. Copies `upstream_wrap_key` → `/etc/sandboxd/secrets/upstream-wrap.key` (`0600`).
3. Copies `cluster_pat` → `/etc/sandboxd/secrets/cluster-pat` (`0600`).
4. Re-renders `/etc/sandboxd/cluster.env` with the `SB_MIRROR_*` / `SB_AUTO_IMPORT_*` lines.
5. Restarts `sandboxd` (gated by `sandboxd_restart_after_ops_config`, default true).

The cluster PAT is **file-sourced** - never an env var, never visible in
`systemctl show sandboxd` or process listings.

### Step 5 - Verify

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

### What each var means

Non-secret keys live in `../config/cluster.yml` (shared SoT, committable).
Secret values live in `../config/secrets.yml` (shared SoT, gitignored). The
two `*_src` vars in `group_vars/all/local.yml` are an Ansible-only fallback
for Vault/SOPS rendering - not needed if `config/secrets.yml` holds the
values directly.

**`../config/cluster.yml` - `mirror.*` / `auto_import.*`:**

| Key | Purpose | Where the value comes from |
|---|---|---|
| `mirror.host` | Vhost sandboxd rewrites `ghcr.io` / `gcr.io` / `quay.io` / `registry.k8s.io` pulls onto. Empty disables rewrite entirely. Docker Hub is intentionally not rewritten. | AOCR side - derived from `aocr_global_domain` |
| `mirror.push_host` | Optional. Push vhost (e.g. `aocr.aerol.ai`) so already-pushed refs aren't double-rewritten. Leave empty unless sandboxes also push. | AOCR side |
| `mirror.upstreams` | Default `docker.io=docker,ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s`. Override only if your AOCR exposes different upstream shortnames. | AOCR operator |
| `auto_import.enabled` | Master switch for F21. When true, every successful private pull triggers a re-mount under `cluster/<id>/_imported/...`. | You |
| `auto_import.hooks_url` | AOCR hooks service root, e.g. `https://aocr.aerol.ai`. Sandboxd appends `/v1/internal/imports`. | AOCR side - same as `aocr_global_domain` |
| `auto_import.cluster_id` | **A label you choose**, not internal AOCR config. AOCR validates only the format (`^[A-Za-z0-9_-]{1,64}$`) and uses it as a namespace prefix for imported tags. Pick a meaningful per-cluster name like `prod-us-east-1`, `staging`, `dev-suman`. | You |
| `auto_import.retention_suffix` | Suffix appended to imported tags. Drives the reaper's idle-eviction window (see [`aocr.sh/RETENTION.md`](https://github.com/aerolai/aocr/blob/main/RETENTION.md)). | Operator policy |

`request_timeout`, `reconcile_interval`, and `max_in_flight` in the same
file have sensible defaults - only tune if recovery storms or remote latency
warrant it.

**`../config/secrets.yml` - `aocr.*` (gitignored):**

| Key | Purpose | Where the value comes from |
|---|---|---|
| `aocr.upstream_wrap_key` | Base64 32-byte AES-GCM key. Written to `/etc/sandboxd/secrets/upstream-wrap.key` via `copy: content:` (no_log). Sandboxd wraps per-pull upstream creds with this; only AOCR's mirror can unwrap. Without it, private upstream pulls 401 at the mirror. | AOCR side - `aocr_auth_upstream_wrap_key` from `secrets.yml`, or `cat secrets/upstream_wrap_key` |
| `aocr.cluster_pat` | Bearer token sandboxd presents on `POST /v1/internal/imports`. Written to `/etc/sandboxd/secrets/cluster-pat` via `copy: content:` (no_log). Despite the name, this is AOCR's `internal_api_token`, not the UUID-keyed cluster PAT used by `auth/src/clusterPat.ts` (different concept; see `aocr_aerol_stitch.md`). | AOCR side - `aocr_internal_api_token` or `cat secrets/internal_api_token` |

**Ansible local override (gitignored) - Vault/SOPS fallback only:**

| Var | Purpose | Where the value comes from |
|---|---|---|
| `sandboxd_upstream_wrap_key_src` | Path on the **control node** to a file holding the wrap key. The play copies it to `/etc/sandboxd/secrets/upstream-wrap.key` via `copy: src:`. Use when Vault/SOPS/Secrets Manager renders the file. If `aocr.upstream_wrap_key` in `config/secrets.yml` is also set, secrets.yml wins. | AOCR side - `secrets/upstream_wrap_key` (auto-generated on first AOCR deploy) |
| `sandboxd_auto_import_cluster_pat_src` | Path on the **control node** to a file holding the cluster PAT. Same precedence rules as the wrap key. | AOCR side - `secrets/internal_api_token` |

### Rotating secrets

- **Wrap key.** Add the new key alongside the old one in AOCR's
  `UPSTREAM_AUTH_WRAP_KEYS` (comma-separated), then update the cluster
  side: replace `aocr.upstream_wrap_key` in `../config/secrets.yml`
  (default) or overwrite the file at `sandboxd_upstream_wrap_key_src`
  (Vault/SOPS mode). Rerun `configure-ops.yml`. After every node has
  rotated, drop the old key from AOCR.
- **Internal API token / cluster PAT.** Rotate AOCR's `INTERNAL_API_TOKEN`,
  then update `aocr.cluster_pat` in `../config/secrets.yml` (default) or
  overwrite the file at `sandboxd_auto_import_cluster_pat_src` (Vault/SOPS
  mode), and rerun `configure-ops.yml`. Auto-imports queued under the old
  token will fail and the local reconciler will retry under the new one.

### TL;DR

1. AOCR was deployed once; its secrets sit in `aocr.sh/secrets/` (or
   inline in `aocr.sh/ansible/inventory/group_vars/all/secrets.yml`).
2. Set `mirror.host` and `auto_import.*` in `../config/cluster.yml` (shared
   with Terraform - committable, no secrets).
3. Set `aocr.upstream_wrap_key` and `aocr.cluster_pat` in
   `../config/secrets.yml` (copy from `secrets.example.yml`, gitignored,
   shared with Terraform). For Vault/SOPS rendering, leave those empty and
   point `sandboxd_*_src` at staged paths in `group_vars/all/local.yml`.
4. `ansible-playbook playbooks/configure-ops.yml`.
5. Verify with `grep` / `ls` on a node and `curl /v1/images` on AOCR.

## Install Firecracker on existing nodes

`configure-ops.yml` installs the Firecracker binary, jailer, and a guest
kernel image whenever `firecracker.enabled: true` in `../config/cluster.yml`.
No per-host or per-arch configuration is required - the play detects
`uname -m`, picks the matching upstream asset, verifies its SHA256, and
installs to the paths sandboxd already reads from
(`SB_FIRECRACKER_BINARY`, `SB_JAILER_BINARY`, `SB_FIRECRACKER_KERNEL`).

### Host requirements (read this first)

Firecracker is a **KVM-only VMM**. The host must expose `/dev/kvm`:

- **AWS EC2:** only bare-metal instance types pass KVM through to the OS.
  Use `*.metal` SKUs (`c5n.metal`, `m5zn.metal`, `c7g.metal`, `i3.metal`,
  `m5.metal`, `c5.metal`, etc.). Standard `t3`/`m5`/`c5`/`c6i`/`m6i`/`r5`
  instances are themselves Nitro guests - `/dev/kvm` does not exist and
  Firecracker cannot run there.
- **GCP:** N2/N1 with `--enable-nested-virtualization` on the image.
- **Azure:** Dv3/Ev3+ with nested virtualization.
- **Bare metal / on-prem:** Intel VT-x or AMD-V enabled in BIOS, then
  `sudo modprobe kvm_intel` (or `kvm_amd`).

The play **hard-fails** with a remediation message if `/dev/kvm` is missing.
If you need to install `configure-ops.yml`'s other artifacts (OTEL,
backup, runbooks) on a host that can't run Firecracker, set
`firecracker.enabled: false` in `../config/cluster.yml` and re-run. To
install Firecracker on a *subset* of capable hosts only, target the play
with `--limit` at a group whose nodes all expose `/dev/kvm`.

```yaml
# ../config/cluster.yml
firecracker:
  enabled: true
  kernel_path: "/var/lib/sandboxd/firecracker/vmlinux"
```

```bash
ansible-playbook playbooks/configure-ops.yml
```

What the play actually does, per host:

1. Runs `uname -m` and maps `x86_64|amd64 → x86_64`, `aarch64|arm64 → aarch64`.
   Anything else fails fast - Firecracker upstream only publishes those two.
2. Stats `/dev/kvm`. Missing? Fails fast (the host is a non-nested VM or virt
   is off in BIOS - cheaper to fail here than at first `CreateSandbox`).
3. Probes `firecracker --version`. If the installed binary already matches
   `firecracker_version`, skips the download. Idempotent re-runs are cheap.
4. Downloads `firecracker-<ver>-<arch>.tgz` + its `.sha256.txt` sidecar
   from `github.com/firecracker-microvm/firecracker/releases`, verifies with
   `sha256sum -c`, extracts, installs binary + jailer.
5. Downloads the guest kernel from `s3.amazonaws.com/spec.ccfc.min`
   (the upstream-blessed CI bucket) to `firecracker.kernel_path`. The
   defaults are pinned to a known-good combination (see below).
6. Creates `firecracker.run_dir`, `templates_dir`, and `jailer_chroot_base`.

### Pins and overrides

Defaults in `inventory/group_vars/all/defaults.yml`:

| Var | Default | What it controls |
|---|---|---|
| `firecracker_version` | `v1.15.1` | GitHub release tag; binary + jailer come from `firecracker-microvm/firecracker/releases/download/<ver>/` |
| `firecracker_kernel_ci_version` | `v1.15` | CI bucket directory; usually `v<major>.<minor>` of the release |
| `firecracker_kernel_version` | `5.10.245` | Guest kernel patch level; the bucket also ships 6.1 if you need a newer guest |
| `firecracker_binary_url` | `""` | Set in `local.yml` to pull binary from a private mirror; bypasses upstream + checksum |
| `firecracker_jailer_url` | `""` | Same for the jailer |
| `firecracker_kernel_url` | `""` | Same for the kernel; useful if you ship a hand-built `vmlinux` |

Bump the version pins together: when Firecracker releases `v1.16.0`, set
`firecracker_version: "v1.16.0"` and `firecracker_kernel_ci_version: "v1.16"`,
then list the bucket to pick the latest patch:

```bash
curl -s 'https://s3.amazonaws.com/spec.ccfc.min/?prefix=firecracker-ci/v1.16/x86_64/vmlinux-5.10&list-type=2' \
  | grep -oE '<Key>[^<]+</Key>' | sort -V | tail -3
```

Both `x86_64` and `aarch64` ship the same kernel patch in lockstep, so one
`firecracker_kernel_version` value covers a mixed fleet.

### Limit to specific hosts

`firecracker.enabled` is a cluster-wide switch. To install on a subset of
hosts without flipping the cluster default, target the play with `--limit`:

```bash
ansible-playbook playbooks/configure-ops.yml --limit aerolvm_role_worker
```

### Why this differs from `scripts/install.sh`

`scripts/install.sh` is day-0 bootstrap and only handles binaries that ship
with sandboxd itself (sandboxd, toolboxd, runsc, the NVIDIA toolkit). The
Firecracker runtime is opt-in and large enough to want its own day-2
lifecycle, so it lives here instead.

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
| Install / upgrade Firecracker binary + kernel   | Ansible     |
| Restart a service, rotate a PAT, tail logs      | Ansible     |
| Run one-off shell commands across many nodes    | Ansible     |

Terraform's `user_data` only runs at instance launch - it can't update an
already-running node. That's what this folder exists for.
