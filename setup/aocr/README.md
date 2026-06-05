# Connecting AerolVM to AOCR

End-user setup guide for wiring an AerolVM cluster to an already-deployed
[AOCR](https://github.com/aerolai/aocr) so private image pulls flow through
the authenticated mirror and (optionally) auto-import into the cluster's
own namespace after first pull.

> **Reference:** [`AUTHENTICATED_MIRROR.md`](../../AUTHENTICATED_MIRROR.md)
> documents every `SB_MIRROR_*` / `SB_AUTO_IMPORT_*` env var, the wrap-key
> threat model, and the F17-F21 phase numbering. This page only covers how
> to feed those settings into the cluster via Terraform or Ansible.

## Prerequisites

You need an AOCR deployment that is already up and reachable from every
AerolVM node. From the AOCR operator, get these three values:

| You need                  | Where it lives on the AOCR side                                | What it's for                                                                 |
|---------------------------|----------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Mirror host**           | The vhost AOCR exposes for cached pulls (e.g. `mirror.aocr.example.com`) | Sandboxd rewrites `ghcr.io`/`gcr.io`/`quay.io`/`registry.k8s.io` pulls onto this host. |
| **Upstream wrap key**     | `aocr.sh/secrets/upstream_wrap_key` (base64, 32 bytes)         | Wraps per-pull upstream credentials so the mirror - and only the mirror - can unwrap them. Required for **private** upstream pulls. |
| **Internal API token**    | `aocr.sh/secrets/internal_api_token` (64-char string)          | Bearer token sandboxd presents on `POST /v1/internal/imports`. **Only needed for auto-import (F21).** |

Plus one identifier you choose yourself:

| You need        | What it's for                                                                                            |
|-----------------|----------------------------------------------------------------------------------------------------------|
| **Cluster ID**  | This cluster's name on the AOCR side (matches `^[A-Za-z0-9_-]{1,64}$`). Imported tags land under `cluster/<id>/_imported/...`. |

The wrap key and the internal API token are real secrets. Treat them like
`pat_token` and `cloudflare_api_token`.

## Pick your path

| You provision nodes with | Use                                |
|--------------------------|------------------------------------|
| Terraform                | [Terraform setup](#terraform-setup) |
| Ansible only             | [Ansible setup](#ansible-setup)     |
| Both (Terraform → Ansible later) | [Terraform setup](#terraform-setup) - Ansible's `configure-ops.yml` will read the same `/etc/sandboxd/cluster.env` and overwrite cleanly if you run it later. |

---

## Terraform setup

AOCR config is split across two shared SoT files at the repo root that
both Terraform and Ansible read:

- `config/cluster.yml` (committed) holds the non-secret knobs: mirror host,
  upstreams, auto-import toggle / hooks_url / cluster_id, retention suffix,
  timeouts, max-in-flight.
- `config/secrets.yml` (gitignored - `cp config/secrets.example.yml config/secrets.yml`
  on first checkout) holds the two AOCR secrets: `aocr.upstream_wrap_key`
  and `aocr.cluster_pat`.

Nothing AOCR-specific lives in `terraform.tfvars` anymore.

### Modes

**Off (default).** Leave `mirror.host` empty and `auto_import.enabled = false`
in `config/cluster.yml`. The bootstrap template skips the AOCR section.

**Mirror-only - cached + wrapped private pulls.**

```yaml
# config/cluster.yml
mirror:
  host: "mirror.aocr.example.com"
  upstreams: "docker.io=docker,ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s"
```

```yaml
# config/secrets.yml  (gitignored)
aocr:
  upstream_wrap_key: "BASE64_32_BYTES_FROM_aocr.sh/secrets/upstream_wrap_key"
  cluster_pat:       ""
```

Pulls of `ghcr.io/...`, `gcr.io/...`, `quay.io/...`, and `registry.k8s.io/...`
flow through the mirror. Private pulls use wrapped credentials.

**Mirror + auto-import (full F21).** Plan-time validation rejects
`auto_import.enabled = true` without all three of `auto_import.hooks_url`,
`auto_import.cluster_id`, and `aocr.cluster_pat`:

```yaml
# config/cluster.yml
mirror:
  host: "mirror.aocr.example.com"
  upstreams: "docker.io=docker,ghcr.io=ghcr,gcr.io=gcr,quay.io=quay,registry.k8s.io=k8s"

auto_import:
  enabled: true
  hooks_url: "https://aocr.example.com"     # AOCR hooks service root, no trailing slash
  cluster_id: "prod-aerolvm-us-east-1"
  retention_suffix: "--idle-90d"             # optional; default --idle-90d
```

```yaml
# config/secrets.yml  (gitignored)
aocr:
  upstream_wrap_key: "BASE64_32_BYTES_FROM_aocr.sh/secrets/upstream_wrap_key"
  cluster_pat:       "TOKEN_FROM_aocr.sh/secrets/internal_api_token"
```

After this, each successful private pull triggers a re-mount under
`cluster/prod-aerolvm-us-east-1/_imported/<host>/<repo>:<tag>--idle-90d`
on the AOCR side, fully decoupled from the original upstream credential.

`config/secrets.yml` is loaded via `sensitive(yamldecode(...))` so plan/apply
output won't print the wrap key or PAT.

### Apply

```sh
terraform apply
```

Existing nodes recycle (`user_data_replace_on_change = true`) because the
bootstrap script content changed. The new bootstrap:

1. Creates `/etc/sandboxd/secrets/` at `0700`.
2. Writes the wrap key to `/etc/sandboxd/secrets/upstream-wrap.key` (`0600`) if `upstream_wrap_key` is non-empty.
3. Writes the cluster PAT to `/etc/sandboxd/secrets/cluster-pat` (`0600`) if `cluster_pat` is non-empty.
4. Appends `SB_MIRROR_*` / `SB_AUTO_IMPORT_*` to `/etc/sandboxd/cluster.env`.
5. `systemctl restart sandboxd`.

The cluster PAT is **file-sourced**, never an env var - it never appears
in `systemctl show sandboxd` or process listings.

---

## Ansible setup

Ansible reads the **same** `config/cluster.yml` and `config/secrets.yml`
files Terraform uses, so the YAML blocks under [Terraform setup](#terraform-setup)
above are also the Ansible config - there is no separate inline-value var
to set in `local.yml` anymore.

For fleet / Vault-rendered workflows, leave `aocr.upstream_wrap_key` /
`aocr.cluster_pat` empty in `config/secrets.yml` and point at staged file
paths from `Ansible/inventory/group_vars/all/local.yml`:

```yaml
# inventory/group_vars/all/local.yml - gitignored
sandboxd_upstream_wrap_key_src:          "/home/you/aerol-secrets/upstream_wrap_key"
sandboxd_auto_import_cluster_pat_src:    "/home/you/aerol-secrets/cluster_pat"
```

The playbook writes the bytes to `/etc/sandboxd/secrets/upstream-wrap.key`
and `/etc/sandboxd/secrets/cluster-pat` on each managed host at `mode 0600`
either way. See [`Ansible/README.md` § Step 2](../../Ansible/README.md#step-2--choose-how-to-hand-the-secrets-to-the-play)
for the full file-layout pattern.

Then:

```sh
ansible-playbook Ansible/playbooks/configure-ops.yml
```

Sandboxd restarts on each host as the env file changes (controlled by
`sandboxd_restart_after_ops_config`).

The full list of plumbing defaults lives in
[`Ansible/inventory/group_vars/all/defaults.yml`](../../Ansible/inventory/group_vars/all/defaults.yml).

---

## Verifying it works

After bootstrap (Terraform) or `configure-ops.yml` (Ansible) finishes,
ssh into any node:

```sh
# 1. Env wired up
sudo grep -E '^SB_(MIRROR|AUTO_IMPORT)_' /etc/sandboxd/cluster.env

# 2. Secrets installed with correct perms
sudo ls -l /etc/sandboxd/secrets/
# -rw------- 1 root root  ... upstream-wrap.key
# -rw------- 1 root root  ... cluster-pat   (auto-import only)

# 3. Sandboxd picked them up
systemctl is-active sandboxd
curl -sf http://127.0.0.1:21212/health
```

Trigger a private pull through the SDK or `docker pull` against a
sandbox, then on the AOCR side:

```sh
# Mirror cache populated?
curl -sf https://mirror.aocr.example.com/v2/_catalog | jq

# Auto-import landed?
curl -sf https://aocr.example.com/v2/_catalog | jq \
  | grep "cluster/prod-aerolvm-us-east-1/_imported/"
```

## Troubleshooting

| Symptom                                                       | Likely cause                                                                                       |
|---------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| Public pulls succeed but private pulls 401                    | `upstream_wrap_key` empty or doesn't match an active key in AOCR's `UPSTREAM_AUTH_WRAP_KEYS`.       |
| `terraform plan` rejects with "hooks_url, cluster_id, cluster_pat are all required" | You set `auto_import_enabled = true` but omitted one of those three. They are mandatory together. |
| Sandboxd refuses to boot with auto-import config              | Startup guard mirrors the same Terraform validation. Check `journalctl -u sandboxd` for the missing field. |
| Auto-import POSTs 401                                         | `cluster_pat` doesn't match AOCR's `INTERNAL_API_TOKEN`. Re-fetch from `aocr.sh/secrets/internal_api_token`. |
| Imported tags never appear under `cluster/<id>/_imported/...` | Check `journalctl -u sandboxd | grep auto_import` for the reconciler's per-image outcome.          |

## Rotating secrets

- **Wrap key:** add the new key alongside the old one in AOCR's
  `UPSTREAM_AUTH_WRAP_KEYS` (comma-separated), then bump `upstream_wrap_key`
  in your tfvars/group_vars and re-apply. After every node has rotated,
  drop the old key from AOCR.
- **Cluster PAT:** rotate AOCR's `INTERNAL_API_TOKEN` and update
  `cluster_pat` / `sandboxd_auto_import_cluster_pat_src`, then re-apply.
  Auto-imports queued under the old token will fail and the reconciler
  will retry under the new one.
