# Single-Node Setup

Deploy AerolVM on one bare-metal server or VPS with a public domain, wildcard
TLS, and Caddy reverse-proxying sandbox traffic. This is the standard
production deployment for a single-tenant or low-volume installation.

When to pick this over [`cluster.md`](./cluster.md):

- Your workload fits on one host's CPU + memory.
- You don't need failover - a host outage means a sandbox outage until you
  bring the host back.
- You want minimal moving parts (no raft, no gossip, no inter-node mTLS).

When to pick [`local.md`](./local.md) instead: you're developing the SDK on a
laptop and don't need a public domain.

---

## Architecture (one host)

```
                            Internet
                                │
                            ┌───┴───┐
                            │ :443  │ caddy (TLS termination, SNI routing)
                            └───┬───┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
       https://api.example       https://<id>.example
              │                 │
              ▼                 ▼
        ┌──────────┐      ┌─────────────────────┐
        │ sandboxd │      │  sandbox containers │
        │  :21212  │◄─────┤  (Docker / gVisor)  │
        └────┬─────┘      └─────────────────────┘
             │
             ▼
        SQLite at /var/lib/sandboxd/state.db
```

Single binary (`sandboxd`) plus Caddy plus Docker. SQLite is the source of
truth for sandbox state.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Linux host (apt-based) | Debian 12+ or Ubuntu 22.04+ tested. Arm or x86_64. |
| Public IPv4 | Static. Bound DNS records (see below). |
| Domain you control | e.g. `sandbox.example.com`. Subdomains under this become sandbox URLs. |
| DNS provider with API access | Cloudflare is currently the only supported provider for DNS-01. |
| `sudo` / root | The installer writes to `/etc/`, `/var/lib/`, and `systemd`. |
| Open ports | `443/TCP` (HTTPS), `2220/TCP` (SSH gateway), `22000-23000/TCP` (raw-TCP exposes - only if you'll use them). |

`21212/TCP` (the API port) and `2019/TCP` (Caddy admin) bind to the host but
should **not** be exposed publicly - Caddy fronts the API on `:443`.

---

## Step 1 - DNS records

Create both records before running the installer. Wildcard issuance fails
without them.

```
A     sandbox.example.com    →  <server-ip>
A     *.sandbox.example.com  →  <server-ip>
```

The wildcard is mandatory: every sandbox gets its own subdomain
(`https://<sandbox-id>.sandbox.example.com`) and exposed ports get
`https://<sandbox-id>-<port>.sandbox.example.com`.

Verify propagation before continuing:

```bash
dig +short sandbox.example.com
dig +short anything.sandbox.example.com
```

Both should return your server IP.

---

## Step 2 - Cloudflare API token

Caddy uses DNS-01 challenges (not HTTP-01) so the wildcard cert renews
without ever touching `:443`. Create a **scoped** token at
[Cloudflare → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens):

| Permission | Scope |
|---|---|
| Zone → Zone → Read | The zone for `example.com` |
| Zone → DNS → Edit | The zone for `example.com` |

Save the token - the installer needs it.

> **Why DNS-01 only?** HTTP-01 with Caddy's `ask` endpoint would accept any
> subdomain probe and could burn the Let's Encrypt 50-cert/week quota for the
> whole domain. DNS-01 issues exactly two certs (`<domain>` + `*.<domain>`)
> and renews them on a schedule, regardless of how many sandboxes exist.

---

## Step 3 - Open the firewall

On your VPS provider's security group / `ufw` / cloud firewall:

```
ALLOW 443/TCP        from anywhere      # HTTPS API + sandbox URLs
ALLOW 2220/TCP       from anywhere      # SSH gateway (set SB_ENABLE_SSH_GATEWAY=false to skip)
ALLOW 22000-23000/TCP from anywhere     # Raw-TCP sandbox exposures (only if you'll use them)
```

`80/TCP` is **not** needed - DNS-01 doesn't go through HTTP.

---

## Step 4 - Install

One command:

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --pat-token your-secret-pat \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token>
```

Optional add-ons (combine as needed):

| Flag | Purpose |
|---|---|
| `--with-gvisor` | Adds gVisor's `runsc` runtime; sandboxes opt in via `runtime: "gvisor"`. Recommended for untrusted code. |
| `--with-nvidia-gpu` | Installs `nvidia-container-toolkit` and registers the `nvidia` Docker runtime. Driver must already be present (`nvidia-smi` works). |
| `--with-amd-gpu` | Installs ROCm and exposes `/dev/kfd` + `/dev/dri`. x86_64 only. |
| `--idle-timeout-min 30` | Auto-stop idle sandboxes after N minutes. |

What the installer does:

1. Installs Docker, fuse3 / sshfs / nfs-common / rclone / mountpoint-s3 (for
   external-storage mounts), and a custom Caddy build with the
   `caddy-l4` and `caddy-dns/cloudflare` plugins.
2. Downloads `sandboxd` + `toolboxd` binaries.
3. Writes `/etc/sandboxd/sandboxd.env` and `/etc/caddy/Caddyfile`.
4. Registers `sandboxd.service` (always-restart, 5s backoff) and
   `sandboxd-healthcheck.timer` (probes `/health` every 30s).
5. Starts everything.

Verify:

```bash
curl https://sandbox.example.com/health
```

Should return `200 OK` with a JSON body. If the cert isn't ready yet (first
DNS-01 challenge can take 30-90s), check `journalctl -u caddy -f`.

---

## Step 5 - Connect from an SDK

```ts
import { Sandbox } from "@aerol-ai/sdk";

const sb = new Sandbox({
  baseURL: "https://sandbox.example.com",
  apiKey: process.env.SB_PAT_TOKEN,
});
```

See [SDK Setup](https://microvm.aerol.ai/sdk-setup) for the other four SDK
languages.

---

## Day-to-day operations

| Task | Command |
|---|---|
| View daemon logs | `journalctl -u sandboxd -f` |
| View Caddy logs | `journalctl -u caddy -f` |
| Restart daemon | `sudo systemctl restart sandboxd` |
| Restart Caddy | `sudo systemctl restart caddy` |
| Re-read PAT | `grep SB_PAT_TOKEN /etc/sandboxd/sandboxd.env` |
| Re-read Cloudflare token | `cat /etc/default/caddy` |
| Update binaries | Re-run the installer with the same flags. State and certs are preserved. |
| List sandboxes | `curl -H "Authorization: Bearer $SB_PAT_TOKEN" https://sandbox.example.com/v1/sandboxes` |

The systemd watchdog (`sandboxd-healthcheck.timer`) restarts the daemon if
`/health` fails. The daemon itself restarts on any non-zero exit
(`Restart=always`, max 10 restarts per 5 min).

**Switching the netrules backend** (`SB_NETRULES_BACKEND=exec|netlink` in
`/etc/sandboxd/sandboxd.env`): check `iptables -V` first. On iptables-nft
hosts (modern default) the backends interoperate and an in-place switch is
safe. On iptables-legacy hosts the two backends write to different kernel
tables and cannot remove each other's rules — destroy all sandboxes before
flipping, or recycled container IPs inherit stale egress rules. sandboxd
logs a boot warning when it detects this combination.

---

## What's on disk

| Path | Purpose |
|---|---|
| `/etc/sandboxd/sandboxd.env` | Env vars (PAT, ports, paths). Mode 0600. |
| `/etc/caddy/Caddyfile` | Caddy site config (HTTPS sites, TLS provider). |
| `/etc/default/caddy` | Cloudflare API token. Mode 0600. |
| `/var/lib/sandboxd/state.db` | SQLite - sandboxes, ports, sessions. **Source of truth.** |
| `/var/lib/sandboxd/credential_encryption.key` | AES key for sealed registry/mount creds at rest. **Back this up.** |
| `/var/lib/sandboxd/ssh_host_ed25519_key` | SSH-gateway host key. |
| `/var/lib/sandboxd/mounts/` | FUSE mount roots for external-storage sandboxes. |
| `/var/lib/caddy/` | Issued TLS certs and ACME state. |
| `/run/sandboxd/` | Runtime credentials directory (tmpfs-backed in production). |

---

## Backups

To restore service on a new host with the same data, back up:

1. `/var/lib/sandboxd/state.db` - the state database.
2. `/var/lib/sandboxd/credential_encryption.key` - without it, sealed
   registry passwords and mount credentials in the DB cannot be decrypted.
3. `/etc/sandboxd/sandboxd.env` - env config.
4. `/var/lib/sandboxd/ssh_host_ed25519_key` - preserves the SSH host
   fingerprint so clients don't get a host-key-changed warning.
5. `/var/lib/caddy/` (optional) - saves a fresh DNS-01 challenge on restore.

A simple nightly tarball is sufficient for most installations:

```bash
sudo tar -C / -czf /backup/aerolvm-$(date +%F).tar.gz \
  var/lib/sandboxd \
  etc/sandboxd \
  var/lib/caddy
```

Containers themselves are NOT in the backup - they get recreated from the
state DB on first start. That recreation needs the credential key, hence
its inclusion above.

---

## Updating

Re-run the installer with the same flags. The daemon restarts in place; the
state DB and certs are preserved.

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh \
  | sudo bash -s -- \
      --domain sandbox.example.com \
      --pat-token your-secret-pat \
      --dns-provider cloudflare \
      --dns-api-token <cloudflare-token>
```

To pin a version add `--version vX.Y.Z`.

---

## Uninstall

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/uninstall.sh \
  | sudo bash
```

Removes the daemon, binaries, and `/etc/sandboxd/`. Caddy, Docker, and
`/var/lib/sandboxd/` are intentionally left in place. To wipe state too:

```bash
sudo rm -rf /var/lib/sandboxd /var/log/sandboxd /run/sandboxd
docker ps -a --filter 'label=aerol.sandbox' -q | xargs -r docker rm -f
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `curl https://...` hangs | DNS not propagated, or `:443` blocked | `dig +short`; check security group |
| `connection refused` on `:443` | Caddy not running | `systemctl status caddy`; `journalctl -u caddy` |
| `502 Bad Gateway` from Caddy | Daemon down | `systemctl status sandboxd`; `journalctl -u sandboxd` |
| TLS cert issuance fails | Wrong Cloudflare token scope | Token must have `Zone:Read` + `DNS:Edit` on the right zone |
| Sandbox creation 500 | Docker not running, or out of capacity | `docker ps`; check `/v1/admission` |
| Mount errors | `fuse3` / sshfs / mountpoint-s3 missing | Re-run installer; it installs these |

Health watchdog already auto-restarts on `/health` failure. For deeper
issues, `journalctl -u sandboxd -f` is the first stop.
