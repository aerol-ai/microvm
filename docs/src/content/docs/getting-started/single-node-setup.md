---
title: Single-Node Setup
description: Install AerolVM on one Linux host with domain routing, wildcard TLS, and optional runtime or GPU flags.
---

Single-node setup is the production path for one AerolVM host. Use it when you want public preview URLs, a stable control-plane domain, SSH access into sandboxes, and optional runtime or GPU support on a single Linux machine.

## Install on a VPS

Domain-mode installs use DNS-01 wildcard TLS. When `--domain` is set, the installer also requires `--dns-provider` and `--dns-api-token`.

```bash
curl -fsSL https://github.com/aerol-ai/microvm/releases/latest/download/install.sh | sudo bash -s -- \
    --domain sandbox.example.com \
    --pat-token your-secret-pat \
    --dns-provider cloudflare \
    --dns-api-token your-cloudflare-api-token
```

If you omit `--pat-token`, the installer generates a token and prints it once at the end.

## Domain and DNS

Set `--domain` to the base hostname for your installation. Public sandbox URLs use these forms:

```text
https://<sandbox-id>.<domain>
https://<sandbox-id>-<port>.<domain>
```

Required DNS records:

```text
A     sandbox.example.com   -> <server-ip>
A     *.sandbox.example.com -> <server-ip>
```

When domain mode is active, the control-plane API is also served at `https://<domain>/v1/...`.

## Firewall and Security Groups

Open these inbound TCP ports before running the installer:

| Port | Protocol | Required for | Notes |
|---|---|---|---|
| `443` | TCP | HTTPS API and sandbox preview URLs | Primary public entry point. |
| `2220` | TCP | SSH gateway | Configurable with `SB_SSH_LISTEN_ADDR`. |

Port `21212` stays internal behind Caddy in domain mode, and port `2019` must remain bound to `127.0.0.1` only.

## Wildcard TLS via DNS-01

Cloudflare is the current documented DNS-01 provider. Create a scoped API token with these permissions:

- Zone -> Zone -> Read
- Zone -> DNS -> Edit

Caddy issues exactly two certificates, `<domain>` and `*.<domain>`, then renews them on a schedule.

## Container Runtimes

| Runtime | Installer flag | Notes |
|---|---|---|
| Docker | Default | Lowest overhead. Best for trusted workloads. |
| gVisor | `--with-gvisor` | Adds a user-space kernel boundary for untrusted code. |
| Firecracker | `--with-firecracker` | MicroVM runtime for fast, secure isolation. |
| Kata Containers | Not available yet | Create requests return `runtime not yet implemented`. |

If you want gVisor on the host, add `--with-gvisor` to the install command above. gVisor is not compatible with `--privileged` containers, ignores `disk_gb`, requires cgroupv2 plus systemd, and does not support GPU passthrough.

## GPU Support

| Vendor | Installer flag | Notes |
|---|---|---|
| NVIDIA | `--with-nvidia-gpu` | Requires NVIDIA drivers and a working `nvidia-smi`. |
| AMD | `--with-amd-gpu` | Requires ROCm-compatible hardware on `x86_64`. |
| Apple Silicon | No installer flag | Available only for local macOS development through Docker Desktop. |

GPU support is not compatible with the gVisor runtime for the same sandbox. Add the matching GPU flag to the base install command when you provision the host, then see [GPU Sandboxes](/gpu-sandboxes) for the sandbox creation flow in each SDK.

## Multi-Node Clusters

If one host is not enough, move to [Cluster Setup](/cluster-setup). Cluster mode adds transparent forwarding, raft-coordinated placement, and owner failover on top of the base install.

## Next Steps

- [SDK Setup](/sdk-setup) to connect your control plane.
- [Sandboxes](/sandboxes) to create environments on the host.
- [SSH Access](/ssh-access) to connect to running sandboxes.