---
title: Server Setup
description: Choose the AerolVM setup path that fits local development or a single-node production host.
---

AerolVM has two distinct single-host setup paths. Choose the local path when you want the fastest possible development loop on your own machine, or choose the single-node path when you want a Linux host that serves public sandbox traffic over your domain.

## Choose Your Setup Path

### Local Setup

Run AerolVM directly on your Mac or Linux machine. The API listens on `http://localhost:21212`, there is no domain or TLS setup, and your SDK connects straight to the local daemon.

[Open Local Setup](/getting-started/local-setup)

### Single-Node Setup

Install AerolVM on one Linux host or VPS. This path configures Caddy, wildcard TLS via DNS-01, SSH access, and the production-facing networking needed for sandbox preview URLs.

[Open Single-Node Setup](/getting-started/single-node-setup)

## Which One Should You Use?

| If you need... | Use this page |
|---|---|
| The fastest local development loop on macOS or Linux | [Local Setup](/getting-started/local-setup) |
| A public sandbox host with your own domain and TLS | [Single-Node Setup](/getting-started/single-node-setup) |
| Multiple hosts with placement and owner failover | [Cluster Setup](/cluster-setup) |

## Next Steps

- [SDK Setup](/sdk-setup) to connect your client.
- [Sandboxes](/sandboxes) to create and manage environments.
- [Cluster Setup](/cluster-setup) if you need more than one host.