---
title: AerolVM vs Daytona vs e2b
---

A side-by-side look at how AerolVM compares to the two most common alternatives for running isolated code environments - and why we built it.

## How AerolVM Compares

| | AerolVM | e2b | Daytona |
|---|---|---|---|
| **Hosting** | Self-hosted on your infra | Cloud (managed, no self-host) | Self-hosted |
| **Set Up Complexity** | Easy for Single Node | No self-host | Extremely Complex for Single Node |
| **Can run locally** | ✅ | ✗ | ✗ |
| **Open source** | ✅ | ✗ | ✅ |
| **Primary use case** | AI agents + ephemeral CI | AI agent code execution | Developer workspaces |
| **Sandbox startup** | <70ms | ~200s | <90ms |
| **Runtime isolation** | Docker, gVisor (kernel-level), Firecracker (microVM) | Kata | Docker |
| **Serveless Sandbox(based on Lambda Arch)** | ✅ | ✗ | ✗ |
| **Security** | gVisor + FireCracker (Extremely secure) | FireCracker(Extremely secure) | ✗ |
| **Port Isolation** | ✅ | ✗ | ✗ |
| **Persistent** | ✅ | ✗ | ✅ |
| **Sandbox Lifecycle** | Infinite | 1 day | Infinite |
| **Multi-node cluster** | ✅ Raft-coordinated, split server / worker / ingress roles | Managed (opaque) | ✗ |
| **HA / failover** | ✅ Replicated placement, owner-death detection, reconcile | Managed | ✗ |
| **Drop-in SDK compatibility** | ✅ `/daytona` and `/e2b` API facades- existing SDKs work unchanged | ✗ | ✗ |
| **Persistent PTY sessions** | ✅ Reconnect with output replay | ✗ | ✗ |
| **External storage** | S3, NFS, SSHFS, rclone | ✗ | ✗ |
| **GPU Support** | ✅ | ✗ | ✗ |
| **TCP Support** | ✅ | ✗ | ✗ |
| **TLS+SNI Support** | ✅ | ✗ | ✗ |
| **SSH access** | ✅ Per-sandbox Ed25519 via gateway | ✗ | ✅ |
| **Per-sandbox egress control** | ✅ | ✗ | ✗ |
| **Per-sandbox network quotas** | ✅ Ingress / egress byte caps that drop traffic when exceeded | ✗ | ✗ |
| **Multi-tenant tagging** | ✅ Tag filtering with AND semantics for control-plane scoping | ✗ | ✗ |
| **Port allowlist** | ✅ Explicit exposure required before public traffic reaches a port | ✗ | ✗ |
| **SDK languages** | TS, Python, Go, Rust, Java | TS, Python | TS, Python, Ruby, Go, Java |
| **Pricing for 100 Concurrent Sandboxs 4GB RAM + 2VCPU + 16GB Disk per Month** | ~4000$ (Check the calculation below) | ~12000$ | ~12000$ |

***IMPORTANT: Note these Sandboxes are built on Shared Infra so even though you are being charged for 4GB + 2VCPU you might not be consuming the entire resources.***

***Calculation: ***

Using AWS on-demand `m4.4xlarge` as a reference machine:

- `m4.4xlarge` = 16 vCPU, 64 GiB RAM, about `$0.80/hr`, or `0.80 x 730 ~= $584/month`
- Vendor headline pricing assumes 100 sandboxes shaped like `2 vCPU + 4 GiB` each:
	- `100 x 2 = 200 vCPU`
	- `100 x 4 = 400 GiB RAM`
- But these environments are usually overprovisioned. If actual usage is only 25% of the advertised shape, the real shared-infra footprint is:
	- `200 / 4 = 50 vCPU`
	- `400 / 4 = 100 GiB RAM`
- That fits on 4 `m4.4xlarge` workers:
	- `50 / 16 = 3.125`, so 4 workers by CPU
	- `100 / 64 = 1.56`, so 2 workers by RAM
	- CPU is the bottleneck, so `4 x $584 = $2,336/month`
- Even with a much more conservative 2x overprovision assumption, the raw compute is still only:
	- `200 / 2 = 100 vCPU`
	- `400 / 2 = 200 GiB RAM`
	- `100 / 16 = 6.25`, so 7 workers
	- `7 x $584 = $4,088/month`

That is the point of the comparison: the `~$12,000/month` number is the vendor price for 100 full-size environments, while the actual packed AWS footprint can be far lower because these workloads are usually overprovisioned. That is exactly why shared worker VMs matter.

The 16 GB disk allocation sits on top of this, but compute is the main cost driver here.


## AerolVM vs e2b

**e2b** is a managed cloud service optimized for AI agent sandboxes. It is the fastest way to get started if you do not want to run any infrastructure yourself, but the trade-offs add up quickly:

- **No self-hosting.** Your code, your customers' code, and your data all run on e2b's infrastructure. Regulated workloads, air-gapped deployments, and bring-your-own-cloud requirements are off the table.
- **Per-sandbox-hour pricing.** Costs scale linearly with usage. A team running 1,000+ sandboxes can pay $500+ per month on e2b vs. ~$20/month on a single host with AerolVM.
- **Hard sandbox lifetime cap.** Sandboxes expire after 1 day. AerolVM sandboxes live indefinitely and support persistent stop/start.
- **No GPU, no external storage, no SSH, no TCP ports, no per-sandbox egress control, no per-sandbox network quotas, no multi-tenant tagging.**

**Already on the e2b SDK?** AerolVM exposes an `/e2b` API facade so your existing e2b SDK code can point at an AerolVM server and keep working- no rewrite required. Migrate one environment variable at a time.

AerolVM covers the same AI execution use case while running entirely on your own host, with stronger isolation for untrusted workloads and predictable infrastructure cost instead of metered billing.

## AerolVM vs Daytona

**Daytona** targets persistent developer workspaces - IDE integration, git-based environments, long-lived dev containers. It is not designed for ephemeral, high-frequency sandbox creation that AI agents need.

- **Slow lifecycle.** Daytona workspaces take seconds to start because they're full persistent VMs. AerolVM boots a sandbox in under 90ms - the difference between an agent waiting on infrastructure and an agent running code.
- **Setup complexity.** Daytona is genuinely difficult to self-host: multiple components, infrastructure dependencies, and ongoing operational overhead. AerolVM is a single-binary install with a one-line script.
- **No kernel-level isolation, no per-sandbox egress control, no port allowlist.** Daytona assumes you trust the people using your workspaces. AerolVM assumes you don't trust the code running inside the sandbox.
- **Workspace ergonomics over agent ergonomics.** Daytona's SDK and feature surface are built for humans editing code in an IDE. AerolVM's SDKs (TS, Python, Go, Rust, Java) are built for programmatic, high-throughput use.

**Already on the Daytona SDK?** AerolVM exposes a `/daytona` API facade so existing Daytona SDK code can point at an AerolVM server unchanged. You keep your SDK, you swap the backend.

If your use case is "developers SSH into a long-lived workspace once a day," Daytona is a reasonable fit. If your use case is "an agent spawns 10,000 sandboxes per hour, runs untrusted code, and tears them down," AerolVM is built for it.

## Scaling beyond a single host

Both e2b (managed) and AerolVM are designed for high-throughput sandbox traffic; Daytona is not. Where AerolVM differs from e2b is *how* you scale: instead of paying a per-sandbox-hour bill on someone else's infra, you bring up an AerolVM cluster on your own.

- **Raft-coordinated placement.** Sandboxes are placed by a replicated FSM, so any node can answer "where does sandbox X live?" without a leader round-trip.
- **Role-split topology.** Nodes opt into `server` (Raft voter), `worker` (runs sandboxes), `ingress` (holds the public route table), or any comma-separated hybrid. Voter count stays at 3 or 5 no matter how many workers you add- the same separation Kubernetes uses for masters vs. nodes. See [Cluster Ingress](/cluster-ingress).
- **Single advertised endpoint.** Front the ingress tier with a cloud NLB, MetalLB VIP, or DNS round-robin; the SDK and end users hit one hostname regardless of which worker owns a given sandbox.
- **Failover.** Worker death is detected via gossip; orphaned sandboxes surface `410 Gone` for clients to recreate on the surviving fleet. Placement spec, sealed credentials, and exposed-port intents are replicated through Raft. See [Durability and Failover](/durability).

## Why we built AerolVM

We built AerolVM because running AI-generated code safely kept turning into the same painful choice.

1. Hosted sandboxes were easy to start with, but the pricing made us nervous. If an agent got stuck in a loop, the meter kept running. E2B charges while sandboxes run, and Modal uses usage-based serverless pricing too.

2. Running it ourselves was not much better. Firecracker gave us a solid microVM layer, but not the whole product we needed around it: files, logs, exec, networking, cleanup, and SDKs.

3. We also did not want to run random AI code in plain Docker and hope for the best. Docker’s own docs call out the daemon attack surface and root privileges unless you use rootless mode.

4. We wanted gVisor built in from day one, because it adds another isolation layer between the code and the host OS.

And we did not want to spend weeks gluing together the basics before we could ship: file upload, streaming exec, logs, exposed ports, egress rules, cleanup, and language SDKs.

So we built AerolVM. AerolVM is a sandbox system you can run on your own infrastructure, with isolation, fast startup, networking controls.

## Next Steps

- [Quick Start](/quick-start) - spin up a sandbox in under five minutes
- [Server Setup](/getting-started) - self-host AerolVM on your own infrastructure
- [Create Sandbox](/sandboxes) - lifecycle states, parameters, and configuration options
