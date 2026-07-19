# HN launch draft — five isolation runtimes, one API, one latency ladder

> Fill after a successful `make integration-cluster-hetero-obs keep` +
> `make integration-obs-snapshot`. Paste PNGs from
> `integration-tests/reports/obs/` and rows from
> `integration-tests/reports/cluster-hetero-benchmark-with-obs-catalogue.md`.

## 1. Hook

We built five isolation runtimes behind one API and benchmarked them on
comparable metal-class EC2. Here's the create-to-serving latency ladder.

**Screenshot:** D2 capability matrix / create-latency board
(`aerolvm-d2-*.png`).

## 2. The ladder explained

| Runtime | Warm create p50 (fill) | Trade |
|---|---|---|
| isolate | _ms_ | density; jail-off today — not a containment claim |
| WASM | _ms_ | host-mediated, resident compile-once |
| Firecracker | _ms_ | dedicated guest kernel |
| containerd | _ms_ | OCI / familiar containers |
| gVisor | _ms_ | userspace kernel isolation |

Hardware (T7): 5× `c5.metal` workers (one per runtime), 2× `m6i.large` ingress,
3× `t3.medium` Raft, `m6i.large` obs. Region: us-east-1. Method: soak-accumulated
samples (N disclosed in bench JSON), not SAMPLES=10 smoke.

**Screenshot:** D3 boot-time attribution (`aerolvm-d3-boot.png`).

## 3. Breadth

Same platform ran Postgres+RLS/TLS, Redis TCP, a Temporal-shaped 5-step
workflow, JupyterLab, a 3-trainer ML farm, gVisor kernel probe, isolate egress
attribution, and (with key) a claude-code agent.

**Table:** paste catalogue summary by category (passed / skipped / failed).

## 4. Scale & self-healing

10-node cluster, density to capacity rejection, drain/failover UCs light up D5/D6
live.

**Screenshots:** D5 cluster health, D6 capacity/density.

## 5. Cost

Self-host illustrative ~$4k/mo vs ~$12k e2b/Daytona at 100 sandboxes (README).
Flagship soak itself: ~$63–84 for 3–4 hours of comparable-metal hardware.

**Screenshot:** D11 cost board (dated).

## 6. Reproduce

```bash
make integration-cluster-hetero-obs keep
make integration-obs-snapshot SCENARIO=cluster-hetero-benchmark-with-obs
# artefacts: integration-tests/reports/*-bench.json, *-catalogue.{json,md}, reports/obs/*.png
```

Mixed (cheap, t3) validates connectivity only — never a headline source (CM-4):

```bash
make integration-cluster-mixed-obs keep
```
