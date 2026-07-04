# AerolVM — Sandbox Placement Architecture

This folder explains **how AerolVM decides which cluster node owns a sandbox** and how that decision is kept consistent under concurrency, failure, and retries.

It is written for architects and senior engineers who need the full picture: coordination layers, consistency boundaries, request flows, and failure modes. Code references point at the real implementation under `internal/cluster/`.

## How to read these documents

| Document | What you get |
|----------|----------------|
| [00-architecture-at-a-glance.md](./00-architecture-at-a-glance.md) | **One-page** diagrams — share this first in a review |
| [01-overview.md](./01-overview.md) | Design goals, single-node vs cluster, the three coordination layers |
| [02-cluster-topology.md](./02-cluster-topology.md) | Node roles (server / worker / ingress), Raft vs gossip vs capacity pull |
| [03-placement-workflow.md](./03-placement-workflow.md) | End-to-end **create** flow: select → reserve → forward → run → place |
| [04-placement-fsm.md](./04-placement-fsm.md) | Placement FSM states, Raft operations, reservations, invariants |
| [05-routing-and-forwarding.md](./05-routing-and-forwarding.md) | How API and ingress traffic reaches the owner after placement |
| [06-failover-and-recovery.md](./06-failover-and-recovery.md) | Dead-owner handling, orphan vs recreate, recovery blobs |

## One-sentence summary

**Any node can accept a create request; the receiving node picks an owner using power-of-two-choices over fresh capacity snapshots, commits that choice to a Raft-backed placement map in two steps (reserve, then place), runs the sandbox on the owner, and forwards all later API calls to that owner.**

## Related material elsewhere in the repo

- Operator setup: [`setup/cluster.md`](../setup/cluster.md)
- Engineering deep-dive (published docs): [`docs/src/content/docs/engineering-placement-failover.mdx`](../docs/src/content/docs/engineering-placement-failover.mdx)
- Package overview comment: [`internal/cluster/cluster.go`](../internal/cluster/cluster.go)
