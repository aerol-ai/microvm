# Data-plane load balancer (shard-aware ingress)

**This is a prerequisite for any ingress tier above 10 nodes**, including the
100-ingress figure quoted by `plans/secrets-hardening.md` and
`plans/audit-export-connectors.md`. Operator-facing statement:
`docs/src/content/docs/cluster-ingress.mdx` ("Ingress tiers above 10 nodes")
and `setup/runbooks/cluster-ingress-topology.md`. Terraform threads the flag
through `shard_aware_ingress` and refuses more than 10 ingress-capable nodes
without it at plan time.

## Problem

Clusters with more than 10 live ingress-capable nodes
(`cluster.MaxReplicatedIngressRouteNodes`) cannot safely advertise every public
sandbox route on every ingress: above that size each ingress node subscribes
only to its rendezvous-hashed shard subset (primary plus one failover replica
per shard), so a router that picks any ingress node for any sandbox sends most
connections to a node without the route. Without a shard-aware front router,
operators must keep `SB_CLUSTER_SHARD_AWARE_INGRESS=false`, and the daemon
**fails closed** on the topology check when ingress cardinality exceeds the
limit (see "Failure modes").

## Required router contract

An upstream L4/L7 load balancer (or edge proxy) must resolve sandbox ownership
before forwarding user traffic:

1. On each new connection / HTTP Host match for a sandbox id (or derived
   hostname), call the control plane:

   `GET /v1/cluster/ingress-route/{id}`

   (operator / fleet PAT; already implemented in `pkg/api/v1`).

2. Route the request to one of the `owners[]` returned by that endpoint
   (`node_id`, `api_url`, `internal_url`, `data_plane_host`; the first entry is
   the primary shard owner, the second its failover replica). Cache with a
   short TTL; on miss, 404 or 503, fail closed rather than spraying all
   ingresses.

3. Set `SB_CLUSTER_SHARD_AWARE_INGRESS=true` on every sandboxd only after the
   upstream router implements this path (or an equivalent shard lookup).

## Out of scope (this pass)

A full in-tree LB / Envoy control-plane integration. This document is the
operator contract; the API stub already exists under `/v1/cluster/ingress-route/{id}`.

**100-ingress scale remains operator LB + `SB_CLUSTER_SHARD_AWARE_INGRESS`.**
It is not delivered in-repo: operators must front the fleet with an external
shard-aware router that honors the ingress-route contract above. The daemon
only exposes the lookup API and the topology gate.

## Failure modes

| Misconfiguration | Behavior |
|---|---|
| >10 ingress, flag false | Enterprise: boot refused, error names the flag. Open-source: boot logs the violation and never starts the ingress reconciler; `/health` is `degraded` with the reason; a warning repeats every reconcile cycle; `aerolvm_cluster_topology_ok` is 0 and `SandboxdClusterTopologyViolation` fires. Creates are **not** refused by this rule (the mixed-role / missing-tier rule above 10 live nodes is separate). |
| Flag true, dumb LB | Most connections land on an ingress node without the route: cross-node 404 / wrong owner. The daemon cannot detect this — operator owns it. |
| Route API unavailable | LB must fail closed; no random peer fallback |
