# Data-plane load balancer (shard-aware ingress)

## Problem

Clusters with more than 10 live ingress-capable nodes cannot safely advertise
every public sandbox route on every ingress. Without a shard-aware front
router, operators must keep `SB_CLUSTER_SHARD_AWARE_INGRESS=false` and the
daemon **fail-closes** create/topology checks when ingress cardinality exceeds
the limit.

## Required router contract

An upstream L4/L7 load balancer (or edge proxy) must resolve sandbox ownership
before forwarding user traffic:

1. On each new connection / HTTP Host match for a sandbox id (or derived
   hostname), call the control plane:

   `GET /v1/cluster/ingress-route/{id}`

   (operator / fleet PAT; already implemented in `pkg/api/v1`).

2. Route the request to the `OwnerDataPlaneHost` (or equivalent) returned by
   that endpoint. Cache with a short TTL; on miss or 404, fail closed rather
   than spraying all ingresses.

3. Set `SB_CLUSTER_SHARD_AWARE_INGRESS=true` on every sandboxd only after the
   upstream router implements this path (or an equivalent shard lookup).

## Out of scope (this pass)

A full in-tree LB / Envoy control-plane integration. This document is the
operator contract; the API stub already exists under `/v1/cluster/ingress-route/{id}`.

## Failure modes

| Misconfiguration | Behavior |
|---|---|
| >10 ingress, flag false | Daemon refuses topology / create (fail-closed) |
| Flag true, dumb LB | Cross-node 404 / wrong owner — operator owns this |
| Route API unavailable | LB must fail closed; no random peer fallback |
