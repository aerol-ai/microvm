# 07 - Diff Map

This page maps the critique to implementation areas. It is not a full task
breakdown, but it should be enough to estimate the PRs needed to turn PR #58
into release-grade cluster mode.

## P0 - Fix create routing determinism

Files:

- `pkg/api/v1/cluster_handler.go`
- `internal/cluster/forward.go`
- `internal/cluster/cluster.go`
- tests in `pkg/api/v1/*cluster*_test.go`

Changes:

- Add target-locked forwarding for `POST /v1/sandboxes`.
- Better: add reservation-first create and an internal create-local endpoint.
- Forwarded create must not run fresh random placement.
- Add tests for:
  - node A selects node B;
  - node B receives forwarded create;
  - node B creates locally without forwarding again;
  - stale/mismatched target is rejected deterministically.

## P0 - Stop 200 voters

Files:

- `internal/config/config.go`
- `cmd/sandboxd/main.go`
- `internal/cluster/client.go`
- `internal/cluster/voter_autojoin.go`
- `internal/cluster/raft.go`
- `scripts/cluster-init.sh`
- `scripts/cluster-join.sh`
- `setup/cluster.md`
- docs under `docs/src/content/docs/`

Changes:

- Add `SB_NODE_ROLE=server|worker|ingress|mixed`.
- Only server/mixed nodes start Raft.
- Workers heartbeat to servers instead of joining Raft.
- Disable auto-voter promotion for workers.
- Add explicit server promote/demote/remove APIs or CLI.
- Update docs from "add nodes in pairs as voters" to "add workers freely; keep
  servers at 3 or 5."

## P0 - Placement watch and durable revisions

Files:

- `internal/cluster/fsm.go`
- new `internal/cluster/watch.go`
- `pkg/api/v1/cluster_handler.go`

Changes:

- Deep-copy FSM snapshot values.
- Persist or derive durable revision from Raft log index.
- Add full placement list endpoint with revision.
- Add watch/long-poll endpoint:
  - workers watch assignments;
  - ingress watches route map.
- Add compaction/relist behavior.

## P0 - Owner-aware ingress for HTTP/TLS

Files:

- new `internal/cluster/ingress.go`
- `pkg/caddy/client.go`
- `cmd/sandboxd/main.go`
- `internal/config/config.go`
- scripts and docs

Changes:

- Add `sandboxd --mode ingress` or equivalent env.
- Ingress watches placement/route map.
- Caddy/caddy-l4 routes SNI/hostnames to owner workers.
- Batch route updates.
- Expose route lag and route miss metrics.
- Update install docs to put public wildcard DNS on ingress, not all workers.

Alternative PR:

- Envoy/HAProxy management server instead of Caddy ingress.

## P0/P1 - Raw TCP decision

Files:

- `internal/service/service.go`
- `internal/store/store.go`
- `internal/cluster/fsm.go`
- `pkg/models/types.go`
- ingress implementation

If raw TCP remains direct-to-owner:

- update docs and SDK wording;
- ensure failover responses make clients re-fetch exposure info.

If raw TCP must be cluster-stable:

- add cluster-wide ingress port reservations;
- add route map `ingress_port -> owner_host:owner_port`;
- update `ExposePortResponse` to return ingress endpoint;
- update failover replay to preserve the ingress endpoint when possible.

## P0/P1 - Proper placement resources

Files:

- `pkg/capacity/capacity.go`
- `internal/cluster/gossip.go`
- `internal/cluster/placement.go`
- `pkg/models/types.go`
- `internal/service/service.go`

Changes:

- Add disk inventory and reservation.
- Add GPU inventory and scheduling filters.
- Add runtime capability labels.
- Add taints/drain state.
- Add health/degraded state.
- Add scheduler reason codes.

## P0/P1 - Cluster-wide uniqueness and idempotency

Files:

- `internal/cluster/fsm.go`
- `pkg/api/v1/cluster_handler.go`
- facade handlers that use sandbox names or idempotency keys

Changes:

- Add `name -> sandbox_id` control-plane index.
- Add name reservation before create.
- Add cluster-wide idempotency reservation.
- Add duplicate-name concurrent create tests across different owners.

## P1 - Failover storm control

Files:

- `internal/cluster/dead_owner.go`
- `internal/cluster/owner_watcher.go`
- `internal/service/service.go`

Changes:

- Batch dead-owner reassignment.
- Cap reassigns per target per dead-node event.
- Cap per-owner recreate concurrency.
- Add exponential backoff/parked state for repeated image pull failure.
- Add image-cache hints in worker heartbeat.

## P1 - Operator lifecycle APIs

Files:

- `pkg/api/v1/cluster_handler.go`
- `pkg/api/v1/routes.go`
- `internal/cluster/*`
- scripts/docs

Changes:

- `POST /v1/cluster/nodes/{id}:drain`
- `POST /v1/cluster/nodes/{id}:uncordon`
- `DELETE /v1/cluster/nodes/{id}`
- `POST /v1/cluster/servers/{id}:promote`
- `POST /v1/cluster/servers/{id}:demote`
- Ensure docs only reference endpoints that exist.

## P1 - Setup script hardening

Files:

- `scripts/cluster-init.sh`
- `scripts/cluster-join.sh`
- script tests if available

Changes:

- Derive/create credential key before TLS bundle creation.
- Fail if advertise addresses are unspecified or loopback unless explicitly
  forced.
- Validate API advertise URL reachability from a peer when possible.
- Add dry-run output of final env.

## P1 - Documentation cleanup

Files:

- `setup/cluster.md`
- `docs/src/content/docs/cluster-setup.md`
- `docs/src/content/docs/durability.mdx`

Changes:

- Align create flow with implementation.
- State exact API forwarding security path.
- Mark current data plane limitations prominently.
- Mark snapshots unsupported in cluster mode.
- State raw TCP and UDP semantics.
- Replace "sandboxes survive node failure" with "placement/spec can recreate,
  but runtime state is lost" unless the product intentionally wants recreate.

