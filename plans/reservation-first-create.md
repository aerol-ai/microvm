# Reservation-First Create (B1 + B2)

Resolves the two release blockers in
`plans/cluster-criticial-thinking-stage-2/02-release-blockers-in-current-pr.md`:

- **B1.** Forwarded creates could re-run `SelectPlacement` on the receiving
  node and reschedule to a third node, causing 421-loop risk.
- **B2.** The setup doc claimed "raft intent before docker run" while the
  code did "docker run, then raft" — a control-plane integrity gap.

The branch already carried a B1 hotfix (`X-Cluster-Create-Target` header
locks the second hop). This change replaces that with the long-term fix:
write a raft **reservation** for the chosen owner before the body is
forwarded, run the local create against the reservation, then promote the
reservation to a placement on success.

## Flow

For a create that lands on node `A` and targets node `T`:

1. `A` runs `SelectPlacement` against gossip + the FSM's pending-reservation
   totals. If `A == T`, fall through to the single-commit path (no
   intermediate state can be lost when ownership doesn't straddle a network
   hop).
2. `A` mints a sandbox ID, seals + redacts the request, and writes
   `opReserve{SandboxID, OwnerNodeID=T, Spec=redacted, SealedSecrets=sealed, ExpiresUnix=now+120s}`
   to raft. The reservation validates name uniqueness and capacity
   availability inside the FSM apply.
3. `A` forwards the request to `T` with two headers:
   - `X-Cluster-Create-Target: T` — locks the second hop (no second
     `SelectPlacement`), preserving the B1 fix.
   - `X-Cluster-Create-ID: <reserved-id>` — tells `T` to run
     `CreateSandboxWithID` against the reserved row.
4. `T` runs the local create. On success, `T` commits `opPlace` with
   `Spec=nil, SealedSecrets=nil` — the FSM inherits both from the existing
   reservation, atomically transitioning `State: Reserved → Placed`. On
   failure, `T` calls `CancelReservation` to free the capacity immediately.
5. If `T` crashes between reservation and promote, the leader's
   reservation-GC sweep (5s tick, 120s TTL) cancels the row within ~125s.

## FSM model

`Placement` gains two optional fields (in `internal/cluster/types.go`):

```go
type Placement struct {
    // ... existing fields ...
    State       PlacementState `json:"state,omitempty"`        // "" (placed), "reserved"
    ExpiresUnix int64          `json:"expires_unix,omitempty"` // valid only when State == "reserved"
}
```

Zero values mean "no reservation, normal placed row" so legacy snapshots
restore unchanged.

Three FSM ops touched (`internal/cluster/fsm.go`):

- **`opReserve` (new, opCode 7)**. Writes the reservation. Idempotent on
  exact `SandboxID + OwnerNodeID` re-reserve. Rejects placed rows
  (`ErrReservationConflict`), conflicting names
  (`ErrNameConflict`), and capacity overcommit
  (`ErrCapacityExceeded`). Allowed to overwrite an expired reservation
  (TTL is the lease).
- **`opCancelReserve` (new, opCode 8)**. Deletes only when
  `State == Reserved`. No-op on missing or placed rows.
- **`opPlace` (extended)**. When a reservation for `SandboxID + OwnerNodeID`
  exists, promote it: clear `State`, inherit `Spec` / `SealedSecrets` from
  the reservation if `nil`. Falls back to the original behavior for the
  single-node and self-wins paths.

Placement scoring (`internal/cluster/placement.go`) now subtracts pending
reservations per node from each candidate's headroom, so two creates that
both pass through scoring on the same leader see each other.

## Why router-writes (Node A reserves)

Two alternatives were considered:

1. **Leader writes the reservation on `A`'s behalf via an internal RPC.**
   Loses no correctness, but adds an HTTP round-trip on the create critical
   path AND moves the reservation logic out of the FSM (where it can
   serialize cleanly with other applies) into a privileged endpoint.
2. **`T` writes the reservation on receipt.** Loses the property we want:
   if `A` selects `T` and forwards but `T` is mid-restart, the cluster
   never sees intent and another concurrent create can race for the same
   capacity. Router-writes give the cluster intent the instant `A` loses
   ownership of the request.

## TTL

120 seconds. Covers slow GPU image pulls; worst-case orphan window is
~125s with the 5s GC tick. Reservation-GC is leader-gated (same cadence
template as `startDeadOwnerLoop`) — followers don't tick.

## Latency

One extra raft commit per cross-node create (the reservation). Healthy
clusters: ~3–10ms. The promote commit (`opPlace`) was already on the
critical path before this change, so the marginal cost is the reserve
commit only. Same-node creates collapse to a single commit — no regression.

Called out explicitly per `pr-review.md` invariant 2 (boot-path latency).

## Rolling-upgrade ordering

`opReserve` and `opCancelReserve` are new raft opcodes. A pre-upgrade node
that receives one through replication rejects it (unknown opcode). The
safe upgrade procedure:

1. Upgrade all non-leader nodes first. They can replicate opcodes 7/8
   silently because they don't issue them yet (the create handler only
   reserves when the cluster handler is the new code, which is bundled).
2. Upgrade the leader last. Once the new leader steps up, follower applies
   succeed because every voter is on the new opcode set.

Mixed clusters where the leader is upgraded first and a follower is still
on the old binary will see the follower's FSM diverge on the first
reservation. This is the same shape as any opcode addition; documenting
the ordering is sufficient.

## Files touched

**Server:**

- `internal/cluster/types.go` — `Placement.State`, `Placement.ExpiresUnix`,
  `PlacementState` enum.
- `internal/cluster/errors.go` — `ErrReservationConflict`,
  `ErrCapacityExceeded`.
- `internal/cluster/fsm.go` — `opReserve`, `opCancelReserve`, extended
  `opPlace`, `pendingReservationsByNode`,
  `validateCapacityAvailableLocked`.
- `internal/cluster/client.go` — `ReserveOnTarget`, `CancelReservation`,
  reservation-GC loop wiring.
- `internal/cluster/cluster.go` — `Client` interface methods.
- `internal/cluster/noop.go` — single-node stubs.
- `internal/cluster/placement.go` — reservation-aware `SelectPlacement`,
  `nodeFits` / `headroomScore` take pending reservations.
- `internal/cluster/dead_owner.go` — `startReservationGCLoop`,
  `reconcileReservations`.
- `internal/cluster/owner_watcher.go` — `selectRecreationTargetExcluding`
  passes pending reservations to scoring.
- `internal/service/service.go` — exported `GenerateSandboxID`.
- `pkg/api/v1/cluster_handler.go` — handler reorder; `X-Cluster-Create-ID`
  header constant; reservation TTL.

**Tests:**

- `internal/cluster/fsm_reserve_test.go` (new) — 12 tests covering opReserve
  idempotency, name collision, capacity check, expired-reservation
  overwrite, promote inheritance, cancel semantics, snapshot round-trip,
  pending-reservation sums.
- `pkg/api/v1/cluster_handler_test.go` (extended) — reservation written
  before forwarding, X-Cluster-Create-ID matches reserved ID,
  reservation failure → 503, name conflict → 409, missing create-ID on
  forwarded request → 400.

**Docs:**

- `docs/src/content/docs/cluster-setup.md` — new "How sandbox create works
  in cluster mode" section.
- This file.
