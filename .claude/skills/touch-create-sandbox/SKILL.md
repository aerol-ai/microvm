---
name: touch-create-sandbox
description: Safely modify Service.CreateSandbox or anything it transitively calls. Walks the boot path step-by-step, enforces the failure-cleanup rules, and reminds you to document boot-latency impact in the PR. Use when the user asks to "change sandbox creation", "add this to sandbox boot", "modify CreateSandbox", or any change that lands inside internal/service/service.go near the create path. Proactively suggest as soon as a change is proposed that adds DB queries, HTTP calls, file I/O, or lock acquisitions to sandbox boot.
---

# Touch `CreateSandbox` / the sandbox boot path

`Service.CreateSandbox` latency is a load-bearing UX metric. Treat the boot path as protected.

## Entry points

There are three public ways a sandbox is born — all funnel into the same private
`createSandbox` worker in `internal/service/service.go`:

- `Service.CreateSandbox(ctx, req)` — fresh user-driven create; generates a new sandbox ID.
- `Service.CreateSandboxWithID(ctx, req, id)` — failover-recreate entry point. Reuses an
  existing sandbox ID and short-circuits to the existing local record if there is one
  (idempotent at the cluster boundary).
- `Service.RecreateSandbox(ctx, id, spec, secrets, exposedPorts)` — implements
  `cluster.SandboxRecreator`. Called by the cluster owner watcher when an FSM placement
  points to self after another owner died. It re-merges encrypted cluster secrets
  (`OpenClusterSecretsForNode`), calls `CreateSandboxWithID`, then replays the
  replicated port intents. Only sandboxes with `failover.policy=recreate` reach this path.

If you're editing the boot path, your change has to be safe on all three.

## The boot path (in `createSandbox`)

1. `ClusterTopologyError()` — cluster topology gate (errors fail fast before any work).
2. Cluster-mode role check: if cluster is enabled and this node is not a worker,
   reject with `cluster.ErrNoPlacementTarget` — non-worker nodes must forward
   `CreateSandbox` to a placement target.
3. `normalizeCreateRequest(req)` + `NormalizeCreateImageDistribution(ctx, &req)`
   + `NormalizeCreateFailover(&req)`.
4. Validation: image / runtime / mount count + per-mount / lifecycle / GPU /
   network-byte limits.
5. `s.sealMounts(req.Mounts)` — AEAD-seal mount specs via `pkg/secrets`.
6. Generate `toolboxToken` and sandbox SSH keypair (Ed25519).
7. Choose sandbox ID: `idOverride` if non-empty (recreate path), else generate
   a fresh one. The ID is also the container name, so it must be stable before
   `docker.Create`.
8. `s.admitter.Admit(sandboxID, capacityRequestFromCreate(req))` — capacity
   reservation. Every failure path below this point must `releaseAdmission()`.
9. `s.mounts.MountAll(ctx, sandboxID, req.Mounts)` — external-storage mount.
   Every failure path below this point must also `cleanupMounts()`.
10. `s.docker.Create(ctx, req, sandboxID, toolboxToken, binds)` — container
    creation.
11. `s.sealRegistry(req.Registry)` — AEAD-seal registry creds before the row
    is built, so a marshal/encrypt error rolls back through the same chain as
    any later store error.
12. `s.caddy.UpsertSandboxRoute(ctx, sandboxID, containerIP, toolboxPort)` —
    install the L7 toolbox route.
13. `s.store.Create(ctx, sandbox)` — persist the row.
14. `s.store.PutMounts(ctx, sandbox.ID, sealedMounts)` if there were any
    mounts.

## Failure-cleanup rules

The rollback chain after each successful step is cumulative. Every failure path
**below** admission must call `releaseAdmission()`. Every failure path **below**
`mounts.MountAll` must also call `cleanupMounts()`. Every failure path **below**
`docker.Create` must additionally call `s.docker.Destroy(ctx, sandbox)`. Every
failure path **below** `caddy.UpsertSandboxRoute` must additionally call
`s.caddy.DeleteSandboxRoute(ctx, sandbox.ID)`. Every failure path **below**
`store.Create` must additionally call `s.store.Delete(ctx, sandbox.ID)`.

These rollback helpers are local closures + inline calls inside `createSandbox`.
**Use them, don't reinvent.** If you add a new step between two existing steps,
ALSO add the matching rollback into the chain and call out the rollback rule in
the PR description's "Failure-path consistency" section.

## What you must document in the PR

Fill in **"Sandbox boot impact"** in the PR template. Don't leave it blank.

Answer:
- What was added (DB query, HTTP round-trip, file I/O, lock acquisition, FSM
  propose, gossip publish)?
- Expected added latency in the success case
- When it fires (every create? first create? on a flag? on a feature gate? only
  on the cluster recreate path?)
- Whether it's bounded

> "It's only on the first call" is **still impact** and must be called out.

If the added work is best-effort and could fail on a cold start, use the lazy-bootstrap pattern instead of putting it inline. See `Service.EnsureLayer4Ready` in `internal/service/service.go` as the canonical shape.

## The lazy-bootstrap pattern (when "first-call only" is justified)

```go
type Service struct {
    xMu    sync.Mutex     // serializes the slow path
    xReady atomic.Bool    // lock-free fast-path latch
}

func (s *Service) EnsureXReady(ctx context.Context) error {
    if s.xReady.Load() { return nil }        // fast path: single atomic load
    s.xMu.Lock()
    defer s.xMu.Unlock()
    if s.xReady.Load() { return nil }        // double-check after lock
    if err := s.bootstrapX(ctx); err != nil {
        return err                           // leave latch false, next caller retries
    }
    s.xReady.Store(true)                     // latch forever
    return nil
}
```

Mirror `EnsureLayer4Ready` (and the parallel `clusterReady` latch) — don't reinvent. **Anti-patterns:** retrying bootstrap on every request; failing the daemon outright on a transient bootstrap error; logging-and-forgetting so the first user request gets a confusing "X not found".

## Cluster-mode notes

- The cluster placement decision happens **above** `Service.CreateSandbox` — at
  the API layer, a non-worker node forwards the request to a chosen worker.
  Don't add placement logic inside `createSandbox`.
- `idOverride` is non-empty **only** on the cluster owner watcher's recreate
  path. Any new work you add to `createSandbox` runs on the recreate path too —
  make sure it's idempotent (the sandbox may have been partially created on
  the previous owner before it died).
- If you touch anything that mutates cluster state (FSM, gossip, capacity
  heartbeats, recovery store), the change is now **dual-fragile**: boot-path
  latency + cluster correctness. Get a second opinion before merging.

## Idempotency

Whatever you add must be safe under retry + concurrent duplicate creates. See `pr-review.md` §1.
