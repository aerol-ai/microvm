---
name: touch-create-sandbox
description: Safely modify Service.CreateSandbox or anything it transitively calls. Walks the boot path step-by-step, enforces the failure-cleanup rules, and reminds you to document boot-latency impact in the PR. Use when the user asks to "change sandbox creation", "add this to sandbox boot", "modify CreateSandbox", or any change that lands inside internal/service/service.go near the create path. Proactively suggest as soon as a change is proposed that adds DB queries, HTTP calls, file I/O, or lock acquisitions to sandbox boot.
---

# Touch `CreateSandbox` / the sandbox boot path

`Service.CreateSandbox` (`internal/service/service.go:80`) latency is a load-bearing UX metric. Treat the boot path as protected.

## The boot path, in order

1. `normalizeCreateRequest(req)` + image / runtime / mount / lifecycle / GPU validation
2. `s.sealMounts(req.Mounts)` (AEAD via `pkg/secrets`)
3. Generate `toolboxToken`, sandbox SSH keypair, sandbox ID
4. `s.admitter.Admit(...)` — capacity reservation
5. `s.mounts.MountAll(...)` — external storage mount
6. `s.docker.Create(...)` — container creation
7. Store row insert (`Store.Create`) + caddy route install

## Failure-cleanup rules

Every failure path **below** admission must call `releaseAdmission()`. Every failure path **below** `mounts.MountAll` must call `cleanupMounts()`. These are local closures in `CreateSandbox` — use them, don't reinvent.

If you add a new step between two existing steps, ALSO add a defer/cleanup for it and call out the rollback rule in the PR description's "Failure-path consistency" section.

## What you must document in the PR

Fill in **"Sandbox boot impact"** in the PR template. Don't leave it blank.

Answer:
- What was added (DB query, HTTP round-trip, file I/O, lock acquisition)?
- Expected added latency in the success case
- When it fires (every create? first create? on a flag? on a feature gate?)
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

Mirror `EnsureLayer4Ready` — don't reinvent. **Anti-patterns:** retrying bootstrap on every request; failing the daemon outright on a transient bootstrap error; logging-and-forgetting so the first user request gets a confusing "X not found".

## Idempotency

Whatever you add must be safe under retry + concurrent duplicate creates. See `pr-review.md` §1.
