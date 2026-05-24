# TODOS

Deferred work captured during reviews. Each item has enough context that someone
picking it up in 3 months understands the motivation, the current state, and where
to start.

---

## Custom domains — cert blob GC after removal

**What:** Background sweep prunes Caddy cert blobs in shared storage whose hostname
is no longer present in the FSM hostname → sandbox map.

**Why:** When a user removes a custom domain via `DELETE /v1/sandboxes/{id}/custom-domains/{hostname}`,
the route matcher is updated and the FSM entry is deleted, but Caddy keeps the
issued cert in storage (S3 when `--caddy-storage-s3` is enabled) until natural
expiry. Bloat-only — correctness is intact. Becomes noticeable at high churn
(thousands of one-off custom domains per month).

**Pros:** Tidy storage; lower S3 cost at scale; clearer "what certs exist" answer.
**Cons:** Adds a periodic task to the reconcile loop; must be careful not to
prune a cert that's being renewed concurrently (use the same certmagic lock).
**Context:** Plan `plans/custom-domains.md` §6 risks #4 mentions this. Reconcile
already has a zombie matcher GC pass; this is a sibling pass over cert storage.
The certmagic-s3 plugin exposes a list/delete API.
**Depends on:** Custom-domains v1 landed.

---

*(Daemon-wide ACME budget counter was originally captured here; promoted to
custom-domains v1 scope per outside-voice review decision OV5A — see
`plans/custom-domains.md` and the GSTACK REVIEW REPORT therein.)*
