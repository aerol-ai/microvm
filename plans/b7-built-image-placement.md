# B7 — Local-only built images can't be placed in a cluster (UC-74)

Status: **implemented (single-worker placement + node-bound tag)**; the original
replicate-to-all implementation from PR [#253](https://github.com/aerol-ai/microvm/pull/253)
was removed during the 2,000-node enterprise review
(`self-node-placement`) · documented in [`pr-review.md` §7.1](../pr-review.md) ·
Severity: P2 (feature broken in cluster mode, no data risk) ·
Area: `internal/cluster` placement + `internal/service` image distribution +
`pkg/api/v1` build · Source: cluster-hetero integration scenario, UC-74
("Create with built image graph"). Parent: `plans/cluster-hetero-failures-fix.md`.

> **Current design:** the build router selects exactly one Docker worker, that
> worker returns `aerolvm-build/node-<base32-node-id>/<digest>:latest`, and every
> create decoder extracts that affinity into `capacity.Request.RequiredNodeID`.
> Build and create are therefore O(1) network work. AOCR remains the option for
> durable/cross-worker reuse, but is not required for this local-image contract.

## 1. Symptom

```
UC-74 | Create with built image graph (CreateWithImage)
     ❌ lifecycle_extra_test.go:99: create with image:
        cluster: no worker placement target available
```

Plain docker creates place fine in the same cluster (UC-11, UC-53 pass), so this
is specific to the **built-image** path, not placement in general.

## 2. Reproduction (live, 8-node cluster-hetero)

```
# build returns a node-local content-addressed tag
POST /v1/images/build  {"dockerfile_content":"FROM alpine:3.20\nRUN echo uc74 > /uc74.txt"}
  -> 200 {"image":"aerolvm-build/7222513189e4820d:latest"}

# create from that tag
POST /v1/sandboxes     {"image":"aerolvm-build/7222513189e4820d:latest","name":"uc74-repro"}
  -> {"error":"cluster: no worker placement target available"}
```

`CreateWithImage` in every SDK is two server calls
(`sdk/go/pkg/microvm/client.go:148`): `BuildImage` then `Create` with the
returned tag.

## 3. Root cause (code-traced)

```
client.CreateWithImage(img, opts)
  │
  ├─ POST /v1/images/build         pkg/api/v1/build.go:49  buildImage()
  │     • builds on WHICHEVER NODE RECEIVES THE REQUEST (not placement-routed)
  │     • in cluster-hetero that node is the ingress/server (the API entrypoint)
  │     • returns tag  aerolvm-build/<hash>:latest   (BuiltImageNamespace, build.go:51)
  │     • the image now exists ONLY on that one non-worker node
  │
  └─ POST /v1/sandboxes            pkg/api/clustercreate/clustercreate.go
        ├─ NormalizeCreateImageDistribution → classifies as local_only       (image_distribution.go)
        ├─ if service.ImageRequiresLocalPlacement(req):                       (clustercreate.go:71)
        │       → returns true for aerolvm-build/* (IsLocalOnlyImageRef)      (image_distribution.go:190)
        │       → create is PINNED to self (the building node)
        │       → but self is ingress/server, and...
        └─ CanOwnSandboxRole("server"/"ingress") == false                    (placement.go:355)
              → the only node with the image cannot run sandboxes
              → no worker has the image
              → ErrNoPlacementTarget
```

The two design rules collide:

1. **A local-only image can only run where it physically exists** — so the
   create is pinned to the build node (`ImageRequiresLocalPlacement`).
2. **Only worker/mixed nodes run sandboxes** (`CanOwnSandboxRole`).

The build endpoint is **not placement-aware**, so in a role-separated cluster
the build lands on the API-terminating node (ingress/server), which violates
rule 2. Single-node and all-mixed clusters work because the build node is also a
worker; role-separated clusters (the production topology) are where it breaks.

### Key code references

| What | Where |
|------|-------|
| Build endpoint (not routed) | `pkg/api/v1/build.go:49` |
| Built-image namespace `aerolvm-build` | `pkg/docker/build.go:51` |
| `IsLocalOnlyImageRef` | `pkg/docker/...` (matches `aerolvm-build/*`) |
| Pin-to-self for local images | `pkg/api/clustercreate/clustercreate.go:71` |
| `ImageRequiresLocalPlacement` | `internal/service/image_distribution.go:190` |
| Role gate | `internal/cluster/placement.go:355` (`CanOwnSandboxRole`) |
| AOCR distribution mode (exists) | `pkg/models/types.go:401` (`ImageDistributionAOCR`) |
| Snapshot/image pusher (exists) | `internal/service` (`snapshotPusher`, `DestRefFor`) |

## 4. Fix options

### Implemented resolution — worker placement with an encoded affinity

This is Option A with the missing cross-call affinity made structural. The
existing `image` response field carries a Docker-valid node-bound repository,
so no SDK response field or compatibility branch is required. A fabricated or
malformed affinity cannot broaden placement: it either decodes to one exact
node or is treated as an ordinary local-only image and fails when unavailable.

- One placement decision and at most one peer build request.
- The follow-up create is constrained to the same live, non-drained worker.
- The receiver verifies that the returned image tag names the selected worker.
- Cluster-control routing headers are accepted only from an authenticated live
  mTLS peer.
- Cluster-disabled/single-node builds retain `aerolvm-build/<digest>:latest`.
- A dead/full/drained build owner returns a retryable placement failure; the
  local image is intentionally not advertised as portable.

### Option A — Build on a worker (route the build through placement)

`buildImage` selects a worker via placement and builds there (locally or by
forwarding the build request), then `CreateWithImage`'s create is pinned to that
same worker.

- ✅ Image lands where it can run; `ImageRequiresLocalPlacement` then resolves correctly.
- ✅ No image bytes cross the network beyond the build context.
- ❌ Build and create are two independent calls — must thread the chosen worker
  from build → create (a new response field / sticky placement) so they agree.
- ❌ A worker chosen at build time may be full/drained at create time → re-pin churn.
- ❌ Concentrates build load on workers (CPU/disk) instead of control-plane nodes.
- Effort: human ~2-3 days / CC ~3-4h. Touches `pkg/api/v1/build.go`,
  `internal/cluster` (build placement + forward), SDK (carry build node), tests.

### Option B — Distribute the built image via AOCR (recommended)

After building, push the image to the cluster registry (AOCR) so it's
pullable on any worker; the create then uses the normal (non-local) placement
path and the consumer-side puller fetches it.

- ✅ Reuses machinery that already exists: `ImageDistributionAOCR`
  (`models/types.go:401`), the snapshot/image pusher (`DestRefFor`,
  `normalizeSnapshotImageDistribution`), and the consumer-side puller that
  template/snapshot creates already rely on.
- ✅ Build can stay on any node; create uses standard power-of-two placement.
- ✅ Image is durable + reusable across creates, not pinned to one node's lifetime.
- ❌ Adds a push (and a first-create pull) to the build→create latency — the same
  cost snapshot/AOCR images already pay; acceptable for a build-then-run flow.
- ❌ Requires AOCR to be configured for the cluster (it is, in cluster-hetero).
  Need a graceful fallback for clusters without AOCR (keep local_only + pin, but
  emit a clear "build node is not a worker; configure AOCR or build on a worker"
  error instead of a bare `ErrNoPlacementTarget`).
- Effort: human ~2-3 days / CC ~3-4h. Touches `pkg/api/v1/build.go` (push after
  build), `internal/service/image_distribution.go` (classify the pushed ref as
  AOCR, not local_only), tests.

### Option C — Atomic build-on-placement-target

Merge build+create into one server operation: select placement first, then build
on the chosen target, then create. Requires a new combined endpoint.

- ✅ Build and run are guaranteed co-located; no cross-call state.
- ❌ Largest change: new endpoint + SDK method across all 5 SDKs; breaks the
  clean "build returns a reusable tag" contract; the built image isn't reusable
  by a second create without rebuilding.
- Effort: human ~1-2 weeks / CC ~1-2 days. Not recommended.

## 5. Recommendation

**Keep the implemented node-bound Option A for local builds.** It satisfies the
two-call SDK contract without O(workers) amplification. Use Option B only when
the product explicitly promises durable or cross-worker reuse; adding AOCR to
every local build speculatively would increase latency and configuration surface.

### Independent quick win (do first, ~30 min)

Whatever the chosen option, replace the bare `ErrNoPlacementTarget` for a
local-only image whose build node can't own sandboxes with an actionable error,
e.g. *"image is local-only and was built on a non-worker node; enable AOCR image
distribution or build on a worker."* This turns a confusing scheduler error into
a diagnosable one and is safe to ship on its own. Site:
`pkg/api/clustercreate/clustercreate.go:71` (the `ImageRequiresLocalPlacement`
branch) — detect `!CanOwnSandboxRole(self.Role)` and return the specific message.

## 6. Test plan

Unit:
- `pkg/docker/build_test.go` — node affinity round-trips and malformed tags fail
  closed.
- `pkg/api/v1/build_test.go` — one selected worker builds and an unbound/wrong
  response is rejected.
- v1/shared facade placement tests — `RequiredNodeID` survives normalization and
  forces the create back to the build worker.
- cluster-off tests — the historical local tag and local build path are unchanged.

Integration (cluster-hetero, UC-74 already exists):
- UC-74 goes green once the image is distributable/placeable.
- Add UC-74b: build an image, then create two sandboxes from the same tag and
  assert both are pinned to the encoded worker (local reuse, not distribution).

## 7. Risks / call-outs (per CLAUDE.md + pr-review.md)

- Cluster-correctness: changes touch placement + image distribution. Document
  split-brain/leader-change behavior and keep single-node a no-op.
- Boot-path latency: Option B adds a push + first-pull; call it out in the PR
  with the first-create number, same axis as snapshot/AOCR creates.
- Idempotency: build is content-addressed (idempotent by hash); the AOCR push
  must be safe under retry (re-push of an existing tag is a no-op).
- Failure-path: if the AOCR push fails, the create must fail cleanly with a clear
  error and not leave a half-distributed image or a dangling reservation.
