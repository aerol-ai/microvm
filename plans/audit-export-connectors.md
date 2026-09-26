# Audit evidence export connectors (Kubernetes audit-backend model)

Status: **Implemented** (2026-09-11) on `plans/secrets-hardening`. Supersedes the
"retained audit ACLs live in the Raft FSM" part of `plans/secrets-hardening.md`
E1b and the single hard-coded HTTP exporter in `internal/service/secret_audit_export.go`.

Owner rules that apply: this touches `internal/cluster/fsm.go` (Raft FSM —
regression tests next to the file and a cluster-correctness call-out per
CLAUDE.md #6), `internal/service` audit paths, and `pkg/wasm/worker` egress.
It adds **no** work to `CreateSandbox`; the only hot-path change is that the
per-start `secretIncarnationForSeal` SQLite read now also returns `owner_ref`
in the same query (zero additional round-trips).

---

## Problem

Two designs were mixed together on this branch:

1. **Evidence.** Every node keeps a hash-chained JSONL (`secrets.jsonl`) and a
   cursor-tailer ships batches to one hard-coded HTTPS receiver. That is the
   right shape but it is a single backend welded to the service.
2. **Post-delete authorization/routing.** Every `opDelete` wrote an `AuditACL`
   into the Raft FSM with a 30-day TTL, replicated to every node, cloned whole
   into every snapshot, and pruned with an O(N) full-map scan under the FSM
   write lock. At 100k concurrent sandboxes with 10-minute lifetimes that is
   ~167 deletes/s → ~432M FSM entries at 30 days. `SB_SECRET_AUDIT_RETENTION_DAYS=0`
   produced `ExpiresUnix=0`, which the pruner skipped — a permanent leak.

This is the classic etcd mistake: keeping *history* in the consensus store
because it is the one place every node can read. Kubernetes does not do this,
and neither will we.

## What we copy from Kubernetes

kube-apiserver separates three things that must not share a store:

| Kubernetes | AerolVM equivalent | Store |
|---|---|---|
| etcd holds only live objects; audit events never enter it | Raft FSM holds live placements, ownership, delete fences, and a **bounded, short-grace deleted-sandbox routing index** | Raft |
| `--audit-log-path` (log backend) | `file` / `stdout` backends | local disk |
| `--audit-webhook-config` (webhook backend, batched POST, kubeconfig auth) | `webhook` backend (batched NDJSON POST; bearer, HMAC, or mTLS) | remote |
| Buffered backend: bounded in-memory queue in front of the real backend, drop-on-overflow with a counter | `fileAuditSink` bounded channel → local JSONL crash buffer → cursor-tailer → backend; overflow writes a `gap` marker and a counter | local disk + remote |
| No audit read API in the apiserver; history lives in the backend (SIEM, object store) | `GET /v1/sandboxes/{id}/audit` serves what a node can prove **locally**, plus bounded cluster routing during the grace window; long-tail history is the backend's job | remote |

The one place we differ from a literal copy: Kubernetes has no per-object
"who may read this deleted object's audit?" question, because it has no audit
read API. We do (E1b), so we keep a *small, bounded, short-TTL* routing index
in Raft — not the 30-day ACL map — and the durable authorization record lives
in each evidence-holding node's SQLite (`sandbox_audit_acl`, already present,
already pruned).

**We will not store 30-day retained audit ACL maps in Raft.** Anything in the
FSM about a deleted sandbox is bounded by `SB_AUDIT_DELETED_GRACE` (default 1h)
*and* by `SB_AUDIT_DELETED_INDEX_MAX` (default 100k entries, oldest evicted),
pruned in O(expired) from an expiry heap, and `SB_AUDIT_DELETED_GRACE=0`
disables it entirely (pure Kubernetes mode: post-delete history is the
backend's).

## Architecture

```
request path            fileAuditSink (bounded chan, non-blocking Emit)
  loadEnv/loadMounts ─►   │ overflow: gap marker + counter (OSS) | spill file (enterprise)
  UnsealRegistry          ▼
  egress ingest         secrets.jsonl  (hash-chained, fsync ≤1s, torn-tail repaired at boot)
                          │
                          ▼  cursor-tailer (1 goroutine, O(batch), durable cursor, backoff)
                        auditexport.Backend.Export(ctx, Batch)
                          ├─ noop     (OSS default)
                          ├─ stdout / file
                          ├─ webhook  (NDJSON POST, Idempotency-Key, bearer | HMAC | mTLS)
                          ├─ s3       (one object per batch, key = batch id → idempotent)
                          └─ bus      (publisher seam; Kafka/NATS impl registers itself)
```

- **The local JSONL is the buffer, not a cache.** The tailer never drops: a
  failing backend makes the cursor lag and the file grow, `prune` refuses to
  rotate unexported bytes, and `aerolvm_audit_export_lag_bytes` + an alert
  make the lag visible. Retention is the only pressure valve and it is explicit.
- **At-least-once.** A crash between "receiver acked" and "cursor persisted"
  re-sends the batch. Every batch carries a deterministic `BatchID`
  (`sha256(node, offset, events)`) as `Idempotency-Key`; the S3 key *is* the
  batch id, so a re-send overwrites the same object. Receivers must dedupe on
  `event_id` or the batch id. Duplicates are documented, never hidden.
- **Backoff.** Exponential with full jitter, capped at
  `SB_AUDIT_EXPORT_MAX_BACKOFF` (5m); reset on the first success.
- **Health** is observed, not probed: `Healthy` reports the last export outcome
  so a health check never adds a second network failure mode.

## Interface

```go
package auditexport

type Batch struct {
    NodeID, BatchID, Offset string
    Events                  []json.RawMessage // already-redacted, hash-chained lines
    ShippedAt               time.Time
}

type Backend interface {
    Name() string
    Export(ctx context.Context, batch Batch) error
    Healthy(ctx context.Context) error
}

func Register(name string, f Factory)   // backends self-register in init()
func Open(cfg Config) (Backend, error)  // validates, then builds by name
```

`internal/service` keeps the existing `controlplane.AuditExporter` seam: a
managed build may still inject its own exporter; otherwise the service wraps
`auditexport.Open(cfg)` in an adapter. One pipeline, two ways to plug a backend.

## Configuration

| Env var | Default | Notes |
|---|---|---|
| `SB_AUDIT_EXPORT_BACKEND` | `noop` (`webhook` if `SB_SECRET_AUDIT_EXPORT_URL` is set) | `noop` \| `stdout` \| `file` \| `webhook` \| `s3` \| `bus` |
| `SB_AUDIT_EXPORT_BATCH_MAX` | `4096` | events per batch |
| `SB_AUDIT_EXPORT_FLUSH_INTERVAL` | `1s` | tailer tick |
| `SB_AUDIT_EXPORT_MAX_BACKOFF` | `5m` | retry cap |
| `SB_AUDIT_QUEUE_MAX` | `1024` (`8192` enterprise) | in-memory emit queue |
| `SB_AUDIT_OVERFLOW_POLICY` | `gap` (`spill` enterprise) | `gap` = drop + marker; `spill` = durable spill file |
| `SB_AUDIT_EXPORT_FILE_PATH` | — | `file` backend (`-` = stdout) |
| `SB_AUDIT_EXPORT_WEBHOOK_URL` / `..._BEARER_TOKEN` | — | aliases of `SB_SECRET_AUDIT_EXPORT_URL` / `..._BEARER_TOKEN` |
| `SB_AUDIT_EXPORT_WEBHOOK_HMAC_KEY` | — | `X-Aerol-Signature: sha256=<hex>` over the body |
| `SB_AUDIT_EXPORT_WEBHOOK_{CA,CERT,KEY}_FILE` | — | mTLS |
| `SB_AUDIT_EXPORT_S3_{BUCKET,PREFIX,ENDPOINT,REGION}`, `..._S3_PATH_STYLE` | — | S3-compatible; credentials from the default AWS chain |
| `SB_AUDIT_EXPORT_BUS_{BROKERS,TOPIC}` | — | consumed by a registered `BusPublisher` |
| `SB_AUDIT_DELETED_GRACE` | `1h` | Raft routing-index TTL for deleted sandboxes; `0` disables |
| `SB_AUDIT_DELETED_INDEX_MAX` | `100000` | hard cap on that index; oldest evicted |
| `SB_SECRET_AUDIT_RETENTION_DAYS` | `30` | local JSONL + SQLite ACL retention. **`0` now means "retain nothing beyond the crash buffer"**: ACL rows are not retained past the next prune tick and the JSONL keeps one day. It never means forever. |

Enterprise mode requires a non-`noop` backend (or an injected exporter) and
an external witness, exactly as before; a `webhook` must be `https` with at
least one of bearer, HMAC, or mTLS.

## Post-delete authorization and routing

- **Authorization** for `GET /v1/sandboxes/{id}/audit` on a deleted sandbox is
  answered by the evidence-holding node from its own `sandbox_audit_acl` row
  (written at destroy, pruned by retention). Every event now also carries
  `owner_ref`, so a node can authorize from the evidence itself even after the
  row is gone, and an exported record is self-describing downstream.
- **Routing** from an ingress node during the grace window uses the bounded
  Raft index (`owner_ref` + `audit_node_ids`, ≤64 nodes). After the grace, or
  when the index was capped, the API returns the existing sticky
  `503 index incomplete` with an explicit coverage block — never a fleet scan,
  never a remote round-trip on the request path. The backend holds the rest.
- The service checks SQLite first, Raft second; single-node / `Noop` cluster
  never touches Raft.

## Reliability

- Torn local tail from a crash: cut at open, `torn_tail` gap marker, boot
  continues (already shipped, `b58da51`). Interior chain breaks still fail closed.
- Export is O(batch): the tailer reads at most `BATCH_MAX` lines from the
  cursor under the flock, releases it, then ships. Never O(file) per tick.
- Worker egress spill: one writer goroutine owns all spill I/O; the dial-path
  overflow branch increments a pending-gap counter and returns. No flock, no
  fsync, no log line on the dial path.

## Scale bar

- 2000 nodes / 100k sandboxes / 100 ingress: export cost is per-node and
  per-batch; nothing here scales with the fleet. The 100-ingress figure
  presumes the fleet's own prerequisite for an ingress tier above 10 nodes: a
  shard-aware router on `GET /v1/cluster/ingress-route/{id}` and
  `SB_CLUSTER_SHARD_AWARE_INGRESS=true` (`plans/data-plane-load-balancer.md`);
  the daemon fails closed at that size without it.
- Raft: live placements only, plus ≤`SB_AUDIT_DELETED_INDEX_MAX` routing stubs
  pruned from a heap. Snapshot growth is bounded by that cap.
- No per-request full-file scan is introduced here; the audit read path's own
  O(file) scan is tracked separately (review finding #3).

## Compatibility

- Single-node: `noop` backend, no Raft, `sandbox_audit_acl` handles
  post-delete reads exactly as today.
- Cluster off → connectors still run (they only need the local JSONL).
- `SB_SECRET_AUDIT_EXPORT_URL` keeps working (it selects the `webhook` backend).
- Snapshot wire format is unchanged: `AuditACLs` stays a `map[string]AuditACL`
  so an older binary can still read a newer snapshot; the expiry heap is
  derived on restore.

## Migration

1. **Deploy.** New binaries apply old log entries (`opDelete` with a 30-day
   `ExpiresUnix`) into the capped index; the cap bounds memory immediately.
   Restore from an old snapshot loads the map, then evicts down to the cap.
2. **Prune.** The leader keeps issuing `opPruneAuditACL`; it now pops the
   expiry heap (O(expired)) instead of scanning the map.
3. **New deletes** carry `ExpiresUnix = now + SB_AUDIT_DELETED_GRACE`.
4. **Rollback** is safe: the snapshot payload shape is unchanged, and an old
   binary that reads a new snapshot simply sees fewer, shorter-lived ACLs.
5. Nothing to migrate in SQLite: `sandbox_audit_acl` already exists.

## Tests

- `pkg/auditexport`: registry, config validation, backoff, every backend
  (webhook: bearer + HMAC + mTLS + 5xx/redirect; s3: key layout + real client
  against an httptest endpoint; bus: not-implemented seam; file/stdout).
- `internal/service`: backend wiring from config, backoff on failure, cursor
  safety, torn-tail boot (existing), single-node post-delete authz via SQLite,
  retention=0 semantics.
- `internal/cluster`: FSM index is bounded (cap eviction), pruned from the
  heap, expires by grace, survives restore from an oversized old snapshot,
  and replays old 30-day entries deterministically. "ACL not in FSM after
  grace" regression.
- `pkg/wasm/worker`: overflow on the dial path does no I/O.

## Non-goals

- A SIEM. Query, retention, and WORM policy on the receiver are the operator's.
- Long-term history in Raft, under any TTL.
- Synchronous export on any sandbox request path.
