# Audit read index: O(page) sandbox audit reads

Status: implemented (stacked on `plans/secrets-hardening` / PR #374).
Fixes review finding "audit reads are O(total retained fleet events) per
request".

## The problem

`GET /v1/sandboxes/{id}/audit` answered a 100-row page by reading the node's
whole `secrets.jsonl`, JSON-decoding every line and SHA-chaining every line,
then keeping the page in a bounded heap. Memory was O(page); CPU and I/O were
O(every retained event on the node), and each page rescanned from the top.

At the target (2,000 nodes, 100k concurrent sandboxes, egress attribution on)
a node retains on the order of 10^8 records over 30 days. One page was a
multi-gigabyte scan. Eight scans could run at once, the node limiter admitted
50 req/s, so requests queued on the semaphore until their context deadline
and surfaced as 504s — the limiter's 429 never fired. The cluster-internal
per-sandbox endpoint that ingress fan-out hits was not rate-limited at all,
so one public request could become up to 64 unmetered full scans.

## What ships

### Per-sandbox posting-list index (`secret_audit_index`)

The audit writer already knows where each record lands (it appends
`line + "\n"` per batch under a flock). After each batch it hands the
offsets to an indexer, which appends `(offset, length, time, kind)` to the
sandbox's posting list in one SQLite transaction — on the writer goroutine,
outside the flock, never on a request path.

- **Storage.** One row per (sandbox, incarnation, chunk) with up to 2,048
  delta-encoded entries (~8 bytes each), so a hot sandbox rewrites one ~16KB
  row per batch rather than one row per event and the index stays at a few
  percent of the log. Gap markers live under the empty sandbox id because
  every page must surface them. Checkpoints and sandbox-less records are
  not indexed (no query can return them) but the index still advances past
  them.
- **Reads.** The page collector asks the index for the sandbox's chunks
  (plus gap chunks; chunks whose newest entry precedes the cursor are skipped
  in SQL), selects the `limit+1` smallest by time in a bounded heap, reads
  exactly those records with `pread`, checks each against its own hash, and
  applies the unchanged `(time, key)` contract. Records at the cursor's
  exact time and at the page's boundary time are all read so a
  same-nanosecond burst can never split a page differently from the scan.
  Then it scans `[indexed_through, EOF)` — normally empty or one batch — so
  index lag never hides an event.
- **Retention.** Prune drops a byte prefix and prepends a checkpoint line, so
  every kept offset moves by one constant. Pass 2 of prune now tracks exact
  byte positions; if every kept line was copied byte-for-byte the index is
  re-based in one O(chunks) transaction (delete chunks below the floor, trim
  the one straddling chunk per list, shift the rest). If not (a re-normalized
  line, a blank line) the index is rebuilt. Blob offsets are relative to
  each chunk's base so the shift is a column update.
- **Consistency.** `secret_audit_index_meta` pins the file generation
  (hash of the first line, as the export cursor does), the byte covered, and
  the last indexed record's offset and hash. At boot the maintainer proves
  the stored index still describes the file with one bounded read of that
  record; a mismatch, a foreign generation, or coverage beyond EOF discards
  the index and rebuilds it from the file in 8MB slices, each committed under
  the flock after re-checking the generation so a concurrent prune cannot
  interleave. Readers compare the meta's generation against the file they
  opened and reopen once if retention raced them. Anything the append or
  prune hooks cannot handle inline (an offset gap, a failed transaction) sets
  the index not-ready and wakes the maintainer — one recovery path.
- **Self-protection.** An index entry that points at bytes that are not a
  record, or at another sandbox's record, serves the page from the file and
  forces a rebuild. The index can only ever make a page cheaper, never
  different.

### Verify on demand, not on every read

Page reads check each returned record against its own `event_hash`; they
no longer re-hash the chain. The whole chain is verified:

- at boot (unchanged; a torn tail is cut and marked, anything else refuses);
- before every retention sweep (unchanged);
- incrementally as records are indexed: the indexer runs the real chain
  verifier over every new line. A break latches `broken`, the index stays
  off until restart, and every local read answers `503` — a forged record
  can be self-consistent, only the chain exposes it, and once it is known
  broken the node must not serve evidence from that log (as strict boot
  would refuse it);
- on demand: `POST /v1/audit/verify` (operator PAT) re-verifies every record,
  one at a time per node, reporting head, record count, and whether the
  verified head equals the writer's tip.

### Admission

- The 8 local read slots fail fast: a read that cannot get a slot within
  50ms returns `ErrSecretAuditBusy` → `429 Retry-After: 1`, never a queue
  that ends in a 504. With the index a slot is held for milliseconds, so
  hitting this means saturation.
- The peer endpoint (`GET /cluster/internal/sandboxes/{id}/audit`) gets its
  own per-node token bucket at `SB_AUDIT_RATE_LIMIT_NODE`, separate from the
  public one, so a fleet-wide fan-out storm and a node's own public traffic
  cannot starve each other.

## Scale bar

| Operation | Before | After |
|---|---|---|
| One page | O(retained events on node), hashed | O(page) reads + O(sandbox entries) decode |
| Per append batch | — | one SQLite tx, O(distinct sandboxes in batch) |
| Retention | O(file) rewrite | + O(chunks) index shift |
| Boot | O(file) chain scan (unchanged) | + one bounded read to validate the index |
| Index size | — | ~8 B/event (vs ~300 B/event of log) |

## Compatibility and migration

- `SB_AUDIT_INDEX_ENABLED=true` by default; `false` restores scan-per-page.
- First boot on an existing log: the maintainer builds the index in the
  background; pages are served by the scan until it is ready
  (`aerolvm_audit_index_ready`). No downtime, no format change to the JSONL.
- Rollback: the two tables are ignored by older builds; the JSONL is
  untouched. A newer build after a rollback finds the meta's generation or
  coverage stale and rebuilds.
- Single-node / storeless: no store means no index; everything else is the
  same code path with `scanFrom = 0`.
- Wire contract of the audit API is unchanged (same events, same cursors —
  the scan path is the oracle in `secret_audit_index_test.go`).

## Non-goals

- Cross-node history: the export backends (`plans/audit-export-connectors.md`)
  remain the source of record after the deleted-sandbox grace.
- Indexing anything but `(sandbox, incarnation)`: kind filters use a class
  byte for exclusion only; time-range queries would need a different key.
- Making boot O(1): the boot chain scan is unchanged and separate.
