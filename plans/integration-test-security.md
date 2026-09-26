# Integration test: security hardening (`integration-test-security`)

Status: **REVIEWED** (/plan-eng-review 2026-09-19) — D1/D4/D8 + cadence decided (§11);
review decisions D2-D5 folded into §2, §4.1, §7, §10, §12; D2/D3/D5/D6/D7/D9
stand on their recommendations unless changed.
Covers: the `plans/secrets-hardening` branch (142 commits, 826 files, PRs #374 → #450).
Companion to: [`integration-tests.md`](./integration-tests.md) (harness design),
[`secrets-hardening.md`](./secrets-hardening.md) (the feature contract),
[`audit-export-connectors.md`](./audit-export-connectors.md),
[`audit-read-index.md`](./audit-read-index.md).

---

## 1. What this plan is for

Three things, in dependency order:

1. **Build the deploy artifacts locally instead of waiting for `release.yml`.**
   The harness must be able to provision a cluster from the working tree — no
   tag, no GitHub release, no 15-minute wait. The integration run owns the
   build.
2. **Make the branch provisionable at all.** It currently is not (§3.1) — the
   cluster bootstrap path is broken by this PR's own security changes.
3. **Actually test what the PR shipped.** 826 files of secret sealing, KMS,
   cross-node fan-out, audit chain/export/witness, cluster mTLS, enterprise
   mode, env sealing, storage retirement — and **two new integration use cases**
   (UC-58c, UC-109). That is the gap.

Focus scenarios, per the ask: **`cluster-3-mixed`** (cheap, 3× t3 spot — the
iteration loop) and **`cluster-hetero`** (8 nodes, dedicated server/ingress/worker
roles — the one that can prove placement, failover and reseal across real role
boundaries). Every security *profile* ("version") runs on both.

---

## 2. The feature surface under test

Derived from `git diff main...HEAD`. This is the checklist the UC matrix in §7
must cover.

| # | Area | Code | New config |
|---|---|---|---|
| F1 | Secret **provider seam** | `pkg/secrets/{provider,factory,local,kms,kms_provider,awskms,envelope}.go` | `SB_SECRET_PROVIDER` (`local`\|`awskms`), `SB_SECRET_AWS_KMS_KEY_ID`, `SB_SECRET_PROVIDER_STRICT_BOOT` |
| F2 | **Recipient-set sealing + fan-out** | `internal/service/seal_distribute.go`, `secret_blob_store.go`, `internal/cluster/secret_replication.go` | `SB_SECRET_RECIPIENT_BACKUP_COUNT` (2), `SB_SECRET_FANOUT_MIN_ACK_WAIT` (2s), `SB_SECRET_OUTBOX_STANDALONE_GRACE` |
| F3 | **Cross-node failover open** (the CRITICAL defect this program exists to fix) | `internal/cluster/owner_watcher*.go`, `agent_owner_watcher.go`, recovery replication | — |
| F4 | **Reseal on membership change** | generation-CAS reseal, staged retirement, replacement ACK | `SB_SECRET_TOMB_RETENTION_DAYS` |
| F5 | **Env sealing at rest (D8) + API contract (D9)** | `internal/store/env_binding_migration.go`, `parseIncludeEnv` (`pkg/api/v1/handlers.go:199`) | — |
| F6 | **Audit chain** (hash-linked JSONL, spill, index, quota) | `pkg/auditlog/{event,hash,index,spill,capability}.go`, `internal/service/secret_audit*.go` | `SB_AUDIT_QUEUE_MAX`, `SB_AUDIT_OVERFLOW_POLICY` (`gap`\|`spill`), `SB_AUDIT_INDEX_ENABLED`, `SB_SECRET_AUDIT_RETENTION_DAYS`, `SB_SECRET_AUDIT_STRICT_BOOT`, `SB_SECRET_AUDIT_BOOT_VERIFY` |
| F7 | **Audit read API + live fan-out** | `pkg/api/v1/audit_handler.go`, `internal/service/secret_audit_query.go` | `SB_AUDIT_DELETED_GRACE`, `SB_AUDIT_DELETED_INDEX_MAX` |
| F8 | **Audit rate limiting** | `pkg/api/v1/audit_limit.go` | `SB_AUDIT_RATE_LIMIT_IDENTITY` (10), `_NODE`, `_OPERATOR`, `SB_AUDIT_EGRESS_SANDBOX_RATE`/`_BURST` |
| F9 | **Audit export connectors** | `pkg/auditexport/{file,s3,webhook,bus,bus,backoff,health}.go` | `SB_AUDIT_EXPORT_BACKEND`, `_FILE_PATH`, `_S3_*`, `_WEBHOOK_*` (incl. mTLS + HMAC), `_BUS_*`, `_BATCH_MAX`, `_FLUSH_INTERVAL`, `_MAX_BACKOFF` |
| F10 | **External witness / tamper evidence (E2b)** | `internal/service/secret_audit_witness.go` | `SB_SECRET_AUDIT_EXTERNAL_WITNESS`, `_EXPORT_URL`, `_EXPORT_BEARER_TOKEN`, `_WITNESS_INTERVAL` |
| F11 | **Audit ingest endpoint + ownership lease** | `internal/service/audit_ingest.go`, `audit_ownership_lease.go`, `audit_auth.go` | `SB_AUDIT_INGEST_PORT`, `SB_AUDIT_INGEST_TOKEN` |
| F12 | **Cluster mTLS / peer identity** | `internal/cluster/{tls,raft_tls,peer_dial,peer_client_cache,incarnation}.go`, `scripts/cluster-sign-node.sh` | `SB_CLUSTER_TLS_DIR`, `SB_CLUSTER_INSECURE_CREDENTIALS` |
| F13 | **Operator authz split** | `pkg/api/v1/operator_auth.go` | — |
| F14 | **Enterprise mode fail-fast profile** | `internal/config/config.go:2389-2454`, `pkg/daemon/daemon.go:325,549,663` | `SB_ENTERPRISE_MODE` |
| F15 | **Node storage retirement** | `internal/service/node_storage_retirement.go`, `/v1/cluster/nodes/{id}/storage-retired`, `/v1/cluster/storage-retirements` | — |
| F16 | **Isolate jail realization** | `pkg/isolate/{chroot,cgroup,seccomp,jail_realized,shim}*.go` | `SB_ISOLATE_USE_JAIL`, `SB_ISOLATE_SECCOMP_MODE`, `SB_ISOLATE_JAIL_PIDS_MAX`, `SB_ISOLATE_JAIL_CGROUP_ROOT` |
| F17 | **Egress attribution audit** | `pkg/wasm/worker/egress_audit.go`, isolate egress pool | `SB_EGRESS_ATTRIBUTION_ENABLED` |
| F18 | **Fleet-scale read paths** (paging, bounded caches) | `pkg/api/clusterlist/list.go`, `internal/cluster/bounded_*`, `fsm_owner_page` | — |
| F19 | **Ingress topology gate** | `Terraform/validate/ingress.go`, daemon topology error | `SB_CLUSTER_SHARD_AWARE_INGRESS` |
| F20 | **Mount credential placement hygiene** | `models.ValidateSecretsPlacement` | — |
| F21 | **Isolate orphan sweep** (added by eng review 2026-09-19) | `internal/service/service.go:5049-5061` | — |
| F22 | **JS-bundle cluster fan-out** (added by eng review 2026-09-19) | `pkg/api/v1/js_bundle_cluster.go` | — |
| ~~F23~~ | ~~Facade env contract under D9~~ — **deferred**, see §12 | `pkg/api/daytona/handlers.go:789,1020` | — |

**55 new `SB_*` knobs.** None of them has a provisioning path today (§3.2).

> **Eng review 2026-09-19.** F1-F20 were derived from the plan author's read of
> the diff. The review re-derived the surface independently from
> `git diff main...HEAD` and found three rows missing. F21 and F22 are now in
> scope (D4); F23 is deferred with the reason recorded in §12. The lesson for
> whoever extends this plan: build the feature table from the diff, not from
> the PR description.

---

## 3. Findings — what blocks this today

Each was verified against the branch tip (`25e748a9`).

### 3.1 RESOLVED (2026-09-23) — cluster bootstrap was broken on this branch

`scripts/cluster-join.sh` was rewritten so that `ca.key` never leaves the seed.
A joiner now mints `node.key` + `node.csr` locally and **exits 2 before
restarting the daemon** unless `--signed-cert` is supplied
(`cluster-join.sh:352-362`). It also **requires** `--cred-bundle`
(`cluster-join.sh:200`), a second tarball `cluster-init.sh` now emits
separately from the trust bundle (`cluster-init.sh:410-419`).

`Terraform/templates/bootstrap.sh.tftpl` does neither:

- the seed publishes only `gossip-key.txt` + `aerolvm-tls-bundle.tar.gz`
  (lines 204-209) — **no cred bundle**;
- the joiner calls `cluster-join.sh` with `--tls-bundle` and no `--signed-cert`
  and no `--cred-bundle` (lines 240-246).

The Terraform diff on this branch touches `bootstrap.sh.tftpl` by **4 lines**
(the `SB_CLUSTER_SHARD_AWARE_INGRESS` export) and nothing else. So **every
multi-node scenario fails to form a cluster on this branch.** This is not a
test-harness gap; it is a shipping defect in the PR — the documented install
path no longer works unattended. Fixing it is Phase 2 and is a prerequisite for
literally everything else here.

> **FIXED (T5/T6, 2026-09-23).** `cluster-3-mixed` forms **3 members**. The seed
> publishes the cred bundle and runs a bounded `aerolvm-csr-signer` loop;
> joiners do a two-pass join (`exit 2` is the "CSR ready" success signal),
> uploading their CSR under an IAM-assigned prefix they cannot choose. The seed
> takes the node id from `nodes/<caller identity>` — an object only Terraform
> writes — because `cluster-sign-node.sh` stamps `DNS:node:<id>` from its flag
> and never inspects the CSR, so a caller-chosen id would let any joiner mint a
> cert for another node. Verified on the live certs (§10, T5).

### 3.2 No provisioning path for any new knob

`config/cluster.yml` has no `secrets:` or `audit:` section, and
`bootstrap.sh.tftpl`'s ops-env block (lines 419-450) writes none of the 55 new
variables. The only lever today is `extra_user_data`, which runs **after**
`systemctl restart sandboxd` (line 727-729), so a scenario must append to the
env file and restart a second time — the pattern
`single-node-isolate.tfvars:62-65` uses. That is fine for one flag, unusable as
the mechanism for a profile matrix.

### 3.3 Checksum verification is now mandatory — and it has a trap

`install.sh`'s `verify_downloads` used to warn and continue; it now **fails**
when the checksums file is missing or an asset has no entry
(`install.sh:291-318`). Two consequences for a local-build pipeline:

- the local build **must** emit a `checksums.txt` whose second column matches
  the URL basenames exactly (`sandboxd_linux_amd64`, `toolboxd_linux_amd64`);
- Caddy is downloaded from the *default* release URL unless
  `--caddy-binary-url` is passed explicitly, and a non-explicit Caddy URL **is**
  checksum-verified against our file (`install.sh:724`). A checksums.txt with
  only sandboxd+toolboxd therefore breaks the Caddy install. Either build Caddy
  locally too, or pass `--caddy-binary-url` explicitly (which sets
  `CADDY_BINARY_URL_EXPLICIT=true` and skips that check).

The good news: `install.sh` already supports `--sandboxd-url`, `--toolboxd-url`,
`--checksums-url`, `--caddy-binary-url`, and derives the asset name via
`basename "${URL%%\?*}"` (`install.sh:790-791`) — **the query string is
stripped, so presigned S3 URLs work as-is.** No `install.sh` change is needed.

### 3.6 FOUND + FIXED — every successful DELETE answered 404

The first live run of the local-build harness immediately paid for itself.
`UC-16` failed with `destroy sb-…: sandbox not found`, and a direct probe
reproduced it **3/3** — each time with the container removed and the row gone,
i.e. the destroy *succeeded* and only the reply was wrong.

`DestroySandbox` races its own side effects: `rt.Destroy` makes the engine emit
die+destroy, `handleDestroyEvent` removes the sandbox row, and `DestroySandbox`
then reaches its own `store.Delete`, gets `ErrNotFound`, and returns it —
`WriteStoreAwareError` turns that into 404.

Not a new intolerance (`main` returns the same bare error) but a new **ordering**:
this branch deliberately moved `store.Delete` to the end of the destroy boundary
so the secret tomb, wasm cleanup and placement delete precede it. That widened
the window enough that the event watcher wins every time.

`events.go` already documents the mirror-image race as benign, and the two other
callers of `deleteSandboxRowAndFenceAudit` both guard with
`!errors.Is(err, store.ErrNotFound)`. `DestroySandbox` was the one call site that
did not. Fixed there; the helper still returns the error because
`audit_ownership_lease_test` asserts it and states "the caller treats that as
success". Regression test verified to fail without the fix. Re-verified live:
`DELETE → 204`, `GET` after → 404, 3/3.

### 3.7 FOUND + FIXED — a stop could silently delete the sandbox (containerd)

Surfaced by `UC-14` on the re-run; **intermittent** (1 of 2 probes vanished),
which is why run 1 passed it. Node journal, twice:

```
die (stop_mode=manual, exit 0)  →  POST /stop 200  →  "destroyed via docker event" (+2ms)  →  GET 404
```

Root cause: `internal/runtime/containerd/events.go:77` maps
`runtime.TaskDeleteEventTopic` to action `"destroy"`. In containerd
`TaskDeleteEventTopic` is **`/tasks/delete`** — the *task* (the process) being
reaped, which happens on any normal stop. The **container** object survives and
is restartable. Docker's `destroy` means the container was removed; containerd's
analogue is `/containers/delete`, not `/tasks/delete`.

So on the containerd engine — **the default for every non-local deployment** —
stopping a sandbox can delete its row, breaking stop/start (UC-14/UC-15) and
losing the sandbox. The same file already reasons carefully about this exact
class of bug for `TaskPaused`/`TaskResumed` ("mapping TaskPaused→stop made an
internal CreateSnapshot pause tear the live sandbox down"); `TaskDelete` was
missed.

The driver's own code settles it:

| | |
|---|---|
| `Stop` (`lifecycle.go:381-386`) | `task.Kill(SIGTERM)` → `task.Delete(ctx)` — the **task** only; the container survives |
| `Destroy` (`lifecycle.go:436`) | … → `container.Delete(ctx, WithSnapshotCleanup)` — publishes `/containers/delete` |

**Fixed.** `/tasks/delete` joins `TaskPaused`/`TaskResumed` in the ignored set;
`/containers/delete` is added as a second subscription filter and mapped to
`destroy`, so genuine destroys still register promptly instead of waiting for
reconcile. `ContainerDelete` names the container with `GetID()` rather than
`GetContainerID()`, and precedence is asserted — task events carry both, where
`ID` is the *exec* id.

Verified live: stop/start went from 1-of-2 sandboxes vanishing to **4/4
surviving and restarting**.

Known follow-up (recorded, not a regression): a warm-adopted `park-*`
container's destroy event can no longer resolve its `sandbox_id` label, because
the container is gone by the time `/containers/delete` arrives. Those rows fall
to the reconcile orphan sweep instead of prompt deletion — slower, but correct.
Also newly visible: `handle docker event failed … unknown sandbox placement`
now WARNs on every API-driven destroy, because `container.Delete` is the last
step of `Destroy` so the event always arrives after the placement is gone.
Benign, but noisy in cluster runs.

### 3.8 FOUND + FIXED — route upsert raced Caddy's @id index

Fixing §3.7 let **UC-15** (start a stopped sandbox) reach code that had never
run, which failed with a bare `insert caddy route failed: 400`.

The bare status was itself the problem: this client discarded the admin API's
response body, so the cause existed only in Caddy's journal on the box — which
does not survive teardown, making it a dead end in CI. After making the client
carry Caddy's own text, the answer appeared immediately:

```
indexing config: duplicate ID 'sandbox-sb-…' found at
  /config/apps/http/servers/srv0/routes/0 and /config/apps/http/servers/srv0/routes/N
```

Caddy rebuilds its `@id` index when it loads a config. While that is in flight,
`PATCH /id/<routeID>` answers **404 for a route that IS present**. `upsertRoute`
read that as "absent", inserted a second copy, and Caddy rejected the whole
config. It affects any route upsert during a reload — start, `expose_port`,
custom domains — and measured **2 of 8** stop→start cycles on a public sandbox.

A duplicate-ID rejection is positive proof the route exists, so the in-place
PATCH was right all along and is simply retried. Scoped to that one message: an
insert that fails for any other reason still fails immediately.

Verified live: **0 of 12** failures, and the full suite went to
**pass 58 · fail 0**.

### 3.8a Harness: a TLS timeout threw away a healthy run

`run_one` treated `wait_for_tls` as a verdict (`|| inconclusive=1`) even though
`wait_for_health` immediately afterward talks to the same `https://` base URL —
so a healthy API already proves the handshake. An instance **replacement** blew
the 300s budget (the new box must obtain and load the cert while the old A
record is still cached) and the whole suite run was discarded as inconclusive;
the box was serving a valid Let's Encrypt cert minutes later.

Replacement is now the COMMON case, because the local-build pipeline changes
`user_data` on every code change. TLS is now a bounded pre-wait that logs and
defers to the health probe.

### 3.9 Why these three matter for the plan

None was visible to `make test`, which stayed green throughout. All three sit on
the ordinary lifecycle path — destroy, stop, start — not in the secrets surface
this plan was written to exercise. They were found by the *first* scenario the
harness ran, before a single security use case existed.

That is the argument for §1's ordering: the branch could not be trusted on real
infrastructure at all, and the local-build pipeline is what made the branch
runnable. It also means the S1-S6 matrix should be expected to surface more of
this class before it reaches the F1-F22 surface.

### 3.4 Coverage reality check

| | |
|---|---|
| Files changed | 826 |
| New non-test source files | 73 |
| New integration UCs | **2** (UC-58c secret fan-out chaos, UC-109 isolate jail) |
| New scenarios | 1 (`single-node-isolate-jail`) |

Unit/package coverage is high (the plan holds ~95% on the four core packages),
but nothing has run the KMS provider, any export connector, the witness loop,
the audit ingest endpoint, mTLS peer rejection, enterprise boot gating, or
storage retirement **against real infrastructure**.

### 3.5 Toolchain is ready

`zig 0.16.0`, `go 1.26.6 darwin/arm64`, `docker 20.10.17` are present locally.
`sandboxd` needs CGO (`mattn/go-sqlite3 v1.14.48`); `toolboxd` is
`CGO_ENABLED=0`; Caddy is built CGO-free via `xcaddy`. The zig cross-compile
recipe is already proven in this repo's history (containerd live-deploy loop).

---

## 4. Phase 1 — local artifact build

### 4.1 New: `integration-tests/lib/build.sh`

One entry point, content-addressed, cached.

```
integration-tests/lib/build.sh build   [--ref <commit>] [--arch amd64,arm64] [--with-caddy] [--with-receiver]
integration-tests/lib/build.sh publish [--ttl 12h]
integration-tests/lib/build.sh urls    [--ref <commit>]   # prints the three tfvar values
integration-tests/lib/build.sh artifacts-init             # one-time bucket bootstrap
```

`--ref` (default `HEAD`) builds any commit into its own `AEROL_BUILD_ID`
namespace via a detached worktree, so `--ref main` and `--ref HEAD` coexist in
the artifacts bucket. **UC-165 depends on this** (D5): the latency baseline is
`main`-built binaries, not a security-profile-off run, because the security
defaults are already on (see §7 group L). It is one flag on a pipeline that has
to exist anyway — not a feature built for one test.

**Build ids.** `AEROL_BUILD_ID = <short-sha>[-dirty-<tree-hash>]`, where
`tree-hash` is `git diff HEAD | sha256`. Identical tree ⇒ identical id ⇒ skip
build and skip upload. This is what makes a re-run against a `--keep` cluster
free.

**Outputs** (`integration-tests/.build/<AEROL_BUILD_ID>/`, gitignored):

```
sandboxd_linux_amd64      CGO=1, zig cc -target x86_64-linux-gnu.2.31
toolboxd_linux_amd64      CGO=0
caddy_linux_amd64         xcaddy, optional (--with-caddy)
audit-receiver_linux_amd64  optional (--with-receiver), see §6.4
sandboxd_linux_arm64      zig cc -target aarch64-linux-gnu.2.31   (arm64 scenarios)
toolboxd_linux_arm64
checksums.txt             sha256sum of every file above, GNU two-space format
buildinfo.json            git sha, dirty flag, ldflags version, build host/time
```

Version stamping mirrors `release.yml`:
`-trimpath -ldflags "-X github.com/aerol-ai/microvm/internal/version.Version=itest-<AEROL_BUILD_ID>"`
so `/health` and the report both identify exactly which tree ran.

`toolboxd` keeps `-s -w` (Makefile rationale: it is bind-mounted into every
sandbox).

**Preflight.** Fail fast and loud with the fix command when `zig`/`go`/`xcaddy`
is missing. `zig cc` target strings changed across zig releases — pin the
verified pair in `buildinfo.json` and assert `file sandboxd_linux_amd64`
reports `ELF 64-bit LSB, x86-64, dynamically linked` before publishing.

### 4.2 Artifact hosting — persistent bucket + presigned URLs

Mirror the `make integration-cert-store-init` precedent: a long-lived bucket
**outside** every scenario's Terraform state, so per-scenario `destroy` never
wipes it.

```
aerol-itest-artifacts-<acct>/builds/<AEROL_BUILD_ID>/{sandboxd_linux_amd64,…,checksums.txt}
```

Hardened identically to the cert bucket (public-access-block, AES256,
versioning) plus a **7-day lifecycle expiry** — these are throwaway test
binaries, not releases.

`publish` emits presigned GET URLs (default 12h, covering slow `*.metal`
provisioning) and `urls` prints them as ready-to-paste tfvars.

Why presigned rather than an IAM grant on the node role: zero IAM change, works
with the existing `curl_download` path, and the basename-strip in `install.sh`
already handles the query string.

> **DECIDED (D4):** a presigned URL lands in EC2 user-data, readable from IMDS
> by anything on the box. The PAT and the Cloudflare token are already there,
> and these are throwaway scenario clusters with `ttl=4`, so this is accepted.
> Recorded so it is a decision, not an accident. Mitigations that cost nothing:
> 12h expiry (not 7d), read-only GET, and a bucket whose only contents are test
> binaries.

### 4.3 Terraform wiring

Three new variables in `Terraform/variables.tf`, defaulting to `""` so
production renders byte-identically:

```hcl
variable "sandboxd_url"  { type = string, default = "" }
variable "toolboxd_url"  { type = string, default = "" }
variable "checksums_url" { type = string, default = "" }
```

Threaded into `nodes.tf` → `bootstrap.sh.tftpl`, appended to `INSTALL_ARGS`
next to the existing `caddy_binary_url` block:

```bash
%{ if sandboxd_url != "" ~}
INSTALL_ARGS+=(--sandboxd-url '${sandboxd_url}' --toolboxd-url '${toolboxd_url}' --checksums-url '${checksums_url}')
%{ endif ~}
```

`install_script_url` / `cluster_init_script_url` / `cluster_join_script_url`
already exist — point them at the **locally built copies** of
`scripts/install.sh`, `cluster-init.sh`, `cluster-join.sh` published alongside
the binaries. Otherwise the node bootstraps with released scripts against a
branch daemon, which is exactly the mismatch that produced §3.1.

### 4.4 `run.sh` integration

New flags, default **on** (the ask: the integration test owns the build):

| Flag | Effect |
|---|---|
| *(default)* | build → publish → provision from local artifacts |
| `--released` | current behaviour: `releases/latest`, skip build |
| `--version <tag>` | pin to a released tag (A/B against a known-good) |
| `--no-build` | reuse the last published `AEROL_BUILD_ID` (fast re-provision) |

`wait_for_bootstrap_assets` (`run.sh:483-501`) must skip the GitHub reachability
poll in local-build mode and instead probe the presigned URLs directly.

> **CORRECTED during execution (2026-09-23).** This section originally said
> `HEAD` the presigned URLs. That does not work: a SigV4 presigned URL signs the
> HTTP **method**, so a `HEAD` against a GET-presigned URL fails
> `SignatureDoesNotMatch` and would have rejected every healthy build. Measured
> against the real bucket: `HEAD → 403`, `GET --range 0-0 → 206`. The
> implementation uses a one-byte ranged GET, which is the same signed method,
> costs one byte, and proves signature validity as well as reachability.

The scenario report gains a `build` block (`AEROL_BUILD_ID`, git sha, dirty
flag) so `reports/*.json` says which tree produced the numbers.

**Makefile:**

```
make itest-build                 # build only
make itest-publish               # build + upload, print presigned tfvars
make itest-artifacts-init        # one-time bucket bootstrap
```

(`make itest-build publish` in the draft would have made `publish` a second
*goal*, not a flag; the harness's bare-word flag convention is reserved for
`run.sh` flags, so publish is its own target. `BUILD_FLAGS="--ref main"` passes
through to `build.sh` for the UC-165 baseline arm.)

---

## 5. Phase 2 — unblock cluster bootstrap (§3.1)

This is a **product fix**, not test scaffolding: the shipped install path must
work unattended.

> **DECIDED (D1, 2026-09-19): its own PR, stacked on `plans/secrets-hardening`
> and merged before it.** Everything in §6-§8 blocks on that PR landing, and so
> does any cluster scenario anyone else runs against this branch. Scope it to
> exactly §5.1 + §5.2 (bootstrap rendezvous + the generic env hook) — the KMS
> key (§5.3) and audit sinks (§5.4) ride with the scenario work, since nothing
> on the shipped install path needs them.
>
> Branch: `fix/cluster-bootstrap-csr-rendezvous`. It needs the CLAUDE.md
> cluster-fragility call-out (single-node unaffected, joiner path changed) and a
> green `cluster-3-mixed` provision as its own exit criterion.

### 5.1 The S3 signing rendezvous

Extend `bootstrap.sh.tftpl` (both node branches), using the bundle bucket.

> **CORRECTION (outside voice, verified).** An earlier draft of this section
> said the nodes "already have `Get/Put/List`" on the bundle bucket, citing
> `Terraform/iam.tf:74-90`. That range is **`seed_rw`** — the seed's policy.
> `joiner_r` (`iam.tf:83-92`) grants only `s3:GetObject`, `s3:HeadObject` and
> `s3:ListBucket`. **Joiners cannot Put**, so the CSR upload below does not work
> without an IAM change. T5 must add a scoped `s3:PutObject` on `csr/*` to
> `joiner_r`.
>
> **And the obvious fix is insecure.** `scripts/cluster-sign-node.sh:88-91`
> stamps `subjectAltName = DNS:node:${NODE_ID}` straight from the `--node-id`
> flag and **never inspects the CSR's subject**. If the seed's signing loop
> derives the node id from the S3 object *filename*, then any joiner that can
> Put into `csr/` can upload `csr/server-1.csr` and be handed a valid cert for
> `node:server-1` — total defeat of F12, while UC-151 and UC-153 still pass.
> **Node id must be bound to the uploader, not to a caller-chosen name:** give
> each joiner a per-node key prefix (`csr/$${node_name}/`) enforced by a bucket
> policy keyed on the instance role/tag, and have the signer take the node id
> from the prefix it polled, never from inside the object. Add a UC asserting a
> joiner cannot obtain a cert for another node's id.

**Seed, after `cluster-init.sh`:**
1. publish `gossip-key.txt`, `aerolvm-tls-bundle.tar.gz` (existing) **and
   `aerolvm-cred-bundle.tar.gz`** (new — from `--cred-bundle-out`);
2. start a **signing loop** (`systemd` unit `aerolvm-csr-signer`, or a
   backgrounded `while` bounded by `seed_wait_max_seconds`): poll
   `s3://<bundle>/csr/`, for each `<node>.csr` run
   `cluster-sign-node.sh --csr … --node-id <node> --out …` and upload
   `s3://<bundle>/crt/<node>.crt`. Idempotent: skip when the `.crt` exists.

**Joiner:**
1. wait for the three seed artifacts (existing loop, extended to the cred bundle);
2. run `cluster-join.sh … --tls-bundle … --cred-bundle …` **without**
   `--signed-cert` — tolerate `exit 2`, that is the CSR-ready signal;
3. upload `/etc/sandboxd/tls/node.csr` → `s3://<bundle>/csr/$(hostname -s).csr`;
4. poll for `crt/$(hostname -s).crt`, download it;
5. re-run `cluster-join.sh … --signed-cert /tmp/node.crt` — this run installs
   the cert, writes `cluster.env` and restarts the daemon.

`$(hostname -s)` is the node id both scripts derive
(`cluster-join.sh:266`, `cluster-init.sh:258`), and the signed cert must carry
`DNS:node:<id>` — which is precisely why signing stays on the seed rather than
Terraform minting certs with the `tls` provider: Terraform cannot know the
EC2-assigned hostname at plan time, and `internal/cluster` verifies that SAN.

**Failure mode to instrument:** if the signer dies, joiners hang. Bound the
poll by `seed_wait_max_seconds` and emit the same `[bootstrap]` diagnostics the
existing block does, so `collect_failure_logs` picks it up.

### 5.2 Generic env hook: `extra_sandboxd_env`

One new variable replaces per-knob plumbing for all 55:

```hcl
variable "extra_sandboxd_env" { type = map(string), default = {} }
```

Rendered into the ops-env block **before** the final `systemctl restart
sandboxd` (`bootstrap.sh.tftpl:450`, ahead of line 727), so no second restart
and no `extra_user_data` abuse. Per-node override via a `nodes[*].sandboxd_env`
map merged over the global one — needed because `SB_NODE_ROLE`-specific
profiles (ingress-only audit rate limits, worker-only jail settings) differ per
node in hetero.

Values that are only known at apply time (KMS key ARN, S3 audit bucket, webhook
URL) stay as dedicated template vars, not map entries.

### 5.3 KMS key provisioning

Gated on a new `secret_kms_enabled` bool:

- `aws_kms_key` + alias `alias/aerolvm-itest-<scenario>`, `deletion_window_in_days = 7`;
- node role policy: `kms:Encrypt`, `kms:Decrypt`, `kms:DescribeKey` on that key ARN;
- bootstrap writes `SB_SECRET_PROVIDER=awskms`, `SB_SECRET_AWS_KMS_KEY_ID=<arn>`.

Cost: $1/month prorated + $0.03/10k requests — negligible, and it must be a
*real* key: `pkg/secrets/fake_kms.go` already covers the offline contract, so a
fake here would test nothing new.

> **T7 verified 2026-09-23.** Strict boot defaults ON, because `config.go:2414`
> *requires* it for awskms whenever `SB_ENTERPRISE_MODE` is true — defaulting it
> off would make S4/S6 fail at daemon start with a config error rather than run.
> `AWS_REGION` is pinned rather than left to the SDK's IMDS fallback, so a
> missing region is a clear boot failure instead of an opaque KMS timeout at
> seal time.
>
> **Ordering matters and is now asserted:** the KMS block renders BEFORE the
> `extra_sandboxd_env` loop, because `cluster.env` is a systemd
> `EnvironmentFile` where the last assignment wins. That is what lets a scenario
> override a Terraform-set default. If the order flips, the override silently
> stops working and the scenario looks configured when it is not — mutation-
> verified in `bootstrap_render_test.go`.
>
> The hand-written overlay the exit criterion calls for is now a supported file:
> `.tf/<scenario>/override.tfvars`, chained last in `tf_varfile_args` and read by
> both apply and destroy. Gitignored, so it cannot be mistaken for a committed
> scenario.
>
> **Bonus coverage this run produced for free:** D9's "omit env by default,
> audited opt-in" and the Daytona `"env":{}` contract (the reverted `omitempty`)
> were both confirmed live, and the audit chain + audit read API (F6/F7,
> normally T13) returned a well-formed event with `ref`, `actor`, `node_id`,
> `result` and a chain `event_id`.

### 5.4 Audit export sinks

- **s3** — new `audit_export_enabled` bool → bucket
  `aerolvm-itest-audit-<scenario>` (force_destroy, lifecycle 3d) + node role
  `PutObject`; bootstrap writes `SB_AUDIT_EXPORT_BACKEND=s3` + `_S3_BUCKET`,
  `_S3_REGION`, `_S3_PREFIX=<scenario>/`. The suite reads it back with the
  AWS SDK (already a dependency).
- **file** — always on in the security scenarios via
  `SB_AUDIT_EXPORT_FILE_PATH=/var/log/aerol-audit-export.jsonl`; read over SSH
  with the existing `harness.SSHRun`.
- **webhook** — see §6.4.

> **CORRECTED during execution (2026-09-25).** This section, and the S2 profile
> in §6.2, assumed a node could export to **file AND s3 at once**. It cannot.
> `SB_AUDIT_EXPORT_BACKEND` selects exactly one of
> `noop|stdout|file|webhook|s3|bus` and `pkg/auditexport` has no fan-out
> backend. A scenario that wants both connectors proves them on **different
> nodes**, through each node's own `sandboxd_env` — which is exactly what T6's
> per-node override is for, and which single-node cannot express at all.
>
> Second constraint from the same package: `file` and `stdout` are **rejected
> when enterprise mode is on** ("keeps audit evidence on this node"), so S4 and
> S6 must use `webhook`, `s3` or `bus`. S1's "enterprise off, file export" is
> fine as written.
>
> `SB_AUDIT_EXPORT_S3_PREFIX` is scenario-scoped, not per-node:
> `auditexport.ObjectKey` already interleaves `node=<id>` into the key, so a
> per-node prefix repeats the node twice in every path.
>
> IAM is **PutObject only**. A node must not be able to read the fleet's audit
> trail back, nor delete its own records to cover a compromise — which is the
> whole reason evidence ships off-node. The audit bucket is also kept separate
> from the bootstrap bundle bucket, because that one is readable by every
> joiner.

---

## 6. Phase 3 — the security profile matrix ("versions")

### 6.1 Profile axes

| Axis | Values |
|---|---|
| Secret provider | `local` · `awskms` |
| Posture | OSS default · `SB_ENTERPRISE_MODE=true` |
| Cluster mTLS | signed per-node certs (real) · `SB_CLUSTER_INSECURE_CREDENTIALS=true` (negative control) |
| Audit export | `file` · `s3` · `webhook`(+HMAC) · none |
| Witness | off · `SB_SECRET_AUDIT_EXTERNAL_WITNESS=true` + receipts |
| Recipient backups | `1` (min) · `2` (default/enterprise floor) · `3` (hetero) |
| Audit index | on (default) · off (`SB_AUDIT_INDEX_ENABLED=false`) |
| Overflow policy | `gap` · `spill` |
| Egress attribution | on · off |
| Isolate jail | off · on + `seccomp=enforce` + pids cap |

The full cross-product is meaningless; the matrix below picks the combinations
that are each *load-bearing for a distinct failure mode*.

### 6.2 Scenarios

New files under `integration-tests/scenarios/`, each a `.tfvars` + `.caps.yml`
pair (the harness's unit of a scenario).

| # | Scenario | Topology | Profile | Cost/run | Purpose |
|---|---|---|---|---|---|
| S1 | `single-node-secrets` | 1× t3.medium spot | local, enterprise off, file export, index on | ~$0.05 | Smoke + single-node Noop path + create-latency baseline. Cheapest gate; runs first. |
| S2 | `cluster-3-mixed-secrets` | 3× t3.medium spot | **local**, mTLS real, backups=2, file+s3 export, witness off, index on | ~$0.2 | The iteration loop. Fan-out, failover open, reseal, audit fan-out, mTLS. |
| S3 | `cluster-3-mixed-secrets-kms` | 3× t3.medium spot | **awskms** + strict boot, otherwise = S2 | ~$0.2 | The KMS provider's **own** UC set — *not* S2 parity, see the box below. |
| S4 | `cluster-3-mixed-secrets-enterprise` | 3× t3.medium spot | **enterprise on**: witness on, s3 export, strict boot, backups=2, no escape hatches, jail on | ~$0.25 | Fail-fast profile end to end; boot gates; witness receipts. |
| S5 | `cluster-hetero-secrets` | 8 nodes (3 server / 1 ingress / 4 worker, 1× c5.metal) on-demand | local, enterprise on, backups=3, s3+webhook export, index off on ingress | ~$14/h | **Flagship.** Role-separated failover, reseal on drain/add, audit fan-out across a real ingress tier, storage retirement, fleet-scale read paths. |
| S6 | `cluster-hetero-secrets-kms` | = S5 | awskms + enterprise | ~$14/h | Pre-merge only. The one run that proves the shipped enterprise+KMS posture. |

> **The "D7 contract parity" claim was wrong (outside voice, verified).**
> `pkg/secrets/kms_provider.go:92-95` documents and implements `_ = nodeID` —
> `KMSProvider.Open` **never checks the envelope recipient set**; IAM is the
> entire boundary. So UC-112 ("absent on non-recipients"), UC-114 (foreign
> identity refused) and UC-119 (not-in-set → distinct error) assert a property
> that **deliberately does not exist** under `awskms`, and
> `secrets.ErrRecipientDenied` — the only error
> `internal/cluster/owner_watcher.go:170-179` treats as permanent — can never
> fire there. Running S2's UCs on S3 therefore produces either false reds or
> vacuous greens. **S3 gets its own set:** revoke `kms:Decrypt` from one node's
> role and assert *that* node's open fails while others succeed; assert the IAM
> boundary, not the recipient boundary. Also add a **key-rotation** UC:
> `pkg/secrets/awskms.go:98-115` does not classify `IncorrectKeyException`, so it
> falls through to `ErrProviderUnavailable` — a permanent operator error read as
> transient, which drives `recreateOwnedPlacement` through 5 retries into endless
> reassignment (`owner_watcher.go:180-190`). Re-point
> `SB_SECRET_AWS_KMS_KEY_ID` at a second key and assert a **distinct, permanent**
> error. Fix the classification in the same PR.

S5/S6 reuse `cluster-hetero.tfvars`'s node map verbatim (including
`spot = false` — spot reclaim mid-run makes multi-node convergence flaky, and
the metal box exceeds the spot vCPU quota). Overlay only the profile.

**Negative controls are not scenarios.** The enterprise boot-gate matrix
(§7, UC-138/139) and the insecure-credentials rejection (UC-136b) are
node-local: SSH in, write a bad env, `systemctl restart sandboxd`, assert it
refuses, restore, restart. That costs seconds inside S4 rather than a whole
cluster each.

### 6.2a Two provisioning facts the scenarios must honour (outside voice, verified)

**Disruptive gating — this would have silently voided 17 UCs.**
`integration-tests/run.sh:335` sets `AEROL_ALLOW_DISRUPTIVE=1` only when the
scenario name is the literal string `cluster-hetero`. `harness.DisruptiveAllowed()`
turns a `0` into a `t.Skip`, **not** a failure. None of S1-S6 is named
`cluster-hetero`, so every `D`-tagged UC — **including UC-117, the plan's own
T12 milestone** — would report ⚪ skip on every new scenario and the gate would
go green having tested none of them. Fix in T10: replace the name match with a
`disruptive: true` field in `.caps.yml`, and make T12's exit criterion assert
**PASS**, not merely not-FAIL.

**Isolate is not provisioned anywhere in S1-S6.** UC-150, UC-163 and UC-164 need
`CapIsolate`/`CapIsolateJail`, which come only from
`default_with_isolate = true` (`Terraform/variables.tf:356` → `install.sh
--with-isolate`). §6.1 lists the jail as an axis and S4's row says "jail on",
but no scenario sets the flag and §6.3 has no isolate capability. Enterprise +
isolate is also a four-way hard boot gate (`config.go:2427-2440`: jail true,
seccomp `enforce`, `pids_max>0`), and the known workerd-chroot gotcha means
jail-on has **never provisioned green on a cluster**. Decide in T10: either give
S4 `default_with_isolate = true` plus both capabilities and budget the
jail-realization risk, or drop UC-150/163/164 from this program and say so.
Silently shipping three UCs that can never run is the worst of the three.

### 6.2b The disruptive gate opens — and the existing D-tagged UCs still cannot use it

Verified on the first live `cluster-3-mixed-secrets` run (2026-09-26).

`run.sh` logged `disruptive fault-injection tests enabled for
cluster-3-mixed-secrets (caps: disruptive: true)` — on a scenario **not** named
`cluster-hetero`, which the old name match would have silently left off.

`DisruptiveAllowed()` then returned true, and the proof is in *where* the
skips were recorded:

| UC | recorded at | meaning |
|---|---|---|
| UC-58 | `z_disruptive_cluster_test.go:32` | the line AFTER the gate — an unconditional `t.Skip("driven by infra fault injection; Phase 2 follow-up")` |
| UC-58c | `z_disruptive_cluster_test.go:141` | also after the gate — "requires cluster-hetero worker-x/y/z topology" |

The gate's own skip is at line 30. Nothing landed there, so the gate opened.

**But no EXISTING D-tagged use case can run on S2**, for two reasons that have
nothing to do with the gate: UC-58 and UC-58b are unimplemented stubs, and
UC-58c needs the hetero worker topology. So T10 proves the mechanism; it
cannot yet prove a D-tagged case *passing* on S2, because there is not one to
run.

**This lands on T12.** Its exit criterion — "UC-117 green on S2" — must
therefore assert PASS (not merely not-FAIL, which the plan already says) AND
be written so that UC-117 is neither a stub nor hetero-only. The two skips
above are exactly the failure modes to avoid when writing group B.

### 6.3 New capabilities

`integration-tests/suite/harness/usecases.go`:

```go
CapSecrets      Capability = "secrets"       // secret/audit UCs are meaningful here
CapSecretsKMS   Capability = "secrets-kms"   // SB_SECRET_PROVIDER=awskms + real key
CapEnterprise   Capability = "enterprise"    // SB_ENTERPRISE_MODE=true
CapClusterMTLS  Capability = "cluster-mtls"  // real signed per-node certs, no escape hatch
CapAuditExport  Capability = "audit-export"  // an off-node exporter + a readable sink
CapAuditWitness Capability = "audit-witness" // external witness wired to a receiver
```

Same advertisement-only shape as `CapGvisor`/`CapIsolate`: provisioning turns
the feature on, the capability tells the matrix the UC is applicable. A missing
capability ⇒ ⚪ skip, never a red.

### 6.4 The audit receiver

Webhook export, the witness endpoint and the ingest endpoint all need something
listening. One small binary, built by the same pipeline (§4.1
`--with-receiver`), shipped over the same presigned URL, run as a systemd unit
on the **ingress** node (hetero) or the seed (mixed):

`integration-tests/cmd/audit-receiver/main.go` — ~120 lines:

- `POST /audit` — verifies `Authorization: Bearer` and the
  `SB_AUDIT_EXPORT_WEBHOOK_HMAC_KEY` signature, appends to
  `/var/log/aerol-audit-webhook.jsonl`;
- `POST /witness` — stores chain heads, returns a receipt;
- `GET /_probe/{n}` — returns the last *n* records (so the suite reads results
  over HTTP instead of SSH);
- `--fail-next <n>` / `POST /_chaos/fail?n=` — returns 503 for the next *n*
  requests, to prove the exporter's backoff and at-least-once delivery
  (`pkg/auditexport/backoff.go`) rather than just the happy path.

It is a test fixture and lives under `integration-tests/`, never in `pkg/`.

### 6.4a Enterprise cannot boot the shipped binary — four stacked constraints

Discovered while verifying T9 (2026-09-26). The witness is **not an HTTP
endpoint** in the shipped build: `SB_SECRET_AUDIT_EXTERNAL_WITNESS` requires a
non-noop `controlplane.Witness`, `cmd/sandboxd` passes `nil` to `daemon.Run`,
so the provider is `controlplane.Noop()` and `daemon.go:293` refuses to start.
Enterprise mode *forces* that flag (`config.go:2394`). So **S4 and S6 could not
boot at all**, taking §7 group I, F10 and F14 with them.

Resolved (user decision) with a **test-only daemon**: `cmd/sandboxd` gained a
nil `providerFactory` var, and `provider_itest.go` — compiled only with
`-tags itestwitness`, which nothing in the Makefile or release workflow passes
— supplies an HTTP Witness pointed at the receiver. It lives in `package main`
rather than a second `cmd/` so the wasm-worker, isolate-jail-shim and
resident-host re-exec paths are shared, not duplicated. `build.sh
--with-itest-witness` emits it as a **separate** `sandboxd-witness_linux_<arch>`
artifact, so the default path still provisions the binary a release ships.

Verified live, in order, on one box:

| | |
|---|---|
| shipped binary + `SB_SECRET_AUDIT_EXTERNAL_WITNESS=true` | refuses: *"requires a non-noop controlplane.Witness"* |
| tagged binary, same config | boots; head `abe49336…` appears at `/witness/<node>` |

**Four constraints S4/S6 must satisfy, all measured:**

1. **Non-noop witness** → the `-tags itestwitness` artifact.
2. **`file`/`stdout` audit backends are rejected** under enterprise ("keeps
   audit evidence on this node") → use `webhook`, `s3` or `bus`.
3. **The webhook URL must be HTTPS** under enterprise — *"audit export webhook
   URL must use https when SB_ENTERPRISE_MODE=true"*. **The receiver is
   plain HTTP today, so it needs TLS before any enterprise scenario runs.**
   This is the one piece of §6.4 still outstanding.
4. **The witness must be on from FIRST BOOT** — but the reason is a PRODUCT
   BUG, not correct behaviour, and the first write-up of this section got it
   wrong. Retrofitting the witness fails with
   `witness mismatch: local_head="…" witnessed_head=""`, which reads like "the
   witness is missing history". It is not: the witness holds that exact head.
   `ValidateSecretAuditWitness` can look it up under the node id
   `"standalone"` (the Noop cluster's id, `internal/cluster/noop.go:43`) while
   the shipping path publishes under the real cluster node id, because the
   boot check can run before `AttachCluster`. Reproduced live; **intermittent**
   (failed twice, then three clean restarts), which makes it worse — a
   fail-closed boot that looks like flake. A fresh node never hits it because
   the check short-circuits on an empty chain. Tracked in `TODOS.md`; it needs
   a product fix, not a scenario workaround.

Verified 2026-09-26 that all four together do let an enterprise node boot:
`SB_ENTERPRISE_MODE=true` + awskms + the witness build + the TLS receiver gave
`secret provider boot canary ok provider=awskms`, `audit export connector
configured backend=webhook`, a witnessed head, and `active / restarts=0`.

---

## 7. Phase 4 — use cases

New UCs start at **UC-110** (UC-109 is the current max). New catalogue category
`catSEC()` with `SEC-nn` rows; remember `catalogue_test.go`'s hard-coded row
count (`want = 299`) must be bumped in the same commit.

Legend — **Caps**: `S`=CapSecrets, `C`=CapCluster, `K`=CapSecretsKMS,
`E`=CapEnterprise, `M`=CapClusterMTLS, `X`=CapAuditExport, `W`=CapAuditWitness,
`D`=disruptive (`AEROL_ALLOW_DISRUPTIVE=1`).

> **PREREQUISITE (outside voice, verified) — the suite cannot read the recipient
> set today.** Every `/v1/cluster/internal/*` route is registered as
> `internalOp = op(withInternalMTLS(...))` (`pkg/api/v1/routes.go:161-163`), and
> `cluster.AuthenticatedPeerNodeID` (`internal/cluster/tls.go:41-43`) rejects any
> request without `r.TLS.VerifiedChains` and a `node:<id>` SAN. The suite reaches
> the public API over HTTPS with a PAT and holds **no peer client certificate**,
> so it cannot call them at all — and `PublicInternalSecretPath` exposes only
> POST/HEAD/DELETE (`routes.go:195-197`), with **no list verb**. That makes
> **UC-112, UC-113, UC-114 and the `SecretHolders()` helper unimplementable as
> written**, and UC-111/116/121/122/125 all depend on that helper. It also makes
> UC-154's positive half ("`/v1/cluster/internal/*` … accept the fleet PAT")
> false — PAT suffices only for `op()`-only routes such as `/v1/audit/verify`.
>
> **T11 must first add an operator-authenticated read** — e.g.
> `GET /v1/cluster/sandboxes/{id}/secret-holders`, `op()`-gated, returning the
> recipient set and per-holder generation — before group A can be written.
> Re-scope UC-154 to the `op()`-only routes and add a case asserting that an
> `internalOp` route refuses a PAT-only caller (which is the correct behaviour).

> **T12 IMPLEMENTATION FINDINGS (outside voice, verified against the tree
> 2026-09-26).** Three things in §7 did not survive contact with the product.
>
> 1. **There is no `secret.seal` audit event.** The stored kinds are
>    `secret_open`, `egress`, `gap`, `retention_checkpoint` and
>    `retention_redacted` (`internal/service/secret_audit.go:51-58`), and the
>    only emitter is `beginSecretAuditOwned`, called from the env, mounts,
>    registry and cluster-placement **decrypt** paths — the product audits
>    OPEN, never seal. UC-110 as written would have asserted on an event that
>    is never emitted, i.e. it would have failed for a reason unrelated to
>    sealing, or (with a `>= 0` style check) passed vacuously. **UC-110 now
>    asserts the observable equivalent**: the material is unreadable by
>    default, and reading it back emits exactly one `secret_open` with
>    `ref=env:<id>` naming the actor and carrying no plaintext.
> 2. **UC-113 cannot replay the peer push.** The fan-out POST needs the sealed
>    body, which only the owner holds and which no read API exposes — by
>    design, and #479 deliberately did not change that. UC-113 is therefore
>    scoped to the invariant the replay exists to preserve, observed through
>    the peer HEAD and the operator view: repeated observation must not move
>    the generation, rewrite the row, or grow the recipient set. That catches
>    the regressions that bite (a read path that bumps a generation; a fan-out
>    that re-runs and double-books) but NOT the PUT handler's own conflict
>    behaviour, which stays covered offline. The scope limit is stated in the
>    test's own comment, not just here.
> 3. **UC-121 is disruptive.** "Add a node" means Terraform, which the suite
>    cannot do mid-run. The same membership transition the reseal path keys off
>    is a SWIM leave + rejoin, so the case bounces a non-owner node's daemon —
>    which makes it disruptive, a `D` the plan's caps column did not carry. It
>    honours `DisruptiveAllowed()` so it skips rather than wrecking a
>    non-disruptive run.
>
> Two constants in the first draft of the group D helpers were also wrong and
> would have made **UC-129 and UC-130 skip silently** (a green matrix with two
> unrun cases): the store is `state.db`, not `sandboxd.db` (install.sh writes
> `SB_DB_PATH=/var/lib/sandboxd/state.db`), and the sealed column is
> `sealed_blob`, not `sealed_env` (`store.go:149`). Both are now read from the
> node's own config rather than hardcoded.
>
> Two guards were added so the next group cannot repeat the shape of these
> mistakes: `harness.KnownCapabilities` is now the single list the
> well-formedness test checks against (its hand-written copy had already gone
> stale — every UC requiring one of the six T7-T10 secrets capabilities failed
> as a "typo"), and `integration-tests/safety/registry_claims_test.go` fails
> `make test` if any `Implemented` use case has no test claiming its id, which
> otherwise surfaces only as a MISSING row at the end of a paid live run.

### A. Sealing and fan-out (F1, F2)

| UC | Assertion | Caps |
|---|---|---|
| UC-110 | Create with sealed material → sandbox runs; the default read carries nothing; reading it back emits exactly one `secret_open` (`ref=env:<id>`) naming the actor, with no plaintext. **Not `secret.seal` — see the box above.** | S |
| UC-111 | `failover.policy=recreate` create → `failover_ready=true` within the min-ACK window; holder count ≥ owner+1 | S,C |
| UC-112 | Sealed row is present on **each** recipient and absent on non-recipients (peer HEAD over mTLS, run on the node with its own cert — the operator view reports intent, only the peer says the bytes arrived) | S,C,M |
| UC-113 | Peer-visible sealed state is stable under repeated observation: one row, one generation, one recipient set. **Scope-limited — see the box above.** | S,C,M |
| UC-114 | A caller on the internal port with no peer certificate (or an operator PAT instead of one) is refused — network position is not entitlement | S,C,M |
| UC-115 | Zero-ACK HA create is **retracted**: block the fan-out port on all peers, create with `recreate` → create fails loudly and leaves no orphan sandbox/row | S,C,D |
| UC-116 | `SB_SECRET_RECIPIENT_BACKUP_COUNT=1` vs `3` → recipient-set size tracks the knob, capped at cluster size. **NOT on enterprise** — `config.go:2452` refuses `<2` under `SB_ENTERPRISE_MODE`. | S,C,**!E** |

### B. Cross-node failover open — the critical path (F3)

| UC | Assertion | Caps |
|---|---|---|
| **UC-117** | **CRITICAL.** Kill the owner of an HA sandbox carrying real credentials → it recreates on a recipient peer **and the credentials still work** (mounted secret readable inside the new sandbox, not just `status=running`). This is the test the §0 probe stood in for. | S,C,D |
| UC-118 | The recreated sandbox's **env** is intact (F5 × F3). **Parametrized (D5 review, D3): runtime × restore path**, not a single containerd case — see §7.3. | S,C,D |
| UC-119 | A node **not** in the recipient set that somehow acquires ownership fails with a *distinct, legible* error — not a silent empty-env boot | S,C,D |
| UC-120 | Owner killed **mid-fan-out** (extends UC-58c): either recreates, or fails loudly with `failover_ready=false`; never a half-sealed sandbox | S,C,D |

### C. Reseal on membership change (F4)

| UC | Assertion | Caps |
|---|---|---|
| UC-121 | A membership change (SWIM leave + rejoin) reseals existing HA sandboxes; the generation advances and then STOPS — a generation that keeps climbing is a reseal loop, one KMS call per iteration | S,C,**D** |
| UC-122 | **Drain** a recipient → reseal to a replacement, replacement ACKs, promoted generation visible, old recipient's row is tombstoned | S,C |
| UC-123 | The **retired** recipient can no longer open (fail closed), and the tomb is swept after `SB_SECRET_TOMB_RETENTION_DAYS` (use a 0-day setting to force it). **NOT on enterprise scenarios** — `config.go:2417` refuses zero retention under `SB_ENTERPRISE_MODE`, so this UC would take an S4/S5/S6 node down rather than assert anything. | S,C,**!E** |
| UC-124 | Reseal is **idempotent under concurrent triggers**: drain two nodes at once → one winning generation, no split recipient set | S,C,D |
| UC-125 | Restart the whole cluster → `ReFanoutClusterSecrets` restores holder counts; `failover_ready` is not stuck false. **Must run on S4 (enterprise), not just S2** — `pkg/daemon/daemon.go:663-666` makes a re-fanout error **fatal** under enterprise while S2 only logs a warning, and `seal_distribute.go:701-707` errors whenever the authoritative placement read is unavailable, which is exactly the state of a cold start before quorum. On S2 this passes while the enterprise posture deadlocks every worker. Give the boot re-fanout the same bounded retry `replayClusterOwnership` already has (`daemon.go:656-658`). | S,C,D,**E** |

### D. Env sealing and the API contract (F5)

| UC | Assertion | Caps |
|---|---|---|
| UC-126 | `GET /v1/sandboxes/{id}` and `List` **omit** `env` by default | S |
| UC-127 | `?include_env=true` returns it, and emits exactly one audit event naming the actor | S |
| UC-128 | Env is **absent from the Raft placement spec** — read `/v1/cluster/placements/{id}` and assert no env keys | S,C |
| UC-129 | On disk: `sandboxes` has no plaintext env column; the sealed row round-trips; upsert preserves it (SSH + `sqlite3`) | S |
| UC-130 | A **lost** sealed env fails loud, not empty: corrupt the sealed row, restart → sandbox refuses to boot with a clear error | S,D |

### E. Audit chain, read API, fan-out (F6, F7)

| UC | Assertion | Caps |
|---|---|---|
| UC-131 | `POST /v1/audit/verify` passes on a live node after a workload | S |
| UC-132 | **Tamper detection**: corrupt one JSONL line over SSH → verify fails and names the break | S,D |
| UC-133 | `GET /v1/sandboxes/{id}/audit` **fans out**: queried on a non-owner node it returns pre-failover history the owner never had | S,C |
| UC-134 | `coverage` is **honest**: kill a node, re-query → that node is reported unreachable, not silently dropped | S,C,D |
| UC-135 | Evidence **survives owner death**: after UC-117, the audit history for the sandbox is still complete | S,C,D |
| UC-136 | Post-delete: within `SB_AUDIT_DELETED_GRACE` the history is readable and scoped to the right incarnation; a recreated id does **not** leak the previous incarnation's events | S |
| UC-137 | `SB_AUDIT_INDEX_ENABLED=false` returns the **same** events as index-on (parity), and an incomplete index returns 503 rather than a short answer | S |
| UC-138 | Pagination: `next_cursor` walks a >1-page history with no duplicates and no gaps | S |

> **T13 IMPLEMENTATION FINDINGS (outside voice, verified 2026-09-26).**
>
> - **There is no `SB_SECRET_AUDIT_DIR`.** The audit directory is the DB's
>   directory — `internal/service` derives it with
>   `secretAuditDataDir(cfg.DBPath)`. An early draft of the group E/F scripts
>   assumed the env var existed, which would have pointed four cases at a path
>   that does not exist and turned them into silent skips. They now read
>   `SB_DB_PATH` from the node's own env and take its dirname.
> - **UC-144's fault must be injected at the WITNESS, not at the node.** The
>   boot gate calls `Witness.LastWitnessedHead` (`secret_audit_witness.go:365`),
>   so the only honest injection is to record a disagreeing head at the
>   receiver and restart the node. The first draft invented an
>   `SB_..._PLANTED_HEAD` env knob; that produces a case that skips forever,
>   which §6.2a calls the worst of the available options. `/witness` takes the
>   bearer token only (no HMAC), so `harness.PlantWitnessHead` reads the token
>   from the receiver's own 0600 env file over SSH.
> - **UC-132 tampers with the MIDDLE of the chain, not the tail.** A tail edit
>   is indistinguishable from a torn write after a crash — which the product
>   deliberately tolerates and records as a gap — so tampering with the tail
>   would have asserted nothing about tamper detection.
> - **The suite reaches the audit receiver over SSH + loopback**, not across
>   the network: its `/_probe`, `/_stats` and `/_chaos` endpoints are
>   deliberately unauthenticated, and not exposing them is the point. That
>   also avoids a second TLS trust decision inside the test process.
> - **UC-139 and UC-140 must configure the backend they test.** `pkg/auditexport`
>   is single-valued (no fan-out), so a scenario running the webhook backend
>   cannot also be asserting the file or s3 one; each case switches a node with
>   `WithNodeEnv` and switches it back. UC-139 skips (not fails) when the
>   profile refuses an on-node exporter — that refusal is UC-158's assertion.

### F. Export connectors and witness (F9, F10, F11)

| UC | Assertion | Caps |
|---|---|---|
| UC-139 | **file** backend: records appear in `SB_AUDIT_EXPORT_FILE_PATH`, one JSON object per line, hash-chained | S,X |
| UC-140 | **s3** backend: objects land under the prefix; contents reconstruct the chain | S,X |
| UC-141 | **webhook** backend: receiver sees records with a valid HMAC and bearer token | S,X |
| UC-142 | **Backoff / at-least-once**: `/_chaos/fail?n=5` → exporter retries and eventually delivers every record; no silent loss; `aerolvm_audit_export_*` expvars move | S,X |
| UC-143 | **Witness**: chain heads reach the receiver on the configured interval; receipts persist; `aerolvm_secret_audit_witness_healthy=1` | S,W,E |
| UC-144 | **Witness fail-closed at boot**: plant a receipt disagreeing with the local chain → enterprise node refuses to start | S,W,E,D |
| UC-145 | **Ingest endpoint**: `SB_AUDIT_INGEST_PORT` accepts a correctly-tokened event and **rejects an untokened one**; the listener is loopback-only (`audit_ingest.go:79`); ownership lease means exactly one node ingests | S,C,E |
| UC-145b | **Retention prune — the only path that destroys evidence** (outside voice; nothing covered it). `internal/service/secret_audit.go:1426-1518` rewrites `secrets.jsonl` in place, emits `retention_redacted` stubs and a fresh checkpoint, and re-bases the index (`secret_audit_index.go:238-272`), gated by `secretAuditFullyExported` plus, under a witness, an exact-head ack (`secret_audit_query.go:116-133`). UC-123 covers only the *tomb* sweep; UC-132 corrupts a line in a live file. Set `SB_SECRET_AUDIT_RETENTION_DAYS=0`, **stop the receiver**, force a prune, assert **nothing was dropped** (export is lagging, so the gate must hold); restart the receiver, re-prune, assert `POST /v1/audit/verify` still returns `ok:true` **across the checkpoint boundary**. | S,W,E |

### G. Quota, rate limits, overflow (F8)

| UC | Assertion | Caps |
|---|---|---|
| UC-146 | Per-identity limit: exceed `SB_AUDIT_RATE_LIMIT_IDENTITY` → 429 with `Retry-After`; a second identity is unaffected | S |
| UC-147 | Per-node ceiling: concurrent peer fan-out beyond `SB_AUDIT_RATE_LIMIT_NODE` → 429 on the peer path, and the operator limit is separate | S,C |
| UC-148 | Overflow `gap`: flood past `SB_AUDIT_QUEUE_MAX` → a gap marker with a non-zero `dropped` count; the chain still verifies across the marker | S |
| UC-149 | Overflow `spill`: same flood with `spill` → records drain from disk and the chain is complete after the burst | S |
| UC-150 | Egress attribution: sandbox egress produces events carrying the **right** `sandbox_id`; the per-sandbox rate cap bounds one tenant's share of the shared evidence file | S,E |

### H. Cluster mTLS and authz (F12, F13)

| UC | Assertion | Caps |
|---|---|---|
| UC-151 | Every node presents a cert with `DNS:node:<id>`; `ca.key` exists **only** on the seed (assert absent on joiners) | M,C |
| UC-152 | A plaintext (non-TLS) call to the cluster-internal port is refused | M,C |
| UC-153 | **Forged identity**: a cert with the wrong `node:<id>` SAN (or self-signed) is rejected by the peer dialer | M,C |
| UC-154 | Operator-only routes (`/v1/cluster/internal/*`, `/v1/audit/verify`, storage-retirement) reject a tenant-scoped token with 403 and accept the fleet PAT | S |
| UC-155 | Removed peer is **revoked**: drain + remove a node, then replay its client cert → refused | M,C,D |

> **T14 IMPLEMENTATION FINDINGS (outside voice, verified 2026-09-26).**
>
> - **UC-158 and UC-159 are folded into UC-156's matrix, not separate tests.**
>   The off-node-exporter refusal (`daemon.go:326`) is one more forbidden row,
>   and "the matrix must not leave the fleet degraded" is a property of EVERY
>   row — asserting it once at the end cannot attribute the damage to the row
>   that caused it, and every row after that one would then fail for a reason
>   unrelated to what it tests. `assertNodeBackInService` runs after each row
>   and checks both "the unit is active" AND "the node is back in the member
>   list", because a node that is running but out of the member list is
>   exactly the 2+1 split this project has produced before.
> - **Every gate row asserts the MESSAGE, not just the refusal.** A bad
>   binary, a full disk or a bound port also make a node fail to start, so a
>   matrix that checked only `Started == false` would go green having proven
>   nothing. The `want` fragments are lifted from `config.go`'s enterprise
>   block and `daemon.go`, not invented.
> - **Group I prefers a joiner over the seed.** Refusing the seed's boot on a
>   cluster removes the rendezvous every joiner needs, which turns one red row
>   into a split cluster.
> - **UC-153 forges a certificate with a VALID `node:<id>` SAN on an untrusted
>   issuer.** That is the forgery that distinguishes "does the server check the
>   name?" from "does the server check who SIGNED the name?" — only the second
>   is an identity check.
> - **UC-154's negative half needs a tenant-scoped token the suite cannot
>   mint.** It runs the PAT-acceptance half unconditionally and logs plainly
>   that the tenant-refusal half did not run unless `AEROL_TENANT_TOKEN` is
>   set, rather than reporting a pass for an assertion it skipped.

### I. Enterprise profile (F14)

| UC | Assertion | Caps |
|---|---|---|
| UC-156 | Boot-gate matrix — for each forbidden combination, sandboxd **refuses to start** with the documented message: short PAT; `SB_CONTAINER_PRIVILEGED=true`; `SB_RESOURCE_LIMITS_DISABLED=true`; `SB_SECRET_AUDIT_STRICT_BOOT=false`; `awskms` without strict boot; zero retention; `SB_AUDIT_EGRESS_SANDBOX_RATE=0`; isolate without jail; `seccomp≠enforce`; `pids_max<=0`; insecure gossip/credentials; `backups<2` | E,D |
| UC-157 | `ca.key` present in `SB_CLUSTER_TLS_DIR` → enterprise node refuses to boot | E,C,D |
| UC-158 | On-node-only exporter (`file`) under enterprise → refuses to boot with the off-node-exporter error | E,D |
| UC-159 | Restore the good env after each case → the node rejoins the cluster cleanly (the matrix must not leave the fleet degraded) | E,C,D |

### J. Storage retirement and fleet-scale reads (F15, F18, F19)

| UC | Assertion | Caps |
|---|---|---|
| UC-160 | Drain a worker → a storage-retirement obligation appears in `GET /v1/cluster/storage-retirements`; `POST .../storage-retired` clears it; deletion obligations are honoured before the node leaves | S,C |
| UC-161 | `GET /v1/cluster/sandbox-index` and the paged list paths stay bounded with N sandboxes (assert page size + `next_cursor`, not a full inventory) | C |
| UC-162 | Ingress topology gate. **Scope corrected (outside voice, verified):** the daemon half needs >`MaxReplicatedIngressRouteNodes` = 10 live ingress-capable members (`internal/cluster/shards.go:28`), and `cluster-hetero.tfvars` has exactly **one** `ingress` node — no proposed scenario reaches 2, let alone 11. `Terraform/validate/ingress.go` also has no caller outside its own unit test; the real gate is the `nodes.tf:211` precondition. So: assert the **`terraform plan` precondition** with an 11-ingress overlay (plan-only, never applied — free), plus a **single-node env-injection** check that an enterprise daemon refuses to boot when told it has an oversized tier. Drop the live >10-node cluster. | E |

> **T15 IMPLEMENTATION FINDINGS (outside voice, verified 2026-09-26).**
>
> - **UC-162's scope was corrected a second time.** §6.2's own correction
>   already dropped the live >10-node cluster; the replacement — "assert the
>   `terraform plan` precondition with an 11-ingress overlay (plan-only, never
>   applied — free)" — does not work either. `Terraform/` uses an S3 backend
>   and AWS data sources, so `terraform plan` cannot run without initialising
>   real state and credentials, and a failure would be indistinguishable from
>   the precondition firing. What IS free and real is the **drift**: the
>   Terraform gate hardcodes `10` while the daemon's refusal comes from
>   `cluster.MaxReplicatedIngressRouteNodes`, and `Terraform/validate/ingress.go`
>   has no caller outside its own unit test — so nothing connects the two
>   numbers. If the constant moves and the literal does not, Terraform
>   provisions a tier the daemon then refuses to serve. That assertion now
>   lives in `integration-tests/safety/ingress_gate_test.go` so it runs in
>   `make test` (the drift is introduced at commit time, not deploy time), and
>   UC-162 keeps the live half: this deployment's member count is inside the
>   cap. Mutation-checked by bumping the literal to 25.
> - **UC-163 probes all four jail properties in ONE remote script.** Four SSH
>   round trips could describe four different workerd processes if the group
>   restarts in between, and "uid from one process, seccomp from another" is
>   not evidence that any single process is jailed. It also asserts the
>   process is still SERVING: a jail that is only correct when idle is not a
>   boundary. `root == "/"` is called out explicitly — that is the
>   populated-chroot gotcha this project already hit once.
> - **UC-164 is built on UC-104's scaffolding** (`egressProbeBundle`,
>   `uploadBundle`, `newIsolateSandbox`, `execFetch`), not on an invented
>   `fetch` exec verb. The first draft used `sb.Exec("fetch ...")` and a
>   non-existent `AllowedHosts` field; the real ones are `NetworkAllowOut` and
>   `NetworkBlockAll`. Reusing the jail-off case's shape is also what makes
>   the jail-on result comparable to it.
> - **UC-160 asserts the attestation SURVIVES.** Discharging an obligation
>   must not delete the record: the attestation is the evidence that the
>   storage was destroyed, and an obligation that vanishes on discharge leaves
>   nothing to audit.

### K. Isolate jail under enterprise (F16, F17)

| UC | Assertion | Caps |
|---|---|---|
| UC-163 | Enterprise + isolate: workerd runs jailed — non-root uid, populated chroot, `Seccomp: 2`, cgroup `pids.max` = the configured cap (extends UC-109 to the enterprise posture) | E |
| UC-164 | Per-sandbox egress attribution holds under the jail: allowed host → 200, non-allowed → 403, and the audit event names the right sandbox | E |

### L. Non-regression (boot path)

| UC | Assertion | Caps |
|---|---|---|
| UC-165 | **Default create latency unmoved.** UC-94 on `cluster-3-mixed`, **`main`-built binaries vs branch-built binaries** (D5 review): **p50 within +10%, p99 within +20%**. `AEROL_BENCH_SAMPLES=25` so t3 spot noise does not eat the 10% band; both arms on identical instance types, same run, stored as `reports/cluster-3-mixed-bench-main-baseline.json`. **Do not** compare security-profile-on against security-profile-off — see the box below. | S,CapBenchmark |
| UC-166 | HA create (`failover.policy=recreate`) latency is reported **separately**, including the first-call case, so the min-ACK wait is visible rather than averaged away. **Must include a KMS row** — `SealAndDistribute` runs synchronously on the cluster create path under a 5s `commitCtx` (`pkg/api/clustercreate/clustercreate.go:336-339`), and `pkg/secrets/envelope.go:150,167` mints a fresh DEK and calls `wrap()` **once per seal with no cache anywhere in `pkg/secrets`** — one live AWS KMS round trip per HA create and per failover open. Without `K`, S3/S6 (the only profiles that pay it) are never measured. | S,C,**K**,CapBenchmark |

### M. Surfaces the first F-table missed (added by eng review 2026-09-19, D4)

| UC | Assertion | Caps |
|---|---|---|
| UC-167 | **Isolate orphan sweep.** Force a Destroy failure on an isolate sandbox, run `POST /v1/admin/reconcile`, assert no orphaned workerd process remains (SSH + `pgrep workerd`). **The product fix landed 2026-09-19** (D6): `internal/service/service.go` now aggregates `isolate.ListManaged` and calls `removeOrphans` for it, with offline coverage in `reconcile_isolate_orphan_test.go`. This UC is the live confirmation, no longer an expected failure. **Known limit:** isolate's `ListManaged` reads the driver's in-memory map, so the sweep only reclaims groups leaked within one daemon lifetime — the crash/restart case needs a host-backed enumeration seam (TODOS.md). Do **not** write this UC to assert restart survival until that lands. | CapIsolate |
| UC-168 | **JS-bundle cluster fan-out.** `pkg/api/v1/js_bundle_cluster.go` implements a 3-way list protocol (`X-Cluster-JSBundle-Forwarded`, `X-Cluster-JSBundle-Aggregate`, `X-Aerol-Missing-JSBundle-Peers`). Upload bundles on two nodes, list from ingress, assert the aggregate carries both; then kill a peer and assert the response **declares** the missing peer rather than silently returning a short list. Same honesty property as UC-134. | CapIsolate,CapCluster |
| UC-169 | **Plaintext leak sweep** (was §7.2, previously unnumbered). After a full workload on a security scenario, SSH every node and `grep -r` the canary secret across `/var/log/`, `/var/lib/sandboxd/`, the audit JSONL, the Raft log dir, and `journalctl -u sandboxd`. Zero hits. Uses `AssertNoPlaintext`'s encodings (raw, base64, hex, URL-encoded). | S |

**61 use cases** — UC-110…UC-169 plus UC-145b (retention prune, added by the outside voice). UC-117, UC-118 and UC-165 are the three that
would individually justify the exercise.

### 7.3 UC-118 parametrization (D3)

The bug class is *"a restore path forgot to call `hydrateSandboxEnvForRestore`"*,
not *"env is broken on runtime X"*. A store row on this branch never carries
env — the column is dropped and sealed `sandbox_env` is the only source — so
`store.Get` returns `Env == nil` and every consumer must hydrate explicitly.
There are three call sites (`service.go:1297`, `wasm_recreate.go:31`, and
`StartSandbox` loading inline). Drivers read `sandbox.Env` straight off the
struct (`internal/runtime/wasm/passivate.go` builds the restored instance's base
env from it; `exec.go` merges it into every exec), so a missed hydrate produces
an **empty environment with no error**.

PR #432 was exactly this, and it was WASM-only and retry-only: the first
recreate attempt built the row from the decrypted spec and worked; only a retry
after a failed restore lost env. A containerd-only UC-118 passes while that path
is broken.

```
                    │ failover │ recreate │ stop →  │ snapshot │
                    │ recreate │  RETRY   │  start  │  resume  │
  ──────────────────┼──────────┼──────────┼─────────┼──────────┤
  containerd        │    ✔     │    ✔     │    ✔    │    ✔     │
  wasm (durable)    │    ✔     │  ✔ #432  │    ✔    │    ✔     │
  isolate           │    ✔     │    ✔     │    ✔    │    n/a   │
  firecracker       │    ✔     │    ✔     │    ✔    │    ✔     │
```

Implement with the catalogue's existing `expandRT` helper
(`harness/catalogue_rows.go`) rather than a bespoke loop. The **retry** column is
the load-bearing one and needs fault injection: fail the first restore, then
assert env on the second attempt. Runs on `cluster-hetero-secrets` (S5), the
only scenario carrying every runtime; per-runtime skips elsewhere.

> **Why `main` and not a profile flip (D5).** The draft compared the security
> profile against "the same scenario without it." That baseline does not exist
> on this branch: `internal/config/config.go:1748-1790` ships
> `SecretRecipientBackupCount=2`, `SecretAuditStrictBoot=true`,
> `AuditIndexEnabled=true`, `EgressAttributionEnabled=true`,
> `SecretProvider="local"` — every cluster scenario is **already** paying for
> sealing, the audit chain and the fan-out. A profile-flip comparison measures
> enterprise-mode over default-mode, and a synchronous audit append in
> `StartSandbox` would slow **both arms equally**, holding the ratio and leaving
> the test green through the exact regression it exists to catch. The repo has
> precedent: the Firecracker work found a 2s-per-create regression that had been
> shipping unnoticed. `main` vs branch is the only comparison that answers
> "did this PR cost create latency."
>
> **The baseline scenario also has to be created (outside voice, verified).**
> `cluster-3-mixed.caps.yml` does **not** advertise `benchmark` — the word
> appears there only in a comment — so UC-94 cannot run on it. The one
> benchmark-capable 3-node cluster is `cluster-3-mixed-docker`, which uniquely
> carries `docker-engine` to hold dockerd against the containerd default, so
> A/B-ing a containerd security scenario against it compares two engines, not two
> commits. T16 must add a `cluster-3-mixed-bench` pair: containerd engine,
> `benchmark` capability, same instance types as S2.

### 7.1 Test file layout

Go runs test files in lexical order, and the repo already encodes that:
`suite/z_disruptive_cluster_test.go:5-7` explains the `z_` prefix keeps node-kill
tests from racing earlier UCs. **Every disruptive file here takes the same
prefix** — UC-155 drains and removes a member, and UC-156..159 restart daemons
with deliberately-invalid env; unprefixed, both sort ahead of the `secrets_*`,
storage-retirement, isolate and benchmark files and would wreck them.

```
integration-tests/suite/
  secrets_seal_test.go            A  UC-110..116
  secrets_reseal_test.go          C  UC-121..124        (UC-125 is disruptive → z_)
  secrets_env_test.go             D  UC-126..129        (UC-130 is disruptive → z_)
  audit_chain_test.go             E  UC-131,133,136..138
  audit_export_test.go            F  UC-139..143,145,145b
  audit_limits_test.go            G  UC-146..150
  cluster_mtls_test.go            H  UC-151..154        (UC-155 is disruptive → z_)
  storage_retirement_test.go      J  UC-160..162
  isolate_enterprise_test.go      K  UC-163..164
  benchmark_test.go               L  UC-165..166        (extend existing)
  reconcile_orphans_test.go       M  UC-167
  js_bundle_cluster_test.go       M  UC-168
  leak_sweep_test.go              M  UC-169
  harness/secrets.go                 shared helpers

  z_secrets_failover_test.go      B  UC-117..120
  z_secrets_restart_test.go       C  UC-125
  z_secrets_env_loss_test.go      D  UC-130
  z_audit_tamper_test.go          E  UC-132,134,135,144
  z_cluster_mtls_revoke_test.go   H  UC-155
  z_enterprise_gate_test.go       I  UC-156..159
```

`AEROL_ALLOW_DISRUPTIVE` is a **runtime env var**, not a build tag — a
disruptive file is compiled and run either way, and `harness.DisruptiveAllowed()`
skips inside the test. The draft called it a build tag; that would have implied
the file is excluded from the binary, which it is not. See §6.2a for the gating
bug that makes this matter.

`harness/secrets.go` carries the helpers every file needs, so assertions stay
declarative:

- `CreateHASandbox(t, c, creds, env)` — create with `failover.policy=recreate`
  and wait for `failover_ready`
- `AwaitFailoverReady(t, c, id, timeout)`
- `SecretHolders(t, c, id) []string` — recipient set via the operator endpoint
- `AuditEvents(t, c, id, opts) SecretAuditPage`
- `AssertNoPlaintext(t, haystack, secrets...)` — one place that knows every
  shape a leak could take (JSON, base64, hex, URL-encoded)
- `WithNodeEnv(t, node, kv, fn)` — set env, restart, run `fn`, **always**
  restore and restart (deferred), so a failed boot-gate case cannot strand a
  node. Load-bearing for the whole of §I.

### 7.2 The leak sweep

Now **UC-169** in group M. The draft described it in prose without assigning a
number, which would have kept it out of the registry and the coverage matrix
entirely — the failure mode §7 group M exists to prevent. It is cheap to write
and it is the only check that covers leak paths nobody thought to enumerate.

---

## 8. Make targets and reports

```make
# Build
make itest-build                          # local artifacts only
make itest-artifacts-init                 # one-time bucket

# Security scenarios (local build is the default)
make integration-secrets-single           # S1  ~$0.05
make integration-secrets-mixed            # S2  ~$0.2
make integration-secrets-mixed-kms        # S3  ~$0.2
make integration-secrets-mixed-enterprise # S4  ~$0.25
make integration-secrets-hetero           # S5  ~$14/h
make integration-secrets-hetero-kms       # S6  ~$14/h

make integration-secrets-all              # S1→S4 sequentially (the gate)
make integration-secrets-flagship         # S5 + S6 (pre-merge only)

# Iterate against a kept cluster
make integration-secrets-mixed keep
make integration-secrets-only             # re-run only the SEC UCs, no re-provision
```

Reports follow the existing convention —
`integration-tests/reports/<scenario>.{md,json}` + the `index.md` matrix — with
the new `build` block from §4.4 and the `SEC-*` catalogue category. A security
run that shows ⚪ for a UC because the *scenario* lacked the capability is fine;
one that shows 🟡 PENDING means a UC was registered without a test, which is
the signal we want.

---

## 9. Cost model

| Run | Nodes | Wall clock | ~Cost |
|---|---|---|---|
| S1 | 1× t3.medium spot | 12 min | $0.05 |
| S2/S3/S4 | 3× t3.medium spot | 25 min | $0.20-0.25 |
| **Gate (S1→S4)** | | **~1.5 h** | **~$0.75** |
| S5 | 8 nodes incl. c5.metal, on-demand | 60 min | ~$14 |
| S6 | same | 60 min | ~$14 |
| **Flagship (S5+S6)** | | **~2 h** | **~$28** |

Plus: KMS $1/mo prorated, S3 audit buckets pennies (3-day lifecycle), artifacts
bucket pennies (7-day lifecycle).

**DECIDED cadence:** the **gate (S1→S4, ~$0.75, ~1.5h) runs on every push to
the branch** — cheap enough to be routine. The **flagship (S5+S6, ~$28, ~2h)
runs once before merge**, and again after any change to `internal/cluster`, the
fan-out path, or the reseal protocol. `make integration-reap` still bounds
leakage; `ttl=4` tags apply.

---

## 10. Sequencing

Phases 1 and 2 are strictly ordered — nothing else can run until a cluster
forms. Phases 3-4 parallelise by area.

**PR split (D1 + D9).** T5/T6 are their own PR
(`fix/cluster-bootstrap-csr-rendezvous`), stacked on `plans/secrets-hardening`
and merged first. T1-T4 + T7-T11 are the infrastructure PR. T12-T17 stack by UC
group. T1-T4 do not depend on T5 and can be built in parallel with it — they
only need `single-node`, which still bootstraps fine.

Status column added during execution. **DONE** means the exit criterion was met
and verified, not merely that code was written.

| # | Task | Depends on | Exit criterion | Status |
|---|---|---|---|---|
| T1 | `lib/build.sh` build + checksums + buildinfo | — | `sandboxd_linux_amd64` is a valid ELF, checksums verify | **DONE** 2026-09-23 — `ELF 64-bit LSB, x86-64`, `shasum -c` all OK; `--ref main` worktree arm builds too |
| T2 | Artifacts bucket + presign + `itest-artifacts-init` | T1 | `urls` prints working presigned URLs | **DONE** 2026-09-23 — `s3://aerol-itest-artifacts-263611243038`; anonymous ranged GET 206, unsigned GET 403; install.sh's own `awk $2 == name` selection replayed against the live URLs and the downloaded bytes verify |
| T3 | TF vars `sandboxd_url`/`toolboxd_url`/`checksums_url` → bootstrap | T2 | `single-node` provisions from a local build | **DONE** 2026-09-23 — live on `sandbox.hith.chat`: `/health` returned `version":"itest-7b9c7b666f89-dirty-53bab30c2d7e"`, and the node's own cloud-init log shows `sandboxd_linux_amd64: OK` / `toolboxd_linux_amd64: OK` from install.sh's checksum verification against our presigned artifacts. First time this branch has run on real infrastructure. |
| T4 | `run.sh` local-build default + `--released`/`--version`/`--no-build` | T3 | **existing `single-node` scenario** provisions + passes from a local build (the draft said "`make integration-secrets-single` green", but S1's file pair is not created until T10 — circular) | **DONE** 2026-09-23 — final state on a **freshly provisioned instance, never hot-patched**: **pass 58 · fail 0 · skip 55 · missing 0 · inconclusive 0**, suite exit 0, report carries the `build` block (`407155348862`, clean tree). Got there via run 1 = 57/1 and three real branch defects found and fixed (§3.6-§3.8); UC-15 is the 58th, which had never run before because §3.7 deleted the sandbox on stop. |
| T5 | **Bootstrap CSR rendezvous + cred bundle** (§5.1) — *own stacked PR* | — (parallel with T1-T4) | `cluster-3-mixed` forms 3 members on this branch | **DONE** 2026-09-23 — **3 members**, the first multi-node cluster this branch has formed. Rendezvous timeline: seed published all 3 artifacts (incl. cred bundle) at 05:38:24, both joiners uploaded CSRs and both certs were signed by 05:38:48, 3 members at 05:39:33. Security property verified on the live certs: each SAN is `DNS:node:<Terraform-assigned name>` resolved from `nodes/<IAM caller identity>`, never from the uploader. |
| T6 | `extra_sandboxd_env` + per-node override (§5.2) — *same PR as T5* | T5 | a scenario can set any `SB_*` without `extra_user_data` | **DONE** 2026-09-23 — global `extra_sandboxd_env` merged under each node's `sandboxd_env`, rendered into `cluster.env` **before** the final `systemctl restart sandboxd` (asserted by an offline render test, which also fails if the block moves after the restart). |
| T7 | KMS key + IAM (§5.3) | T6 | `SB_SECRET_PROVIDER=awskms` boots and seals **on `single-node` with a hand-written env overlay** (scenarios arrive in T10) | **DONE** 2026-09-23 — real CMK `cd1a8f8c` + `alias/aerolvm-itest-single-node-secrets`. **Boots:** `secret provider boot canary ok provider=awskms`, strict boot on, 0 restarts. **Seals:** env set at create is withheld from the default read (`{}`); `?include_env=true` returned it decrypted, and the audit chain recorded the opt-in with the exact `correlation_id` sent. Full suite **pass 58 · fail 0 · skip 55 · 0 inconclusive** with the provider active. |
| T8 | Audit sinks: s3 bucket + IAM, file path (§5.4) | T6 | records land in both, same `single-node` overlay | **DONE** 2026-09-23 — **exit criterion corrected**: a node exports to exactly ONE backend, so "both" is proven by flipping the backend on one box, not by running both at once. **s3:** records at `aerolvm-itest-single-node/node=<id>/2026/09/25/<batch>.jsonl` carrying the exact `correlation_id` sent. **file:** `/var/log/aerol-audit-export.jsonl` (0600 root) grew 1130→1673 bytes with the event. Clean suite re-run **pass 58 · fail 0 · 0 inconclusive** with KMS + s3 export both active. |
| T9 | `audit-receiver` binary + systemd unit + chaos endpoint (§6.4) | T1, T6 | webhook + witness receive; `/_chaos` forces retries | **DONE** 2026-09-26 — all three verified live. **webhook:** backend resolved to `webhook` from the export URL alone, 5 batches / 0 rejected (so bearer + HMAC verified). **witness:** head `abe49336…` recorded and returned by `/witness/<SB_NODE_ID>`. **chaos:** `fail_next=3` consumed as 503s, then the exporter backed off and redelivered (`batches` 3→4). Needed a `-tags itestwitness` daemon — see §6.4a. |
| T10 | Capabilities + 7 scenario file pairs (§6.2/6.3, + `cluster-3-mixed-bench`) — **incl. the `disruptive:` caps field replacing run.sh's name match, and the isolate provisioning decision** (§6.2a) | T6-T9 | scenarios load, caps gate correctly, a `D`-tagged UC actually runs on S2 | **CODE DONE** 2026-09-26. Capabilities already existed (PR #451). **`disruptive:` field DONE** and mutation-verified — this was the 17-UC silent hole. All 7 pairs written with Makefile targets + `integration-secrets-gate`. New offline validation catches unknown capability names (**already caught a real `gvisor-runtime` typo**), missing twins, duplicate/unmarked `cluster_name`, and enterprise-without-witness. **Live S2 run 2026-09-26: pass 71 · fail 0 · skip 42 · 0 inconclusive.** The gate PROVABLY opens — see §6.2b. |
| T10b | **Operator-authenticated recipient-set read** (`GET /v1/cluster/sandboxes/{id}/secret-holders`, `op()`-gated) | T6 | the suite can read holders over PAT; group A is implementable | |
| T11 | `harness/secrets.go` helpers (§7.1) | T10, T10b | `WithNodeEnv` always restores on failure; `SecretHolders()` works | |
| T12 | UC groups A-D (sealing, failover, reseal, env) | T11 | **UC-117 green on S2** | |
| T13 | UC groups E-G (audit chain, export, limits) | T11 | chain verifies; backoff proven | |
| T14 | UC groups H-I (mTLS, enterprise gates) | T11 | full boot-gate matrix, fleet healthy after | |
| T15 | UC groups J-K (retirement, jail) | T11 | | |
| T16 | UC group L + **`main` baseline arm** (§7 UC-165/166, D5) | T12, T1 (`--ref`) | both arms measured in one run; band met | |
| T16b | UC group M (§7 UC-167/168/169, D4) | T11 | UC-167 **fails**, exposing the isolate sweep gap; fix `removeOrphans` in the same PR | |
| T17 | Catalogue rows + row-count bump (`catalogue_test.go` `want = 299`) + new `catSEC()` category | T12-T16b | `make test` green offline | |
| T18 | Flagship run S5 + S6, publish reports | all | matrix in `reports/index.md` | |

T12 is the milestone that matters: **UC-117 green on S2** means the defect the
whole secrets-hardening program exists to fix is proven fixed on real
infrastructure, which nothing currently demonstrates.

---

## 11. Decisions

### Decided 2026-09-19

| # | Question | Decision |
|---|---|---|
| **D1** | Where does the §3.1 bootstrap fix land? | **Its own blocking PR, stacked on `plans/secrets-hardening` and merged before it.** `fix/cluster-bootstrap-csr-rendezvous`, scoped to §5.1 + §5.2. Keeps the installer fix reviewable on its own and unblocks anyone running a cluster against this branch, without holding the 826-file PR open behind test work. |
| **D4** | Presigned URLs in EC2 user-data — acceptable? | **Yes.** Throwaway `ttl=4` scenario clusters already carry the PAT and Cloudflare token in user-data. 12h expiry, GET-only, test-binaries-only bucket. |
| **cadence** | How often does the matrix run? | **Gate (S1→S4) every push** (~$0.75, ~1.5h). **Flagship (S5+S6) once pre-merge** and after any `internal/cluster` / fan-out / reseal change (~$28, ~2h). |
| **D8** | Latency band for UC-165 | **p50 +10%, p99 +20%** vs the same scenario without the security profile, on `cluster-3-mixed`, with `AEROL_BENCH_SAMPLES=25` and a stored baseline artifact. |

### Standing recommendations (assumed unless changed)

| # | Question | Assumption |
|---|---|---|
| D2 | Local build default, or opt-in? | **Default**, with `--released` / `--version <tag>` / `--no-build` to opt out. Matches the ask and existing fast-loop practice. |
| D3 | Real AWS KMS, or the offline fake? | **Real.** `pkg/secrets/fake_kms.go` already covers the contract offline; a fake here proves nothing new. ~$1/month. |
| D5 | Build Caddy locally, or reuse the release binary? | **Reuse the release** by default (this PR does not touch `pkg/caddy`), passed as an *explicit* `--caddy-binary-url` to dodge the §3.3 checksum trap. `--with-caddy` builds it when needed. |
| D6 | Six scenarios, or flip profiles on a kept cluster? | **Six.** Enterprise mode changes boot behaviour, so it must be proven from a cold boot. Flip-and-rerun stays available for iteration only. |
| D7 | arm64 artifacts in scope now? | **Not now.** `cluster-arm64` / `single-node-fc-arm64` stay on released binaries until the x86 matrix is green; `--arch` exists from day one so adding it later is one flag. |
| D9 | One PR or stacked by group? | **Stacked** — T5/T6 (D1), then T1-T4 + T7-T11 (infrastructure), then A-D / E-G / H-L. |

---

## 12. Out of scope

### Deferred with known risk (eng review 2026-09-19)

**Upgrade, rolling upgrade, and backup/restore — DECIDED out of scope (D2).**
Every scenario in this plan provisions from scratch, so none of the following is
exercised. Recorded here so the risk is a decision, not an oversight:

1. **The on-boot migration is irreversible and untested live.**
   `internal/store/store.go:1051-1064` seals existing plaintext env, then
   `ALTER TABLE sandboxes DROP COLUMN env_json` (and `toolbox_token`).
   `validateCurrentSecretSchema` (`store.go:1317`) then refuses any DB where
   those columns still exist. After a successful migration there is **no
   downgrade**; on failure the daemon does not start (`store.go:963-970`).
   `env_binding_migration_test.go` covers a synthetic old schema, not a DB a
   shipped binary wrote.
2. **Rolling upgrade can diverge the FSM.** The branch adds `opBeginDelete`,
   `opPruneAuditACL` and `opUpdateSecretRecipients`. An old node applying one
   returns `unknown op` (`fsm.go:1572`) and **silently skips it**, so a
   mixed-version cluster disagrees about the recipient set.
   → Until tested, the release must document **full-cluster stop before
   upgrade**, not a rolling restart.
3. **`scripts/sandboxd-backup.sh:67-69` omits the credential key.** It captures
   `state.db`, `raft/` and `/etc/sandboxd`, but not
   `/var/lib/sandboxd/credential_encryption.key` — the default
   `SB_CREDENTIAL_ENCRYPTION_KEY_PATH`. Restoring that backup onto a fresh box
   generates a *new* key and every sealed env and toolbox token is permanently
   unreadable. Cluster installs happen to survive because `cluster-join.sh`
   writes `SB_CREDENTIAL_ENCRYPTION_KEY` into `/etc/sandboxd/cluster.env`, which
   *is* captured; **single-node installs do not.**
   → **This is a product bug, not a test gap. File it separately** — deferring
   the test does not defer the defect.

**Facade env contract under D9 — PARTLY FIXED 2026-09-19 (D6).**
The facade now supports `?include_env=true`, mirroring /v1
(`hydrateEnvIfRequested` in `pkg/api/daytona/handlers.go`, covered by
`include_env_test.go`), so a Daytona caller can read env back and the read is
audited. What is **not** fixed: the default response still serializes
`"env": {}`, which claims the sandbox has no environment rather than that none
was returned. `json:"env,omitempty"` was tried and **reverted** — the Daytona
SDK's deserializer rejects a payload with no `env` key and
`TestDaytonaSDKContracts` fails across the whole read surface. A Daytona-
compatible signal is needed; tracked in TODOS.md.

### Deferred, low risk

| Deferred | Why |
|---|---|
| `bus` (Kafka) export backend live test | Needs a broker; `file`/`s3`/`webhook` cover the connector contract and the off-node-exporter gate. Revisit on a customer ask. |
| Vault provider | `pkg/secrets/factory.go` returns "not implemented"; nothing to test. |
| Multi-region / cross-account KMS | Single-region key proves the provider seam. |
| 2000-node / 100k-sandbox fleet scale | UC-161 asserts the read paths are *bounded*; proving the absolute numbers is the investor-benchmark program's job (`plans/investor-benchmark-observability.md`). |
| Credential brokering into sandboxes | Out of scope in `secrets-hardening.md` §8 (E5). |
| arm64 security matrix | D7. |

---

## GSTACK REVIEW REPORT

`/plan-eng-review` — 2026-09-19 — branch `plans/secrets-hardening`
Scope (D1): the plan doc **plus** a code-grounded gap analysis, re-deriving the
shipped surface from `git diff main...HEAD` and diffing it against the UC table.

### Runs

| Run | Status | Findings |
|---|---|---|
| Step 0 — scope challenge | complete | Complexity check triggered (build.sh + receiver + 7 scenarios + 15 test files + 4 TF vars + KMS + 2 buckets). No cut recommended — the surface is 826 files. TODOS.md: no blockers. |
| §1 Architecture | complete | 1 finding (upgrade/rolling/backup lane) — **user decided out of scope (D2)**, risks recorded in §12 |
| §2 Code quality | complete | 3 doc defects, auto-fixed: UC count 56→60, §7.2 leak sweep had no UC number (now UC-169), F-table built from the PR description rather than the diff |
| §3 Tests | complete | 2 findings → D3 (env parity matrix), D4 (missed surfaces) |
| §4 Performance | complete | 1 finding → D5 (baseline does not exist on this branch) |
| Outside voice | **Codex unavailable** (`gpt-6-astra` needs a newer CLI; retry on `gpt-5.5` hit the account usage limit after ~197k tokens). Fell back to the Claude subagent path. | 15 findings, 7 spot-verified against source |

### Findings absorbed

Confirmed by reading source, highest severity first.

| # | Sev | Conf | Anchor | Problem | Disposition |
|---|---|---|---|---|---|
| 1 | P0 | 9 | `run.sh:335` | `allow_disruptive_for` matches the literal `cluster-hetero`; `DisruptiveAllowed()` turns `0` into `t.Skip`. All 17 `D`-tagged UCs — **incl. UC-117, the T12 milestone** — would silently skip ⚪ on every new scenario. | §6.2a + T10 |
| 2 | P0 | 9 | `routes.go:161-163`, `tls.go:41-43` | Every `/v1/cluster/internal/*` route is mTLS-gated; the suite has a PAT and no client cert, and there is no list verb on `PublicInternalSecretPath`. UC-112/113/114 + `SecretHolders()` unimplementable; UC-154's positive half false. | §7 prereq box + new T10b |
| 3 | P0 | 9 | `iam.tf:83-92` | `joiner_r` has no `s3:PutObject` — the CSR upload in §5.1 cannot run, so T5 (the blocking PR) is broken as written. Plan cited `seed_rw`'s range by mistake. | §5.1 correction |
| 4 | P0 | 8 | `cluster-sign-node.sh:88-91` | Signer stamps `DNS:node:${NODE_ID}` from the flag and never inspects the CSR subject. With §5.1 deriving node id from a joiner-controlled S3 filename, any joiner could mint a cert for another node. Defeats F12 while UC-151/153 pass. | §5.1 — bind id to uploader prefix + new UC |
| 5 | P1 | 9 | `kms_provider.go:92-95` | `KMSProvider.Open` does `_ = nodeID`; recipient-set authorization does not exist under `awskms`. S3's "D7 contract parity" claim is false; `ErrRecipientDenied` can never fire. | §6.2 box — S3 gets IAM-boundary UCs instead |
| 6 | P1 | 8 | `daemon.go:663-666`, `seal_distribute.go:701-707` | Boot re-fanout error is **fatal** under enterprise but a warning otherwise; a cold start before quorum can deadlock every enterprise worker. UC-125 tagged `S,C,D` runs only where it's a warning. | UC-125 retagged `+E` |
| 7 | P1 | 8 | `clustercreate.go:336-339`, `envelope.go:150,167` | One live KMS round trip per HA create/open, no cache, synchronous under a 5s commit ctx. UC-165/166 carry no `K`, so S3/S6 are never latency-measured. | UC-166 `+K` |
| 8 | P1 | 8 | `awskms.go:98-115` | `IncorrectKeyException` unclassified → `ErrProviderUnavailable`; a permanent key error is retried then escalated forever. No UC rotates the key. | §6.2 box — key-rotation UC + fix classification |
| 9 | P1 | 9 | `z_disruptive_cluster_test.go:5-7` | §7.1 ignored the repo's `z_` lexical-ordering convention; mTLS-revoke and enterprise-gate files would sort ahead of and wreck the rest. Also called an env var a build tag. | §7.1 rewritten |
| 10 | P1 | 8 | `config.go:2417`, `config.go:2452` | UC-123 (zero retention) and UC-116 (`backups=1`) mutate env the enterprise validator refuses; tagged `S,C`, they'd down an S4/S5/S6 node. Caps system has no negation. | Both tagged `!E`; negation is a T10 item |
| 11 | P1 | 8 | `variables.tf:356`, `config.go:2427-2440` | No S1-S6 sets `default_with_isolate`; §6.3 has no isolate capability. UC-150/163/164 can never run. Jail-on has never provisioned green on a cluster. | §6.2a — explicit decision required in T10 |
| 12 | P1 | 8 | `cluster-3-mixed.caps.yml` | Does not advertise `benchmark`; the only benchmark-capable 3-node cluster is dockerd-pinned. The UC-165 baseline scenario does not exist. | §7-L — add `cluster-3-mixed-bench` in T16 |
| 13 | P1 | 7 | `secret_audit.go:1426-1518` | The retention rewrite — the one path that destroys evidence — has no UC. Prune-with-export-lagging, prune-with-witness-disagreeing and verify-after-prune all uncovered. | New UC-145b |
| 14 | P2 | 8 | plan §10 | T4/T7/T8 exit criteria reference scenarios created in T10 — circular. | Re-anchored to `single-node` + overlay |
| 15 | P2 | 8 | `shards.go:28`, `cluster-hetero.tfvars:43` | UC-162's daemon half needs >10 ingress-capable nodes; hetero has 1. `Terraform/validate/ingress.go` has no caller outside its unit test. | UC-162 rescoped to plan-precondition + env injection |

Primary-review findings (not re-listed above): §3.1 cluster bootstrap broken on
this branch; the irreversible `DROP COLUMN env_json` migration with no live
coverage; `isolate` missing from `removeOrphans`; the Daytona facade env break;
the UC-count and unnumbered-leak-sweep defects.

### Decisions taken this session

| ID | Decision |
|---|---|
| D1 | Review scope: plan + code-grounded gap analysis |
| D2 | Upgrade / rolling-upgrade / backup-restore — **out of scope**; risks recorded in §12, backup-key omission to be filed as a separate product bug |
| D3 | UC-118 parametrized over runtime × restore path (§7.3) |
| D4 | Add UCs for the isolate orphan sweep (UC-167) and js-bundle fan-out (UC-168); facade env contract deferred to §12 |
| D5 | UC-165 baselines against `main`-built binaries, not a profile flip |

VERDICT: **REQUEST CHANGES — plan updated in place, not yet implementable.**
Four P0s stand between this plan and a working first run, and three of them
(#1, #2, #3) would each have produced a green gate over untested code. All are
now written into the plan with anchors and owners. The plan is materially
stronger than the draft: 60 UCs, an added prerequisite (T10b), a corrected
T5 design, and a latency baseline that measures the right thing. Re-review is
not required before implementation, but T5 must not be written from the
pre-correction §5.1.

CODEX: unavailable this run (CLI/model mismatch, then account usage limit) —
outside voice served by the Claude subagent fallback. Cross-model confirmation
of these 15 findings is still outstanding; re-run `/codex review` against this
plan after 8:56 PM if you want it.

### D6 follow-up — all three unresolved decisions closed 2026-09-19

The user elected to fix all four items. Landed in the working tree, `go test
./...` green:

| Item | Resolution | Files |
|---|---|---|
| Isolate orphan sweep (part 1) | `isolate.ListManaged` joined the aggregation and `removeOrphans` gained its isolate arm, with a comment recording the in-memory-`byID` limit | `internal/service/service.go`, `internal/service/reconcile_isolate_orphan_test.go` (3 tests) |
| Isolate orphan sweep (part 2) | Deferred by design — needs a `ListGroups` seam on `HostSupervisor` and a cgroup/chroot walk | TODOS.md |
| Caps negation | `UseCase.Excludes` + `Scenario.BlockingCaps`, checked after `Requires` so an exclusion always wins; `Require` now reports the two skip reasons distinctly. Six new capabilities added (`CapSecrets`, `CapSecretsKMS`, `CapEnterprise`, `CapClusterMTLS`, `CapAuditExport`, `CapAuditWitness`) | `harness/usecases.go`, `skip.go`, `client.go`, `skip_test.go` (2 tests, 10 cases) |
| Daytona env | `?include_env=true` opt-in added, mirroring /v1's spellings. **`omitempty` was tried and reverted** — the real Daytona SDK rejects a payload with no `env` key and `TestDaytonaSDKContracts` failed across the read surface. The empty-vs-withheld ambiguity remains | `pkg/api/daytona/handlers.go`, `dto.go`, `include_env_test.go` (2 tests, 15 cases) |
| S4 isolate | Approved. `default_with_isolate = true` + `CapIsolate`/`CapIsolateJail` on `cluster-3-mixed-secrets-enterprise`, executed in T10. De-risked: `PrepareJailBase` (`pkg/isolate/chroot.go:42`, wired at `pkg/daemon/isolate_wiring.go:38`) closes the chroot-populate blocker that previously made jail-on unusable | plan §6.2a → T10 |

NO UNRESOLVED DECISIONS
