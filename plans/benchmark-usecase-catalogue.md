# Benchmark Use-Case Catalogue — the 200+ questions

Companion to [`investor-benchmark-observability.md`](./investor-benchmark-observability.md).
This is the **enumerated** master list the deck/blog tables and the
`reports/<scenario>-catalogue.json` record are generated from — not a
"108 × runtimes" hand-wave. Each row is one *question we ask the platform*, with the
runtime(s) it runs on, the scenario(s) it belongs to, and the signal that makes it
green.

**Legend**
- **Runtime**: `cd`=containerd/docker · `gv`=gVisor · `wa`=WASM · `is`=isolate ·
  `fc`=Firecracker · `all`=every runtime available in that scenario.
- **Scn**: `M`=`cluster-mixed-benchmark-with-obs` (cd/gv/wa/is) ·
  `H`=`cluster-hetero-benchmark-with-obs` (adds fc, arm64, HA) · `M+H`=both.
- Rows whose runtime isn't available in a scenario simply skip there (registry-driven,
  reported as ⚪), so "M+H" on a fc row means "H only in practice."
- IDs are category-prefixed so the catalogue stays countable and dedup-safe. Many map
  1:1 onto an existing `harness.Registry` UC (noted `↔UC-NN`); the rest are new
  simulation/coverage rows added by `suite/sims/` + the extended registry.

**Category index (running totals):**

| # | Category | Prefix | Rows |
|---|---|---|---|
| 1 | Provisioning & control plane | PROV | 14 |
| 2 | Sandbox lifecycle | LIFE | 25 |
| 3 | Runtime specialization | RT | 11 |
| 4 | Exec & code execution | EXEC | 15 |
| 5 | Files & filesystem | FILE | 13 |
| 6 | Sessions & PTY | SESS | 10 |
| 7 | Networking & ingress | NET | 18 |
| 8 | Egress & network policy | EGR | 10 |
| 9 | Isolation & untrusted code | ISO | 11 |
| 10 | Snapshots & fast boot | SNAP | 10 |
| 11 | Real long-running services | SVC | 16 |
| 12 | Heavy compute & data | COMP | 10 |
| 13 | AI agents | AI | 12 |
| 14 | Mounts & external storage | MNT | 14 |
| 15 | Cluster correctness & HA | HA | 16 |
| 16 | Capacity & density | DEN | 8 |
| 17 | Latency benchmarks | LAT | 12 |
| 18 | Serverless & lifecycle automation | SLESS | 10 |
| 19 | SSH gateway | SSH | 6 |
| 20 | Templates & images | TMPL | 13 |
| 21 | Facade compatibility (Daytona/E2B) | FAC | 15 |
| 22 | Multi-region & multi-arch | REG | 5 |
| 23 | GPU | GPU | 3 |
| 24 | Observability | OBS | 10 |
| 25 | Idempotency & resilience | IDEM | 10 |
| | **TOTAL** | | **287** |

---

## 1. Provisioning & control plane — PROV (14)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| PROV-01 | Does a 3-node mixed cluster form? ↔UC-03 | — | M | members=3 |
| PROV-02 | Does the 10-node hetero cluster form? | — | H | members=10 |
| PROV-03 | Is a Raft leader elected? ↔UC-05 | — | M+H | leader present |
| PROV-04 | Do heterogeneous node roles match the tfvars? ↔UC-04 | — | H | roles match |
| PROV-05 | Does wildcard DNS resolve to the ingress? ↔UC-07 | — | M+H | A-record → ingress |
| PROV-06 | Is the control-plane API reachable over HTTPS? ↔UC-08 | — | M+H | 200 over TLS |
| PROV-07 | Is the TLS chain valid (apex + wildcard)? ↔UC-09 | — | M+H | chain verifies |
| PROV-08 | Is auth enforced (no PAT → 401)? ↔UC-10 | — | M+H | 401 |
| PROV-09 | Does /v1/capacity report host capacity? ↔UC-61 | — | M+H | non-empty |
| PROV-10 | Does admin/reconcile run clean? ↔UC-63 | — | M+H | no error |
| PROV-11 | Are specialized runtimes advertised in gossip capacity? ↔UC-87 | all | H | each advertised |
| PROV-12 | Does a second ingress node serve routes (HA ingress)? | — | H | both ingress answer |
| PROV-13 | Is the persistent shared cert store reused (no re-issue)? | — | M+H | cert from store |
| PROV-14 | Does the cluster survive a seed restart + rejoin? | — | H | members restored |

## 2. Sandbox lifecycle — LIFE (25)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| LIFE-01..05 | Does create → running work? ↔UC-11/23/24/25/26 | cd, gv, wa, is, fc | M+H | status=running |
| LIFE-06 | Get sandbox by id ↔UC-12 | cd | M+H | row returned |
| LIFE-07 | List includes the sandbox ↔UC-13 | cd | M+H | present |
| LIFE-08..11 | Does stop → stopped work? | cd, gv, wa, is | M | status=stopped |
| LIFE-12 | Stop → stopped (firecracker) | fc | H | status=stopped |
| LIFE-13..16 | Does start (stopped) → running work? ↔UC-15 | cd, gv, wa, is | M | running |
| LIFE-17 | Start stopped → running (firecracker) | fc | H | running |
| LIFE-18..21 | Does delete → 404 work? ↔UC-16 | cd, gv, wa, is | M | 404 after delete |
| LIFE-22 | Delete → 404 (firecracker) | fc | H | 404 |
| LIFE-23 | Resize CPU/mem/disk ↔UC-18 | cd | M+H | applied |
| LIFE-24 | Resize with firecracker overlay disk | fc | H | applied |
| LIFE-25 | Update lifecycle (idle auto-stop) ↔UC-19 | cd | M+H | policy set |

## 3. Runtime specialization — RT (11)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| RT-01 | Is containerd the default engine (no dockerd in path)? | cd | M+H | engine=containerd |
| RT-02 | Does gVisor run under a userspace kernel (runsc)? ↔UC-25 | gv | M+H | runsc active |
| RT-03 | Does the WASM resident host compile-once / instantiate-many? | wa | M+H | 1 compile, N instantiate |
| RT-04 | Does isolate run one workerd process per tenant group? | is | M+H | group reused |
| RT-05 | Does Firecracker give a dedicated guest kernel per VM? ↔UC-24 | fc | H | guest uname |
| RT-06 | Is Kata correctly not-implemented (negative)? ↔UC-27 | — | M+H | clean 4xx |
| RT-07 | Is an unspecified-runtime create honored, not forced to docker? ↔UC-91 | — | H | placed by default |
| RT-08 | Does a runtime create place on a capability-matching worker? ↔UC-90 | all | H | correct worker |
| RT-09 | Does Firecracker cold-boot from a plain OCI image? ↔UC-88 | fc | H | boots |
| RT-10 | Do Firecracker template clones have distinct kernel entropy? ↔UC-80 | fc | H | unique entropy |
| RT-11 | Does isolate serve a fetch handler from an uploaded bundle? ↔UC-103 | is | M+H | body matches |

## 4. Exec & code execution — EXEC (15)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| EXEC-01..05 | Does toolbox exec return output? ↔UC-39/44 | cd, gv, wa, is, fc | M+H | stdout matches |
| EXEC-06 | Does `code-run` (python interpreter) work? | cd | M+H | result |
| EXEC-07 | Does `code-run` (node interpreter) work? | cd | M+H | result |
| EXEC-08 | Interactive exec stream: stdin → stdout + exit code ↔UC-68 | cd | M+H | streamed + code |
| EXEC-09 | Exec with workdir + env ↔UC-69 | cd | M+H | env honored |
| EXEC-10 | Non-zero exit code propagates | cd | M+H | code≠0 surfaced |
| EXEC-11 | Large stdout streams without truncation | cd | M+H | full bytes |
| EXEC-12 | Long-running exec can be killed | cd | M+H | terminated |
| EXEC-13 | Isolate exec → fetch handler mapping | is | M+H | handler body |
| EXEC-14 | WASM invoke via exec increments invoke metrics | wa | M+H | invoke_total++ |
| EXEC-15 | Exec succeeds under gVisor (syscall-filtered) | gv | M+H | stdout matches |

## 5. Files & filesystem — FILE (13)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| FILE-01 | Upload a file into the sandbox ↔UC-40 | cd | M+H | present |
| FILE-02 | Download a file; bytes round-trip ↔UC-41 | cd | M+H | bytes equal |
| FILE-03 | List files | cd | M+H | listing |
| FILE-04 | File info (stat) | cd | M+H | metadata |
| FILE-05 | Move / rename a file | cd | M+H | moved |
| FILE-06 | Search file contents | cd | M+H | matches |
| FILE-07 | Find files by name | cd | M+H | matches |
| FILE-08 | Git clone + status via toolbox git | cd | M+H | repo present |
| FILE-09 | Streaming upload with progress | cd | M+H | completes |
| FILE-10 | Streaming download with progress + abort | cd | M+H | abort honored |
| FILE-11 | Multi-file batch upload | cd | M+H | all present |
| FILE-12 | Large file (100 MB) round-trips | cd | H | bytes equal |
| FILE-13 | File ops work under gVisor | gv | M+H | round-trip |

## 6. Sessions & PTY — SESS (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| SESS-01 | Create session + run command ↔UC-42 | cd | M+H | output |
| SESS-02 | Session lifecycle (list/get/signal/resize) ↔UC-70 | cd | M+H | states |
| SESS-03 | Session recording is downloadable ↔UC-71 | cd | M+H | recording bytes |
| SESS-04 | Sessions proxy streams ↔UC-45 | cd | M+H | stream |
| SESS-05 | Session replay after reattach | cd | M+H | replay |
| SESS-06 | Idempotent session by name | cd | M+H | same session |
| SESS-07 | PTY create + send input | cd | M+H | echoed |
| SESS-08 | PTY resize | cd | M+H | resized |
| SESS-09 | PTY kill + wait | cd | M+H | exited |
| SESS-10 | Async session with streamed logs | cd | M+H | logs stream |

## 7. Networking & ingress — NET (18)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| NET-01..05 | Expose port → preview URL ↔UC-29 | cd, gv, wa, is, fc | M+H | URL returned |
| NET-06 | Is the preview URL reachable over HTTPS after expose? ↔UC-30 | cd | M+H | 200 |
| NET-07 | Is expose_port idempotent (same URL)? ↔UC-31 | cd | M+H | same URL |
| NET-08 | Does unexpose remove the route? ↔UC-33 | cd | M+H | route gone |
| NET-09 | Is the default `<id>.<domain>` unreachable until expose? ↔UC-32 | cd | M+H | not routable |
| NET-10 | Private-by-default: exec works while private ↔UC-97 | cd | M+H | no public URL, exec ok |
| NET-11 | Raw TCP host-port reachable (L4) ↔UC-34 | cd | M+H | TCP connect |
| NET-12 | TLS-SNI expose (protocol=tls) — Postgres :5432 | cd | M+H | TLS wire |
| NET-13 | Raw TCP expose (protocol=tcp) — Redis :6379 | cd | M+H | RESP reachable |
| NET-14 | Raw TCP expose — SOCKS5 VPN :1080 | cd | M+H | proxy answers |
| NET-15 | Mask request host (dev-server Host rewrite) | cd | M+H | upstream sees rewrite |
| NET-16 | Add custom domain → DNS instructions ↔UC-35 | cd | M+H | CNAME record |
| NET-17 | Custom domain reachable after CNAME ↔UC-36 | cd | M+H | 200 |
| NET-18 | Ingress DNS target published ↔UC-77 | — | M+H | target present |

## 8. Egress & network policy — EGR (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| EGR-01 | Allow-out CIDR is permitted | cd | M+H | reachable |
| EGR-02 | Deny-out CIDR is blocked | cd | M+H | dropped |
| EGR-03 | block-all drops real traffic ↔UC-98 | cd | M+H | no egress |
| EGR-04 | Byte-in limit enforced (DROP on cross) | cd | H | capped |
| EGR-05 | Byte-out limit enforced | cd | H | capped |
| EGR-06 | Network usage counters returned ↔UC-37 | cd | M+H | counters |
| EGR-07 | Network limits patch enforced ↔UC-38 | cd | M+H | applied |
| EGR-08 | Isolate per-sandbox egress: allow vs block-all in one tenant ↔UC-104 | is | M+H | 200 vs 403 |
| EGR-09 | Isolate egress-pool exhaustion → EGRESS_DENY | is | H | deny on exhaust |
| EGR-10 | gVisor + block-all high-trust boundary | gv | M+H | contained |

## 9. Isolation & untrusted code — ISO (11)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| ISO-01 | gVisor kernel-probe: is the host kernel invisible (synthetic /proc)? | gv | M+H | synthetic fields |
| ISO-02 | Docker kernel-probe baseline: host kernel leaks (diff target) | cd | M+H | real host fields |
| ISO-03 | Firecracker: does uname show the guest kernel, not the host? | fc | H | guest kernel |
| ISO-04 | Isolate: cross-tenant process boundary holds | is | M+H | separate processes |
| ISO-05 | Are Linux capabilities dropped under gVisor (CapEff)? | gv | M+H | reduced caps |
| ISO-06 | secure-burner-browser: isolated Chromium desktop serves | gv | M+H | noVNC 200 |
| ISO-07 | burner-minecraft: disposable desktop streams via noVNC | cd | M+H | dashboard + noVNC |
| ISO-08 | GPU + gVisor rejected (negative) ↔UC-28 | gv | M+H | rejected |
| ISO-09 | Snapshot-clone entropy uniqueness (no duplicate UUID) | fc | H | unique |
| ISO-10 | Untrusted code cannot reach host filesystem | fc/gv | H | denied |
| ISO-11 | Untrusted code cannot reach host network (block-all) | fc/gv | H | denied |

## 10. Snapshots & fast boot — SNAP (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| SNAP-01 | Snapshot create ↔UC-20 | cd | M+H | snapshot id |
| SNAP-02 | Register snapshot + create from it ↔UC-21/75 | cd | M+H | boots from snap |
| SNAP-03 | Snapshot resume preserves in-sandbox state | cd | H | state intact |
| SNAP-04 | Warm-pool hit (docker) | cd | M+H | pool hit metric |
| SNAP-05 | Warm-pool hit (WASM resident) | wa | M+H | resident reuse |
| SNAP-06 | Warm-pool hit (isolate blank host) | is | M+H | group reuse |
| SNAP-07 | Warm-pool hit (Firecracker paused VMM) | fc | H | vmm acquire hit |
| SNAP-08 | Cold vs warm create delta is measured | all | M+H | delta reported |
| SNAP-09 | Template reuse skips OCI→ext4 build (fc) | fc | H | template hit |
| SNAP-10 | Create from a Daytona AI-agent snapshot (penify) | cd | M+H | boots |

## 11. Real long-running services — SVC (16)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| SVC-01 | Postgres 16 + row-level security boots (your-own-supabase) | cd | M+H | RLS query OK |
| SVC-02 | Postgres exposed over TLS-SNI (:5432) | cd | M+H | psql over TLS |
| SVC-03 | Postgres role DSNs (anon/authenticated/service_role) enforce RLS | cd | M+H | anon denied, svc allowed |
| SVC-04 | Redis 7 + Upstash-compatible REST API (create-upstash-redis) | cd | M+H | SET/GET via REST |
| SVC-05 | Redis raw TCP (:6379) reachable | cd | M+H | RESP round-trip |
| SVC-06 | Temporal-clone workflow completes (Create-Your-Own-Temporal) | cd | M+H | 5-step done |
| SVC-07 | Temporal workflow retries a failed activity | cd | M+H | retry then success |
| SVC-08 | Temporal durable state survives (host SQLite WAL) | cd | H | state persisted |
| SVC-09 | Temporal serverless vs durable modes both run | cd | H | both modes |
| SVC-10 | Hosted JupyterLab on a public URL (headless-jupyter) | cd | M+H | tokenized 200 |
| SVC-11 | DuckDB SQL-over-HTTP endpoint (duckdb-dataset-explorer) | cd | M+H | SQL answers |
| SVC-12 | Deploy a GitHub app to a public URL (ai-app-hosting) | cd | M+H | app serves |
| SVC-13 | Host an app on a custom domain (ai-app-hosting-2) | cd | H | custom-domain 200 |
| SVC-14 | SOCKS5 burner VPN (burner-vpn) | cd | M+H | proxy works |
| SVC-15 | EdTech coding-interview platform w/ nested sandboxes | cd | H | nested create |
| SVC-16 | One-click per-user sandbox app | cd | H | user sandbox up |

## 12. Heavy compute & data — COMP (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| COMP-01 | Parallel ML tuning fleet: 3 trainers (hyperparameter-tuning-farm) | cd | M+H | 3 accuracies |
| COMP-02 | Fleet spin-up → crush job → teardown | cd | M+H | all destroyed |
| COMP-03 | Kaggle → Parquet ETL with Polars (kaggle-to-parquet) | cd | M+H | parquet emitted |
| COMP-04 | DuckDB in-memory analytics over a dataset | cd | M+H | query result |
| COMP-05 | matplotlib chart artifacts (Daytona charts) | cd | M+H | PNGs returned |
| COMP-06 | RandomForest training returns accuracy | cd | M+H | accuracy |
| COMP-07 | Parallel fan-out of N sandboxes (scale test) | cd | H | N running |
| COMP-08 | CPU-bound benchmark per runtime (throughput) | all | H | ops/s recorded |
| COMP-09 | Data download → process → download-back pipeline | cd | M+H | result bytes |
| COMP-10 | FFmpeg-style transcode job (compute burst) | cd | H | output file |

## 13. AI agents — AI (12)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| AI-01 | claude-code generates a repo architecture doc (arch.md) | cd | M+H | arch.md non-empty |
| AI-02 | claude-code PR-review auto-fix | cd | H | diff produced |
| AI-03 | claude-code writes tests (bulk test generation) | cd | H | tests generated |
| AI-04 | claude-code security-remediation pass | cd | H | fixes produced |
| AI-05 | claude-code large-scale refactor | cd | H | refactor applied |
| AI-06 | AI agent runs under gVisor (untrusted output isolated) | gv | H | contained + output |
| AI-07 | Penify AI-agent snapshot boots + runs (Daytona create-vm) | cd | M+H | agent runs |
| AI-08 | Hosted AI-agent-orchestrator app on custom domain | cd | H | serves |
| AI-09 | AI code-interpreter: generate + execute code | cd | M+H | code + result |
| AI-10 | AI agent with docker-in-docker (penify image) | cd | H | dind works |
| AI-11 | AI agent long-running with idle-stop lifecycle | cd | H | stops when idle |
| AI-12 | Per-user AI agent sandbox at density | is/cd | H | many tenants |

## 14. Mounts & external storage — MNT (14)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| MNT-01 | S3 mount readable inside sandbox | cd | H | object read |
| MNT-02 | NFS mount read/write | cd | H | round-trip |
| MNT-03 | SSHFS mount read/write | cd | H | round-trip |
| MNT-04 | rclone mount readable | cd | H | object read |
| MNT-05 | Platform volume attach: write + read-back ↔UC-81 | cd | M+H | data returned |
| MNT-06 | Volume persists across destroy; re-attach sees data ↔UC-82 | cd | M+H | persisted |
| MNT-07 | Two sandboxes share one volume ↔UC-83 | cd | M+H | both read |
| MNT-08 | Read-only volume rejects writes ↔UC-84 | cd | M+H | write denied |
| MNT-09 | Volume subpath mount for multi-tenancy | cd | H | isolated paths |
| MNT-10 | Platform volumes rejected on WASM (negative) ↔UC-85 | wa | M+H | rejected |
| MNT-11 | Platform volumes rejected on Firecracker (negative) ↔UC-86 | fc | H | rejected |
| MNT-12 | Mount list returned ↔UC-66 | cd | M+H | listing |
| MNT-13 | Max 8 mounts/sandbox enforced | cd | H | 9th rejected |
| MNT-14 | Sensitive mount target refused (/etc, /usr) | cd | H | refused |

## 15. Cluster correctness & HA — HA (16)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| HA-01 | New sandbox gets a placement ↔UC-53 | cd | M+H | placement id |
| HA-02 | Non-owner request forwards to owner ↔UC-54 | cd | M+H | correct answer |
| HA-03 | Sandbox index consistent across nodes ↔UC-55 | cd | M+H | consistent |
| HA-04 | Drain node → sandboxes evacuate ↔UC-56 | cd | H | evacuated |
| HA-05 | Uncordon restores schedulability ↔UC-57 | cd | H | schedulable |
| HA-06 | Owner failover → replica serves ↔UC-58 | cd | H | replica serves |
| HA-07 | Recreate-via-failover preserves identity ↔UC-58b | cd | H | same id |
| HA-08 | WASM live-migrate across nodes ↔UC-59 | wa | H | migrated |
| HA-09 | WASM export/import round-trip | wa | H | state restored |
| HA-10 | Orphan reclaim-local ↔UC-60 | cd | H | reclaimed |
| HA-11 | Delete-orphan | cd | H | removed |
| HA-12 | Cross-node SSH rejects a forged key ↔UC-67 | cd | H | rejected |
| HA-13 | Create through a non-worker ingress reaches a worker ↔UC-92 | cd | H | placed |
| HA-14 | FC template lifecycle through a non-FC entry node ↔UC-93 | fc | H | works |
| HA-15 | Placement spreads via power-of-two-choices | all | H | balanced |
| HA-16 | Leader change mid-flight doesn't drop a create | cd | H | create survives |

## 16. Capacity & density — DEN (8)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| DEN-01 | containerd density to rejection ↔UC-95 | cd | M+H | count@ceiling |
| DEN-02 | gVisor density to rejection | gv | H | count@ceiling |
| DEN-03 | WASM density to rejection | wa | H | count@ceiling |
| DEN-04 | isolate density per tenant group | is | H | count@ceiling |
| DEN-05 | Firecracker density to rejection | fc | H | count@ceiling |
| DEN-06 | Admission rejects over capacity (503) ↔UC-62 | cd | M+H | 503 |
| DEN-07 | Host pressure (cpu/mem/disk) reported per node | — | M+H | metrics |
| DEN-08 | Density holds with byte-quota'd sandboxes | cd | H | count@ceiling |

## 17. Latency benchmarks — LAT (12)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| LAT-01 | containerd create latency (p50/p90/p99) ↔UC-94 | cd | M+H | percentiles |
| LAT-02 | gVisor create latency | gv | M+H | percentiles |
| LAT-03 | WASM create latency (resident) | wa | M+H | percentiles |
| LAT-04 | isolate create latency (warm) | is | M+H | percentiles |
| LAT-05 | Firecracker create latency (warm pool) | fc | H | percentiles |
| LAT-06 | docker-cold vs warm delta | cd | M+H | delta |
| LAT-07 | Sparse warm-path holds ≤30ms (docker) | cd | M+H | p50≤30ms |
| LAT-08 | Burst warm-path under concurrency | cd | H | percentiles |
| LAT-09 | Stage attribution: containerd (create/start/netrules) | cd | M+H | stage ms |
| LAT-10 | Stage attribution: WASM (compile/instantiate) | wa | M+H | stage ms |
| LAT-11 | Stage attribution: Firecracker (spawn/load/resume/post_resume) | fc | H | stage ms |
| LAT-12 | cluster_promote overhead measured | all | M+H | promote ms |

## 18. Serverless & lifecycle automation — SLESS (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| SLESS-01 | Idle-stop after stopIfIdleFor | cd | M+H | stopped |
| SLESS-02 | Idle-destroy after destroyIfIdleFor | cd | M+H | destroyed |
| SLESS-03 | Scale-to-zero wake on HTTP (serverless) | cd | M+H | wakes + serves |
| SLESS-04 | Wake cold-start latency recorded | cd | H | wake p50 |
| SLESS-05 | Wake circuit-breaker opens on repeated failure | cd | H | circuit open |
| SLESS-06 | stop-at-age enforced | cd | H | stopped@age |
| SLESS-07 | destroy-at-age enforced | cd | H | destroyed@age |
| SLESS-08 | ai-app-hosting-serverless scales to zero + wakes | cd | H | wake serves |
| SLESS-09 | burner-vpn-serverless scales to zero | cd | H | wake serves |
| SLESS-10 | TTL-driven reaper terminates aged infra | — | M+H | reaped |

## 19. SSH gateway — SSH (6)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| SSH-01 | Per-sandbox Ed25519 key returned on create | cd | M+H | key present |
| SSH-02 | SSH connect with the per-sandbox key ↔UC-43 | cd | M+H | shell |
| SSH-03 | SSH gateway listens on the ingress public host ↔UC-89 | cd | H | reachable |
| SSH-04 | Forged key rejected cross-node ↔UC-67 | cd | H | rejected |
| SSH-05 | SSH local port-forward works | cd | H | forwarded |
| SSH-06 | SSH session attach/replay | cd | H | attached |

## 20. Templates & images — TMPL (13)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| TMPL-01 | Build image from a Dockerfile ↔UC-46 | cd | M+H | image built |
| TMPL-02 | Rich Dockerfile builder (env/workdir/entrypoint/cmd/user/expose) ↔UC-76 | cd | M+H | honored |
| TMPL-03 | CreateWithImage graph ↔UC-74 | cd | M+H | boots |
| TMPL-04 | Declarative image (pipInstall/runCommands/env) — Daytona | cd | M+H | snapshot built |
| TMPL-05 | FC template create ↔UC-47 | fc | H | template id |
| TMPL-06 | FC template list + get ↔UC-48 | fc | H | present |
| TMPL-07 | FC template rebuild ↔UC-49 | fc | H | rebuilt |
| TMPL-08 | FC template delete ↔UC-50 | fc | H | deleted |
| TMPL-09 | WASM module register + list/get ↔UC-51 | wa | M+H | present |
| TMPL-10 | WASM module push to registry ↔UC-52 | wa | M+H | pushed |
| TMPL-11 | Isolate js-bundle CRUD (upload/list/get/delete) ↔UC-105 | is | M+H | round-trip |
| TMPL-12 | Private registry auth (sealed creds) | cd | H | pulls |
| TMPL-13 | Image build graph → create in one flow | cd | M+H | boots |

## 21. Facade compatibility (Daytona/E2B) — FAC (15)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| FAC-01 | Daytona SDK: create-vm from snapshot | cd | M+H | created |
| FAC-02 | Daytona: exec-command + codeRun | cd | M+H | output |
| FAC-03 | Daytona: full session lifecycle (create/get/exec/logs/delete) | cd | M+H | states |
| FAC-04 | Daytona: file-operations (list/create/upload/search/replace/download) | cd | M+H | all ok |
| FAC-05 | Daytona: streaming upload/download + progress + abort | cd | M+H | completes |
| FAC-06 | Daytona: PTY (create/input/resize/kill/wait) | cd | M+H | interactive |
| FAC-07 | Daytona: volumes multi-mount + subpath | cd | H | shared |
| FAC-08 | Daytona: lifecycle state machine + setLabels | cd | M+H | labeled |
| FAC-09 | Daytona: region us + eu snapshots | cd | H | both regions |
| FAC-10 | Daytona: declarative image with resources | cd | M+H | built |
| FAC-11 | Daytona: git-lsp (clone + LSP symbols/completions) | cd | M+H | symbols |
| FAC-12 | Daytona: network-settings (blockAll / allowList) | cd | M+H | enforced |
| FAC-13 | Daytona: auto-delete / auto-archive intervals | cd | M+H | applied |
| FAC-14 | Daytona: pagination (sandbox + snapshot lists) | cd | M+H | pages |
| FAC-15 | E2B facade: exec + files round-trip (compat) | cd | H | compat |

## 22. Multi-region & multi-arch — REG (5)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| REG-01 | Region `us` snapshot + create | cd | H | created |
| REG-02 | Region `eu` snapshot + create | cd | H | created |
| REG-03 | arm64 Firecracker host boots a VM (optional 12th node) | fc | H | boots |
| REG-04 | Foreign-arch snapshot rejected on arm64 cluster ↔UC-79 | fc | H | rejected |
| REG-05 | Foreign-arch snapshot rejected (offline guard) ↔UC-78 | — | H | rejected |

## 23. GPU — GPU (3, aspirational — needs a GPU host)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| GPU-01 | GPU sandbox request honored (if GPU host present) | cd | H | gpu visible |
| GPU-02 | GPU + gVisor rejected (negative) ↔UC-28 | gv | M+H | rejected |
| GPU-03 | Specific GPU device-ids honored | cd | H | mapped |

## 24. Observability — OBS (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| OBS-01 | /v1/metrics scrape returns output ↔UC-64 | — | M+H | text |
| OBS-02 | Grafana reachable + Prometheus datasource healthy | — | M+H | 200 |
| OBS-03 | All sandboxd nodes are `up` in Prometheus | — | M+H | up==N |
| OBS-04 | Create-funnel metrics populate under load | — | M+H | series move |
| OBS-05 | Per-runtime WASM invoke metrics increment | wa | M+H | invoke_total |
| OBS-06 | Warm-pool hit metrics (docker/vmm) increment | cd/fc | M+H | hit_total |
| OBS-07 | Raft/gossip/lease metrics live | — | M+H | series |
| OBS-08 | Host-pressure metrics track density | — | M+H | rises |
| OBS-09 | Ingress/Caddy admin metrics live | — | M+H | series |
| OBS-10 | Dashboard snapshot captured to reports/obs | — | H | PNG saved |

## 25. Idempotency & resilience — IDEM (10)

| ID | Question | Runtime | Scn | Signal |
|---|---|---|---|---|
| IDEM-01 | create-with-id idempotent under retry ↔UC-17 | cd | M+H | one sandbox |
| IDEM-02 | Concurrent duplicate create (5×) ↔UC-65 | cd | M+H | one wins, no leak |
| IDEM-03 | expose-port idempotent (same URL) ↔UC-31 | cd | M+H | same URL |
| IDEM-04 | custom-domain add idempotent | cd | H | no dup |
| IDEM-05 | sandboxd restart reconcile survives ↔UC-100 | cd | H | state intact |
| IDEM-06 | containerd restart: shims survive + events resubscribe ↔UC-101 | cd | H | shims alive |
| IDEM-07 | dockerd coexistence: AEROLVM-USER jump survives restart ↔UC-102 | cd | H | jump intact |
| IDEM-08 | Neighbor isolation on same bridge ↔UC-99 | cd | H | blocked |
| IDEM-09 | Host-port pool: no leak on retry / PK conflict | cd | M+H | pool stable |
| IDEM-10 | Snapshot register idempotent | cd | M+H | one row |

---

## How the count works (honest accounting)

- **287 catalogue rows.** Some rows are ranges (e.g. `LIFE-01..05` = 5 create-per-runtime
  questions); expanded, the runtime crossings push the true executed-question count
  **well past 300** on the hetero scenario. The mixed scenario runs the subset whose
  runtime/caps it satisfies (roughly ~180 rows; the fc/arm64/GPU/HA-drain rows skip).
- **Not padding:** every runtime crossing is a *distinct* proof (exec working on WASM
  says nothing about exec working under gVisor's userspace kernel or inside a
  Firecracker guest). Where a crossing adds no signal, it's collapsed to one row.
- **~70 rows map 1:1 to existing `harness.Registry` UCs** (`↔UC-NN`) — those already run
  today; the catalogue *records* them into the JSON with investor-phrased questions.
  The remaining ~217 are the new `suite/sims/` simulations + extended coverage rows.

## Wiring (see the main plan §8)

- `suite/harness/catalogue.go` holds this list as a registry: `{ID, Question, Category,
  Subcategory, Runtimes, Scenarios, UCRef, SignalDesc}`. Adding a row here + a test that
  emits its `catid=<ID>` marker is all that's needed — `catalogue/gen.go` is
  registry-driven like `report/gen.go`.
- Each executed row records `{id, question, category, subcategory, runtime, scenario,
  latency_ms, success, public_url, artifact}` into `reports/<scenario>-catalogue.json`.
- `catalogue/gen.go` renders `reports/<scenario>-catalogue.md` grouped
  Category → Subcategory → rows, plus a `summary.by_category` roll-up — the exact tables
  that go into the deck and the HN post.
