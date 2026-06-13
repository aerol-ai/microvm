# Integration Test Harness — Plan

Status: **Phase 0 BUILT** (branch `integration-test-harness`). Offline parts
verified: harness self-tests, report classifier, prod-safety tripwires all pass
in `make test`; the live suite compiles under `-tags=integration`; Terraform
validates with a config_dir + spot dynamic block. The actual on-AWS green run is
the operator's to trigger (`make integration-single`) — it needs creds +
`domains.yml`. Phases 1-3 below are not built yet.

## 1. Goal

Stand up real AerolVM deployments using the **already-released install artifacts**
(`install.sh` / `cluster-init.sh` / `cluster-join.sh` pulled from
`releases/latest`, exactly as `docs/.../local-setup.md` and
`single-node-setup.md` document), then drive the **live `/v1` API and the Go SDK**
against each deployment to prove the whole stack works end-to-end — including
domain routing, TLS, port exposure, every runtime, and cluster correctness.

The harness must also emit a **coverage-style report** (CodeCov-like, but for
behavioural use cases rather than source lines): a grid of *use case × scenario*
showing pass / fail / skipped(=not applicable to that scenario) / pending(=not
yet implemented). This is the artifact that tells us "what is tested and what is
still a gap."

Design constraints (from the request):
- **Reuse the existing `Terraform/` module and `Ansible/` playbooks.** The
  `var.nodes` map already expresses every topology we need (roles, per-node
  `with_firecracker` / `with_gvisor`, instance sizes). We add *scenario var-files*,
  not new infra code.
- **DRY / YAGNI.** No second Terraform module, no bespoke coverage engine. The
  report is generated from `go test -json` output plus a use-case registry. The
  test client reuses `sdk/go` (`pkg/microvm`) so the suite doubles as **Go-SDK**
  integration coverage (the other four SDKs are out of scope until Phase 3 —
  Codex #5).

## 2. The four scenarios

| # | Scenario | How it's provisioned | Topology | Domain/TLS |
|---|----------|----------------------|----------|------------|
| 1 | **Local-mode** | `install.sh --local` on a **throwaway Linux EC2 box** (TF, 1 node, no DNS) | 1 process, `SB_ENABLE_CADDY=false`, API on `http://localhost:21212` | none — suite reaches the API via an SSH local port-forward (`-L 21212:localhost:21212`) so no Cloudflare record or TLS is involved |

> **Naming caveat (Codex #8).** This scenario exercises the **`--local` install
> codepath** (no Caddy, localhost API) on a Linux host — not the macOS launchd
> path. It is "local-mode on Linux," not "local dev on a Mac." The macOS
> daemon path (`com.aerol.sandboxd` launchd plist) is **NOT** covered here; see
> NOT-in-scope.
| 2 | **Single-node** | Terraform 1-node `mixed` + `install.sh --domain` path via bootstrap | 1 node | wildcard DNS + DNS-01 TLS |
| 3 | **Cluster — 3× mixed** | Terraform, `var.nodes` = 3 × `role="mixed"` (shared responsibilities) | 3 nodes, all Raft voters + workers + ingress | wildcard DNS + TLS |
| 4 | **Cluster — heterogeneous (8 nodes)** | Terraform, `var.nodes` = dedicated roles per node | 3× `server` (low-end) + 1× `ingress` (low-end) + 4× `worker`: docker, firecracker, gvisor, wasm | wildcard DNS + TLS |

**Scenario 4 = 8 nodes (RESOLVED).** 3× `server` + 1× `ingress` + 4× specialised
workers. Cost is controlled by instance sizing, set in `cluster-hetero.tfvars`:

| Node | Role | Instance type | Why |
|------|------|---------------|-----|
| server-1/2/3 | `server` | `t3.small` | Raft voters only — no sandboxes, no public traffic, tiny footprint |
| ingress-1 | `ingress` | `t3.small` | Holds the route table + Caddy; no sandbox compute |
| worker-docker | `worker` | `t3.medium` | Docker runtime |
| worker-gvisor | `worker` (`with_gvisor`) | `t3.medium` | gVisor (ptrace/systrap — no KVM needed) |
| worker-wasm | `worker` (wasm enabled) | `t3.medium` | WASM runtime |
| worker-fc | `worker` (`with_firecracker`) | **`*.metal` (see cost flag)** | Firecracker needs `/dev/kvm`, only exposed on EC2 bare-metal |

> **Cost flag — the firecracker worker (RESOLVED: keep it, on spot).**
> Firecracker requires KVM, which on EC2 is **only** available on bare-metal
> instances (e.g. `c5.metal`/`m5.metal`, ~$4+/hr) — there is no `t3`-class
> equivalent. Decision: keep the metal firecracker node but request it as a
> **spot instance** (typically ~60-70% cheaper), with auto-teardown + a tight
> `ttl` reaper tag, and scenario 4 stays **on-demand only**. To keep things
> simple and cheap, **all integration nodes default to spot** (the `t3` nodes are
> trivially spot-friendly); on-demand can be forced per run.
>
> **Spot interruption is an infra event, not a test failure.** If AWS reclaims a
> node mid-run, `run.sh` marks that scenario **inconclusive** (distinct from
> fail) in the report and exits non-zero with a clear reason, rather than logging
> false UC failures. Bare-metal spot capacity can also be scarce in a given AZ —
> the runner surfaces a clean "spot capacity unavailable" message and can
> fall back to on-demand for the metal node via `--metal-on-demand`.

Each scenario is fully described by two files (see §5):
`scenarios/<name>.tfvars` (topology) and `scenarios/<name>.caps.yml` (capability
matrix — what the suite is *allowed to expect* there).

## 3. Use cases (66 — exceeds the 50 minimum)

Each use case has a stable ID. The registry (`suite/harness/usecases.go`) tags
each one with the capabilities it requires; the report marks a use case
**skipped** in any scenario whose `caps.yml` doesn't satisfy the tag (e.g.
firecracker UCs are skipped on Local), which is exactly the "what's pending here"
signal.

### A. Provisioning & control plane (UC-01 … UC-10)
- **UC-01** Local install completes; `sandboxd` healthy on `:21212`.
- **UC-02** Single-node Terraform bootstrap completes; `sandboxd` active.
- **UC-03** 3× mixed cluster forms; `/v1/cluster/members` lists 3.
- **UC-04** Heterogeneous cluster forms; member roles match the tfvars.
- **UC-05** Raft leader elected; `/v1/cluster/leader` returns a stable leader.
- **UC-06** Member count == expected for the scenario.
- **UC-07** Wildcard DNS (`*.<domain>`) resolves to an ingress IP.
- **UC-08** Control-plane API reachable at `https://<domain>/v1/...`.
- **UC-09** Valid TLS chain served for apex **and** wildcard host.
- **UC-10** Auth enforced: request without PAT → `401`.

### B. Sandbox lifecycle (UC-11 … UC-22)
- **UC-11** Create docker sandbox → reaches `running`.
- **UC-12** Get sandbox by id returns it.
- **UC-13** List sandboxes includes it.
- **UC-14** Stop sandbox → `stopped`.
- **UC-15** Start/resume stopped sandbox → `running`.
- **UC-16** Delete sandbox → subsequent get is `404`.
- **UC-17** Create-with-id is idempotent (duplicate id returns same sandbox, no error).
- **UC-18** Resize CPU/mem/disk applied.
- **UC-19** Update lifecycle (idle auto-stop) persists.
- **UC-20** Snapshot create succeeds.
- **UC-21** Register snapshot + create sandbox from snapshot.
- **UC-22** ~~Recreate sandbox~~ **MOVED to group G (failover).** `RecreateSandbox`
  has no public route (`routes.go` exposes none — Codex #7); it's only reachable
  via cluster failover/orphan machinery. Reframed as a cluster-only check that
  overlaps UC-58, not a single-node API test.

### C. Runtimes (UC-23 … UC-28)
- **UC-23** Docker-runtime sandbox runs.
- **UC-24** Firecracker-runtime sandbox runs (firecracker worker).
- **UC-25** gVisor-runtime sandbox runs (gvisor worker).
- **UC-26** WASM-runtime sandbox runs (wasm worker; module staged via Ansible).
- **UC-27** Kata runtime → `runtime not yet implemented` (negative).
- **UC-28** GPU + gVisor on same sandbox rejected (negative).

### D. Networking & ingress (UC-29 … UC-38)
- **UC-29** Expose port returns a preview URL.
- **UC-30** `https://<id>-<port>.<domain>` is reachable and serves the app.
- **UC-31** Expose port is idempotent (same URL on repeat call — pr-review rule #1).
- **UC-32** Default `https://<id>.<domain>` preview URL reachable.
- **UC-33** Unexpose port → route gone (`404`/connection refused).
- **UC-34** L4 / raw TCP host-port reachability check.
- **UC-35** Add custom domain → DNS instructions returned. **Requires a dedicated
  custom-domain FQDN** (`pkg/models/custom_domain.go` rejects any hostname under
  the deployment base domain — Codex #3), so this needs a 4th test FQDN that is
  NOT under the scenario's `itest.domains` base. Added to the domain pool config.
- **UC-36** Custom domain reachable after CNAME is in place (same dedicated FQDN).
- **UC-37** `GET .../network/usage` returns counters.
- **UC-38** `PATCH .../network/limits` enforced.

### E. Exec, files, sessions, SSH (UC-39 … UC-45)
- **UC-39** Toolbox exec returns command output.
- **UC-40** Upload file into sandbox.
- **UC-41** Download file from sandbox; bytes round-trip.
- **UC-42** Create session + run a command in it.
- **UC-43** SSH into sandbox with per-sandbox Ed25519 key.
- **UC-44** Exec works on every available runtime in the scenario.
- **UC-45** Sessions proxy streams (long-running output).

### F. Templates, images, wasm modules (UC-46 … UC-52)
- **UC-46** Build image from a Dockerfile (`POST /v1/images/build`).
- **UC-47** Create template.
- **UC-48** List + get template.
- **UC-49** Rebuild template.
- **UC-50** Delete template.
- **UC-51** Register wasm module + list/get.
- **UC-52** Push wasm module to registry (`/v1/wasm-modules/push`).

### G. Cluster correctness (UC-53 … UC-60) — cluster scenarios only
- **UC-53** New sandbox gets a placement (`/v1/cluster/placements/{id}`).
- **UC-54** Request hitting a non-owner node transparently forwards to the owner.
- **UC-55** `/v1/cluster/sandbox-index` consistent across all nodes.
- **UC-56** Drain a node → its sandboxes evacuate / node cordoned.
- **UC-57** Uncordon restores schedulability.
- **UC-58** Owner failover: kill owner node, recovery replica serves the sandbox.
- **UC-59** WASM live-migrate a sandbox across nodes.
- **UC-60** Orphan reclaim-local + delete-orphan paths work.
- **UC-58b** (reframed UC-22) Recreate-via-failover preserves sandbox identity —
  exercised through the owner-failover/recovery path, cluster-only.

### H. Capacity, admission, ops, idempotency (UC-61 … UC-66)
- **UC-61** `/v1/capacity` reports host capacity.
- **UC-62** Admission rejects create when over capacity (negative).
- **UC-63** `POST /v1/admin/reconcile` runs clean (no spurious mutations).
- **UC-64** `/v1/metrics` scrape returns expvar/Prometheus output.
- **UC-65** Concurrent duplicate create (N goroutines, same id) → exactly one sandbox.
- **UC-66** `GET .../mounts` lists configured external-storage mounts.

### Test hygiene contract (review issue 2 — RESOLVED)

Because every UC runs against **one shared deployment on small workers**, the
`harness/` package enforces:
- **Unique resource names** per test: `<run-id>-<test-name>` so parallel/repeat
  runs never collide.
- **Mandatory cleanup**: `harness/client.go`'s `NewSandbox(t)` registers a
  `t.Cleanup` that deletes the sandbox — no test leaks state into the next.
- **Capacity-sensitive UCs run serial + last**: UC-62 (admission-over-capacity)
  and UC-65 (concurrent-duplicate-create) are tagged `serial` and run in a final
  phase with the rest of the suite quiesced, so they can't starve create tests
  into false failures.

### Harness self-tests (review issue 4 — RESOLVED, offline)

The harness's own brain + safety guards get unit tests that run in normal
`go test` / CI with **no AWS**: `skip.go` caps-logic, `report/gen.go`
classification (pass/fail/skip/pending/inconclusive, golden-file), and the
`provision.sh` prod-safety tripwires (feed a `prod/`-matching key and the prod
domain, assert non-zero abort). A bug in these is a silent-green or a
prod-destruction risk, so they are non-negotiable.

## 4. How a scenario run works (orchestration)

`integration-tests/run.sh <scenario> [--keep]`:

1. **Provision** (`lib/provision.sh`):
   - Local: TF spins **one throwaway EC2 box** (no DNS, no Cloudflare), then
     `install.sh --local --pat-token <generated>` runs on it. The suite reaches
     the API through an **SSH local port-forward** (`ssh -L 21212:localhost:21212`),
     so `AEROL_BASE_URL=http://localhost:21212` — exactly the local-setup.md flow,
     no domain involved.
   - TF scenarios: `terraform init` against a **separate state key** and a
     **separate `TF_DATA_DIR`** (see §4a — this is what keeps production state
     safe), then `apply` with the scenario var-file and config overlay (see §5
     config-dir change). Bootstrap pulls the released install scripts exactly as
     documented.
2. **Discover endpoint**: read `terraform output -json` (new `api_base_url`
   output) → `{base_url, pat, ingress_ip, nodes[]}`. Local short-circuits to
   `http://localhost:21212`.
   Before any apply, `run.sh` sets `trap 'teardown "$SCENARIO"' EXIT INT TERM`
   (review issue 1) so a crash/Ctrl-C still tears down.
3. **Wait for ready** (`lib/common.sh`): poll `/v1/capacity` (auth) until healthy;
   for domain scenarios also wait on DNS resolution + a valid TLS handshake +
   `/v1/cluster/members` count.
4. **Stage runtime assets** (cluster-hetero only): reuse
   `Ansible/playbooks/stage-wasm-modules.yml` to push the **defined wasm test
   module** (source + digest + `wasm.standard_modules` entry, pinned in
   `scenarios/` — Codex #7-wasm) to the wasm worker. The playbook is invoked with
   the scenario `config_dir` (see §6 — the Ansible playbooks gain a config-dir
   var so day-2 config matches day-0, Codex #1).
5. **Run suite**: `go test -tags=integration -json ./suite/...` (the build tag
   keeps the suite out of the default `make test`, Codex #5) with env
   `AEROL_BASE_URL`, `AEROL_PAT`, `AEROL_SCENARIO=<name>`,
   `AEROL_CAPS=scenarios/<name>.caps.yml`. The suite loads the caps file and
   self-skips use cases the scenario can't satisfy.
6. **Report**: pipe the JSON to `report/gen.go`, which joins it with the use-case
   registry and writes `reports/<scenario>.{json,md,html}` and updates the
   aggregate `reports/index.md` grid. Spot-reclaim → **inconclusive**, distinct
   from fail.
7. **Teardown** (also the `trap` target): `terraform destroy` against the
   scenario's own state key unless `--keep`. Independent of this, a standalone
   `scripts/integration-reap.sh` (cron/CI) terminates any `itest=true` instance
   older than its `ttl` — the belt-and-suspenders net for hard kills (review
   issue 1).

`run.sh all` runs scenarios sequentially and produces the combined matrix.

## 4a. State isolation — production must be untouchable

**The hard constraint:** the existing `Terraform/backend.tf` points at
`s3://aerol-terraform-state-923107117704/prod/terraform.tfstate` with
`use_lockfile = true`, and **production is the `default` workspace at that key**.
The integration harness must be physically incapable of opening, locking, or
destroying that state object.

Rules `lib/provision.sh` enforces:

1. **Separate state key, not workspaces.** Each TF scenario re-inits the same
   module against its own key:
   ```bash
   TF_DATA_DIR="integration-tests/.tf/<scenario>" \
   terraform -chdir=Terraform init -reconfigure \
     -backend-config="key=integration/<scenario>/terraform.tfstate"
   ```
   - The `-backend-config=key=...` override sends state to
     `integration/<scenario>/terraform.tfstate` — a different object in the same
     bucket. `prod/terraform.tfstate` is never read, locked, or written.
   - `TF_DATA_DIR` gives integration its own `.terraform/` cache so re-init never
     disturbs the operator's prod-initialised module directory.
2. **No reuse of `scripts/terraform.sh` for apply/destroy** in scenarios — that
   wrapper is bound to the prod key. The runner calls `terraform -chdir` directly
   with the overrides above. (We still reuse the *module*, just not the
   prod-bound entrypoint.) **Correction to §6 item 4:** drop the
   `scripts/terraform.sh` change; it isn't needed and keeps that prod path
   single-purpose.
3. **Tripwire.** `provision.sh` aborts if the resolved key matches `^prod/`,
   if `terraform workspace show` is not what the scenario expects, or if
   `cluster_name` lacks the `itest` marker.
4. **Distinct resource names + reaper tag.** Every scenario sets
   `cluster_name = "aerolvm-itest-<scenario>"` and an `itest=true` + `ttl`
   tag (via `var.extra_tags`) so resources never collide with prod and a cost
   reaper can sweep leaks.

Net effect: production and integration share **only the read-only module code** —
never state, lock, cache, or resource names.

## 4b. Cloudflare DNS & TLS — real records, isolated names

Domain scenarios (single-node + both clusters) **require Cloudflare** — there is
no public domain or wildcard TLS without it. The harness reuses the existing
path, it does not invent a new one:

- **Records:** `Terraform/dns.tf` creates the apex `A` (`name = domain_name`) and
  wildcard `*.domain_name`, one per ingress node, in the zone derived from
  `domain_name` (or `var.cloudflare_zone_id` if set).
- **Credential:** the **same `cloudflare.api_token` in `config/secrets.yml`**
  (`Zone:DNS:Edit` + `Zone:Read`). That token is *also* what Caddy uses on the
  box for **DNS-01 wildcard TLS issuance** (the `single-node-setup.md` flow). No
  second credential is introduced.

**A test-domain pool, sized to the scenarios.** Let's Encrypt's binding limit is
the **duplicate-certificate cap: 5 issuances of the same hostname set per week**.
The apex + `*.domain` is one fixed set, so re-issuing it every apply/destroy
cycle dies after 5 runs. The operator therefore supplies a **pool of test
domains** (a list, distinct from the prod domain) and the harness leases one per
domain-bearing scenario:

- New config block in the integration config — `itest.domains: [d1, d2, d3]` —
  three FQDNs the operator controls in the same Cloudflare account.
- **Exactly three domain-bearing scenarios** (single-node, cluster-3-mixed,
  cluster-hetero), so the default is **one domain pinned per scenario**: each
  scenario's hostname set is unique ⇒ each gets its own independent LE quota and
  its own `cloudflare_record` set. A full `run.sh all` issues 3 distinct cert
  sets, one per domain — never re-hitting the duplicate cap.
- **Repeated same-scenario runs** lease the *next* domain in the pool
  (round-robin, lease state recorded under `integration-tests/.tf/`) so back-to-
  back reruns spread across the pool instead of re-issuing one set 5+ times.
- The leased domain is written into that scenario's `config/cluster.yml` overlay
  as `ingress.domain_name`, so `dns.tf` + Caddy DNS-01 issue against it
  unchanged.

**The risk this also removes:** `cloudflare_record` is keyed by record *name*.
A pool of dedicated test domains means no scenario ever shares a record name with
prod, so Terraform can never overwrite production's apex/wildcard A records.
`terraform destroy` removes exactly the test records for the leased domain.

**Tripwire.** `provision.sh` aborts if any pool entry equals or is a suffix-match
of the prod `domain_name` in `config/cluster.yml`, so a copy-paste can't aim a
test at the prod hostname. DNS-01 wildcard TLS needs the real public zone — there
is no offline shortcut for UC-09; UC-07/08/09 wait on propagation + a valid
handshake against the leased domain.

**Staging-root pinning (Codex #6).** With LE staging as the default issuer,
normal clients distrust the cert. UC-09 must load the **LE staging root** into a
custom cert pool and assert the handshake validates against it — NOT
`InsecureSkipVerify`, which would make "valid TLS" a no-op. `--prod-tls` swaps in
the real LE roots.

**Cluster cert duplication (Codex #2).** The 3-domain pool stops *cross-scenario*
duplicate issuance, but inside the **3-mixed** scenario all 3 nodes are ingress
and each issues its own cert for the same wildcard set. Under `--prod-tls` that's
3× the same hostname set per run → burns the LE duplicate cap fast. Fix: the
cluster overlays set `caddy_shared_cert_storage.enabled=true` (managed mode) so
one node issues and the rest read from S3. Under default staging TLS it's
harmless, but we enable it so `--prod-tls` cluster runs are safe.

**AOCR / fleet neutralization (Codex #4 — critical).** `config/cluster.yml`
ships with AOCR mirror/auto-import **ON** (prod `cluster_id`) and `locals.tf`
*validates* the matching secrets, so a naive overlay would either make
integration nodes phone home to the prod AOCR/fleet control plane or fail
plan-time validation. The yq overlay therefore also zeroes these out for every
scenario:
```bash
yq '.ingress.domain_name = "<leased>"
    | .auto_import.enabled = false
    | .mirror.host = ""
    | .fleet_control_plane.enabled = false
    | .wasm.enabled = <true for hetero, else base>' \
   config/cluster.yml > .tf/<scenario>/config/cluster.yml
```

**Custom-domain FQDN (Codex #3).** UC-35/36 need a hostname **not** under the
scenario base domain (`pkg/models/custom_domain.go` rejects sub-domains of the
deployment base). The domain pool config gains a `custom_domain` field — a 4th
FQDN — that the suite attaches as the customer domain.

## 5. Files to CREATE

```
integration-tests/
  README.md                       # how to run, prerequisites, cost note (spins real EC2)
  run.sh                          # orchestrator: run.sh <scenario|all> [--keep]
  lib/
    common.sh                     # wait_for_health, wait_for_dns, wait_for_tls, json helpers
    provision.sh                  # local-install + tf-workspace apply/destroy wrappers
  scenarios/
    domains.yml                   # itest: {domains:[d1,d2,d3], custom_domain: dX} — GITIGNORED (mirrors secrets.yml)
    domains.example.yml           # committed template operators copy to domains.yml
    local.caps.yml                # caps: docker only, no domain, single node
    single-node.tfvars            # var.nodes = 1× mixed, spot=true
    single-node.caps.yml          # caps: docker(+gvisor/fc if flagged), domain, single node
    cluster-3-mixed.tfvars        # var.nodes = 3× mixed, spot=true, caddy_shared_cert_storage on
    cluster-3-mixed.caps.yml      # caps: cluster, domain, 3 voters
    cluster-hetero.tfvars         # 3 server(small) + 1 ingress(small) + 4 workers (docker/fc/gvisor/wasm), spot
    cluster-hetero.caps.yml       # caps: cluster, domain, firecracker, gvisor, wasm
    wasm/test-module.wasm         # pinned tiny wasm test module + digest (Codex #7-wasm)
    # NOTE: per-scenario config/cluster.yml overlays are GENERATED at runtime by
    # provision.sh (yq) into integration-tests/.tf/<scenario>/config/ — NOT
    # committed (review issue 3). No drift from the real config/cluster.yml.
  suite/
    harness/
      scenario.go                 # load caps.yml + env (base_url, pat) → Scenario
      usecases.go                 # the UC registry: id, title, required caps, implemented?
      client.go                   # sdk/go pkg/microvm wrapper + NewSandbox(t) w/ unique-name + t.Cleanup
      skip.go                     # t.Skip() when scenario caps don't satisfy a UC's tags
      skip_test.go                # OFFLINE unit test of caps-satisfies logic (review issue 4)
    lifecycle_test.go             # UC-11..UC-21  (//go:build integration)
    runtimes_test.go              # UC-23..UC-28
    networking_test.go            # UC-29..UC-38
    exec_files_test.go            # UC-39..UC-45
    templates_test.go             # UC-46..UC-52
    cluster_test.go               # UC-53..UC-60 + UC-58b (reframed UC-22)
    capacity_ops_test.go          # UC-61..UC-66 (UC-62/65 tagged serial)
    provisioning_test.go          # UC-01..UC-10 (reads discovered topology)
  report/
    gen.go                        # go test -json + usecases registry -> md/html/json grid
    gen_test.go                   # OFFLINE golden-file test of classification (review issue 4)
    templates/report.md.tmpl
    templates/report.html.tmpl    # CodeCov-style colored grid
  reports/
    .gitignore                    # ignore generated *.json/*.md/*.html, keep the dir
  provision_test.bats             # OFFLINE: feed prod-key + prod-domain, assert tripwire aborts (issue 4)
```

Plus `scripts/integration-reap.sh` (lives in `scripts/`, the existing ops-script
home) — terminates `itest=true` instances past their `ttl` (review issue 1).

Notes on reuse:
- `suite/` is a Go test package inside the **existing repo module** (no new
  `go.mod`) so it imports `pkg/models` and `sdk/go` directly. It carries a
  `//go:build integration` tag so the default `make test` never reaches AWS.
- `scenarios/*.tfvars` only override `cluster_name` + `var.nodes` (+ instance
  sizes + `spot`). Secrets/ops stay in the shared `config/` SoT — no duplication.
- Per-scenario `cluster.yml` is **generated at runtime** (yq overlay), never
  committed — single source of truth is the real `config/cluster.yml`.
- **SDK coverage is Go-only** in Phases 1-2 (the suite drives `pkg/microvm`).
  The other four SDKs are deferred to Phase 3 — §1's "SDK coverage" claim is
  scoped to Go (Codex #5).

## 6. Files to UPDATE (minimal, reuse-preserving)

1. **`Terraform/variables.tf`** — add `variable "config_dir"` (default
   `"${path.module}/../config"`). Lets a scenario point Terraform at its own
   `cluster.yml` overlay without clobbering the operator's `config/`. Single new
   variable; everything else unchanged.
2. **`Terraform/locals.tf`** — read `file("${var.config_dir}/cluster.yml")` and
   `secrets.yml` via the new var instead of the hardcoded path. (Secrets overlay
   defaults to the shared `config/secrets.yml` so we never duplicate real
   secrets — scenarios symlink it.)
3a. **`Terraform/variables.tf` + `locals.tf` + `nodes.tf`** — add an optional
   per-node `spot` field to `var.nodes` (default `false`, so prod behaviour is
   unchanged), resolved in `nodes_resolved`, and wired into both `aws_instance`
   resources via an `instance_market_options { market_type = "spot" }` block
   gated on that flag (`spot_options { spot_instance_type = "one-time" }` so a
   reclaimed node is terminated, not stopped — matches ephemeral test intent).
   Integration scenario tfvars set `spot = true`; prod tfvars leave it default.
3. **`Terraform/outputs.tf`** — add `output "api_base_url"` (domain → `https://<domain>`,
   else first ingress public IP) and a machine-readable `integration_targets`
   output (`{base_url, ingress_ip, nodes:[{name,role,public_ip,private_ip}]}`) so
   `run.sh` doesn't have to parse the human `nodes` output.
4. **`scripts/terraform.sh`** — **no change.** (Originally proposed an env
   override; dropped per §4a — that wrapper stays bound to the prod state key so
   it can never be pointed at an integration run by accident. The integration
   runner calls `terraform -chdir` directly with its own backend key +
   `TF_DATA_DIR`.)
5. **`Makefile`** — add `integration-local`, `integration-single`,
   `integration-cluster-mixed`, `integration-cluster-hetero`, `integration-all`,
   `integration-report`, and `integration-reap` targets that shell out to
   `integration-tests/run.sh` / `scripts/integration-reap.sh`. The default
   `test` target stays untouched (the suite's `integration` build tag excludes
   it — Codex #5).
8. **`Ansible/playbooks/configure-ops.yml` + `stage-wasm-modules.yml`** — accept
   a `config_dir` var (default the current `../../config`) instead of hardcoding
   the path, so day-2 ops + wasm staging read the **scenario** overlay, matching
   Terraform's `config_dir` (Codex #1). Backwards compatible — default preserves
   today's behaviour. Same zero-diff discipline as the TF edits.
6. **`.gitignore`** (root) — ignore `integration-tests/reports/*` artifacts,
   scenario `secrets.yml` symlinks, `integration-tests/.tf/` (state cache + lease
   file), and `integration-tests/scenarios/domains.yml` (the real test-domain
   pool; only `domains.example.yml` is committed).
7. **`.github/workflows/`** — *(optional, propose but defer per YAGNI)* a manually
   triggered (`workflow_dispatch`) `integration.yml` that runs `local` for free
   on the runner and gates the EC2 scenarios behind a manual approval, uploading
   the report as an artifact. Listed so it's on the radar; not built in phase 1.

## 7. The report (CodeCov-like, no coverage engine)

`report/gen.go` consumes `go test -json` events. Each test maps to a UC via a
`// uc:UC-29` marker / subtest name convention recorded in the registry. Output:

- **`reports/<scenario>.md`** — per-scenario pass/fail/skip list.
- **`reports/index.md`** — the matrix: rows = UC-01..UC-66, columns = the 4
  scenarios, cells = ✅ pass / ❌ fail / ⚪ skipped(N-A) / 🟡 pending(no test yet).
- **`reports/index.html`** — same grid, colored, for eyeballing.
- A summary line: `covered X/66 across all scenarios; Y still pending`.

"Pending" = a UC in the registry with no corresponding test yet — this is what
tells you the gap, fulfilling the "what is tested vs pending" requirement without
building a real code-coverage tool.

## 8. Phasing (so review can gate scope)

- **Phase 0 — walking skeleton (review D1, do this first).** Single-node
  scenario ONLY, ~5 UCs end-to-end: UC-11 (create), UC-29/30 (expose + reach
  over domain), UC-16 (delete), UC-10 (auth-401). Full pipeline:
  `config_dir` + `spot` TF edits (gated on a **zero-diff prod `terraform plan`**,
  review D2), `run.sh` + `provision.sh` (with tripwires) + `common.sh`, yq
  overlay, `report/gen.go` + matrix, trap+reaper, the offline harness self-tests.
  **Exit criterion: one real green matrix cell on AWS + `make test` unaffected.**
- **Phase 1**: fan out the rest of the single-node UC groups A, B, D, E, F, H;
  add the **Local-mode** scenario.
- **Phase 2**: 3× mixed + heterogeneous cluster scenarios; suite group C
  (runtimes) + G (cluster correctness, incl. UC-58b); Ansible `config_dir` +
  wasm staging wire-up; cluster cert sharing.
- **Phase 3**: optional `workflow_dispatch` CI + optional per-SDK smoke
  (reusing each SDK's existing examples, one canonical happy-path each) — only if
  we decide cross-SDK parity needs live coverage beyond the Go suite.

**Merge gate on the TF edits (review D2):** the PR that lands `config_dir` +
`spot` MUST include `scripts/terraform.sh plan` output showing **"No changes"**
against prod state. Spot is a `dynamic "instance_market_options"` block that
emits nothing when `spot=false`, so prod nodes are not touched.

## 9. Open decisions for review

1. **Scenario 4 node count** — RESOLVED: 8 nodes (3 server + 1 ingress + 4
   workers), low-end sizing per §2 table.
2. **Local scenario host** — RESOLVED: throwaway EC2 box; suite hits
   `http://localhost:21212` via SSH port-forward, no Cloudflare.
3. **Cost guardrails** — RESOLVED: `trap`-based teardown on `run.sh` EXIT/INT/TERM
   + a standalone `scripts/integration-reap.sh` (cron/CI) that terminates
   `itest=true` instances past their `ttl`. Belt and suspenders (review issue 1).
4. **Primary SDK** — RESOLVED: Go SDK is the canonical driver (in-module, zero
   extra toolchain). Other four SDKs deferred to Phase 3; §1 SDK claim scoped to
   Go accordingly.
5. **Test-domain pool** — RESOLVED: pool lives in a gitignored
   `integration-tests/scenarios/domains.yml` (`itest.domains: [d1, d2, d3]`) with
   a committed `domains.example.yml` template, mirroring the `secrets.yml`
   pattern. Operator still needs to drop in the three real FQDNs (distinct from
   prod, in the same Cloudflare account).
6. **TLS issuer** — RESOLVED: **Let's Encrypt staging by default** (UC-09 asserts
   the staging chain), with a `--prod-tls` flag for periodic real-cert checks.
7. **Firecracker metal node** — RESOLVED: keep the `*.metal` firecracker worker,
   request it (and all integration nodes) as **spot** to cut cost. Spot reclaim →
   scenario marked *inconclusive*, not failed; `--metal-on-demand` falls back if
   bare-metal spot capacity is unavailable. Adds an optional `spot` field to
   `var.nodes` (default off — prod unaffected). See §2 cost flag + §6 item 3a.

## 10. What already exists (reuse, don't rebuild)

| Sub-problem | Existing asset | Plan reuses it? |
|---|---|---|
| Provision N nodes with roles/runtimes/sizes | `Terraform/` `var.nodes` map (fully parametric) | Yes — scenario tfvars only |
| Render identical SB_* env day-0/day-2 | `config/cluster.yml` + `locals.tf` SoT | Yes — yq overlay on top |
| Bootstrap released artifacts | `scripts/{install,cluster-init,cluster-join}.sh` via `bootstrap.sh.tftpl` | Yes — unchanged |
| TF wrapper | `scripts/terraform.sh` | Deliberately NOT reused for scenarios (prod-key bound) |
| Wasm module staging | `Ansible/playbooks/stage-wasm-modules.yml` | Yes — + config_dir var |
| Day-2 ops config | `Ansible/playbooks/configure-ops.yml` | Yes — + config_dir var |
| API client | `sdk/go` `pkg/microvm` | Yes — harness wraps it |
| Wire types | `pkg/models` | Yes — imported directly |
| Test-result rendering | `go test -json` | Yes — gen.go consumes it (no gotestsum dep) |

## 11. NOT in scope (considered, deferred)

- **macOS local-dev path** — the launchd `com.aerol.sandboxd` install. Local-mode
  is tested on Linux EC2 only (Codex #8). Mac path deferred; low ROI on CI.
- **Cross-SDK live integration** (TS/Python/Rust/Java) — Phase 3, only if Go-SDK
  coverage proves insufficient. Avoids 5× the maintenance for marginal signal.
- **GPU sandboxes (UC-28 beyond the negative check)** — real NVIDIA/AMD GPU
  nodes are expensive and orthogonal to the core loop. Negative (reject gVisor+GPU)
  stays; positive GPU runs deferred.
- **`workflow_dispatch` CI** — Phase 3. Build the loop locally first.
- **Parallel scenario execution** — sequential by default; parallel is a future
  cost/time trade-off, not needed to prove the harness.
- **Kata runtime positive path** — only the "not implemented" negative (UC-27).

## 12. Failure modes (new codepaths)

| Codepath | Realistic failure | Test? | Error handling | Silent? |
|---|---|---|---|---|
| `provision.sh` tripwire | regex misses a prod-key variant → targets prod | YES (bats, issue 4) | abort non-zero | No (loud abort) |
| `report/gen.go` classify | malformed json-test event → UC mislabeled green | YES (golden, issue 4) | default to fail/unknown | **was silent — now tested** |
| `skip.go` caps logic | unsatisfied UC reported pass not skip | YES (issue 4) | n/a | **was silent — now tested** |
| spot reclaim mid-run | node dies → tests error | partial | marked inconclusive | No |
| DNS/TLS wait | propagation slower than timeout → false fail | needs sane timeout+backoff in common.sh | ret/backoff | No |
| teardown | crash before destroy → EC2 leak | n/a | trap + reaper | No (reaper sweeps) |
| yq overlay | yq missing on runner → bad config silently applied | README prereq + provision.sh `command -v yq` guard | abort | No (guarded) |

No critical gaps remain (silent + no-handling + no-test): the two that *were*
silent — gen.go classification and skip.go — are covered by the issue-4
self-tests. **Flag:** the DNS/TLS wait needs explicit timeout+backoff constants
in `common.sh`; note it for implementation.

## 13. Parallelization (worktree lanes)

| Step | Modules touched | Depends on |
|---|---|---|
| S1 TF edits (config_dir, spot, outputs) | `Terraform/` | — |
| S2 orchestration (run.sh, provision.sh, common.sh, reaper) | `integration-tests/lib`, `scripts/` | S1 (reads outputs) |
| S3 Go suite + harness | `integration-tests/suite` | — (offline-buildable) |
| S4 report generator | `integration-tests/report` | S3 (consumes registry shape) |
| S5 Ansible config_dir | `Ansible/playbooks` | — |

- **Lane A:** S1 → S2 (sequential — S2 consumes TF outputs).
- **Lane B:** S3 → S4 (sequential — shared registry types).
- **Lane C:** S5 (independent).

Launch A, B, C in parallel worktrees. They touch disjoint module dirs (no
conflict). Phase 0's first green run needs A+B merged; C lands with Phase 2.

## 14. Implementation Tasks
Synthesized from this review's findings. Each derives from a specific finding.

- [ ] **T1 (P1, human: ~2h / CC: ~20min)** — teardown — trap + standalone reaper
  - Surfaced by: Architecture issue 1 — leaked EC2 on crash, metal $4/hr
  - Files: `integration-tests/run.sh`, `scripts/integration-reap.sh`, `Makefile`
  - Verify: kill run.sh mid-apply, confirm destroy fires; reap finds stale itest tag
- [ ] **T2 (P1, human: ~half day / CC: ~25min)** — harness — hygiene contract
  - Surfaced by: Architecture issue 2 — shared infra collisions / flaky reds
  - Files: `suite/harness/client.go`, `suite/capacity_ops_test.go`, plan §3
  - Verify: each test deletes its sandbox; UC-62/65 run serial+last
- [ ] **T3 (P1, human: ~2h / CC: ~15min)** — config — runtime yq overlay, no committed copies
  - Surfaced by: Code-quality issue 3 + Codex #1/#4 — drift + prod AOCR/fleet side effects
  - Files: `integration-tests/lib/provision.sh`, `Terraform/{variables,locals}.tf`, `Ansible/playbooks/*.yml`
  - Verify: generated overlay has aocr/fleet off, leased domain set; Ansible reads config_dir
- [ ] **T4 (P1, human: ~1 day / CC: ~40min)** — harness — offline self-tests
  - Surfaced by: Test review issue 4 — silent-green / unguarded tripwire
  - Files: `suite/harness/skip_test.go`, `report/gen_test.go`, `integration-tests/provision_test.bats`
  - Verify: `make test` runs them offline; prod-key/domain inputs abort non-zero
- [ ] **T5 (P1, human: ~3h / CC: ~20min)** — TF — config_dir + spot, zero-diff gated
  - Surfaced by: review D2
  - Files: `Terraform/{variables,locals,nodes,outputs}.tf`
  - Verify: `scripts/terraform.sh plan` shows "No changes" against prod
- [ ] **T6 (P2, human: ~2h / CC: ~15min)** — TLS — UC-09 staging-root pinning
  - Surfaced by: Codex #6
  - Files: `suite/harness/client.go`, `suite/provisioning_test.go`
  - Verify: UC-09 validates against pinned LE staging root, not InsecureSkipVerify
- [ ] **T7 (P2, human: ~3h / CC: ~20min)** — registry — reframe UC-22, wire UC-35/36 FQDN
  - Surfaced by: Codex #3/#7 + unrunnable-UC decision
  - Files: `suite/harness/usecases.go`, `suite/cluster_test.go`, `scenarios/domains.yml`
  - Verify: UC-22→UC-58b cluster-only; custom-domain uses dedicated FQDN
- [ ] **T8 (P2, human: ~1h / CC: ~10min)** — cluster — shared cert storage + wasm module
  - Surfaced by: Codex #2/#7-wasm
  - Files: `scenarios/cluster-3-mixed.tfvars`, `scenarios/cluster-hetero.tfvars`, `scenarios/wasm/`
  - Verify: cluster overlays enable caddy_shared_cert_storage; wasm module pinned w/ digest
- [ ] **T9 (P2, human: ~30min / CC: ~5min)** — build — integration build tag
  - Surfaced by: Codex #5
  - Files: all `suite/*_test.go`, `integration-tests/run.sh`, `Makefile`
  - Verify: `go test ./...` does not pull in suite/; `-tags=integration` does
- [ ] **T10 (P3, human: ~1h / CC: ~10min)** — common.sh — DNS/TLS wait timeout+backoff
  - Surfaced by: Failure modes flag
  - Files: `integration-tests/lib/common.sh`
  - Verify: slow propagation retries within a bounded window, no false fail

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 8 gaps, all 8 folded in |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | CLEAR | 4 issues, all resolved; 0 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | n/a (infra/test tooling) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** found 8 repo-grounded gaps the review missed (config_dir not reaching Ansible, prod AOCR/fleet not neutralized, `make test` build-tag footgun, LE-staging-root TLS check, UC-22 has no public route, UC-35/36 custom-domain rejection, undefined wasm module, local-scenario naming). All 8 verified and folded into the plan.
- **CROSS-MODEL:** no tension — Codex's findings were additive (independent gaps), not contradictions of the review's findings. Both reviewers agree on the architecture.
- **VERDICT:** ENG CLEARED — ready to implement (start Phase 0 walking skeleton). Scope was reduced per review D1 (skeleton-first) and prod-safety gated per D2 (zero-diff plan).

NO UNRESOLVED DECISIONS
