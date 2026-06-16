# arm64 (Graviton) Firecracker hosts

**Status:** implemented in code (2026-06-16). Live arm64 scenarios (T1/T3) still need
operator-run `make integration-arm64*` against Graviton metal + aarch64 kernel artifacts.
**Criticality:** Medium-effort, **high-blast-radius**. It intersects a
security-relevant correctness invariant (snapshot-clone CRNG reseed via
vmgenid), so it is NOT a "swap the instance type" change. Treat the Firecracker
driver + snapshot paths as the fragile area they are (CLAUDE.md: regression test
+ PR call-out required).

## Why this exists

AWS On-Demand "Standard" vCPU quota is the wall for x86 bare-metal Firecracker
hosts — `c5.metal` is 96 vCPU and blew both the Spot
(`MaxSpotInstanceCountExceeded`) and On-Demand (`VcpuLimitExceeded`, limit 32)
quotas during `make integration-cluster-hetero`. A quota increase (request
`f96b013c452a43e1aa88dbb475148864PY2WXGdy`, → 128 vCPU, CASE_OPENED) is the x86
unblock. ARM bare-metal is cheaper per vCPU, so this doc captures the ARM host
option as a deliberate product feature.

## Target decision (eng-review D1)

**Target Graviton2/3 metal (`c7g.metal` / `m6g.metal`), paired with the quota
bump — NOT `a1.metal`.**

- Firecracker's supported aarch64 hosts are **Graviton2 and Graviton3** (per
  Firecracker's support policy). `a1.metal` is **Graviton1 (Cortex-A72)**, which
  is NOT in that matrix.
- The only sub-32-vCPU ARM metal is `a1.metal` (16 vCPU). Every Graviton2/3
  metal (`c6g/c7g/m6g.metal`) is **64 vCPU** — over the current 32 quota.
- So "cheap ARM metal that Firecracker actually supports" requires a quota bump
  anyway. Since ARM and x86 both need quota, spend it on a supported SKU.
- `a1.metal` is demoted to an OPTIONAL spike target (see NOT in scope): if a
  time-boxed proof-of-boot shows Firecracker boots + snapshots correctly on
  Graviton1, it becomes a cheap CI/dev option. Not on the critical path.

## Cluster boundary decision (eng-review D5, from Codex outside-voice)

**Each cluster is single-arch (all-x86 OR all-arm64). NO mixed-arch clusters.**

Codex's critical finding: arch is not a first-class concept anywhere the
scheduler cares — `capacity.Snapshot` carries only `SupportedRuntimes` + bare
`LocalTemplateIDs` (`pkg/capacity/capacity.go:156,161`), placement only checks
`TemplateID` membership (`internal/cluster/placement.go:208`), and failover
replay only ships `TemplateID` into the recreate spec
(`internal/service/cluster_ownership.go:170`). Arch-tagging snapshot refs does
NOT make any of that arch-aware. Full mixed-arch support would mean threading
arch through capacity + placement + failover — i.e. editing the fragile cluster
FSM, the highest-risk area in the repo.

**Decision: homogeneous per-arch clusters.** This deletes the
scheduler/placement/failover problem entirely. The arch-tag guard (item 6)
shrinks from "a feature" to "defense-in-depth so a misconfigured node can't load
a foreign-arch image." Mixed-arch-in-one-cluster is explicitly NOT in scope (see
below) — revisit only if a single logical cluster must ever span archs.

## TL;DR

The codebase is mostly arch-neutral. The Firecracker Go driver compiles for
arm64 unchanged; `skopeo` already pulls host-arch guest images. The real costs
are: (1) producing/hosting an aarch64 guest kernel (`vmlinux` + `.config` with
`CONFIG_VMGENID=y`), and (2) re-validating the snapshot-clone CRNG reseed on a
**non-ACPI** architecture. Net ~M / 3–5 focused days (up from the first scope's
2–4 — snapshots + RNG validation are now in the first pass per eng-review D2).

## Already arch-neutral (verified — no work)

- **Firecracker Go driver** (`internal/runtime/firecracker/`) — no `GOARCH`/x86
  constants. Only platform-tagged files are `_linux`/`_other` (OS, not arch).
- **OCI rootfs builder** (`pkg/oci/builder.go`) — `skopeo copy` passes no
  `--override-arch`, so it defaults to the host arch. On an arm64 host it
  auto-pulls the arm64 image variant. Solves "guest images must be arm64" for
  any multi-arch image (alpine/python/etc. all are).
- **Per-node AMI override exists** (`Terraform/locals.tf:54`,
  `ami_id = coalesce(n.ami_id, var.ami_id, data.aws_ami.ubuntu.id)`).

## ⚠️ The correctness landmine (eng-review D2 — highest severity)

```
x86 (today)                              aarch64 (this plan)
-----------                              -------------------
Firecracker --(vmgenid via ACPI)-->      Firecracker --(vmgenid via FDT)-->
guest kernel CONFIG_VMGENID reseeds       guest kernel CONFIG_VMGENID reseeds
CRNG pre-userspace on restore             CRNG pre-userspace on restore
                                          ^^^ DIFFERENT delivery bus.
baseBootArgs keeps ACPI available         No ACPI bus on arm64 firecracker.
TestBootArgsKeepACPI guards it            That test's assertion is x86-framed.
```

`internal/runtime/firecracker/driver.go:1061`:
```go
const baseBootArgs = "console=ttyS0 reboot=k panic=1 pci=off nomodules quiet"
```
`bootargs_test.go::TestBootArgsKeepACPI` (driver.go:1051-1060 comment) is a
**security regression guard**, not a formatting check: vmgenid rides ACPI on
x86, and `CONFIG_VMGENID` reseeds the guest CRNG from it *before userspace* on
snapshot restore. That is the entire mechanism
`plans/snapshot-clone-rng-userspace.md` Phase C relies on to close the
snapshot-clone entropy window (two clones must not share CRNG state).

**aarch64 Firecracker has no ACPI** — vmgenid is delivered over FDT (device
tree). So on ARM both the delivery path and the regression test are x86-framed.
Shipping arm64 snapshots without re-validating this silently reopens the
snapshot-clone entropy window. **Decision (D2): port snapshots in the first
pass, but the arch-aware `bootargs_test` + an RNG-reseed assertion + dedicated
integration scenarios are part of that same pass — not a follow-up.**

## Work items

| # | Layer | Item | Size |
|---|-------|------|------|
| 1 | Terraform | **arch-aware** `data.aws_ami.ubuntu` (derive amd64/arm64 from instance_type or explicit arch field) | S |
| 2 | Bootstrap | point firecracker artifact URLs at arm64 builds | S (wiring) |
| 3 | **Artifacts** | **build/host aarch64 `vmlinux` (+`CONFIG_VMGENID=y`) + firecracker/jailer aarch64** | **M — critical path** |
| 4 | Driver | arch-conditional `baseBootArgs`; make `TestBootArgsKeepACPI` arch-aware (ACPI on x86, FDT vmgenid on arm64) | M + boot test |
| 5 | Driver/RNG | assert `CONFIG_VMGENID` CRNG reseed fires pre-userspace on Graviton restore | M (security-critical) |
| 6 | Pools/AOCR | **arch-tag snapshot/template refs (GOARCH) + guard the pull path** | M |
| 7 | Tests | arm64 integration scenarios (`.tfvars`+`.caps.yml`) + cross-arch snapshot UC | M |
| 8 | Driver | confirm no x86 CPU template default | XS (verify) |
| 9 | TF/Ansible | provisioning-time single-arch enforcement (plan + preflight) | S |

### 1. Terraform — arch-aware AMI (eng-review D3)
`Terraform/network.tf:11,19` hardcodes `amd64` / `x86_64`:
```hcl
values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
...
name   = "architecture"
values = ["x86_64"]
```
**Decision (D3): make the data source arch-aware** — derive `amd64`/`arm64`
(and the matching `x86_64`/`arm64` architecture filter) from the node's
`instance_type` (or a new explicit `arch` field on the node object in
`variables.tf:222-242`), so any arm64 node auto-resolves the right AMI. Use two
`aws_ami` data sources (one per arch) or a computed local; `locals.tf:54`
selects per node. DRY — no per-node AMI IDs to hand-maintain.
**Repercussion:** `locals.tf` node assembly (line 49-57) must pick the
arch-correct AMI; `nodes.tf` already reads `each.value.ami_id`. Validate that an
arm64 instance_type never pairs with an x86 AMI (add a `validation` block like
the existing role checks at `variables.tf:249-290`).
**Codex MEDIUM (must fix):** `locals.tf:54` is
`coalesce(n.ami_id, var.ami_id, data.aws_ami.ubuntu.id)` — it prefers the
cluster-wide `var.ami_id` (documented as an amd64 Ubuntu override,
`variables.tf:152`) over the data source. An arm64 node would silently inherit
the x86 override. Fix: either (a) make `var.ami_id` arch-keyed too, or (b) add a
validation that the resolved AMI's `architecture` matches the node's arch, or
(c) ignore the global `var.ami_id` for nodes whose arch != the override's arch.
Pick one; don't leave the global override as a silent footgun.

### 2. Bootstrap — artifact URLs
`firecracker.{binary,jailer,kernel,kernel_config}_url`
(`Terraform/variables.tf:365-368`) feed the curl-install block
(`bootstrap.sh.tftpl:279-300`). Wiring only — the work is item 3. The bootstrap
already hard-checks `CONFIG_VMGENID=y` (`bootstrap.sh.tftpl:314`), which the
arm64 kernel must also satisfy. **Repercussion:** none structurally; the
firecracker var defaults (`variables.tf:369-378`, paths like
`/usr/local/bin/firecracker`, `/var/lib/sandboxd/firecracker/vmlinux`) are
arch-neutral and stay.

### 3. Artifacts (the real cost — critical path)
- `firecracker` + `jailer` aarch64: upstream publishes `aarch64` release assets.
- **Guest kernel `vmlinux` (aarch64):** built with `CONFIG_VMGENID=y` plus the
  firecracker-recommended arm64 minimal config. The FDT vmgenid binding must be
  enabled so item 5's reseed works. This is the dependency everything waits on.
  **Repercussion:** wherever x86 vmlinux is built/hosted today, an arm64 twin
  must be produced and the URLs wired per item 2.

### 4. Driver — boot args + arch-aware regression test (D2)
`driver.go:1061` — `console=ttyS0` is the x86 8250 UART. Make `baseBootArgs`
arch-conditional (build-tagged or runtime `runtime.GOARCH` switch). Update
`bootargs_test.go::TestBootArgsKeepACPI` so it asserts the **correct vmgenid
path per arch**: ACPI-available on x86, FDT-vmgenid-available on arm64. Do NOT
just skip the test on arm64 — that drops the security guard.
**Repercussion:** `bootargs_test.go` becomes arch-parameterized; the
`bootArgsKeepACPI` invariant name/comment generalize to "vmgenid reachable".

### 5. RNG reseed assertion (security-critical, D2)
Add a test (or harness check) that `CONFIG_VMGENID` reseeds the guest CRNG
pre-userspace on a Graviton snapshot restore — the arm64 equivalent of the
Hazard-2 guarantee in `plans/snapshot-clone-rng-userspace.md`. If this can't be
asserted in a unit test, it lands in the arm64 integration scenario (item 7) as
an explicit check: restore two clones, confirm distinct CRNG state.
**Repercussion:** updates `plans/snapshot-clone-rng-userspace.md` to record the
arm64/FDT path alongside the x86/ACPI path.

### 6. Snapshot arch guard — defense-in-depth (D4, scoped down by D5)
With homogeneous per-arch clusters (D5), a node should never *see* a foreign-arch
snapshot. This item is now a **safety net against misconfiguration**, not a
scheduler feature — so it stays small.

Codex HIGH correction on the actual files (my first draft named the wrong ones):
- Bare snapshot/template names are canonicalized to AOCR refs **before
  placement** in `internal/service/image_distribution.go:76`.
- Pushers mint refs from bare IDs in
  `internal/service/snapshot_push.go:165` and
  `internal/service/template_push.go:189`.
So the tag must be applied at **push/canonicalization** time, and the **guard at
pull/resume** time — not just on a pull helper.

**Decision (D4): embed `GOARCH` in the pushed ref** (e.g. `...--arch-arm64`,
with "untagged == amd64" back-compat so in-flight x86 snapshots still resolve)
**and reject at resume** if a snapshot's arch != host. Unit test in the
snapshot-push package + the negative UC (item 7). **No** capacity/placement/
failover changes — D5 makes those unnecessary.
**Repercussion:** ref format gains an arch suffix; back-compat rule needed for
existing untagged x86 snapshots. This is a snapshot-path change — PR call-out per
CLAUDE.md, but NOT a cluster-FSM change (D5 kept it out of the fragile area).

### 7. Integration test scenarios (eng-review D2 — "so I can test it properly")
Follow the existing `.tfvars` + `.caps.yml` pattern
(`integration-tests/scenarios/single-node-wasm.*`). `capabilities: [firecracker]`
gates UC-24 / UC-47-50 (`runtimes_test.go:43`).

The homogeneity contract (D5) has THREE things to prove, not one: (a) each arch
works on its own, (b) the two archs produce equivalent behavior (no x86-only
assumptions silently passing), and (c) the system actively rejects a cross-arch
mix rather than half-working. The scenario set below covers all three.

```
HOMOGENEITY TEST MATRIX (D5)
                         x86 (existing)      arm64 (new)        cross-arch
single-node firecracker  single-node-fc *    single-node-fc-    n/a (1 node)
                         (or hetero today)   arm64  [NEW]
all-same-arch cluster    cluster-3-mixed     cluster-arm64      —
                         (x86 baseline)      [NEW]
homogeneity GUARD        —                   —                  UC-78 unit +
(reject foreign arch)                                           UC-79 live [NEW]
parity (same UCs green   UC-24/47-50/20-21   UC-24/47-50/20-21  diff = test
on both archs)           on x86              on arm64           failure
```

- **`single-node-fc-arm64.{tfvars,caps.yml}`** — one `c7g.metal` (or
  `m6g.metal`) worker, arm64 AMI, `capabilities: [docker, firecracker, domain]`.
  Exercises UC-24 (fc sandbox runs) + UC-47-50 (templates) + UC-20/21 (snapshot
  create/restore) on Graviton. **Parity rule:** this scenario runs the *same*
  firecracker UC set the x86 single-node scenario runs — any UC green on x86 but
  red on arm64 is a real arch regression, not a skip. The harness already gates
  by capability, so reuse the existing UC bodies; do NOT fork arm-specific copies
  (DRY — one UC, two scenarios).
- **`cluster-arm64.{tfvars,caps.yml}`** — a small all-arm64 cluster (3 Graviton2/3
  nodes) to prove the cluster paths (UC-03/05/06 forms+leader+count, UC-53/54/55
  placement/forward/index, UC-20/21 snapshot push+pull *between arm64 nodes*) on
  a homogeneous arm64 topology. This is the positive proof that a same-arch
  cluster is fully functional — the case D5 says is the ONLY supported one.
- **UC-78 (unit, offline):** the item-6 arch guard at the resume path — feed a
  foreign-arch (`--arch-amd64`) snapshot ref to an arm64 host and assert
  rejection. Cheap, runs in `make test`. Add to a new
  `internal/service/snapshots_arch_test.go`.
- **UC-79 (live, the homogeneity enforcement test):** the negative integration
  case — stand up an all-arm64 `cluster-arm64`, then attempt to seed it with an
  x86-tagged snapshot (push an `--arch-amd64` ref into the AOCR store the cluster
  pulls from) and assert every arm64 node **refuses to resume it** and surfaces a
  clear error, rather than crashing the VMM or silently producing garbage. This
  is what proves D5's boundary is *enforced*, not just *assumed*. Gate it behind
  a `mixed-arch-negative` capability so only this scenario runs it. (We do NOT
  build a live mixed-arch *cluster* — D5 says that topology is unsupported — we
  inject one foreign artifact into a homogeneous cluster and prove it bounces.)

**New use-cases to register** in the harness use-case registry
(`integration-tests/suite/harness/`) + a `snapshots_arch_test.go` in the suite:
UC-78 (offline guard), UC-79 (live foreign-arch rejection). Both map to the
item-6 guard so the report shows the homogeneity contract is covered.

**Repercussion:** the live scenarios cost money (operator-run via
`make integration-*`), behind the `integration` build tag — never in
`make test`. UC-78's offline unit case keeps the guard's core logic in the cheap
`make test` path; UC-79 is the live belt-and-suspenders proof. Add
`make integration-arm64` (single + cluster) and document in
`integration-tests/README.md`.

### 8. CPU templates
Firecracker x86 CPU templates (`T2`, `C3`) don't exist on aarch64. The driver
doesn't appear to set `CpuTemplate` — confirm nothing in config defaults one
that would 400 on arm64. Verify-only.

### 9. Provisioning-time homogeneity enforcement (eng-review D5 — shift-left)
D5 makes single-arch clusters the contract. Item 6/UC-79 enforce it at *runtime*
(a node refuses a foreign-arch snapshot). But the cheapest place to enforce it is
**before any instance boots** — a mixed-arch cluster should fail `terraform plan`,
not get discovered at first snapshot resume. Three enforcement layers, cheapest
first:

```
ENFORCEMENT LAYERS (cheapest → last-resort)
  terraform plan   →  validation: all nodes share one arch   [item 9, NEW]
  ansible preflight →  assert: all hosts same ansible_architecture  [item 9, NEW]
  runtime resume    →  reject foreign-arch snapshot (item 6 / UC-78 / UC-79)
```

- **Terraform** (`variables.tf`): add a `validation` block on `var.nodes`
  mirroring the existing role checks (`variables.tf:249-290`) —
  `length(distinct([for k, v in var.nodes : node_arch(v)])) == 1`, where
  `node_arch` derives from `instance_type` (or the explicit `arch` field added in
  item 1). Error message: "All nodes in a cluster must share one CPU
  architecture; mixed x86/arm64 clusters are unsupported (see
  plans/arm64-firecracker-hosts.md D5)." This makes `terraform plan` fail fast on
  a mixed map.
- **Ansible** (`Ansible/playbooks/`): add an `assert` preflight to the
  cluster-touching playbooks (`prepare-role-change.yml`, `configure-ops.yml`,
  `update-sandboxd.yml`) that `ansible_architecture` is identical across the
  play's hosts — catches a host that drifted or was added out-of-band outside
  Terraform. Fails before any change is applied.
**Repercussion:** a deliberately-mixed tfvars now fails at plan time (add a
negative Terraform test that asserts the validation fires). No effect on
single-arch clusters — `cluster-3-mixed` (all x86) and `cluster-arm64` (all
arm64) both pass. This is pure guardrail; it removes the "silently built a
mixed cluster" failure mode entirely.

## Files that change (complete list)

| File | Change | Risk |
|------|--------|------|
| `Terraform/network.tf` | arch-aware `aws_ami` data source(s) | low |
| `Terraform/variables.tf` | optional `arch` field on node object + validation | low |
| `Terraform/locals.tf` | select arch-correct AMI per node | low |
| `Terraform/templates/bootstrap.sh.tftpl` | (none structural; CONFIG_VMGENID check already present) | low |
| `internal/runtime/firecracker/driver.go` | arch-conditional `baseBootArgs` | **high** (boot path) |
| `internal/runtime/firecracker/bootargs_test.go` | arch-aware vmgenid assertion | **high** (security guard) |
| `internal/runtime/firecracker/*` (new RNG test) | pre-userspace reseed assertion | **high** |
| `internal/service/snapshot_push.go` / `template_push.go` | arch-tag ref at push (`:165` / `:189`) | medium |
| `internal/service/image_distribution.go` | arch-aware canonicalization (`:76`) | medium |
| `internal/service/*` (resume path) | reject foreign-arch snapshot at resume | medium (defense-in-depth) |
| `internal/pool/vmm/*` | arch-tag awareness on pooled snapshots | low (homogeneous cluster) |
| `plans/snapshot-clone-rng-userspace.md` | document arm64/FDT vmgenid path | low |
| `integration-tests/scenarios/single-node-fc-arm64.{tfvars,caps.yml}` | new scenario (parity UCs) | low |
| `integration-tests/scenarios/cluster-arm64.{tfvars,caps.yml}` | new all-arm64 cluster scenario | low |
| `internal/service/snapshots_arch_test.go` | new — UC-78 offline arch-guard unit | low |
| `integration-tests/suite/*` (registry + UC-78/UC-79) | foreign-arch rejection (offline + live) | medium |
| `Makefile` / `integration-tests/README.md` | `make integration-arm64` target + docs | low |
| `Terraform/variables.tf` (validation) | single-arch-cluster `validation` block + negative test | low |
| `Ansible/playbooks/{prepare-role-change,configure-ops,update-sandboxd}.yml` | `ansible_architecture` assert preflight | low |

## Validation plan

1. Build/host aarch64 `vmlinux` (+`CONFIG_VMGENID=y`, FDT vmgenid) and stage
   firecracker/jailer aarch64 binaries (item 3).
2. Bring up `single-node-fc-arm64` on `c7g.metal` with the arch-aware AMI
   (items 1-2). `CreateSandbox(runtime=firecracker)` → guest **boots to a
   working console** (proves item 4).
3. Snapshot create + restore on the arm64 node (UC-20/21); confirm the
   pre-userspace CRNG reseed (item 5) — two clones, distinct entropy.
4. UC-78 (offline unit): feed a foreign-arch (`--arch-amd64`) snapshot ref to the
   arm64 resume path; assert rejection (item 6 guard, runs in `make test`).
5. Parity: run the SAME firecracker UC set (UC-24/47-50/20-21) on both
   `single-node-fc-arm64` and the x86 baseline; any UC green on x86 but red on
   arm64 is an arch regression.
6. `cluster-arm64`: prove the homogeneous-arm cluster paths (UC-03/05/06,
   UC-53/54/55, UC-20/21 snapshot push+pull between arm64 nodes).
7. UC-79 (live homogeneity enforcement): inject an `--arch-amd64` snapshot into
   the all-arm64 cluster's AOCR store; assert every arm64 node refuses to resume
   it with a clear error (proves D5's boundary is enforced, not assumed).

## Parallelization

| Lane | Work | Depends on |
|------|------|------------|
| A | Artifacts: aarch64 vmlinux + firecracker/jailer (item 3) | — (blocks B, C) |
| B | Terraform arch-aware AMI + scenarios skeleton (items 1, 7-tfvars) | — |
| C | Driver boot-args + bootargs/RNG tests (items 4, 5) | A (needs a bootable arm64 kernel to validate) |
| D | Snapshot arch-tag + pull guard + UC-78 (items 6, 7-UC) | C (snapshots presuppose boot) |

Launch A + B in parallel. C waits on A. D waits on C. Item 8 (verify) anytime.

## NOT in scope (explicitly deferred)

- **Mixed-arch clusters (one cluster spanning x86 + arm64)** — D5. Arch is not
  modeled in `capacity.Snapshot`, `placement.go`, or failover replay
  (Codex critical). Supporting it means threading arch through the cluster FSM
  (the repo's highest-risk area). Homogeneous per-arch clusters avoid it
  entirely. Revisit only if a single logical cluster must span archs; the work
  is capacity + placement + failover, not just ref tagging.
- **`a1.metal` / Graviton1 support** — Firecracker doesn't officially support
  Graviton1. Optional time-boxed proof-of-boot spike only; not on the critical
  path. If it boots + snapshots cleanly, revisit as a cheap CI/dev target.
- **arm64 warm-pool tuning** (`internal/pool/vmm` depth/refill heuristics for
  Graviton) — ships functional; perf-tune later.
- **Multi-arch image build pipeline for first-party guest images** — skopeo
  already pulls host-arch for multi-arch upstream images; first-party arm64
  image builds are separate work.
- **x86 quota path** — the quota bump (CASE_OPENED) remains the way to green the
  current `cluster-hetero` run; independent of this plan.

## Failure modes

| Codepath | Realistic failure | Test? | Error handling? | User sees |
|----------|-------------------|-------|-----------------|-----------|
| arm64 boot args | `console=ttyS0` wrong on arm → guest boots but no console / hangs | item 4 boot test | VMM exit on panic=1 | sandbox stuck in `starting` then fails |
| vmgenid/FDT reseed | reseed doesn't fire pre-userspace → **two clones share CRNG** (silent) | item 5 (CRITICAL) | none today on arm | **silent** — security bug, no surface error |
| cross-arch snapshot pull | arm64 node loads x86 memory image → VMM crash/garbage | item 6 + UC-78 (offline) + UC-79 (live) | resume guard rejects | sandbox fails to resume, clear error |
| arch-aware AMI | arm64 instance + x86 AMI → instance won't boot | item 1 validation | TF plan-time validation | terraform apply error |
| mixed-arch cluster built | operator mixes archs in one `var.nodes` map → cluster half-works | item 9 (TF validation negative test) | TF plan fails + Ansible preflight assert | `terraform plan` error before any instance boots |

**Critical gap:** the vmgenid/FDT reseed (item 5) is the one failure that is
**silent AND security-relevant** — no error surfaces, two clones just share
entropy. This is why D2 puts the RNG assertion in the first pass, not a
follow-up.

## Implementation Tasks
Synthesized from this review's findings. Each derives from a specific finding.
Run with Claude Code or Codex; checkbox as you ship.

- [ ] **T1 (P1, human: ~2d / CC: ~varies)** — Artifacts — build/host aarch64 `vmlinux` (`CONFIG_VMGENID=y`, FDT vmgenid) + firecracker/jailer aarch64
  - Surfaced by: Architecture — item 3, critical path; blocks T3/T4
  - Files: build/release pipeline + `Terraform/variables.tf` firecracker `*_url`
  - Verify: arm64 node boots a firecracker sandbox to a working console
- [x] **T2 (P1, human: ~3h / CC: ~30min)** — Driver — arch-conditional `baseBootArgs` + arch-aware `TestBootArgsKeepACPI`
  - Surfaced by: Architecture Issue 1 — `driver.go:1061`, `bootargs_test.go:18-28`
  - Files: `internal/runtime/firecracker/driver.go`, `bootargs_test.go`
  - Verify: `go test ./internal/runtime/firecracker/...` green on both arch assertions
- [ ] **T3 (P1, human: ~4h / CC: ~1h)** — Driver/RNG — assert CONFIG_VMGENID CRNG reseed fires pre-userspace on Graviton restore
  - Surfaced by: Architecture Issue 1 / critical gap — `plans/snapshot-clone-rng-userspace.md` Phase C
  - Files: `internal/runtime/firecracker/*`, integration scenario
  - Verify: two arm64 clones restored from one snapshot have distinct CRNG state
- [x] **T4 (P1, human: ~4h / CC: ~45min)** — Snapshot — arch-tag refs at push + reject foreign-arch at resume
  - Surfaced by: Architecture Issue 2 + Codex HIGH — `snapshot_push.go:165`, `template_push.go:189`, `image_distribution.go:76`
  - Files: those + resume path; new `snapshots_arch_test.go` (UC-78)
  - Verify: foreign-arch (`--arch-amd64`) ref rejected on arm64 host; untagged x86 still resolves
- [x] **T5 (P2, human: ~2h / CC: ~30min)** — Terraform — arch-aware AMI data source + harden `var.ami_id` override
  - Surfaced by: Code Quality Issue 3 + Codex MEDIUM — `network.tf:11,19`, `locals.tf:54`, `variables.tf:152`
  - Files: `Terraform/network.tf`, `variables.tf`, `locals.tf`
  - Verify: `terraform validate`; arm64 instance_type resolves arm64 AMI, never inherits the amd64 global override
- [x] **T6 (P2, human: ~5h / CC: ~1h)** — Tests — arm64 homogeneity test matrix
  - Surfaced by: Test review + user (homogeneity across archs) — parity + positive cluster + enforcement
  - Files: `integration-tests/scenarios/single-node-fc-arm64.{tfvars,caps.yml}`, `cluster-arm64.{tfvars,caps.yml}`, `internal/service/snapshots_arch_test.go`, harness registry (UC-78/UC-79), `Makefile`, `integration-tests/README.md`
  - Verify: parity UCs green on both archs; `cluster-arm64` cluster UCs green; UC-78 offline rejection in `make test`; UC-79 live arm64 node refuses an `--arch-amd64` snapshot with a clear error
- [x] **T7 (P3, human: ~15min / CC: ~5min)** — Driver — confirm no x86 CPU template default leaks to arm64
  - Surfaced by: Architecture — item 8, verify-only
  - Files: `internal/runtime/firecracker/driver.go` + config defaults
  - Verify: grep confirms no `CpuTemplate` default; arm64 create doesn't 400
- [x] **T8 (P2, human: ~2h / CC: ~30min)** — TF/Ansible — provisioning-time single-arch enforcement
  - Surfaced by: Architecture item 9 (user: enforce homogeneity in Terraform + Ansible) — shift-left of D5
  - Files: `Terraform/variables.tf` (validation + negative test), `Ansible/playbooks/{prepare-role-change,configure-ops,update-sandboxd}.yml` (assert preflight)
  - Verify: a mixed-arch `var.nodes` fails `terraform plan`; single-arch passes; Ansible play aborts if hosts report differing `ansible_architecture`

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 1 | issues_found | 3 findings (1 critical, 1 high, 1 medium), all folded |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | clean | 6 issues, 1 critical gap (vmgenid RNG), all resolved |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | n/a (infra) |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **CODEX:** flagged mixed-arch isn't modeled in capacity/placement/failover (→ chose homogeneous per-arch clusters, D5), corrected the real snapshot-resolution files (`image_distribution.go:76`, `snapshot_push.go:165`), and the `var.ami_id` override footgun — all absorbed into the plan.
- **CROSS-MODEL:** review assumed mixed-arch clusters + ref-tagging; Codex showed that's insufficient. Resolved toward Codex (homogeneous clusters) by user decision D5 — lower blast radius, deletes the FSM work.
- **VERDICT:** ENG CLEARED — ready to implement (deferred behind x86 quota path). 5 decisions locked (D1 target Graviton2/3; D2 snapshots+RNG first pass; D3 arch-aware AMI; D4 arch-tag guard; D5 homogeneous clusters).

NO UNRESOLVED DECISIONS
