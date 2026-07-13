# Phase 0 decisions log — containerd engine

Operator-filled record for `plans/containerd-engine.md` Phase 0(e) exits.
Spike harnesses live under `integration-tests/suite/containerd_phase0_*.go`
(env-gated). **Do not flip the host default** until every row below is
`DECIDED` with a measured note.

| ID | Decision | Status | Record |
|---|---|---|---|
| 0a | docker+runsc cold/warm baseline (bench topology `with_gvisor=true`) | PENDING | Spike: measure Sentry boot + park-slot viability; paste p50 table here. |
| 0b | CreateSandbox-equivalent cold create via API (no `ctr`) in `aerolvm` ns | PENDING | `AEROL_CONTAINERD_SPIKE=1` → log elapsed + within 15% of §1 (~110ms cold target). |
| 0c | runsc boots + serves in driver-built netns+veth | PENDING | `AEROL_CONTAINERD_RUNSC_SPIKE=1`; proof of §4/§5 load-bearing bet. |
| 0d | CNI ADD latency × pool depth vs burst refill | PENDING | Confirm refill ticker math; note p50 ADD ms and chosen `SB_CONTAINERD_NETNS_POOL_DEPTH`. |
| 0e-1 | Shared vs dedicated containerd | DECIDED (default) | **Shared** system containerd + `aerolvm` namespace (coexist with dockerd `moby`). Code/wiring already assumes this; overturn only with measured upgrade/clobber risk on live hosts. |
| 0e-2 | config.toml-less runsc registration | DECIDED (default) | **No containerd config.toml edit** — shim on PATH + per-container runtime options + host-local `ensureRunscConfig` (`host-uds=open`). Live confirm Phase 0(c) still required. |
| 0e-3 | AppArmor profile | DECIDED (default) | **Do not assert AppArmor** beyond dockerd baseline for flip; parity gate is CapEff/Seccomp/NoNewPrivs/masked paths via `security_spec_diff`. Overturn if live AppArmor delta is measured weaker. |
| 0e-4 | containerd version pin | DECIDED (code) | Supported daemon majors **1.6–2.x** (`assertSupportedContainerdVersion`); Go client `v1.7.29`. `Connect` rejects out-of-range. Live confirm on Ubuntu LTS still needed. |
| DiskGB | overlayfs disk quota parity | DECIDED (soft-ignore) | See **DiskGB follow-up** below. |

## How to run spikes

```bash
# 0b — cold create equivalent
AEROL_CONTAINERD_SPIKE=1 \
  SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd \
  go test -tags='integration linux' -run TestContainerdPhase0CreateSpike \
  ./integration-tests/suite/

# 0c — runsc in prepaid netns
AEROL_CONTAINERD_RUNSC_SPIKE=1 \
  SB_TOOLBOX_BINARY_PATH=/usr/local/bin/toolboxd \
  SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true \
  go test -tags='integration linux' -run TestContainerdPhase0RunscNetns \
  ./integration-tests/suite/

# Security parity (Phase 1 / §8) once a live sandboxd is up
AEROL_SECURITY_SPEC_DIFF=1 go test -tags='integration linux' \
  -run TestSecuritySpecDiff ./integration-tests/suite/
```

## Sign-off

When all rows are `DECIDED`, paste the measured runsc table into
`plans/containerd-engine.md` §1/§5 and mark Phase 0 exit complete in the
plan status banner.

---

## DiskGB follow-up (deferred)

`CreateSandbox.disk_gb` is an **operator-facing quota hint**. Capacity
admission already reserves `DiskGB` against host budget (`pkg/capacity`);
that is scheduling math, not filesystem enforcement. This section covers
**in-guest writable-layer enforcement** only.

### What dockerd does today

| Path | Behavior |
|---|---|
| Runtime `docker` (runc) | Sets `HostConfig.StorageOpt["size"] = "<N>G"` (`pkg/docker/client.go`). |
| Runtime `gvisor` | **Ignores** with a warn — runsc does not honor StorageOpt size. |
| Backing FS | StorageOpt size only works when the graph driver supports it — typically **xfs + project quotas (`pquota`)** under `/var/lib/docker`. On ext4 / overlay without pquota, dockerd may accept the field and still not enforce. |

So even on the default docker engine, `DiskGB` is **best-effort**: admission
always accounts for it; kernel quota may or may not.

### What containerd does today

| Path | Behavior |
|---|---|
| Engine `containerd` + any OCI runtime | **Warn + ignore** in `internal/runtime/containerd/lifecycle.go` when `DiskGB > 0`. |
| Helper | `models.DiskGBEnforced(engine, runtime)` returns `false` for containerd and for gVisor; `true` only for docker+runc. |

There is no `StorageOpt` on the containerd create path. The default
snapshotter is **overlayfs**, which does not implement a dockerd-compatible
per-container size option out of the box.

### Why not shipped in Phase 3–5

1. **Host layout unknown.** Production nodes may be ext4, xfs, or mixed;
   overlay project-quota needs explicit mount options and tooling.
2. **API surface differs.** containerd/CRI expose disk limits via different
   knobs (e.g. snapshotter-specific, or cgroup `io` / separate volume mounts)
   — not a one-line port of StorageOpt.
3. **Parity honesty.** Soft-ignore + warn matches gVisor’s posture so we do
   not claim enforcement we cannot prove on the §8 soak hosts.
4. **Admission still works.** Overcommit risk is bounded by capacity
   reservation even without FS quota; the gap is only “sandbox can write
   past DiskGB until the host fills.”

### Candidate implementations (when un-deferred)

Pick one after measuring the soak hosts’ actual FS:

1. **overlayfs + project quota (xfs pquota / ext4 project)** — map each
   sandbox writable upperdir to a project ID sized to `DiskGB`. Closest to
   dockerd StorageOpt semantics; highest ops burden.
2. **Dedicated loop/block device or sparse file per sandbox** — mount as
   rootfs writable layer; hard size cap; heavier create latency.
3. **cgroup memory+disk I/O only** — does **not** cap bytes written; reject
   as a DiskGB substitute.
4. **Document permanent soft-ignore** — if product accepts admission-only
   disk accounting (same as gVisor today).

### Exit criteria to leave soft-ignore

- [ ] Inventory soak / prod node FS (`findmnt`, `xfs_info` / `tune2fs`) and
      record whether dockerd StorageOpt is actually enforced today.
- [ ] Choose option (1)/(2)/(4) and land driver support + unit tests.
- [ ] Live probe: write past `DiskGB` inside a sandbox → ENOSPC (or documented
      non-enforcement if (4)).
- [ ] Update `DiskGBEnforced` + this row to `DECIDED (enforced)` or
      `DECIDED (admission-only)`.
- [ ] Call out in PR description (boot-path / fragile if touching Create).

### Code pointers

- Docker apply: `pkg/docker/client.go` (`StorageOpt size`)
- containerd soft-ignore: `internal/runtime/containerd/lifecycle.go`
- Policy helper: `pkg/models/engine.go` (`DiskGBEnforced`)
- Plan risk: `plans/containerd-engine.md` §7.2
