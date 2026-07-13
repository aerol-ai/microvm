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
| DiskGB | overlayfs disk quota parity | DECIDED (soft-ignore) | containerd warns + ignores `DiskGB` (no StorageOpt equivalent yet). Same soft-ignore posture as gVisor until overlay project-quota lands. |

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
