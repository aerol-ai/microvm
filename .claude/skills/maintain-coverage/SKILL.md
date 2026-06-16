---
name: maintain-coverage
description: Keep the Go tree at its ~85% line-coverage bar when new or changed code lands. Finds the packages your branch touched, measures their coverage, locates the uncovered lines, and writes table-driven tests in the package's existing style. Use before opening any PR, or when the user says "add tests", "the new code has no tests", "check coverage", "bring this up to 85%", or "why did coverage drop". Proactively suggest right after a new package/driver/handler is written and before the PR goes up.
---

# Maintain the ~85% coverage bar

The Go tree (`./cmd/... ./internal/... ./pkg/...`) sits at **~85% line
coverage**. CI uploads the profile to Codecov on every push but does **not**
hard-fail below a threshold (no `codecov.yml` gate). The bar is therefore a
**team convention you enforce by hand** — new code that ships with no tests
silently drags the number down. This skill is the recipe to stop that.

## When this applies

- A new file or package was added (driver, pool, resolver, handler, client).
- An existing function grew new branches (error paths, retries, edge cases).
- Coverage "mysteriously" dropped on a PR.

## Recipe

### 1. Find what your branch changed

```sh
git diff --name-only origin/main...HEAD -- '*.go' | grep -v '_test.go$'
```

Map each changed `.go` file to its Go package (its directory). Those are the
packages whose coverage you must check. Ignore files under
`integration-tests/` (tag-gated, see §6) and generated code.

### 2. Measure per-package coverage

Run the **same command CI runs** (`.github/workflows/test.yml`), but you can
scope it to the packages you touched for a fast loop:

```sh
go test -count=1 -coverprofile=coverage.out ./internal/runtime/wasm/...
go tool cover -func=coverage.out | tail -n 1     # the package/total %
```

For the whole tree (what CI reports):

```sh
go test -count=1 -coverprofile=coverage.out ./cmd/... ./internal/... ./pkg/...
go tool cover -func=coverage.out | tail -n 1
```

A package below ~85% needs work. New packages frequently start near 0%.

### 3. Locate the uncovered lines

```sh
go tool cover -func=coverage.out | grep <yourpackage>   # per-function %
go tool cover -html=coverage.out -o coverage.html        # visual: red = uncovered
```

The per-function view tells you *which* functions are 0% / partial. The HTML
view (or reading the red spans) tells you *which branches* — usually error
paths, the `default:` of a switch, or a guard clause.

### 4. Write tests in the package's existing style

- **Match the table-driven pattern already in the package.** Don't invent a
  new harness. Canonical examples to copy from:
  - `internal/store/store_test.go` — store CRUD + host-port pool regression.
  - `internal/service/layer4_bootstrap_test.go` — latch / single-flight.
  - the `_test.go` next to whatever package you're covering.
- **Cover branches, not just lines.** Each error return, each `case`, each
  guard wants at least one test that reaches it.
- **Keep it offline.** No real network, AWS, or Docker in a plain `_test.go`
  (see §6). Use fakes/interfaces the package already exposes.
- **Comments explain WHY** (a tricky setup, a non-obvious edge), per the repo
  convention — not WHAT the assertion does.

### 5. Re-measure and confirm

Re-run §2 for the package. Confirm it's back at/above ~85% and the total
didn't regress. State the before/after numbers in the PR description.

### 6. What does NOT belong in unit tests

Live behavior that mocks can't prove is **tag-gated**, never in a plain
`_test.go`:

- `//go:build integration` → `integration-tests/suite/` and the
  `wasm-integration` CI job. Run via `make integration-*` (real AWS, costs
  money) or `go test -tags=integration`.
- `//go:build e2e` → ACME end-to-end, `make test-acme-e2e` (needs local
  Docker).

These do not count toward the `make test` / Codecov number, so don't try to
lift coverage by adding them.

## Mandatory regression tests (the floor, not the ceiling)

These areas require a regression test **and** a PR call-out regardless of the
coverage number (see `CLAUDE.md` Hard rules + `pr-review.md`):

- TCP host-port pool: `Store.TryReserveHostPort`, the `host_port` partial
  unique index, `Service.allocateHostPort` → `internal/store/store_test.go`.
- L4 bootstrap latch: `EnsureLayer4` / `EnsureLayer4Ready` / `l4Ready` →
  `internal/service/layer4_bootstrap_test.go`.
- `internal/network/tap` allocator (fragile like the host-port pool) →
  test next to `pool.go`.
- Cluster FSM / placement / recovery / heartbeat →
  `internal/cluster/*_test.go`.

## Checklist before the PR

- [ ] Every changed package re-measured at ~85%+ (numbers in PR description).
- [ ] New package/file has a `_test.go` beside it.
- [ ] New error paths / switch branches each have a test.
- [ ] Fragile-area changes (above) have their named regression test + call-out.
- [ ] No network/AWS/Docker in plain `_test.go`; live checks are tag-gated.
