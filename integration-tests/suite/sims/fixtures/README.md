# Simulation fixtures (vendored stubs)

Minimal fixture bundles for `integration-tests/suite/sims/`. Full examples
live in `~/aerolvm-examples`; these are pinned stubs sufficient for offline
catalogue wiring and optional live runs. Only files listed below exist — the
harness is self-contained and reads nothing from `~/aerolvm-examples` at runtime.

| Fixture | Source (when vendored) | Used by |
|---------|------------------------|---------|
| `postgres/init.sql` | stub (minimal RLS seed) | `postgres-supabase` sim — uploaded + applied, RLS then asserted |

The Redis and Jupyter sims need no fixture file: Redis auth is an inline
`--requirepass` arg and Jupyter's token is an inline `--NotebookApp.token` arg
(see `postgres.go`). Add fixture rows here only when a new sim vendors a real
bundle.

Pin real example commits here when copying from aerolvm-examples:

```
# example: git -C ~/aerolvm-examples rev-parse HEAD
# SOURCE_COMMIT=<sha>
```
