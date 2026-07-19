# Simulation fixtures (vendored stubs)

Minimal fixture bundles for `integration-tests/suite/sims/`. Full examples
live in `~/aerolvm-examples`; these are pinned stubs sufficient for offline
catalogue wiring and optional live runs.

| Fixture | Source (when vendored) | Used by |
|---------|------------------------|---------|
| `postgres/init.sql` | stub (minimal RLS seed) | `postgres-supabase` sim |
| `redis/rest-proxy.sh` | stub | `redis-upstash` sim (REST path) |
| `jupyter/token.txt` | stub | `jupyter-headless` sim |

Pin real example commits here when copying from aerolvm-examples:

```
# example: git -C ~/aerolvm-examples rev-parse HEAD
# SOURCE_COMMIT=<sha>
```
