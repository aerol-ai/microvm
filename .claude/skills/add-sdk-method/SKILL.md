---
name: add-sdk-method
description: Add a method across all five AerolVM SDKs (TypeScript, Python, Go, Rust, Java) in lockstep, plus the synced docs example. Use when the user asks to "expose this in the SDK", "add an SDK method", "wire this up in the clients", or whenever a new /v1 endpoint needs SDK coverage. Proactively suggest after a new /v1 endpoint lands to keep SDK parity.
---

# Add a method to all five SDKs

The SDKs are kept lockstep so the docs' five-tab examples stay accurate.
Touching one SDK without the others should be rare and explained in the PR.

## Per-SDK file map

| SDK | Public surface | Transport (versioned) | Tests |
|---|---|---|---|
| TypeScript | `sdk/typescript/src/Sandbox.ts`, `MicroVM.ts`, `types.ts` | `sdk/typescript/src/internal/api/v1/` | `sdk/typescript/src/*.test.ts` |
| Python | `sdk/python/microvm/client.py`, `types.py` | `sdk/python/microvm/_internal/api/v1/` | `sdk/python/tests/` |
| Go | `sdk/go/pkg/microvm/`, `sdk/go/pkg/types/` | `sdk/go/internal/apiclient/v1/` | `*_test.go` next to source |
| Rust | `sdk/rust/src/lib.rs`, `types.rs` | `sdk/rust/src/` | inline `#[cfg(test)]` |
| Java | `sdk/java/src/main/java/...` | same tree | `sdk/java/src/test/java/...` |

## Per-SDK steps (repeat 5×)

1. Add request/response types in that SDK's `types.*`.
2. Add the transport call in the `v1/` (or equivalent) versioned module.
   **Use the SDK's existing `versioned()` helper / `apiVersion` option — do not
   hand-build `/v1/...` URLs at the call site.** This is what lets `apiVersion`
   pin work without rewriting every method.
3. Surface the new method on the public client (`Sandbox` or `MicroVM`).
4. Add a test.
5. If this SDK is the canonical example for any docs page, update the example.

## Verify locally

```
(cd sdk/typescript && npm ci && npm run build && npm test)
(cd sdk/python && python -m unittest discover -s tests -v)
(cd sdk/go && go test ./...)
(cd sdk/rust && cargo test)
(cd sdk/java && mvn -B -ntp test)
```

CI is path-filtered (`.github/workflows/test.yml`) — only the SDKs whose folders changed will run on PR, so local verification of unchanged SDKs is the only way to catch parity drift before merge.

## Style

- **One PR per method, all 5 SDKs.** Splitting drift across PRs has burned us — keep parity atomic.
- **No version-leakage into the public surface.** Callers pick `apiVersion`; method signatures don't include `v1`.
- **Match the existing argument style of nearby methods** in each SDK. Don't impose Go-isms on Python, etc.
