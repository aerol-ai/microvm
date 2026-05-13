# AerolVM Native SDK Matrix

These are the first-party AerolVM SDKs that are shipped directly from this repository.

| AerolVM SDK | Repository path | Status | Notes |
|---|---|---|---|
| Go | `sdk/go` | Supported | First-party native SDK for the AerolVM `/v1` API. |
| Java | `sdk/java` | Supported | First-party native SDK for the AerolVM `/v1` API. |
| Python | `sdk/python` | Supported | First-party native SDK for the AerolVM `/v1` API. |
| Rust | `sdk/rust` | Supported | First-party native SDK for the AerolVM `/v1` API. |
| TypeScript | `sdk/typescript` | Supported | First-party native SDK for the AerolVM `/v1` API. |

## Notes

| Topic | Current state |
|---|---|
| Native API target | AerolVM SDKs target the native `/v1` API, not the `/daytona` compatibility facade. |
| Language parity | The repo ships five first-party AerolVM SDK languages today: Go, Java, Python, Rust, and TypeScript. |
| Compatibility mode | Daytona compatibility is additive and does not replace or modify the native AerolVM SDKs. |