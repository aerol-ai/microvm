# SDK Compatibility Matrix

This folder tracks the current AerolVM versus Daytona SDK compatibility state.

It is intentionally split into folders so the language-level view and the endpoint-level view stay separate:

| Folder | Purpose |
|---|---|
| `aerolvm/` | Native AerolVM SDK inventory and support status. |
| `daytona/` | Daytona SDK language inventory plus detailed `/daytona` facade support tables. |
| `comparison/` | High-level side-by-side summary of native AerolVM SDKs versus Daytona compatibility. |

## Status Legend

| Status | Meaning |
|---|---|
| Supported | Implemented and intended for normal use. |
| Partial | Implemented only for a subset of the external contract or with reduced semantics. |
| Unsupported | Not implemented in the current AerolVM facade. |

## Files

| File | Description |
|---|---|
| `aerolvm/native-sdk-matrix.md` | First-party AerolVM SDKs and their support level. |
| `daytona/sdk-language-matrix.md` | Official Daytona SDK families and how they map onto the AerolVM `/daytona` facade. |
| `daytona/control-plane-matrix.md` | Daytona control-plane routes and feature fields supported by AerolVM. |
| `daytona/toolbox-matrix.md` | Daytona toolbox routes and feature families supported by AerolVM. |
| `comparison/daytona-vs-aerolvm.md` | Short side-by-side view of native AerolVM SDKs versus Daytona compatibility mode. |

All tables reflect the current implementation in the repository as of 2026-05-13.