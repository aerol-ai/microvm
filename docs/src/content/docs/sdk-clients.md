---
title: SDK Overview
---

AerolVM provides official SDKs for five languages. All SDKs cover the same core surface and share the same authentication model.

## Packages

| Language | Package | Install |
| --- | --- | --- |
| Go | `github.com/aerol-ai/microvm/sdk/go/pkg/microvm` | `go get github.com/aerol-ai/microvm/sdk/go/pkg/microvm@latest` |
| TypeScript | `@aerol-ai/aerolvm-sdk` | `npm install @aerol-ai/aerolvm-sdk` |
| Python | `aerolvm-sdk` | `pip install aerolvm-sdk` |
| Rust | `aerolvm-sdk` | `cargo add aerolvm-sdk` |
| Java | `ai.aerol:microvm-sdk` | See [Java SDK](/java-sdk) for Maven/Gradle setup |

If you are working directly from this repository, each SDK can also be installed from its matching `sdk/<language>` directory.

The Go SDK version is derived from repository tags, not a separate `sdk/go` manifest version. Pin it with a repo tag such as `@v0.1.1`.

## Shared Configuration

All SDKs send the PAT as `Authorization: Bearer <token>`.

- `SB_PAT_TOKEN` is required unless you pass the token explicitly.
- `SB_API_URL` is optional; when omitted, the SDKs default to `http://127.0.0.1:8080`.

## Shared Capabilities

All SDKs cover the main API surface:

- create, list, get, start, stop, destroy, resize, and lifecycle updates
- `GET /health`, mount inspection, file upload/download, and public port exposure
- one-shot exec, streaming exec over WebSocket, and long-lived sessions
- session logs and terminal recordings

Go tracks the wire model most directly because `sdk/go/pkg/types` aliases the server request and response types. The other SDKs expose the same core workflow with language-native wrappers.

## Behavior To Remember

- `create()` is the only call that returns the one-time SSH private key. Persist it immediately; later `get()` and `list()` calls only expose the public key.
- `mounts()` returns redacted mount definitions. Credential material is never returned by the API.
- Go uses `time.Duration` for lifecycle fields. TypeScript, Python, and Rust use integer nanoseconds to match the JSON wire format.

## Language Guides

- [Go SDK](/go-sdk)
- [TypeScript SDK](/typescript-sdk)
- [Python SDK](/python-sdk)
- [Rust SDK](/rust-sdk)
- [Java SDK](/java-sdk)

## Quick Auth Example

### Go

```go
import (
    "os"

    microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
    sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

client, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{
    PATToken: os.Getenv("SB_PAT_TOKEN"),
    APIUrl:   os.Getenv("SB_API_URL"),
})
```

### TypeScript

```ts
import { MicroVM } from '@aerol-ai/aerolvm-sdk'

const client = new MicroVM({
  apiUrl: process.env.SB_API_URL,
  patToken: process.env.SB_PAT_TOKEN,
})
```

### Python

```py
from microvm import MicroVM

client = MicroVM(api_url='https://sandbox.example.com', pat_token='your-token')
```

### Rust

```rust
use aerolvm_sdk::Client;

let client = Client::new(Some("https://sandbox.example.com"), Some("your-token"))?;
```

Start with the language page that matches your project. If you need to self-host AerolVM, see [Server Setup](/getting-started).
