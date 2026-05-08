---
title: SDK Overview
description: Package names, shared auth, and cross-language behavior for the Go, TypeScript, Python, and Rust SDKs.
---

This docs section mirrors the Daytona docs layout, but the content here is taken from the SDKs that live in this repository today.

## Packages

| Language | Package | Install |
| --- | --- | --- |
| Go | `github.com/aerol-ai/microvm/sdk/go/pkg/microvm` | `go get github.com/aerol-ai/microvm/sdk/go/pkg/microvm@latest` |
| TypeScript | `@aerol-ai/microvm-sdk` | `npm install @aerol-ai/microvm-sdk` |
| Python | `aerol-ai-microvm-sdk` | `pip install aerol-ai-microvm-sdk` |
| Rust | `microvm-sdk` | `cargo add microvm-sdk` |

If you are working directly from this repository, each SDK can also be installed from its matching `sdk/<language>` directory.

## Shared Configuration

All SDKs send the PAT as `Authorization: Bearer <token>`.

- `SB_PAT_TOKEN` is required unless you pass the token explicitly.
- `SB_API_URL` is optional; when omitted, the SDKs default to `http://127.0.0.1:8080`.

## Shared Capabilities

All four SDKs cover the main control-plane surface:

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
import { MicroVM } from '@aerol-ai/microvm-sdk'

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
use microvm_sdk::Client;

let client = Client::new(Some("https://sandbox.example.com"), Some("your-token"))?;
```

Start with the language page that matches your project, then pair it with [Getting Started](/getting-started) if you also need to stand up `sandboxd` locally.