---
title: SDK Clients
description: The repository ships SDKs for Go, TypeScript, Python, and Rust, all using bearer-token authentication.
---

## SDK Locations

- Go: `sdk/go`
- TypeScript: `sdk/typescript`
- Python: `sdk/python`
- Rust: `sdk/rust`

## Authentication Model

All SDKs send the PAT as `Authorization: Bearer <token>`.

### Go

```go
import (
    "os"

    microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
    "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

client, err := microvm.NewClientWithConfig(&types.MicroVMConfig{
    PATToken: os.Getenv("SB_PAT_TOKEN"),
    APIUrl:   "https://sandbox-api.example.com",
})
```

### TypeScript

```ts
import { MicroVM } from '@aerol-ai/microvm-sdk'

const client = new MicroVM({
  apiUrl: 'https://sandbox.example.com',
  patToken: process.env.SB_PAT_TOKEN,
})
```

### Python

```py
from microvm import MicroVM

client = MicroVM(api_url='https://sandbox.example.com', pat_token='${SB_PAT_TOKEN}')
```

### Rust

```rust
use microvm_sdk::Client;

let client = Client::new(Some("https://sandbox.example.com"), Some("your_token"))?;
```

## Recommended Next Reads

- [Getting Started](/getting-started) for local setup.
- [Streaming Exec](/exec-streaming) for interactive process control.
- The SDK examples under each language folder for end-to-end usage.