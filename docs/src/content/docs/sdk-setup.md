---
title: SDK Setup
description: Connect AerolVM's native SDKs or compatible Daytona and E2B clients to your server.
---

All AerolVM SDKs connect to the same REST API using a PAT token set during server installation. AerolVM also exposes compatibility facades for the Daytona SDK and E2B SDK, so existing clients can point at the same server without a rewrite.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `SB_PAT_TOKEN` | Yes | The token set with `--pat-token` during installation. |
| `SB_API_URL` | No | Server base URL. Defaults to `http://127.0.0.1:21212` if omitted. |

## Compatibility SDKs

### Daytona

AerolVM exposes a Daytona-compatible API under `/daytona`. Use the official Daytona SDK with your normal AerolVM PAT token and point its `apiUrl` at `https://your-host/daytona`.

See [Using Daytona SDK](/using-daytona-sdk) for setup details and example code.

### E2B

AerolVM also exposes an E2B-compatible control plane under `/e2b` and a runtime proxy under `/e2b/runtime`. Existing E2B SDK code usually only needs environment variable changes.

See [Using E2B SDK](/using-e2b-sdk) for the required environment variables, examples, and current compatibility limits.

## TypeScript

```bash
npm install @aerol-ai/aerolvm-sdk
```

```ts
import { MicroVM } from '@aerol-ai/aerolvm-sdk'

const client = new MicroVM({
  apiUrl: process.env.SB_API_URL,
  patToken: process.env.SB_PAT_TOKEN,
})

const sandbox = await client.create({ image: 'ubuntu:22.04' })
console.log(sandbox.publicUrl)
await sandbox.destroy()
```

## Python

```bash
pip install aerolvm-sdk
```

```py
from microvm import MicroVM

client = MicroVM(
    api_url='https://sandbox.example.com',
    pat_token='your-token',
)

sandbox = client.create(image='ubuntu:22.04')
print(sandbox['id'])
sandbox.destroy()
```

## Go

```bash
go get github.com/aerol-ai/microvm/sdk/go/pkg/microvm@latest
```

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

sandbox, err := client.Create(ctx, microvm.CreateOptions{Image: "ubuntu:22.04"})
fmt.Println(sandbox.PublicURL)
defer client.Destroy(ctx, sandbox.ID)
```

## Java

Add the GitHub Packages repository and dependency to your `pom.xml`. See [Server Setup](/getting-started) for the GitHub token needed for `read:packages`.

```java
import ai.aerol.microvm.MicroVMClient;
import ai.aerol.microvm.MicroVMConfig;

MicroVMClient client = new MicroVMClient(
    new MicroVMConfig()
        .setApiUrl("https://sandbox.example.com")
        .setPatToken(System.getenv("SB_PAT_TOKEN"))
);
```

## Rust

```bash
cargo add aerolvm-sdk
```

```rust
use aerolvm_sdk::Client;

let client = Client::new(
    Some("https://sandbox.example.com"),
    Some("your-token"),
)?;
```

## Next Steps

- [Quick Start](/quick-start) - run your first command inside a sandbox
- [Create Sandbox](/sandboxes) - full sandbox lifecycle with all SDK examples
