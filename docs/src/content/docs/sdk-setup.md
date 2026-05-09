---
title: SDK Setup
---

All AerolVM SDKs connect to the same REST API using a PAT token set during server installation.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `SB_PAT_TOKEN` | Yes | The token set with `--pat-token` during installation. |
| `SB_API_URL` | No | Server base URL. Defaults to `http://127.0.0.1:21212` if omitted. |

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
print(sandbox['public_url'])
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
