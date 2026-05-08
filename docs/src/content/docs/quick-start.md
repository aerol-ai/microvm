---
title: Quick Start
---

**AerolVM** is open-source infrastructure for running isolated code environments. Each sandbox is a fully isolated compute unit with its own filesystem, network stack, and allocated vCPU, RAM, and disk.

## Runtimes

AerolVM supports multiple container runtimes, giving you a choice between security and compatibility:

| Runtime | Status | Use Case |
|---|---|---|
| Docker | ✅ Available | Fast startup, broad image compatibility, standard workloads |
| GVisor | 🗓 Planned | Kernel-level isolation without a full VM - ideal for untrusted code |
| Kata Containers | 🗓 Planned | Full VM isolation with hardware virtualization |
| WebAssembly | 🗓 Planned | Ultra-lightweight, portable workloads |

Today, sandboxes run on Docker. GVisor, Kata, and WebAssembly support are on the roadmap.

## Use Cases

- **AI code execution** - run LLM-generated code safely in isolated environments
- **CI / ephemeral build agents** - spin up a fresh environment per job, destroy when done
- **Interactive developer environments** - persistent workspaces with SSH, port previews, and file sync
- **Data processing pipelines** - attach cloud storage, run transforms, and extract results

---

## 1. Install the SDK

Pick any language:

```bash
# TypeScript / Node.js
npm install @aerol-ai/aerolvm-sdk

# Python
pip install aerolvm-sdk

# Go
go get github.com/aerol-ai/microvm/sdk/go/pkg/microvm@latest

# Rust
cargo add aerolvm-sdk
```

## 2. Create a Sandbox

```ts
import { MicroVM } from '@aerol-ai/aerolvm-sdk'

const client = new MicroVM({
  apiUrl: process.env.SB_API_URL,
  apiKey: process.env.SB_PAT_TOKEN,
})

const sandbox = await client.create({
  image: 'ubuntu:22.04',
})

console.log(sandbox.id)
console.log(sandbox.publicUrl)
```

## 3. Run a Command

```ts
const result = await sandbox.exec({ command: 'echo hello from sandbox' })
console.log(result.stdout) // "hello from sandbox\n"
```

## 4. Transfer a File

```ts
const content = Buffer.from('print("hello")')
await sandbox.uploadFile('/workspace/hello.py', content)

const out = await sandbox.exec({ command: 'python3 /workspace/hello.py' })
console.log(out.stdout) // "hello\n"
```

## 5. Destroy the Sandbox

```ts
await sandbox.destroy()
```

## Next Steps

- [Getting Started](/getting-started) - self-host AerolVM on your own infrastructure
- [Sandboxes](/sandboxes) - lifecycle states and configuration options
- [Streaming Exec](/exec-streaming) - stream stdout/stderr live and use interactive PTY sessions
- [Sessions](/sessions) - persistent terminal sessions that survive reconnects
- [SDK Reference](/sdk-clients) - full API reference for every language
