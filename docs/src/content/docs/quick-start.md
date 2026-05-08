---
title: Quick Start
description: Spin up a sandbox and run your first command in under five minutes.
---

**AerolVM** is an open-source, self-hostable infrastructure for running isolated code environments. It provides composable sandboxes — ephemeral Docker-backed containers with complete isolation, a dedicated filesystem, network stack, and allocated vCPU, RAM, and disk.

Sandboxes are the core primitive. Each sandbox is a Docker container managed by `sandboxd` (the host daemon) with `toolboxd` running inside to handle process execution, file transfers, and port management. Sandboxes spin up in seconds and can run any Docker image.

Agents and developers interact with sandboxes through the REST API or one of the official SDKs (TypeScript, Python, Go, Rust, Java). Operations span the full lifecycle: create, exec, stream output, transfer files, expose ports, and destroy.

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

Point the client at your `sandboxd` instance:

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

- [Getting Started](/getting-started) — build and run `sandboxd` locally
- [Sandboxes](/sandboxes) — lifecycle states and configuration options
- [Streaming Exec](/exec-streaming) — stream stdout/stderr live and use interactive PTY sessions
- [Sessions](/sessions) — persistent terminal sessions that survive reconnects
- [SDK Reference](/sdk-clients) — full API reference for every language
