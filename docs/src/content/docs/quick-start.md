---
title: Quick Start
description: Spin up a sandbox and run your first command in under five minutes.
---

This guide assumes you have a running `sandboxd` instance. If not, see [Getting Started](/getting-started) first.

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

- [Sandboxes](/sandboxes) — lifecycle states and configuration options
- [Streaming Exec](/exec-streaming) — stream stdout/stderr live and use interactive PTY sessions
- [Sessions](/sessions) — persistent terminal sessions that survive reconnects
- [SDK Reference](/sdk-clients) — full API reference for every language
