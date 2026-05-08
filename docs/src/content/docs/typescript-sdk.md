---
title: TypeScript SDK
description: Use the TypeScript client from Node.js or other fetch-compatible runtimes to control sandboxes.
---

The TypeScript SDK lives under `sdk/typescript` and publishes as `@aerol-ai/microvm-sdk`.

## Install

```bash
npm install @aerol-ai/microvm-sdk
```

## Create A Client

```ts
import { MicroVM } from '@aerol-ai/microvm-sdk'

const client = new MicroVM({
  apiUrl: process.env.SB_API_URL,
  patToken: process.env.SB_PAT_TOKEN,
})
```

If you omit a field, the constructor falls back to `SB_API_URL`, `SB_PAT_TOKEN`, and finally `http://127.0.0.1:8080` for the API base URL.

## Create And Use A Sandbox

```ts
const sandbox = await client.create({
  image: 'ghcr.io/aerol-ai/ubuntu:22.04',
  cpu: 1,
  memoryMB: 1024,
  diskGB: 10,
  lifecycle: {
    stopIfIdleFor: 60 * 60 * 1_000_000_000,
    destroyAtAge: 24 * 60 * 60 * 1_000_000_000,
  },
})

const result = await sandbox.exec({ command: 'echo hello from typescript' })

console.log(result.stdout)
console.log(sandbox.publicURL)
console.log(sandbox.sshPublicKey)
console.log(sandbox.sshPrivateKey) // returned only by create()
```

`sandbox.exec()` accepts either a plain command string or a full request object with `workDir`, `env`, and `timeoutSeconds`.

## Streaming Exec And Sessions

```ts
const decoder = new TextDecoder()

const handle = sandbox.execStream({
  command: 'bash',
  tty: true,
  cols: 120,
  rows: 40,
  onStdout: chunk => process.stdout.write(decoder.decode(chunk, { stream: true })),
})

handle.write('echo streamed\n')

const exit = await handle.done
console.log(exit)
```

```ts
const session = await sandbox.createSession({
  name: 'shell',
  command: 'bash',
  workDir: '/workspace',
  pty: true,
  cols: 120,
  rows: 40,
})

const attached = sandbox.attachSession(session.id, {
  cols: 120,
  rows: 40,
  onStdout: chunk => process.stdout.write(decoder.decode(chunk, { stream: true })),
})

attached.write('echo attached\n')

const sessionExit = await attached.done
console.log(sessionExit)
```

## Additional Helpers

- `client.health()` returns the daemon, Docker, Caddy, and SSH gateway status.
- `client.mounts(id)` returns redacted mount specs with `hasCredentials` markers.
- `sandbox.uploadFile()` and `sandbox.downloadFile()` move bytes through the toolbox proxy.
- `sandbox.exposePort()` returns the public URL for that port.
- `sandbox.sessionLog()` and `sandbox.sessionRecording()` return `Uint8Array` payloads.

Lifecycle values are integer nanoseconds in the TypeScript API because the SDK maps the JSON wire format directly.