---
title: Streaming Exec
description: Stream stdout and stderr live, allocate PTYs, forward stdin, and control long-running processes.
---

# Streaming exec (with optional PTY)

`sandbox.exec()` runs a command, buffers its full output, and returns when the
command exits. That's fine for short commands but unusable for long-running
processes (you can't see output until it finishes), large outputs (`toolboxd`
buffers everything in RAM), or interactive shells.

`sandbox.execStream()` is the streaming variant. It opens a WebSocket to the
sandbox, streams stdout/stderr live, accepts stdin from the client, and
optionally allocates a pseudo-terminal so interactive programs (`bash`,
`vim`, `top`, and similar tools) work correctly.

## When to use which

| Use case | Method |
| --- | --- |
| `ls`, `git status`, anything short and non-interactive | `sandbox.exec()` |
| `npm install`, `make`, anything where you want live output | `sandbox.execStream()` |
| `bash`, `python -i`, `vim`, anything interactive | `sandbox.execStream({ tty: true })` |
| Multi-gigabyte output (logs, archives, and similar workloads) | `sandbox.execStream()` |

`exec` keeps working unchanged. `execStream` is purely additive.

## SDK usage

### Live output, no interactivity

```ts
const handle = sandbox.execStream({
  command: 'npm install',
  workdir: '/workspace',
  onStdout: chunk => process.stdout.write(chunk),
  onStderr: chunk => process.stderr.write(chunk),
})

const { code } = await handle.done
console.log(`npm install exited with ${code}`)
```

`onStdout` and `onStderr` receive `Uint8Array` chunks as they arrive with no
buffering on the toolbox side. The `done` promise resolves when the process
exits with the exit code and, if relevant, the signal name.

### Interactive shell with PTY

```ts
const handle = sandbox.execStream({
  command: 'bash',
  tty: true,
  cols: process.stdout.columns,
  rows: process.stdout.rows,
  onStdout: chunk => process.stdout.write(chunk),
})

process.stdin.setRawMode?.(true)
process.stdin.on('data', chunk => handle.write(chunk))

process.stdout.on('resize', () => {
  handle.resize(process.stdout.columns, process.stdout.rows)
})

await handle.done
```

In TTY mode stdout and stderr are merged onto the PTY, so only `onStdout`
fires. Without `tty: true`, the two streams are kept separate.

### Sending signals

```ts
handle.signal('INT')
handle.signal('TERM')
handle.signal('KILL')
```

Signals target the process group, so child processes receive them too.

## Wire protocol

### Endpoint

```text
WS  ws(s)://<sandboxd>/v1/sandboxes/<id>/toolbox/process/exec/stream
```

### Authentication

Two equivalent options are supported:

1. `Authorization: Bearer <pat-token>` for HTTP clients that can send headers.
2. `Sec-WebSocket-Protocol: sandbox.bearer, <pat-token>` for browser WebSocket clients.

### Handshake

The first client frame is a JSON text frame that describes the process to run:

```json
{
  "command": "bash -lc 'echo hello'",
  "workdir": "/workspace",
  "env": {"FOO": "bar"},
  "tty": true,
  "cols": 80,
  "rows": 24
}
```

`command` is required. Everything else is optional.

## Toolboxd implementation notes

- Endpoint registration lives in `cmd/toolboxd/exec_stream.go`.
- The transport is WebSocket based.
- The implementation is additive and does not replace the buffered `exec` path.