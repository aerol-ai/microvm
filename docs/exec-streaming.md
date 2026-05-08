# Streaming exec (with optional PTY)

`sandbox.exec()` runs a command, buffers its full output, and returns when the
command exits. That's fine for short commands but unusable for long-running
processes (you can't see output until it finishes), large outputs (toolboxd
buffers everything in RAM), or interactive shells.

`sandbox.execStream()` is the streaming variant. It opens a WebSocket to the
sandbox, streams stdout/stderr live, accepts stdin from the client, and
optionally allocates a pseudo-terminal so interactive programs (`bash`,
`vim`, `top`, etc.) work correctly.

## When to use which

| Use case | Method |
| --- | --- |
| `ls`, `git status`, anything short and non-interactive | `sandbox.exec()` |
| `npm install`, `make`, anything where you want live output | `sandbox.execStream()` |
| `bash`, `python -i`, `vim`, anything interactive | `sandbox.execStream({ tty: true })` |
| Multi-gigabyte output (logs, archives, etc.) | `sandbox.execStream()` |

`exec` keeps working unchanged. `execStream` is purely additive.

## SDK usage

### Live output, no interactivity

```ts
const handle = sandbox.execStream({
  command: "npm install",
  workdir: "/workspace",
  onStdout: (chunk) => process.stdout.write(chunk),
  onStderr: (chunk) => process.stderr.write(chunk),
});

const { code } = await handle.done;
console.log(`npm install exited with ${code}`);
```

`onStdout` and `onStderr` receive `Uint8Array` chunks as they arrive - no
buffering on the toolbox side. The `done` promise resolves when the process
exits with the exit code (and signal name, if killed by a signal).

### Interactive shell with PTY

```ts
const handle = sandbox.execStream({
  command: "bash",
  tty: true,
  cols: process.stdout.columns,
  rows: process.stdout.rows,
  onStdout: (chunk) => process.stdout.write(chunk),
});

// Forward keystrokes from your terminal into the sandbox.
process.stdin.setRawMode?.(true);
process.stdin.on("data", (chunk) => handle.write(chunk));

// Track terminal resizes.
process.stdout.on("resize", () => {
  handle.resize(process.stdout.columns, process.stdout.rows);
});

await handle.done;
```

In TTY mode stdout and stderr are merged onto the PTY - only `onStdout`
fires (matching standard terminal behavior). Without `tty: true`, the two
streams are kept separate.

### Sending signals

```ts
handle.signal("INT");   // SIGINT - like Ctrl-C in a terminal
handle.signal("TERM");
handle.signal("KILL");
```

Signals target the **process group**, so children of the command also
receive them.

### Go

```go
handle, err := sandbox.ExecStream(ctx, types.ExecStreamOptions{
  Command: "npm install",
  Workdir: "/workspace",
  OnStdout: func(chunk []byte) { _, _ = os.Stdout.Write(chunk) },
  OnStderr: func(chunk []byte) { _, _ = os.Stderr.Write(chunk) },
})
if err != nil {
  return err
}

exit, err := handle.Wait()
if err != nil {
  return err
}
fmt.Printf("npm install exited with %d\n", exit.Code)
```

### Python

```py
handle = sandbox.exec_stream(
    {
        "command": "npm install",
        "workdir": "/workspace",
        "onStdout": lambda chunk: print(chunk.decode("utf-8"), end=""),
        "onStderr": lambda chunk: print(chunk.decode("utf-8"), end="", file=sys.stderr),
    }
)

result = handle.wait()
print(f"npm install exited with {result['code']}")
```

### Rust

```rust
let handle = sandbox.exec_stream(microvm_sdk::ExecStreamOptions {
    command: "npm install".to_string(),
    workdir: Some("/workspace".to_string()),
    on_stdout: Some(Arc::new(|chunk| print!("{}", String::from_utf8_lossy(&chunk)))),
    on_stderr: Some(Arc::new(|chunk| eprint!("{}", String::from_utf8_lossy(&chunk)))),
    ..Default::default()
})?;

let exit = handle.wait()?;
println!("npm install exited with {}", exit.code);
```

## Wire protocol

If you want to write a client in another language, here's the protocol.

### Endpoint

```
WS  ws(s)://<sandboxd>/v1/sandboxes/<id>/toolbox/process/exec/stream
```

### Authentication

Two equivalent ways:

1. `Authorization: Bearer <pat-token>` - works for any HTTP client (curl,
   Go, Python, the `ws` npm package).
2. `Sec-WebSocket-Protocol: sandbox.bearer, <pat-token>` - for browser
   `WebSocket`s, which can't set custom headers. The server echoes
   `sandbox.bearer` back as the agreed subprotocol.

The TS SDK uses (2) so it works in browsers and Node 22+ uniformly.

### Handshake

The first frame the client sends is a JSON text frame describing the
process to run:

```json
{
  "command": "bash -lc 'echo hello'",
  "workdir": "/workspace",
  "env":     {"FOO": "bar"},
  "tty":     true,
  "cols":    80,
  "rows":    24
}
```

`command` is required. Everything else is optional. If `tty` is false, the
process runs with separate stdout/stderr pipes.

### Server → client frames

| Frame type | Contents | Meaning |
| --- | --- | --- |
| Binary | `0x01` + bytes | stdout chunk |
| Binary | `0x02` + bytes | stderr chunk (no-TTY mode only) |
| Text   | `{"type":"exit","code":N,"signal":"..."}` | process has exited |
| Text   | `{"type":"error","message":"..."}` | something went wrong before exec |

If the process was killed by a signal, `code` is `-1` and `signal` is the
signal name (e.g. `"interrupt"`).

### Client → server frames

| Frame type | Contents | Meaning |
| --- | --- | --- |
| Binary | raw bytes | stdin chunk |
| Text   | `{"type":"resize","cols":C,"rows":R}` | terminal size change (TTY only) |
| Text   | `{"type":"signal","signal":"INT"}` | send signal to process group |
| Text   | `{"type":"close"}` | client is done; close stdin |

The server treats EOF on stdin as `close stdin`. Closing the WebSocket also
closes stdin.

### Example with `wscat` and curl

For ad-hoc debugging without the SDK:

```bash
# 1) Get the PAT and sandbox ID.
SBID=...
PAT=...

# 2) Open the stream and send the start message.
wscat \
  -H "Authorization: Bearer $PAT" \
  -c "wss://sandbox.example.com/v1/sandboxes/$SBID/toolbox/process/exec/stream"

> {"command":"echo hello && sleep 2 && echo done"}
< <0x01-prefixed binary frames with output>
< {"type":"exit","code":0}
```

## Toolboxd implementation notes

- **Endpoint**: `cmd/toolboxd/exec_stream.go` registers the
  `GET /process/exec/stream` route. It expects a WebSocket upgrade and
  rejects anything else.
- **PTY**: backed by [`creack/pty`](https://github.com/creack/pty). The
  PTY's master-side file descriptor is the read source for stdout chunks
  and the write target for stdin / resize ioctls.
- **No-TTY mode**: spawns the process with `cmd.StdoutPipe()` and
  `cmd.StderrPipe()`, runs two pump goroutines, and serializes all
  WebSocket writes with a mutex (gorilla/websocket is not safe for
  concurrent writes).
- **Process group**: every spawned command runs in a fresh setpgid /
  setsid group so signals sent via the `signal` control message hit the
  whole tree.
- **Exit reporting**: the server reads `exec.Cmd.Wait()` and returns the
  exit code; if killed by a signal, the code is `-1` and the signal name
  is included.

### Auth flow through sandboxd

```
Client                   sandboxd                       toolboxd
  │                          │                             │
  │── WS upgrade ────────────│                             │
  │   Sec-WS-Protocol:       │                             │
  │   "sandbox.bearer, $PAT" │                             │
  │                          │── extracts $PAT             │
  │                          │   from header               │
  │                          │── replaces with             │
  │                          │   "Authorization: Bearer    │
  │                          │   $TOOLBOX_TOKEN"           │
  │                          │── WS upgrade ──────────────→│
  │                          │                             │── auths via
  │                          │                             │   Authorization
  │                          │                             │── runs PTY/pipes
  │←── frames forwarded ─────────── frames flow backward ──│
```

The PAT never reaches `toolboxd`; only the per-sandbox token does. So even
if `toolboxd` somehow leaked its in-process state, it would only contain
that one sandbox's token, not the global PAT.

## Performance

- Per-frame overhead: 1 byte prefix on stream data, no JSON envelope. A
  stdout chunk of 32 KiB ships as a 32 KiB + 1 byte WebSocket frame.
- Read buffer: 32 KiB chunks (`pumpReader`'s buffer). Tunable in code.
- WebSocket buffers: 64 KiB read/write buffers (set on
  `execStreamUpgrader`).
- Backpressure: if the client falls behind, gorilla's `WriteMessage` will
  block, which in turn blocks the pump's read loop, which causes the
  pipe/PTY to fill, which causes the producer process to block. There's
  no in-memory unbounded buffer, so a slow consumer slows the producer
  rather than OOMing toolboxd.

## Limitations and future work

- **Single connection per command**: there's no resume after the
  WebSocket drops. A network hiccup ends the process (because closing the
  WS closes stdin and triggers `cmd.Process.Kill` indirectly via PTY
  EOF). For long-running processes consider running them under
  `nohup` / `screen` / `tmux` and starting them with the synchronous
  `exec` instead.
- **No bandwidth quotas / max output**: a buggy command that prints
  forever will keep flowing until the WebSocket closes. If you need a
  hard cap, set a server-side timeout and signal `KILL` from the
  client.
- **Single-host**: the WebSocket terminates at the `sandboxd` that owns
  the sandbox. Multi-host scheduling would need session affinity at the
  load balancer.

## File map

| File | Role |
| --- | --- |
| `cmd/toolboxd/exec_stream.go` | WebSocket handler, PTY/pipes plumbing, frame protocol |
| `cmd/toolboxd/main.go` | route registration for `/process/exec/stream` |
| `pkg/api/server.go` | `requireAuth` accepts both `Authorization` header and `Sec-WebSocket-Protocol` token; toolbox proxy forwards WS upgrades and rewrites auth |
| `sdk/typescript/src/types.ts` | `ExecStreamOptions`, `ExecStreamHandle`, `ExecExitInfo` |
| `sdk/typescript/src/internal/client.ts` | `openExecStream` helper, `APIClient.execStream`, `SandboxResource.execStream` |
| `sdk/go/pkg/types/exec_stream.go`, `sdk/go/internal/apiclient/exec_stream.go`, `sdk/go/pkg/microvm/client.go` | Go `ExecStream` types, transport, and public wrapper |
| `sdk/python/microvm/client.py` | Python `exec_stream` handle plus API field normalization |
| `sdk/rust/src/lib.rs`, `sdk/rust/src/types.rs` | Rust `ExecStreamHandle`, callbacks, and websocket transport |

## See also

- [Port allowlist](./port-allowlist.md) - gates `/proxy/<port>/...`
  on the same toolbox HTTP endpoint that hosts the streaming exec
  WebSocket.
