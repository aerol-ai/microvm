title: Sessions

Sessions are persistent processes running inside a sandbox. Unlike `execStream`, which tears down the WebSocket when the connection drops, a session keeps running. Any new client that attaches receives a replay of buffered output and can then interact with the live process.

This makes sessions ideal for interactive shells, long-running agents, and any workflow where continuity across reconnects matters.

## Create a Session

```http
POST /v1/sandboxes/{id}/sessions
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "shell",
  "command": "bash",
  "workdir": "/workspace",
  "pty": true,
  "cols": 120,
  "rows": 40
}
```

Response:

```json
{
  "id": "sess_abc123",
  "name": "shell",
  "status": "running",
  "created_at": "2025-01-01T00:00:00Z"
}
```

## List Sessions

```http
GET /v1/sandboxes/{id}/sessions
Authorization: Bearer <token>
```

## Attach to a Session

Attach over WebSocket to send stdin and receive stdout/stderr:

```http
GET /v1/sandboxes/{id}/sessions/{session_id}/attach
Upgrade: websocket
Authorization: Bearer <token>
```

On connect, the sandbox replays the in-memory output buffer so the client sees past output immediately. Multiple clients can attach to the same session simultaneously.

## Session Log

Retrieve buffered output without opening a WebSocket:

```http
GET /v1/sandboxes/{id}/sessions/{session_id}/log
Authorization: Bearer <token>
```

## SDK Usage

```ts
// TypeScript
const session = await sandbox.createSession({
  name: 'shell',
  command: 'bash',
  pty: true,
  cols: 120,
  rows: 40,
})

const attach = await sandbox.attachSession(session.id, {
  onStdout: (chunk) => process.stdout.write(chunk),
})

attach.write('echo hello\n')
const exit = await attach.waitForExit()
```

```python
# Python
session = sandbox.create_session(
    name='shell',
    command='bash',
    pty=True,
    cols=120,
    rows=40,
)

log = sandbox.session_log(session['id'])
print(log.decode())

attach = sandbox.attach_session(
    session['id'],
    on_stdout=lambda chunk: print(chunk.decode(), end=''),
)
attach.write('echo hello\n')
attach.wait_for_exit()
```

```go
// Go
session, err := sandbox.CreateSession(ctx, microvm.CreateSessionOptions{
    Name:    "shell",
    Command: "bash",
    PTY:     true,
    Cols:    120,
    Rows:    40,
})

attach, err := sandbox.AttachSession(ctx, session.ID, microvm.SessionAttachOptions{
    OnStdout: func(chunk []byte) { os.Stdout.Write(chunk) },
})
attach.Write([]byte("echo hello\n"))
attach.WaitForExit()
```

```java
// Java
import ai.aerol.microvm.model.CreateSessionOptions;
import ai.aerol.microvm.model.Session;
import ai.aerol.microvm.model.SessionAttachOptions;

Session session = sandbox.createSession(
    new CreateSessionOptions()
        .setName("shell")
        .setCommand("bash")
        .setPty(true)
        .setCols(120)
        .setRows(40)
);

var attach = sandbox.attachSession(
    session.id,
    new SessionAttachOptions()
        .setOnStdout(chunk -> System.out.print(new String(chunk)))
);

attach.write("echo hello\n");
attach.waitForExit();
```

## How Sessions Work

The sandbox starts the process with either a PTY or a pipe pair. Output is written into a ring buffer in memory and fanned out to all currently attached WebSocket clients. When a new client attaches, it reads the entire ring buffer before receiving live frames - giving a seamless replay experience.

Sessions are tied to the sandbox's runtime. If the sandbox is stopped and restarted, sessions do not persist across the restart.

## Difference from execStream

| | `execStream` | Session |
|---|---|---|
| Process lifetime | Tied to WebSocket | Independent of connection |
| Reconnect | Process killed on disconnect | Process keeps running |
| Multi-client | No | Yes - concurrent attachment |
| Output replay | No | Yes - ring buffer |
| Use case | One-shot commands | Interactive shells, agents |
