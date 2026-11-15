# Code interpreter on every runtime, and WASM toolbox parity

Status: approved for build by the owner (2026-11-15). Covers the stateful
code interpreter (Daytona `codeInterpreter`, E2B Code Interpreter, the
AerolVM SDKs) and four WASM issues: #535 (streaming exec and code-run),
#178 (Daytona sessions, entrypoint logs and codeInterpreter on WASM), #177
(several exposed ports) and #175 (a listener on the wasmtime engine).

## 1. What we are building, in plain words

A code interpreter is a Python (or Node, Bash, R, Java) process that stays
open inside the sandbox. You send it code many times. It keeps its
variables between runs, streams output while it runs, and returns charts
and tables as rich results.

```
call 1: x = 5          call 2: print(x)
codeRun (have)     -> new Python each time -> "x is not defined"
codeInterpreter    -> same Python stays open -> "5"
```

Today every runtime answers the interpreter routes with HTTP 501
(`cmd/toolboxd/main.go`, `internal/runtime/wasm/toolhost/host.go`), and the
V8 isolate runtime answers them with a wrong HTTP 200.

Competitors ship two wire protocols:

| Who | Feature | Wire |
|---|---|---|
| Daytona | `sandbox.codeInterpreter` (Python) | REST contexts + one WebSocket per run, JSON frames |
| E2B | Code Interpreter SDK, its main product (Python, JS, TS, R, Java, Bash; charts and tables) | REST contexts + `POST /execute` streaming NDJSON, on sandbox port 49999 |

One engine serves both. Each protocol is a thin adapter on top.

## 2. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | One shared engine package, `internal/codeinterp`, used by toolboxd (container and VM runtimes) and by the WASM driver. | One behaviour everywhere; the two adapters are tested once. |
| D2 | A context is one long-lived interpreter process started by a small driver script we write ourselves (clean room). No Jupyter. | Works in any image that has the language. Daytona's implementation is AGPL-3.0 and this repo is MIT: we copy no code from it, only the wire protocol. E2B's server is a reference for wire behaviour only. |
| D3 | Drivers use only the language's standard library. The Python driver uses IPython when the image has it (magics, `!cmd`, identical MIME bundles) and a plain driver otherwise. pandas, numpy and matplotlib are never required; when the user's code loads matplotlib or pandas, the driver turns figures into PNG results and DataFrames into html + data results. | Owner asked for no dependency on data libraries. |
| D4 | Driver protocol is language neutral: frames `KIND LEN\n<LEN bytes>` on file descriptors 3 (requests) and 4 (events). User output goes to the process's real stdout and stderr, which toolboxd reads from pipes, so output from child processes (`!ls`, `os.system`) is captured too. At the end of each run the driver writes a random per-context marker to fd 1 and fd 2 so toolboxd knows all output of that run has arrived. | fd-level capture fixes Daytona's bug where subprocess output is lost. Frames need no JSON parser, so Bash, R and Java drivers stay small. |
| D5 | On WASM the Python driver runs inside `python.wasm` (CPython for WASI) in the sandbox's own worker, in "stdio mode": frames on stdin/stdout, `sys.stdout`/`sys.stderr` replaced by frame writers. There are no child processes on WASM. | Code never runs on the host (#534 removed exactly that). |
| D6 | Contexts live only in memory (toolboxd's, or sandboxd's for WASM). No store or Raft writes. Nothing is added to `CreateSandbox`: the first context starts on first use. A sandbox restart, move or recreate loses all contexts, as on Daytona and E2B. | Boot path stays untouched (pr-review §2). |
| D7 | Paths. Daytona and our SDKs: `/process/interpreter/...` in toolboxd (Daytona's path, already forwarded by the Daytona facade and by `/v1/sandboxes/{id}/toolbox/{path...}`). E2B: toolboxd `/interpreter/e2b/...`; the E2B runtime proxy sends calls with `E2b-Sandbox-Port: 49999` there. No new `/v1` route. | The generic toolbox proxy already gives auth, cluster forwarding, sandbox-token scoping, metrics and WebSocket upgrades. |
| D8 | Our SDKs speak the Daytona WebSocket protocol plus opt-in extensions: the first frame carries `"richOutput": true`, which turns on `result` and `execution_count` frames, and the client may send `{"type":"interrupt"}`. Daytona clients never send `richOutput`, so they see Daytona's exact protocol. Extra routes: `GET /process/interpreter/context/{id}`, `POST /process/interpreter/context/{id}/restart`. | Reuses the WebSocket plumbing all five SDKs already have for exec streams. |
| D9 | Languages: python, javascript, typescript, bash, r, java. Each needs its interpreter in the image (`python3`/`python`, `node` >= 22.13 for TypeScript type stripping, `bash`, `Rscript`, `java` >= 11 with the `jdk.jshell` module). A missing interpreter gives a clear error naming the program. WASM: python only. V8 isolate: none (HTTP 501). | Matches E2B's language list. |
| D10 | E2B template `code-interpreter-v1` maps by default to `python:3.12-slim` (operators override with `SB_E2B_TEMPLATE_MAP_JSON`, for example an image with node, R and data libraries). | The E2B SDK asks for it by default; today that create fails with HTTP 400. |
| D11 | Limits. toolboxd: 32 contexts per sandbox (like PTYs), a queue of 128 runs per context. WASM: 4 contexts per sandbox, idle contexts stopped after 15 minutes, output and log caps in sandboxd memory. Over a limit: HTTP 429 or WebSocket close 1008. | WASM contexts use sandboxd's memory, toolboxd's use the sandbox's own. |
| D12 | Timeouts. Daytona: run timeout (default 600 s, 0 = none) sends SIGINT, waits 2 s, then kills; the context is marked inactive and restarts on next use; the socket closes with 4008. E2B: no server timeout; when the client disconnects, the run is interrupted and the context keeps its state. WASM has no signals, so an interrupt stops the instance (state lost). | Each protocol's own behaviour. |
| D13 | toolboxd advertises the feature in `/version` (`code.interpreter`). The SDKs check it first and raise the existing unsupported-feature error on older agents (old Firecracker templates keep their old toolboxd). | Clean failure on version skew. |

## 3. The engine: `internal/codeinterp`

```
 Daytona WS adapter ─┐                      ┌─ process launcher (toolboxd)
 E2B NDJSON adapter ─┼─► Manager ─► Kernel ─┤
 (our SDKs = Daytona │   contexts,  (one per└─ WASM launcher (sandboxd)
  WS + extensions)   ┘   queues     context)
```

- `Kernel`: `Execute(ctx, Request, Sink) error`, `Interrupt()`, `Kill()`,
  `Done() <-chan struct{}`. `Request{Code, Env, Label}`.
- Events to the `Sink`: `ExecutionCount(n)`, `Stdout(text)`, `Stderr(text)`,
  `Result{Bundle map[mime]any, IsMain bool}`, `Error{Name, Value, Traceback}`,
  `End{Interrupted bool}`.
- `Launcher.Launch(ctx, Spec{Language, Cwd, Env}) (Kernel, error)`.
- `Manager`: contexts `{ID, Language, Cwd, CreatedAt, Active}`, a default
  context per language created lazily, one run at a time per context (FIFO,
  queue cap), limits, restart (same id, state wiped, cwd re-applied),
  delete, and idle stop (WASM). Each adapter owns its own Manager so
  Daytona's `default` and E2B's per-language defaults do not collide; they
  share one per-sandbox limit.
- Process launcher (toolboxd): resolves the interpreter on the child's PATH,
  writes the embedded driver to a private 0700 temp dir, starts it in its
  own process group through toolboxd's child table (toolboxd is PID 1 and
  reaps children), passes fds 3/4, reads fd 1/2 until the run's marker,
  interrupts with SIGINT to the group, kills the group on delete.
- Adapters: `internal/codeinterp/daytona` (WebSocket, gorilla) and
  `internal/codeinterp/e2b` (HTTP NDJSON). Both are `http.Handler`s mounted
  by toolboxd and by the WASM toolhost.

## 4. Wire protocols (what clients see)

### 4.1 Daytona and our SDKs (`/process/interpreter/...`)

| Call | Request | Response |
|---|---|---|
| `POST /process/interpreter/context` | `{"cwd"?, "language"?}` (language defaults to python) | 200 `{"id","cwd","createdAt","active","language"}` (all five always present) |
| `GET /process/interpreter/context` | | 200 `{"contexts":[...]}`; never null; the `default` context is left out |
| `GET /process/interpreter/context/{id}` (ours) | | 200 context, 404 |
| `DELETE /process/interpreter/context/{id}` | | 200 `{"message":"Context deleted successfully"}`; 404 unknown; 400 for `default` |
| `POST /process/interpreter/context/{id}/restart` (ours) | | 200 context |
| `GET /process/interpreter/execute` | WebSocket | see below |

First client frame: `{"code","contextId"?,"envs"?,"timeout"?,"richOutput"?}`.
No `contextId` means the `default` (python) context. Server frames are JSON
text frames that always carry all five fields:
`{"type":"stdout|stderr|error|control","text","name","value","traceback"}`.
Control text is `completed` or `interrupted`; then the server closes with
1000. With `richOutput`, extra frames `{"type":"result", ...E2B result
fields}` and `{"type":"execution_count","count":N}`. Close codes: 1000 done,
4008 timeout, 1002 bad first frame, 1008 empty code / bad timeout /
`context not found: <id>` / limit, 1011 internal. The client may send
`{"type":"interrupt"}` (ours). A client disconnect does not stop the run.

### 4.2 E2B (`/interpreter/e2b/...`, reached through the E2B runtime proxy)

| Call | Response |
|---|---|
| `POST /execute` `{"code","context_id"?,"language"?,"env_vars"?}` | 200, headers flushed at once, NDJSON lines: `number_of_executions`, then `stdout`/`stderr` (`text`, `timestamp`), `result` (MIME fields, `extra`, `is_main_result`), `error` (`name`,`value`,`traceback`), `keepalive` every 5 s idle, and always `end_of_execution` last. Never a blank line. Errors before the stream: 400 both `context_id` and `language`; 404 `Context <id> not found` (text/plain). |
| `POST /contexts` `{"language"?,"cwd"?}` | 200 `{"id","language","cwd"}`; cwd defaults to `/home/user` (created when missing) |
| `GET /contexts` | 200 list in creation order, defaults included |
| `DELETE /contexts/{id}` | 200 `null`; 404 |
| `POST /contexts/{id}/restart` | 200 `null` |
| `GET /health` | 200 `"OK"` |

Language names are normalised (`""` → python, `js` → javascript, `ts` →
typescript). Result fields: `text` (one pair of surrounding quotes
stripped), `html`, `markdown`, `svg`, `png`, `jpeg`, `pdf`, `latex`,
`json`, `javascript`, `data`, `extra`. `chart` is not produced.

### 4.3 E2B facade changes

- `pkg/api/e2b/runtime_proxy.go`: `E2b-Sandbox-Port: 49999` → toolbox path
  `/interpreter/e2b` + path. `X-Access-Token` (the toolbox token) opens
  every path; `E2B-Traffic-Access-Token` opens only `/contexts`,
  `/contexts/{id}`, `/contexts/{id}/restart` and `/health` on port 49999,
  never `/execute` or envd. Constant-time compares.
- Create and connect responses fill `trafficAccessToken` for secure
  sandboxes (the SDK sends it on `/contexts` calls, which never carry
  `X-Access-Token`). It is not the toolbox token: E2B treats the traffic
  token as shareable, so it is HMAC-SHA256 keyed by the toolbox token over
  `"e2b-traffic:" + sandboxID`, hex.
- `POST /e2b/v2/sandboxes` and `POST /e2b/v2/sandboxes/{id}/connect`, so the
  current E2B SDKs (e2b >= 2.51) can create sandboxes at all.
- `code-interpreter-v1` default template (D10).

## 5. WASM work

| Step | Issue | What |
|---|---|---|
| W0 | security | Move each WASM sandbox's worker record (`instance.json`) out of the folder the guest sees as `/work`; check the sandbox id when adopting a worker. New host state never goes under `/work`. The guest HTTP proxy must never dial a host port taken from the request (fixed in W6). |
| W1 | #535 | Worker streaming: a long-lived instance with a stdin pipe and streamed stdout/stderr, run as a named instance next to the sandbox's own (so it never replaces the serving guest), with the sandbox's preopens, limits, network blocks and egress policy. New worker messages `exec_start`, `exec_chunk`, `exec_stdin`, `exec_stdin_close`, `exec_kill`, `exec_exit`; an old adopted worker that does not know them maps to HTTP 501. wazero only; wasmtime answers 501. |
| W2 | #535 | `/process/exec/stream` on WASM, wire-identical to toolboxd's (binary 0x01/0x02 frames, JSON exit). No TTY. |
| W3 | #535 | `/process/code-run` on WASM: runs the language's standard module (`SB_WASM_CODERUN_MODULES`, defaults from `SB_WASM_STANDARD_MODULES`: python, javascript via QuickJS, ruby) on the sandbox's `/work`. |
| W4 | #178 | Daytona `/process/session` family on WASM: a session is a series of confined runs that share `/work` and env; async commands stream logs and accept input. Entrypoint logs: the serving guest's output is kept in a capped ring buffer. Native `/sessions` (interactive terminals) stay 501: WASM has no shell. |
| W5 | #178 | codeInterpreter on WASM: python contexts on `python.wasm` with the stdio-mode driver; Daytona, our SDKs and E2B (python) all work. As built: the driver source goes in as a `-c` argument (nothing under `/work`), and the launcher passes the cwd in `AEROL_INTERP_CWD` because WASI has no cwd to inherit. E2B contexts default to `/work`, not `/home/user` (§4.2), which a WASM sandbox does not have. A running context holds one of the sandbox's streaming run slots. |
| W6 | #177 | Several exposed ports: one pre-opened listener per exposed port, the guest learns which descriptor is which port from an env var, each port gets its own route. |
| W7 | #175 | Listener on the wasmtime engine (design in section 6). |

## 6. #177 and #175 networking

**Today.** Each exposed port P gets a helper listener inside sandboxd that
Caddy dials. Requests cross the worker socket (`MsgProxyHTTP`) to the guest's
one wasip1 listener, an ephemeral loopback port. The number P is dropped on
the way, so every exposed port reaches the same listener.

**#177 design.**
- wazero can pre-open several listeners (checked: `Config.WithTCPListener`
  appends; they follow the dir pre-opens as fds 4, 5, ...). WASI has no
  `getsockname`, so the guest learns the mapping from a new variable
  `AEROL_WASM_LISTEN_FDS="8080=4,9090=5"` (ports ascending).
  `AEROL_WASM_LISTEN_FD` stays and names the lowest port's descriptor, so
  existing guests keep working.
- New worker messages `set_listen_ports` / `listen_ports`. The worker routes a
  request for port P to P's listener once the guest has accepted on it, and
  to the primary listener otherwise (a guest written for one listener still
  serves every port). It never dials a host port named by P.
- The driver keeps the exposed set. Same set: no change (reconcile must not
  restart serving guests). A new port: one re-instantiation with the full
  set, the same state loss the first expose has today. A removed port: the
  allowed-port check already answers 403.
- An old adopted worker that does not know the messages keeps the single
  listener.
- No Caddy, route-index or host-port-pool change; WASM never uses the TCP
  host-port pool. Nothing on the create path.
- Fixed on the way: concurrent exposes of two ports raced on the instance;
  the listener lookup stopped at fd 10.

**#175.** No wasmtime release (checked v37 to v50, the newest) can give a
WASI guest a pre-opened TCP listener on its own: the C API had
`wasi_config_preopen_socket` only in v14-v19, wasmtime-go never wrapped it,
and wasmtime's preview-1 `sock_accept` is a stub. So the engine serves the
guest's sockets itself (pkg/wasm/wasip1_sockets*.go, wasmtime_sockets.go):
- The guest's linker defines WASI, then shadows the preview-1 calls that can
  see a socket (sock_accept/recv/send/shutdown, fd_read/write/close,
  fd_fdstat_get/set_flags, fd_filestat_get, fd_renumber, poll_oneoff) with Go
  versions. Socket fds live from 1<<24 up, a range wasmtime never hands out;
  the guest learns them from AEROL_WASM_LISTEN_FD / AEROL_WASM_LISTEN_FDS.
- Every other fd goes to wasmtime's own implementation through a small
  trampoline module in the same store that imports the guest's memory, so
  both share one WASI fd table.
- poll_oneoff waits on the guest's host sockets plus a stop pipe (ppoll on
  Linux, poll on macOS), so stop, close and the wall timeout end a guest that
  is waiting.
- Needs Linux or macOS and a guest that exports a 32-bit memory; anything
  else still moves to wazero when it exposes a port (the first fix, kept as
  a fallback; `SB_WASM_WASMTIME_LISTEN_FALLBACK=false` refuses instead).
- The `-tags wasmtime` build is broken on Go 1.26 (LLVM bitcode in the
  bundled `libwasmtime.a`; on Linux the section is refused even outside the
  module cache). Planned separately in #1307; the tagged tests run with a
  local copy of the bindings.

## 7. Safety axes (pr-review.md)

- **Idempotency.** Context create is not idempotent by design (each call
  makes a new context, same as Daytona and E2B); delete of an unknown id is
  404 as both protocols require. Runs are never retried by the SDKs.
  `expose_port` on WASM keeps returning the existing URL; a new listener
  never touches the TCP host-port pool.
- **Boot path.** Nothing added to `CreateSandbox`.
- **Failure paths.** A context whose process dies is marked inactive and is
  restarted on next use; the run in flight ends with an error event and
  `end_of_execution` / close. No caddy or store writes.
- **Cluster.** No FSM or placement change; the toolbox proxy already
  forwards to the owner node.
- **Host safety.** No caller input runs on the host. On WASM everything runs
  inside the engine; state on the host lives outside `/work`.

## 8. Tests

- Unit: engine (fake launcher), each driver against the real interpreter
  when present (skip when missing), both adapters with real clients (the
  pinned Daytona Go SDK, an NDJSON client), toolboxd routes, the E2B proxy,
  the worker streaming protocol, the WASM toolhost routes. Every touched
  package stays at or above 85 %.
- Live, local (this Mac, Docker runtime + WASM): Daytona TS/Python/Go SDKs,
  E2B code-interpreter JS/Python SDKs, the five AerolVM SDKs.
- Live, AWS: `cluster-hetero-lite` (containerd, gVisor, WASM, cross-node
  forwarding) and `single-node-fc` (Firecracker, created from an image),
  filtered to the new use cases (UC-707 onward).

## 9. Not in this work

- E2B `chart` extraction (the field is optional; PNGs are returned).
- A `run_code` MCP tool and CLI command (the MCP plan deferred it).
- Daytona browser/Deno TS clients and the Ruby SDK (they authenticate with
  preview tokens the facade does not read; same gap as PTY today).
- Contexts surviving a sandbox restart or move.
- Fixing the `-tags wasmtime` build on Go 1.26 (#1307).
