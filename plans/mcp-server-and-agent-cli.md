# MCP server + agent-friendly CLI — let Claude Code, Cursor & co. drive AerolVM

**Status:** PROPOSED (2026-10-03). Not eng-reviewed. Nothing below is built.
**Related:** `docs/src/content/docs/exec-streaming.mdx`, `sessions.mdx`,
`file-system.mdx` (the surfaces the tools wrap),
`docs/src/content/docs/engineering-idempotency.mdx` (retry contract every
tool must honour), `plans/repo-security-hardening.md` (new dependency review),
`setup/config-defaults.md` (why the remote endpoint ships default-off).

## 1. Why

There is no MCP server and no end-user CLI in the repo. `cmd/` holds only
`sandboxd` (the daemon) and `toolboxd` (the in-guest agent). An agent that
wants a sandbox today has to write SDK code first.

Demand signals:

- People asked for an MCP server in both the Cloudflare Sandbox and the
  Sprites threads.
- E2B shipped `e2b sandbox exec <id> <cmd>` (stdin piping, `--background`,
  `--cwd`, `--env`, `--user`) specifically so Claude Code and Cursor can drive
  a sandbox through their shell tool, with no MCP needed
  ([docs](https://e2b.dev/docs/cli/exec-command)).
- Daytona ships `daytona mcp init [claude|cursor|windsurf]`, with tools for
  shell exec, file upload/download, git clone and preview links
  ([docs](https://daytona.io/docs/mcp)).

Coding agents reach a sandbox platform in two ways, and we need both:

| Path | How the agent uses it | Who needs it |
|---|---|---|
| **CLI** | Its own shell tool: `aerolvm exec sb -- pytest -q`. No MCP config needed. Works in any agent that can run shell commands, and in CI. | Claude Code, Codex, Cursor agent mode, CI scripts, humans |
| **MCP server** | Typed tools with schemas and annotations. The client shows them, gates them and can ask the user to confirm destructive ones. | Claude Desktop, Cursor, VS Code, Claude Code (when the user wants gated tools instead of raw shell) |

## 2. What already exists — this is mostly a front end

Everything an agent needs is already served. The work is client-side, plus one
small server addition (§5.6).

| Agent capability | Already served by | Go SDK entry point |
|---|---|---|
| Create / list / get / stop / start / destroy | `/v1/sandboxes…` (`pkg/api/v1/routes.go`) | `Client.Create/List/ListPage/Get/Stop/Start/Destroy` |
| Buffered exec (stdout, stderr, exit code, timeout; default 5m) | toolbox `/process/execute` (`cmd/toolboxd/main.go`) | `Sandbox.Exec` |
| Streaming exec (stdin, TTY, signals, exit code + signal) | exec-stream WebSocket | `Client.ExecStream` → `ExecStreamHandle` |
| Background processes with log replay | `/v1/sandboxes/{id}/sessions…` | `CreateSession/SessionLog/SignalSession/DeleteSession` |
| Run a code snippet (python / js / ts) | toolbox `/process/code-run` (`daytona_code_run.go`) | none yet; toolbox proxy path |
| Read / write files | toolbox `/files/download`, `/files/upload` | `DownloadFile/UploadFile` |
| List / stat / move / search by name / grep | toolbox `/files`, `/files/info`, `/files/move`, `/files/search`, `/files/find` | none yet; toolbox proxy path |
| Preview URL for a dev server | `POST /v1/sandboxes/{id}/ports/{port}` (already returns the existing URL on a repeat call) | `Sandbox.ExposePort` |
| Snapshot | `POST /v1/sandboxes/{id}/snapshot` | `Client.CreateSnapshot` |
| Auto-cleanup of forgotten sandboxes | `Lifecycle.DestroyIfIdleFor` / `DestroyAtAge` (`pkg/models/types.go`) | `CreateSandboxOptions.Lifecycle` |
| Retries on 421/429/502/503/504 | SDK `RetryConfig` | built in |

The Go SDK lives in the root module (`sdk/go/pkg/microvm`). Its only
third-party dependencies are `gorilla/websocket` and `x/net`, and it builds
with `CGO_ENABLED=0` (verified). A Go CLI can import it directly, with no
second module and no CGO cross-compile.

## 3. Options considered

| # | Option | Verdict |
|---|---|---|
| 1 | **One Go binary, `aerolvm`**: CLI subcommands plus `aerolvm mcp` (stdio MCP), both over one shared tool layer built on the Go SDK | **Do (Phases 1–2)**. One implementation, one release pipeline, a static binary for every OS. |
| 2 | MCP server in TypeScript over the TS SDK (the npx-first ecosystem norm) | Rejected. The MCP server and the CLI would be two implementations of the same operations. We get npx ergonomics back with an npm package that ships the Go binary (Phase 3). |
| 3 | Remote MCP endpoint inside `sandboxd` (`/mcp`, Streamable HTTP) | **Phase 4, gated.** It is the only way claude.ai / ChatGPT connectors can reach us, since they can't run local binaries. It touches `pkg/api` and needs eng review plus a demand checkpoint. |
| 4 | An MCP server per SDK language | Rejected. That is five servers for one protocol. |
| 5 | Leave it to third parties (Composio, community servers) | Rejected. We would not control idempotency, scoping or output bounds, which are the parts that make it safe (§6, §7). |

## 4. Phases

Each task is one PR. Following our stacked-PR policy, nothing merges until the
whole phase's stack is green.

| Phase | Tasks | Server change? | Gate |
|---|---|---|---|
| **1. Tool layer + CLI** | T1 `internal/agenttools` (resolution, get-or-create, output shaping, error mapping) · T2 v1 name lookup (§5.6) · T3 `cmd/aerolvm` core verbs · T4 exec streaming, exit codes, timeouts · T5 `cp` / `ls` · T6 release matrix + `install.sh --cli-only` · T7 `cli.mdx` | T2 only (additive query param) | eng review of this doc |
| **2. stdio MCP** | T8 `aerolvm mcp` (core toolset) · T9 optional toolsets + pinned / ephemeral modes · T10 `aerolvm mcp config <client>` · T11 `mcp.mdx` · T12 integration UCs (CLI + MCP) | none | Phase 1 merged |
| **3. Distribution** | npm package with per-platform binaries (`npx -y @aerol-ai/aerolvm mcp`) · Homebrew tap · `aerolvm login` profiles | none | Phase 2 merged |
| **4. Remote MCP** | `/mcp` on sandboxd, stateless Streamable HTTP, `SB_MCP_ENABLED` default false (§5.7) | yes (`pkg/api`) | demand checkpoint + separate eng review |

## 5. Design

### 5.1 Layout

```
cmd/aerolvm/            main.go, subcommand dispatch (stdlib flag; no CLI framework dependency)
internal/agenttools/    shared operations; imports ONLY sdk/go/... and pkg/models
  resolve.go            "<id-or-name>" → sandbox
  create.go             get-or-create by name (§5.4)
  exec.go               bounded head/tail capture over ExecStream, timeout, exit-code mapping
  files.go              read (line window, binary detection), write, list, search, grep, edit
  output.go             truncation, JSON envelopes, error codes
internal/agentmcp/      MCP tool registry over agenttools (Phase 2); reused by sandboxd in Phase 4
```

The CLI and the MCP server are two front ends over `agenttools`. They share the
behaviour that has to stay identical: name resolution, idempotent create,
output bounds and error mapping. Each front end keeps its own surface. The CLI
has positional args, stdin and live streaming. MCP has JSON-schema args and
bounded results. The tool registry is deliberately not code-generated from the
CLI, because the two ergonomics differ.

**Dependency guard:** a test asserts that `go list -deps ./cmd/aerolvm`
contains nothing under `internal/{service,store,cluster,runtime}`, `pkg/docker`,
`pkg/caddy` etc., and that the binary builds with `CGO_ENABLED=0`. The CLI must
stay a thin, static client. Importing server packages would pull in the
containerd, Raft and SQLite trees.

One new dependency: `github.com/modelcontextprotocol/go-sdk` (official SDK;
v1.7.0 negotiates both 2025-11-25 and the stateless 2026-07-28 protocol,
[releases](https://github.com/modelcontextprotocol/go-sdk/releases)). Pin it
and review its transitive deps under `plans/repo-security-hardening.md`.

### 5.2 The agent-friendly CLI contract

This contract is the actual feature, so these rules are tested, not aspirational:

1. **Never interactive.** No prompts, pagers, spinners or confirmations.
   Destructive verbs take explicit sandbox refs, and there is no
   `destroy --all`.
2. **stdout is data, stderr is everything else.** Progress, warnings and hints
   go to stderr. Colour only on a TTY, and `NO_COLOR` is honoured.
3. **`--json` on every verb.** `AEROLVM_OUTPUT=json` makes it the default for a
   whole agent session. The JSON is the existing wire type from `pkg/models`
   (the same schema the API docs describe) plus at most a few CLI fields
   (`created`, `truncated`). The schema is additive-only.
4. **Machine-readable errors.** With `--json`, stderr gets
   `{"error":{"code":"not_found","message":"…","http_status":404,"retryable":false}}`.
   `code` comes from `models.ErrorResponse.Code` when the server sends one,
   otherwise from the HTTP status.
5. **Exit codes follow `docker exec` / GNU `timeout`, which agents already know:**
   - `exec` returns the remote exit code. A remote kill by signal returns 128+n.
   - Any CLI-side or API failure during `exec` returns 125.
   - `--timeout` expiring returns 124.
   - Every other verb returns 0 on success, 1 on error and 2 on usage error.
6. **Any sandbox can be referenced as `<id-or-name>`.** Resolution tries the
   ID first and falls back to the name lookup (§5.6) on 404.
7. **Retries are safe.** `create` is idempotent (§5.4), `destroy` treats 404 as
   success, and `expose` already returns the existing URL.
8. **Stdin is forwarded only with `-i`** (docker semantics). E2B auto-pipes
   stdin. We don't, because agent harnesses often hand child processes an
   open, never-EOF stdin, and auto-forwarding hangs any remote command that
   reads stdin. This is an open question (§9).
9. **`--help` is written for models.** It is short, has one or two real
   examples per verb, and names the JSON shape.

Verbs (Phase 1):

```
aerolvm create  [--name N] [--image I] [--runtime R] [--cpu C] [--memory-mb M]
                [--env K=V]... [--tag K=V]... [--destroy-if-idle 1h] [--block-network]
aerolvm list    [--tag K=V]... [--page-token T]
aerolvm get     <sandbox>
aerolvm exec    <sandbox> [-i] [-t] [--cwd D] [--env K=V]... [--timeout 5m]
                [--background] -- <cmd> [args...]
aerolvm logs    <sandbox> <session-id> [--follow]      # for --background
aerolvm cp      <src> <dst>        # docker-cp form: sb:/path ↔ local path, "-" = stdin/stdout
aerolvm ls      <sandbox>:<path>
aerolvm expose  <sandbox> <port> [--tcp]
aerolvm start | stop | destroy <sandbox>...
aerolvm snapshot <sandbox> <name>
aerolvm health | version
aerolvm mcp     [...]              # Phase 2
```

Auth and endpoint use the same `SB_API_URL` / `SB_PAT_TOKEN` as all five SDKs.
A config file and `aerolvm login` wait for Phase 3, because an env var is
already the natural interface for an agent.

Operator verbs (templates, WASM module push, cluster drain, audit) are
deliberately absent. They are not agent operations, and a later
`aerolvm admin …` can add them if humans ask.

### 5.3 MCP server (`aerolvm mcp`, stdio)

**Toolsets.** Every extra tool costs the model selection accuracy and context,
so the default set is small. Enable more with `--toolsets core,files,process,code,lifecycle`
or `--toolsets all`.

| Toolset | Tool | Args (abridged) | Annotations | Wraps |
|---|---|---|---|---|
| core | `sandbox_create` | name?, image?, runtime?, cpu?, memory_mb?, env?, destroy_if_idle_minutes? | idempotent (§5.4) | get-or-create |
| core | `sandbox_list` | tags?, page_token? | readOnly | `ListPage` |
| core | `sandbox_destroy` | sandbox | **destructive**, idempotent | `Destroy` (404 = ok) |
| core | `exec` | sandbox, command, cwd?, env?, timeout_seconds? | openWorld | bounded `ExecStream` |
| core | `read_file` | sandbox, path, offset_line?, limit_lines? | readOnly | `DownloadFile` + windowing |
| core | `write_file` | sandbox, path, content | idempotent | `UploadFile` |
| core | `list_files` | sandbox, path | readOnly | toolbox `/files` |
| core | `expose_port` | sandbox, port | idempotent | `ExposePort` |
| files | `edit_file` | sandbox, path, old_string, new_string | — | read → unique-match replace → write |
| files | `search_files` / `grep_files` | sandbox, path, pattern | readOnly | toolbox `/files/search`, `/files/find` |
| process | `start_process` / `process_logs` / `stop_process` | sandbox, command / session_id | — | sessions API |
| code | `run_code` | sandbox, language (python/javascript/typescript), code | openWorld | toolbox `/process/code-run` |
| lifecycle | `sandbox_get` / `sandbox_start` / `sandbox_stop` / `sandbox_snapshot` | sandbox, … | per verb | SDK |

No MCP resources, prompts or sampling in v1 (YAGNI; sampling is deprecated in
2026-07-28 anyway).

**Result shape.** Each result carries `structuredContent` plus a text
rendering for older clients. A non-zero exit code from `exec` is a normal
result (`exit_code: 2`), not `isError`. `isError` is reserved for API
failures, and the message tells the model what to do next, e.g. "sandbox
`foo` not found — it may have been destroyed by its idle lifecycle; call
`sandbox_list` or `sandbox_create`".

**Output bounds.** These protect the context window and the memory of the MCP
process. `exec` and `run_code` capture at most `--max-output-bytes`
(default 16 KiB per stream) as head 4 KiB + tail 12 KiB, since errors live at
the tail. Truncated output reports `truncated: true` and the dropped byte
count. `exec` uses `ExecStream` with ring buffers instead of buffered `Exec`.
Buffered exec decodes the whole body into memory, and toolbox
`/process/execute` does not cap output (`cmd/toolboxd/main.go` handleExec).
`read_file` returns at most 2,000 lines / 256 KiB per call with a
continuation offset. It refuses binary files with their size and type and
suggests `exec` (e.g. `xxd | head`).

**Pinned mode** (`--sandbox <ref>`): this is the "give my agent one sandbox"
shape.
- The `sandbox` arg disappears from every schema.
- `sandbox_create`, `sandbox_list` and `sandbox_destroy` are not registered.
- The model cannot touch any other sandbox the token can see.

`--create-if-missing --image I` creates the sandbox **lazily, on the first tool
call**, never at MCP startup. MCP hosts spawn every configured server at
session start, so an eager create would bill a sandbox for every chat that
never runs code. Creation is single-flight behind a mutex. A failed create is
not latched, so the next call retries. Because the create is name-based
(§5.4), a host restarting the server mid-session reattaches to the same
sandbox.

**Cleanup.** MCP-created sandboxes get a default
`lifecycle.destroy_if_idle_for` of 1h (`--keep` opts out, and the value is
configurable). `--ephemeral` also destroys the pinned sandbox on clean shutdown
(stdin EOF / SIGTERM), but that is best-effort only, since hosts commonly
SIGKILL MCP servers. **The server-side lifecycle TTL is the cleanup guarantee.
Process exit is not.**

**Other modes.**
- `--read-only` registers only `readOnly` tools.
- **stdout hygiene:** stdout is the JSON-RPC channel, so all logging goes to
  stderr and no tool or SDK path may write to stdout.

**Client setup.** `aerolvm mcp config claude-code|claude-desktop|cursor|vscode`
prints the snippet or command, for example:
`claude mcp add aerolvm -e SB_API_URL=… -e SB_PAT_TOKEN=… -- aerolvm mcp --sandbox my-agent --create-if-missing`.
It references the token as an env var where the client supports expansion,
and never writes into another tool's config files (those formats churn, so
it's the user's file to edit).

### 5.4 Idempotent create (CLI + MCP)

Clients retry tool calls, and the SDK retries 5xx. A plain `POST /v1/sandboxes`
retried after a lost response would create a duplicate. Every create from
`agenttools` is therefore keyed by name:

1. `GET` by name (§5.6). If it exists, return it with `created: false`, and
   warn on stderr if the requested spec differs.
2. Otherwise `POST` with that name.
3. On 409 (the store's unique-name partial index won a race), go back to
   step 1.

When the caller gives no name, the CLI generates one (`agent-<12 random
base32>`) **before** the first attempt. The SDK's internal retries and the
caller's retries then all target the same row. We need to verify (task T1)
whether the SDK retries `POST /sandboxes` on transport errors today. If it
does, that is a duplicate-sandbox bug for every SDK user, and it gets its own
issue.

### 5.5 Exec semantics worth pinning in tests

- Exit info from `ExecStreamHandle.Wait()`: `Code`, plus `Signal` mapped to
  128+n.
- `--timeout` cancels the stream, sends `Signal("KILL")` and returns 124.
- `--background` creates a session and prints `{"session_id":…}`.
  `aerolvm logs --follow` attaches to it.
- `-t` requests a TTY (cols/rows from the local terminal) and is only valid
  when stdout is a TTY.

### 5.6 The one server change: v1 name lookup (T2)

v1 has no "get by name". The Daytona facade resolves names via
`Service.ResolveSandboxIDByName` → `store.ResolveSandboxIDByName`, and cluster
mode already keeps a name index in the Raft FSM (`placement-by-name`,
`internal/cluster/agent.go`). The proposal is to add `?name=<name>` to
`GET /v1/sandboxes`. The handler resolves the name through the placement-by-name
lookup in cluster mode (O(1) on the FSM, with no peer fan-out) or through the
store in single-node mode, and returns a 0- or 1-element list.

- It is additive, so a soft-frozen v1 is fine. Follow `/add-v1-endpoint` and
  `/add-sdk-method` so all five SDKs get `get_by_name` in lockstep.
- Tenant scoping must match `scopedGet`. A name owned by another tenant must
  return an empty list, not leak the name's existence. Regression test required.
- Rejected alternative: tag the sandbox with `aerolvm/name=<n>` and look it up
  via the tag filter. That needs no server change, but every lookup becomes a
  `clusterListWrap` fan-out across every node, which is the read-path cost
  shape we just removed from reconcile.

### 5.7 Phase 4 sketch: remote MCP on sandboxd

This is only so Phases 1–2 don't paint us into a corner. It gets its own eng
review.

- Mount `/mcp` on the API mux (not under `/v1`, because MCP versions itself).
  It is off unless `SB_MCP_ENABLED=true`.
- Use **Stateless** Streamable HTTP. Requests carry no `Mcp-Session-Id`
  stickiness, so any node can serve any request behind any LB, and nothing
  touches `internal/cluster`. go-sdk serves 2026-07-28 only in stateless mode
  and negotiates older clients down.
- Tool handlers are the same `internal/agentmcp` registry, driving the Go SDK
  through an **in-process `http.RoundTripper`** that hands the request to the
  API root handler with the caller's `Authorization` header. Every tool call
  then goes through exactly the same auth, tenant scoping, `clusterForwardWrap`,
  rate limiting and idempotency as a direct API call. That means no second
  authz path and no loopback listener assumption.
- Known gap: WebSocket hijack doesn't work in-process, so bounded exec there
  needs either a `max_output_bytes` on toolbox `/process/execute` (a toolboxd
  change) or a real loopback dial. Decide at that review.
- Security: validate `Origin` (DNS rebinding, required by the spec), bearer
  auth via the existing middleware, never register operator tools, per-token
  rate limit. OAuth 2.1 protected-resource metadata for claude.ai connectors
  goes through the `pkg/controlplane` seam (managed build). The open-source
  build stays bearer-only.

## 6. Security

| Threat | Mitigation |
|---|---|
| Prompt injection via sandbox output (a file says "now destroy all sandboxes") | Pinned mode removes cross-sandbox tools. `--read-only`. `destructiveHint` makes clients confirm. Tenant-scoped tokens remain the real boundary, and docs recommend a token scoped to agent sandboxes. |
| Exfiltrating the **host** filesystem through the MCP server | **No MCP tool reads or writes the local machine.** Every file tool targets the sandbox. There is deliberately no `upload_local_file`. (The CLI's `cp` does touch local files, but it is invoked from the user's own shell, which has the same trust as any other shell command.) |
| Token leakage | Env only. Never accepted as a tool arg, never echoed in results, errors or logs. `Authorization` redacted in `--debug`. `mcp config` prints an env reference, not the value. |
| Context or memory flooding (`yes`, huge files) | Head/tail ring buffers, read windows, binary refusal (§5.3). |
| Orphaned, billed sandboxes from abandoned agent sessions | Default `destroy_if_idle_for` on MCP-created sandboxes, lazy create (§5.3). |
| Supply chain (new go-sdk dep, npm wrapper in Phase 3) | Pinned versions, dependency review, release attestation already covers `dist/*`. Run the npm package through the same provenance as `publish-sdks.yml`. |

## 7. Hard-rule call-outs (CLAUDE.md / pr-review.md)

1. **Idempotency.**
   - Safe under retry: create (name-keyed), destroy (404 = ok), expose (the
     server returns the existing URL), write_file (same bytes),
     stop/start/snapshot (existing server semantics).
   - `exec`, `run_code` and `start_process` are inherently not idempotent.
     They are annotated `idempotentHint: false`, and their docs say so.
2. **Boot-path latency.**
   - Phases 1–3 add no work to `CreateSandbox`.
   - T2 is a read path only.
   - Pinned lazy-create moves one create latency onto the first tool call. That
     cost is on the client side and is the intended behaviour.
3. **Lazy bootstrap.** There is no daemon-start work. The client-side lazy
   create uses mutex single-flight without latching on failure, the same intent
   as `EnsureLayer4Ready`.
4. **Failure-path consistency.**
   - There are no new multi-step caddy and store writes.
   - Get-or-create recovers on 409.
   - Ephemeral destroy is best-effort, and lifecycle TTL is the backstop.
   - Nothing leans on reconcile.
5. **TCP pool / L4.** Untouched. `expose_port --tcp` uses the existing
   idempotent expose path.
6. **Cluster.**
   - Phases 1–3 are pure clients of the public API, and any node serves them.
   - T2 reads the FSM name index without writing to it.
   - Phase 4 is stateless and loops through `clusterForwardWrap`.
   - Single-node mode resolves names from the store. `Noop` behaviour is
     unchanged.

## 8. Testing

**Offline (`make test`, keeping each package at ~85% or above):**

- **`internal/agenttools`:** table-driven tests against an `httptest` fake of
  v1 and the toolbox, in the style of `sdk/go/pkg/microvm/client_test.go`.
  They cover:
  - get-or-create including the 409 race
  - ID → name fallback
  - head/tail truncation boundaries
  - binary detection
  - `edit_file` unique-match failure
  - error-code mapping
- **`cmd/aerolvm`:** golden tests for `--json` output and stderr error
  envelopes, plus tests for:
  - exit codes (remote code passthrough, 124 timeout, 125 API failure,
    128+n signal)
  - stdin only with `-i`
  - no ANSI output when not on a TTY
- **`internal/agentmcp`:**
  - The go-sdk in-memory transport drives every tool against the fake API.
  - A **golden snapshot of `tools/list`** (names, schemas, annotations per
    toolset and mode) makes any schema change a reviewed diff.
  - Pinned mode hides `sandbox` and the fleet tools. Read-only mode hides
    writers.
- **stdout hygiene:** spawn the built binary, send `initialize` and a tool call
  on stdin, and assert that every stdout line parses as JSON-RPC.
- **Dependency guard** (§5.1).
- **T2:**
  - handler test
  - store test
  - cluster test where the name is owned by a peer
  - tenant-scoping test (another tenant's name → empty list)

**Live (`integration-tests/`, `integration` tag):**

- A new use case runs CLI create → exec → cp → expose → destroy on
  `single-node` and `cluster-3-mixed`. The cluster run uses name resolution
  for a sandbox owned by another node.
- A second use case drives `aerolvm mcp` with the go-sdk client through the
  same flow, plus pinned lazy create and idle-destroy.

## 9. Open questions (decide at eng review)

1. **Name lookup shape (T2):** `GET /v1/sandboxes?name=` (recommended) or let
   `GET /v1/sandboxes/{id}` accept names. The second option is ambiguous if a
   name can look like an ID.
2. **Auto-generated names** on unnamed CLI/MCP creates (§5.4): is making
   every agent-created sandbox named acceptable? Recommended: yes, since it is
   the only retry-safe create without a server-side idempotency key.
3. **Docs hard rule.** CLAUDE.md requires every new page to cover all five SDK
   languages. `cli.mdx` / `mcp.mdx` are shell and JSON by nature. Proposal:
   - Tabs keyed by MCP client (`syncKey="mcp-client"`).
   - A required "Same thing from the SDK" section with the usual five-language
     `syncKey="lang"` tabs.
   - No curl, so the curl rule is unaffected.
   - The CLI install reuses the existing `install.sh` one-liner with
     `--cli-only`, so no second curl line is added.
   This needs explicit sign-off as a documented exception.
4. **Stdin default:** explicit `-i` (recommended; avoids hangs) or E2B-style
   auto-pipe.
5. **Default toolset:** should `run_code` be in `core`? It depends on an
   interpreter being in the image, so recommended: no, keep it in `code`.
6. **Binary name:** `aerolvm` matches the product and the `~/.aerolvm` local
   install dir. Confirm no clash with packaging plans.

## 10. NOT in scope

- Operator / admin verbs in the CLI or MCP (templates, cluster, audit,
  custom domains, network limits).
- MCP tools that touch the local filesystem.
- Writing other tools' config files.
- MCP resources, prompts or sampling.
- A TUI.
- MCP servers in the other four SDK languages.
- Daytona / E2B facade-specific MCP tools. The facades are wire translators,
  not a second agent surface.
- A server-side create idempotency key (§5.4 sidesteps it; revisit if the
  name approach is rejected).
