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
| 3 | Remote MCP endpoint inside `sandboxd` (`/mcp`, Streamable HTTP) | **Bearer-auth endpoint in this plan as Phase 2b** (CEO review C1). OAuth, which claude.ai / ChatGPT connectors need, stays Phase 4. |
| 4 | An MCP server per SDK language | Rejected. That is five servers for one protocol. |
| 5 | Leave it to third parties (Composio, community servers) | Rejected. We would not control idempotency, scoping or output bounds, which are the parts that make it safe (§6, §7). |

## 4. Phases

Each task is one PR. Following our stacked-PR policy, nothing merges until the
whole phase's stack is green.

| Phase | Tasks | Server change? | Gate |
|---|---|---|---|
| **1. Tool layer + CLI** | T1 `internal/agenttools` (resolution, get-or-create, output shaping, error mapping) · T2 v1 name lookup (§5.6) · T2b per-owner unique names (§5.6, D4) · T3 `cmd/aerolvm` core verbs · T4 exec streaming, exit codes, timeouts · T5 `cp` / `ls` + Go SDK `DownloadFileStream` / `UploadFileStream` (D14) · T6 release matrix + `install.sh --cli-only` · T7 `cli.mdx` + one ROADMAP.md "will do" bullet for the CLI + MCP (CEO review C5) | T2 (additive query param) + T2b (store name index + Raft FSM `nameIndex`; fragile areas) | eng review of this doc |
| **2. stdio MCP** | T8 `aerolvm mcp` (core toolset) · T9 optional `files` / `process` toolsets + pinned / ephemeral modes · T10 `aerolvm mcp config <client>` · T11 `mcp.mdx` · T12 integration UCs (CLI + MCP) | none | Phase 1 merged |
| **3. Distribution** | npm package with per-platform binaries (`npx -y @aerol-ai/aerolvm mcp`) · official MCP Registry entry (`server.json` `io.github.aerol-ai/aerolvm` → the npm package; release step runs `mcp-publisher validate` + `publish` via GitHub OIDC; CEO review C3) · Homebrew tap · `aerolvm login` profiles | none | Phase 2 merged |
| **2b. Remote MCP (bearer)** | `/mcp` on sandboxd, stateless Streamable HTTP, `SB_MCP_ENABLED` default false, bearer auth only (§5.7; CEO review C1) | yes (`pkg/api`) | Phase 2 merged |
| **4. OAuth for hosted connectors** | OAuth 2.1 protected-resource metadata for claude.ai / ChatGPT connectors through `pkg/controlplane` | yes | demand checkpoint + separate eng review |

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
internal/agentmcp/      MCP tool registry over agenttools (Phase 2); reused by sandboxd's /mcp in Phase 2b
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
   `destroy --all`. One exception, added after launch because people
   reached for the CLI to get *into* a sandbox and found no way in:
   `aerolvm shell` opens an interactive shell (a persistent PTY session)
   and, with no sandbox named, asks which one. It refuses to run unless
   stdin and stdout are both terminals, so no agent or script can reach the
   prompt; they keep using `exec`. `aerolvm login` asks for the URL and
   token only on a terminal; a script passes the URL and `--token-stdin`.
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
6. **Any sandbox can be referenced as `<id-or-name>`.** Resolution goes by
   shape (eng review D12): a ref matching `^sb-[0-9a-f]{16}$` (the ID format
   from `generateSandboxID`) is an ID; anything else is a name and uses the
   name lookup (§5.6). That is one request per ref. Creates reject names that
   match the ID shape, next to the reserved `owner:` prefix (D9).
7. **Retries are safe.** `create` is idempotent (§5.4), `destroy` treats 404 as
   success, and `expose` already returns the existing URL.
8. **Stdin is forwarded automatically when it is not a TTY** (E2B style; eng
   review D19). `--no-stdin` turns it off, and `-i` forces forwarding on a
   TTY. Some agent harnesses hand child processes an open stdin that never
   reaches EOF. There, a stdin-reading remote command waits until `--timeout`,
   so `cli.mdx` tells users to pass `--no-stdin` in those harnesses. On WASM
   sandboxes, automatic forwarding is skipped (buffered exec has no stdin); an
   explicit `-i` there fails with the D10 error.
9. **`--help` is written for models.** It is short, has one or two real
   examples per verb, and names the JSON shape.

Verbs (Phase 1):

```
aerolvm create  [--name N] [--image I] [--runtime R] [--cpu C] [--memory-mb M]
                [--env K=V]... [--tag K=V]... [--destroy-if-idle 1h] [--block-network]
aerolvm list    [--tag K=V]... [--page-token T] [--limit N]
aerolvm get     <sandbox>
aerolvm exec    <sandbox> [-i] [-t] [--cwd D] [--env K=V]... [--timeout 5m]
                [--background] -- <cmd> [args...]
aerolvm logs    <sandbox> <session-id> [--follow]      # for --background
aerolvm cp      <src> <dst>        # docker-cp form: sb:/path ↔ local path, "-" = stdin/stdout; streams (D14)
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

*Update (built early, with `aerolvm shell`):* people reaching for a shell had
to export both variables in every terminal, so `aerolvm login [<url>]` landed
ahead of Phase 3, without profiles. It verifies the token with one
authenticated read (`/health` takes no token) and saves one URL + token to
`~/.config/aerolvm/config.json` (0600). `SB_PAT_TOKEN` still wins, and the
saved token is only sent to the URL it was saved for. `aerolvm logout`
forgets it locally. `aerolvm health` now also proves the token works.

Operator verbs (templates, WASM module push, cluster drain, audit) are
deliberately absent. They are not agent operations, and a later
`aerolvm admin …` can add them if humans ask.

### 5.3 MCP server (`aerolvm mcp`, stdio)

**Toolsets.** Every extra tool costs the model selection accuracy and context,
so the default set is small. Enable more with `--toolsets core,files,process`
or `--toolsets all`. (The `code` and `lifecycle` toolsets were deferred at eng
review, D1/D2; see §10.)

| Toolset | Tool | Args (abridged) | Annotations | Wraps |
|---|---|---|---|---|
| core | `sandbox_create` | name?, image?, runtime? (every runtime except `isolate`, D11), cpu?, memory_mb?, env?, destroy_if_idle_minutes? | idempotent (§5.4) | get-or-create |
| core | `sandbox_list` | tags?, page_token? | readOnly | `ListPage` + `WithLimit(20)`; compact rows {id, name, status, runtime, created_at, tags} (D15) |
| core | `sandbox_destroy` | sandbox | **destructive**, idempotent | `Destroy` (404 = ok) |
| core | `exec` | sandbox, command, cwd?, env?, timeout_seconds? | openWorld | bounded `ExecStream` |
| core | `read_file` | sandbox, path, offset_line?, limit_lines? | readOnly | `DownloadFileStream`, reads window + 1 byte (D14) |
| core | `write_file` | sandbox, path, content | idempotent | `UploadFileStream` (D14) |
| core | `list_files` | sandbox, path | readOnly | toolbox `/files` |
| core | `expose_port` | sandbox, port | idempotent | `ExposePort` |
| files | `edit_file` | sandbox, path, old_string, new_string | — | read → unique-match replace → write |
| files | `search_files` / `grep_files` | sandbox, path, pattern | readOnly | toolbox `/files/search`, `/files/find` |
| process | `start_process` / `process_logs` / `stop_process` | sandbox, command / session_id | — | sessions API |

No MCP resources, prompts or sampling in v1 (YAGNI; sampling is deprecated in
2026-07-28 anyway).

**Result shape.** Each result carries `structuredContent` plus a text
rendering for older clients. A non-zero exit code from `exec` is a normal
result (`exit_code: 2`), not `isError`. `isError` is reserved for API
failures, and the message tells the model what to do next, e.g. "sandbox
`foo` not found — it may have been destroyed by its idle lifecycle; call
`sandbox_list` or `sandbox_create`".

**Output bounds.** These protect the context window and the memory of the MCP
process. `exec` captures at most `--max-output-bytes`
(default 16 KiB per stream) as head 4 KiB + tail 12 KiB, since errors live at
the tail. Truncated output reports `truncated: true` and the dropped byte
count. `exec` uses `ExecStream` with ring buffers instead of buffered `Exec`,
except on WASM sandboxes, which refuse streaming exec
(internal/runtime/wasm/toolhost/exec_stream.go:21). There, exec uses buffered
`POST /process/execute` with the response read under a 4 MiB limit: a larger
body returns `output_too_large`, and within the limit the same head/tail
truncation applies. `-i`/`-t` on WASM fail with a clear error (eng review D10).
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

If the pinned sandbox is gone after an earlier successful call (for example
destroyed by the idle lifecycle), the server drops its cached ID and recreates
the sandbox by name. The result of that call carries `sandbox_recreated: true`
and a one-line notice that files from earlier calls are gone; the CLI prints a
stderr warning (eng review D6).

**Cleanup.** MCP-created sandboxes default to `lifecycle.stop_if_idle_for`
30m and `lifecycle.destroy_if_idle_for` 24h (eng review D7; `--keep` opts out,
and both values are configurable). A stopped sandbox keeps its files. Toolbox
calls don't wake a stopped sandbox (`ToolboxTarget`,
internal/service/service.go:4173), so agenttools calls Start first when the
resolved sandbox is `stopped`. `--ephemeral` also destroys the pinned sandbox on clean shutdown
(stdin EOF / SIGTERM), but that is best-effort only, since hosts commonly
SIGKILL MCP servers. **The server-side lifecycle TTL is the cleanup guarantee.
Process exit is not.**

**Isolate sandboxes** have no shell or filesystem (internal/runtime/isolate/exec.go:36).
The MCP runtime enum leaves `isolate` out. Any CLI or MCP file or exec call
against an isolate sandbox returns "isolate sandboxes have no shell or
filesystem; use the SDK's invoke" before reaching the toolbox (eng review D11).

**Create cap (CEO review C4).** Unpinned `aerolvm mcp` allows at most 5
successful creates per process (`--max-creates N`, 0 = unlimited). The 6th
returns `isError` ("create limit reached for this session; destroy a sandbox or
raise --max-creates") without sending a POST. Pinned recreates (D6) and creates
that resolve to an existing sandbox on 409 (D5) don't count. The remote
`/mcp` (Phase 2b) has no session cap; only the managed build's per-owner
admission gate (`pkg/controlplane` `Admitter`) applies there.

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
3. On 409 (the owner's unique-name index won a race), go back to step 1.
   Names are unique per owner (T2b, D4), so a 409 means this owner already
   has the name and step 1 finds it.

Every CLI create carries the tag `aerolvm.created_by=cli`, and every MCP
create (stdio or remote) carries `aerolvm.created_by=mcp` (CEO review C6). The
tag is merged with the user's tags, and a user-supplied value wins.

When the caller gives no name, the CLI generates one (`agent-<12 random
base32>`) **before** the first attempt (eng review D5). The SDK's internal
retries and the caller's retries then all target the same row. Verified at eng
review: the Go SDK does retry `POST /sandboxes` on post-send transport errors
and on 502/503/504 (sdk/go/internal/apiclient/client.go:886-946). Without a
name, a lost reply creates a duplicate. That is a pre-existing bug for every
SDK user and is tracked separately. agenttools test: the fake server creates
the sandbox and then drops the connection; assert exactly one sandbox and the
same ID returned.

### 5.5 Exec semantics worth pinning in tests

- Exit info from `ExecStreamHandle.Wait()`: `Code`, plus `Signal` mapped to
  128+n.
- `--timeout` cancels the stream, sends `Signal("KILL")` and returns 124.
- Any cancellation sends `Signal("KILL")` before closing the stream: CLI
  SIGINT/SIGTERM, MCP `notifications/cancelled`, or ctx done.
- Keepalive (eng re-review RR1): toolboxd pings exec streams every 30s; the
  read deadline is 90s and extends on every pong or message. So an idle proxy
  never closes a silent long command, and a real drop is detected within 90s.
- Kill on drop (CEO review CF3): toolboxd kills the command's process group
  if the WebSocket closes or errors before the exit message is sent. This
  covers a client that dies too suddenly to send anything, and every SDK.
  Sessions (`/sessions`) are unaffected and remain the way to run long-lived
  work. Rollout: containerd/docker/gVisor bind-mount toolboxd from the host
  (`SB_TOOLBOX_BINARY_PATH`), so a host upgrade reaches new sandboxes; running
  sandboxes and Firecracker snapshots/templates keep the old behaviour until
  restart or rebuild (eng re-review correction).
- `--background` creates a session and prints `{"session_id":…}`.
  `aerolvm logs --follow` attaches to it.
- `-t` requests a TTY (cols/rows from the local terminal) and is only valid
  when stdout is a TTY.

### 5.6 Server changes: v1 name lookup (T2) and per-owner names (T2b)

v1 has no "get by name". The Daytona facade resolves names via
`Service.ResolveSandboxIDByName` → `store.ResolveSandboxIDByName`, and cluster
mode already keeps a name index in the Raft FSM (`placement-by-name`,
`internal/cluster/agent.go`). The proposal is to add `?name=<name>` to
`GET /v1/sandboxes`. The handler resolves the name through the placement-by-name
lookup in cluster mode (O(1) on the FSM, with no peer fan-out) or through the
store in single-node mode, and returns a 0- or 1-element list.

- **Client-side check (CEO review CF5).** Servers that predate T2 ignore the
  unknown `name` parameter and return a full page (pkg/api/v1/handlers.go:168
  reads only `tag.*`; the handler otherwise reads only `ids`). So agenttools
  accepts a `?name=` response only if it has at most one row and that row's
  name equals the request. Anything else is `server_unsupported`: "sandboxd
  at <url> does not support name lookup; use the sandbox ID or upgrade". This
  applies to every name resolution, including get-or-create.
- It is additive, so a soft-frozen v1 is fine. Follow `/add-v1-endpoint` and
  `/add-sdk-method` so all five SDKs get `get_by_name` in lockstep.
- Tenant scoping must match `scopedGet`. A name owned by another tenant must
  return an empty list, not leak the name's existence. Regression test required.
- Rejected alternative: tag the sandbox with `aerolvm/name=<n>` and look it up
  via the tag filter. That needs no server change, but every lookup becomes a
  `clusterListWrap` fan-out across every node, which is the read-path cost
  shape we just removed from reconcile.

**T2b: names unique per owner (eng review D4).** Today the store enforces
`CREATE UNIQUE INDEX idx_sandboxes_name ON sandboxes(name) WHERE name <> ''`
(internal/store/store.go:377) while reads are owner-scoped (`scopedGet`,
internal/service/owner_scope.go:47). In a managed multi-tenant install,
tenant B cannot use a name tenant A holds, cannot see why, and the 409 reveals
that the name exists. T2b makes names unique per owner:

- Store: the per-owner unique index **keeps the name `idx_sandboxes_name`**
  (CEO review CF7).
  - A startup migration reads the index definition from `sqlite_master`. If
    it is still the global `(name)` form, the migration drops it and
    recreates `idx_sandboxes_name ON sandboxes(owner_ref, name) WHERE
    name <> ''`, in one transaction.
  - This only relaxes a constraint, so existing rows can't violate it.
  - Because SQLite's `IF NOT EXISTS` checks only the name (verified with
    sqlite3), a rolled-back binary skips its old global statement and still
    boots.
- `store.ResolveSandboxIDByName` and `Service.ResolveSandboxIDByName` take the
  owner. The Daytona facade's `resolveSandbox` (pkg/api/daytona/handlers.go:826)
  resolves names within the caller's owner.
- Cluster: the FSM `nameIndex` (internal/cluster/fsm.go:380-386, "maps sandbox
  Name → SandboxID for cluster-wide name uniqueness") becomes per owner
  **without a gate and without changing the apply code** (eng review D8/D9).
  Every replica derives the index key from `specName(cmd.Spec)`
  (fsm.go:1880). So the node that accepts a tenant create writes an
  owner-qualified key, `owner:<base64url(owner_ref)>/<name>`, into the Raft
  command's `Spec.Name` and `Placement.Name`. Old and new replicas then
  compare identical strings and always reach the same apply result.
  - Operator sandboxes (owner_ref "") keep plain names, so both styles live in
    one index.
  - New code decodes the key back to the user name everywhere it reads
    `Spec.Name` (failover recreate, list, Daytona). It rejects user names
    that start with the reserved `owner:` prefix.
  - Name lookup, including the placement-by-name path
    (internal/cluster/agent.go:339), tries the qualified key first, then the
    plain key filtered by `OwnerRef`. Tenant sandboxes created before the
    upgrade keep resolving by name.
  - Upgrade-window caveats, documented in the release notes:
    - An old node that recreates or lists a new tenant sandbox shows the
      encoded name until it upgrades.
    - An owner can end up with a legacy and a new sandbox of the same name if
      both were created during the window, through an old and a new node. The
      lookup prefers the qualified key.
    - Failover onto a not-yet-upgraded node can hit that node's global store
      index.

### 5.7 Phase 2b: remote MCP on sandboxd (CEO review C1)

In this plan (CEO review D2/C1). It has bearer auth only, and OAuth stays
Phase 4. With a token, Claude Code (`--transport http --header`), Cursor and
VS Code can connect to a URL without installing anything. claude.ai and
ChatGPT connectors still need Phase 4's OAuth.

- Mount `/mcp` on the API mux (not under `/v1`, because MCP versions itself).
  It is off unless `SB_MCP_ENABLED=true`.
- Options are URL query parameters (CEO review CF1): `sandbox`,
  `create_if_missing`, `image`, `runtime`, `toolsets` and `read_only`.
  - They use the stdio flags' names and validation and are parsed on every
    request (stateless). An invalid value returns 400 naming the parameter.
  - Both the stdio flag parser and the remote query parser call one
    `agentmcp` options type and its `Validate()`, so the names and rules
    can't drift (eng re-review; required by CF1).
  - The token stays in the `Authorization` header.
  - Pinned lazy create on different nodes converges on one sandbox through
    the name-keyed get-or-create (D4/D5).
- Observability (CEO review CF6):
  - Metrics: expvar map `aerolvm_mcp`, exported through
    `CollectAerolVMExpvars`, with calls by tool × outcome (`ok`,
    `tool_error`, `api_error`, `bad_request`, `unauthorized`) and latency
    by tool.
  - Per tool call: one structured log line and one OTEL span with tool,
    sandbox_id, owner_ref, outcome and duration_ms. Arguments and outputs
    are never logged.
  - A "Remote MCP" panel row in setup/grafana, and a Prometheus alert when
    the error ratio is over 20% for 10m.
  - Runbook: setup/runbooks/remote-mcp.md.
- Fresh-sandbox notice (eng re-review RR2). The endpoint is stateless, so it
  can't tell a first call from a recreate. Every remote lazy create therefore
  returns `sandbox_created: true` plus "this is a newly created sandbox; files
  from any earlier session are not present". This is stdio D6's protection
  in a stateless form.
- Remote is pinned-only (CEO review CF2). `/mcp` without `sandbox=` returns
  400 ("remote MCP requires ?sandbox=<name>").
  - `sandbox_create`, `sandbox_list` and `sandbox_destroy` are never
    registered remotely.
  - Unpinned mode with the C4 cap stays stdio-only.
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
- Exec: WebSocket hijack doesn't work in-process, so remote exec uses the D10
  buffered `/process/execute` path for every runtime, under the same 4 MiB
  limit (CEO review C1).
  - The in-process transport must stream the handler's response through an
    `io.Pipe`. A recorder that buffers the whole body would hold an
    unbounded response in sandboxd memory before the limit applies.
  - `-i`/`-t` don't exist on this path; MCP `exec` has no stdin.
- Security: validate `Origin` (DNS rebinding, required by the spec), bearer
  auth via the existing middleware, never register operator tools, per-token
  rate limit. OAuth 2.1 protected-resource metadata for claude.ai connectors
  goes through the `pkg/controlplane` seam (managed build). The open-source
  build stays bearer-only.

### 5.8 Claude Code plugin (CEO review C2)

The repo is its own Claude Code marketplace:
- `.claude-plugin/marketplace.json` lists `plugins/aerolvm/`.
- `plugins/aerolvm/.claude-plugin/plugin.json` registers the MCP server
  (`aerolvm mcp`).
- `plugins/aerolvm/skills/aerolvm/SKILL.md` is a short skill:
  - when to reach for a sandbox
  - the core verbs: `create`, `exec`, `cp`, `expose`, `destroy`
  - `--json` and `--no-stdin`
  - pinned MCP mode
  - it points at `aerolvm <verb> --help` for detail, so the model learns
    progressively instead of reading every tool up front.

Users run `/plugin marketplace add aerol-ai/microvm` and then
`/plugin install aerolvm`; the `aerolvm` binary must be on PATH. A CI check
parses both manifests and fails if the skill names a verb that
`aerolvm --help` doesn't list.

## 6. Security

| Threat | Mitigation |
|---|---|
| Prompt injection via sandbox output (a file says "now destroy all sandboxes") | Pinned mode removes cross-sandbox tools. `--read-only`. `destructiveHint` makes clients confirm. Tenant-scoped tokens remain the real boundary, and docs recommend a token scoped to agent sandboxes. |
| Exfiltrating the **host** filesystem through the MCP server | **No MCP tool reads or writes the local machine.** Every file tool targets the sandbox. There is deliberately no `upload_local_file`. (The CLI's `cp` does touch local files, but it is invoked from the user's own shell, which has the same trust as any other shell command.) |
| Token leakage | Env only. Never accepted as a tool arg, never echoed in results, errors or logs. `Authorization` redacted in `--debug`. `mcp config` prints an env reference, not the value. |
| Context or memory flooding (`yes`, huge files) | Head/tail ring buffers, read windows, binary refusal (§5.3). |
| Orphaned, billed sandboxes from abandoned agent sessions | Default lifecycle on MCP-created sandboxes (stop after 30m idle, destroy after 24h), lazy create (§5.3). |
| Supply chain (new go-sdk dep, npm wrapper in Phase 3) | Pinned versions, dependency review, release attestation already covers `dist/*`. Run the npm package through the same provenance as `publish-sdks.yml`. |

## 7. Hard-rule call-outs (CLAUDE.md / pr-review.md)

1. **Idempotency.**
   - Safe under retry: create (name-keyed), destroy (404 = ok), expose (the
     server returns the existing URL), write_file (same bytes),
     stop/start/snapshot (existing server semantics).
   - `exec` and `start_process` are inherently not idempotent.
     They are annotated `idempotentHint: false`, and their docs say so.
2. **Boot-path latency.**
   - Phases 1–3 add no work to `CreateSandbox`.
   - T2 is a read path only.
   - T2b changes the key of the name-uniqueness checks that `CreateSandbox`
     already does (the store unique index and the FSM `nameIndex` reservation)
     from name to (owner, name). It adds no queries, round-trips or locks.
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
   - T2b makes the FSM name index per owner by writing an owner-qualified key
     into the replicated `Spec.Name` (D8/D9). Apply code is unchanged, so old
     and new replicas stay deterministic during a rolling upgrade, with no
     gate. It needs regression tests next to the FSM (`fsm_*_test.go`) and a
     PR call-out covering replay safety and leader-change behaviour.
   - Phase 2b's remote endpoint is stateless and loops through
     `clusterForwardWrap`.
   - Single-node mode resolves names from the store. `Noop` behaviour is
     unchanged.

## 8. Testing

**Offline (`make test`, keeping each package at ~85% or above):**

- **`internal/agenttools`:** table-driven tests against an `httptest` fake of
  v1 and the toolbox, in the style of `sdk/go/pkg/microvm/client_test.go`.
  They cover:
  - get-or-create including the 409 race
  - provenance tag (CEO C6): the create request carries
    `aerolvm.created_by=cli|mcp`; a user-supplied value is kept
  - lost-reply create (D5): the fake server creates the sandbox and then drops
    the connection; exactly one sandbox exists and the same ID is returned
  - old server (CEO CF5): a fake server returns 3 sandboxes for `?name=x` →
    `server_unsupported`, and no follow-up exec/destroy is sent; one row with
    a different name → `server_unsupported`; 0 rows → not_found; 1 matching
    row → used
  - ref routing by shape (D12): `sb-` + 16 hex → ID lookup only; anything
    else → name lookup only; create rejects ID-shaped names
  - head/tail truncation boundaries
  - binary detection
  - `edit_file` unique-match failure
  - error-code mapping
  - large files (D14): `read_file` on a large fake body reads at most window +
    1 bytes; `cp` of a 64 MiB fake file stays under a fixed allocation bound;
    apiclient streaming upload (multipart via io.Pipe) and download
  - WASM exec (D10): a WASM sandbox uses buffered exec with no WebSocket
    dial; a body over 4 MiB → `output_too_large`; long stdout under the
    limit → `truncated: true`; `-t` on WASM → clear error
- **`cmd/aerolvm`:** golden tests for `--json` output and stderr error
  envelopes, plus tests for:
  - exit codes (remote code passthrough, 124 timeout, 125 API failure,
    128+n signal)
  - stdin (D19): forwarded automatically when not a TTY; `--no-stdin`
    disables it; on WASM, automatic forwarding is skipped and an explicit `-i`
    errors
  - no ANSI output when not on a TTY
- **`internal/agentmcp`:**
  - The go-sdk in-memory transport drives every tool against the fake API.
  - A **golden snapshot of `tools/list`** (names, schemas, annotations per
    toolset and mode) makes any schema change a reviewed diff.
  - Pinned mode hides `sandbox` and the fleet tools. Read-only mode hides
    writers.
  - `sandbox_list` (D15): rows carry only {id, name, status, runtime,
    created_at, tags}; at most 20 per page; `next_page_token` passes through;
    apiclient sends `limit=20`.
  - Create cap (CEO C4): 5 creates succeed and the 6th returns the error
    without a POST; a 409 that resolves to an existing sandbox doesn't count;
    `--max-creates 0` lifts the cap.
  - Isolate (D11): the tools/list golden shows the runtime enum without
    `isolate`; a file tool and exec against an isolate sandbox return the
    clear error with no toolbox call.
  - Stopped pinned sandbox (D7): exactly one Start, then the tool runs.
    Created sandboxes carry the 30m stop / 24h destroy lifecycle.
  - Pinned recreate (D6): the first call creates; the fake API then 404s the
    ID; the next call recreates and its result carries `sandbox_recreated:
    true` and the notice exactly once.
- **stdout hygiene:** spawn the built binary, send `initialize` and a tool call
  on stdin, and assert that every stdout line parses as JSON-RPC.
- **Dependency guard** (§5.1).
- **CEO review tests:**
  - RR1: a silent `sleep 120` behind a fake 60s-idle proxy completes; with
    pongs suppressed, the process dies after the 90s deadline.
  - CF3: toolboxd starts `sleep 300`, the test drops the WebSocket, and the
    process group must be gone within 2s; a normal exit still sends the exit
    message; agenttools sends KILL on cancellation.
  - CF1/CF2: each `/mcp` query parameter maps to the same registry config as
    its stdio flag; an invalid value → 400 naming the parameter; no
    `sandbox=` → 400; a remote tools/list never contains the fleet tools.
  - C2: the plugin manifests parse, and the skill names only verbs listed by
    `aerolvm --help`.
  - C3: `mcp-publisher validate` runs in the release workflow.
  - Origin/Host (§5.7, required proof): a disallowed `Origin` → 403; no
    `Origin` header (non-browser MCP clients) → allowed.
  - In-process transport (C1, required proof): the handler's response streams
    through `io.Pipe`. Headers and the first bytes arrive before the handler
    finishes, and a body over 4 MiB never sits whole in sandboxd memory.
  - RR2: a remote `create_if_missing` call that creates → `sandbox_created:
    true` + notice; a call on an existing sandbox → no flag.
  - CF6: one remote tool call increments the right `aerolvm_mcp` counter and
    emits exactly one log line, which contains no arguments.
- **Required proof added at eng review (Section 3)** for behaviour already in
  this plan:
  - lazy pinned create is single-flight: two concurrent first calls produce
    exactly one POST; a failed create is not latched, so the next call
    retries (§5.3).
  - `--ephemeral`: closing stdin, or sending SIGTERM, to the spawned binary
    destroys the pinned sandbox exactly once (§5.3).
  - `aerolvm mcp config <client>` output never contains the `SB_PAT_TOKEN`
    value, even when it is set (§5.3, §6).
  - `--debug` logs redact the `Authorization` header (§6).
  - `?name=` in cluster mode makes no peer fan-out call (§5.6).
  - `destroy` on 404 returns success; a repeat `expose` returns the same URL
    (§5.2 rule 7).
  - `read_file` returns at most 2,000 lines / 256 KiB with a continuation
    offset that reads the rest (§5.3).
  - a non-zero `exit_code` is a normal result, not `isError`; an API failure
    is `isError` with a next-step hint (§5.3).
- **CRITICAL regression (T2b, D9 contract: operator names stay plain):**
  these must keep passing with their meaning unchanged:
  - internal/cluster/fsm_test.go:1192 `TestFSMRejectsDuplicateName`
  - internal/cluster/fsm_test.go:1219 `TestFSMNameReleasedOnDelete`
  - internal/cluster/fsm_test.go:1241 `TestFSMSamePlacementSameNameIdempotent`
  - internal/cluster/fsm_test.go:1257 `TestFSMRestoreRebuildsNameIndex`
  - internal/cluster/fsm_reserve_test.go:156, 193
  - internal/cluster/fsm_recovery_inline_test.go:56
  - internal/store/store_test.go:515 (`ResolveSandboxIDByName` gains an owner
    argument; the "" namespace must behave as today)
  - pkg/api/daytona/handlers_coverage_test.go:659
- **T2:**
  - handler test
  - store test
  - cluster test where the name is owned by a peer
  - tenant-scoping test (another tenant's name → empty list)
- **T2b:**
  - store test: two owners create the same name (both succeed); the same owner
    creates it twice (409); the old global index is gone after migration.
  - rollback (CEO CF7): run the OLD schema statement list against a migrated
    DB that holds cross-owner duplicate names; the open must succeed.
  - FSM tests: `nameIndex` per owner across apply, snapshot and restore.
    Mixed-version determinism: a legacy-mode FSM and a new FSM apply one
    command sequence and end with an identical `nameIndex` (D9).
  - key tests: encode/decode round trip; user names starting with `owner:`
    are rejected; lookup falls back to the plain key filtered by `OwnerRef`.
  - decode fallback (CEO review, required proof of D9): a legacy sandbox
    whose plain name already starts with `owner:` (created before the prefix
    rule) but isn't a valid encoded key decodes to itself and never errors.
  - cluster test: two tenants hold the same name on different nodes.
  - Daytona facade test: name resolution stays within the caller's owner.

**Agent eval (`-tags=agenteval`, operator-run, never in `make test` or CI;
eng review D13):** Claude drives `aerolvm mcp` against a single-node local
sandboxd through 5 tasks with loose pass criteria:
1. create + exec + read the output
2. write a file, then read it back
3. `start_process` a dev server, `expose_port` it and fetch the URL
4. recover after a recreate notice (D6)
5. exec on a WASM sandbox (D10)

Run it before changing any tool name, description or notice text, and before
release.

**Live (`integration-tests/`, `integration` tag):**

- A new use case runs CLI create → exec → cp → expose → destroy on
  `single-node` and `cluster-3-mixed`. The cluster run uses name resolution
  for a sandbox owned by another node.
- A second use case drives `aerolvm mcp` with the go-sdk client through the
  same flow, plus pinned lazy create and idle-destroy.
- A third use case (CEO review C1) drives the remote
  `/mcp?sandbox=x&create_if_missing=1` endpoint with the go-sdk client on
  `cluster-3-mixed`. The request lands on a node that doesn't own the sandbox.

## 9. Open questions (all resolved at eng review, 2026-10-04)

1. ~~**Name lookup shape (T2)**~~ Resolved at eng review (D17):
   `GET /v1/sandboxes?name=`.
2. ~~**Auto-generated names** on unnamed CLI/MCP creates~~ Resolved at eng
   review (D5): yes, `agent-<12 random base32>`.
3. ~~**Docs hard rule.**~~ Resolved at eng review (D18): a documented
   exception for `cli.mdx` and `mcp.mdx`. They use client tabs
   (`syncKey="mcp-client"`) plus a required five-language "Same thing from the
   SDK" section, and CLAUDE.md names the exception.
4. ~~**Stdin default**~~ Resolved at eng review (D19): automatic on a
   non-TTY stdin, with `--no-stdin` to opt out.
5. ~~**Default toolset:** should `run_code` be in `core`?~~ Moot: the `code`
   toolset was deferred at eng review (D1).
6. ~~**Binary name**~~ Resolved at eng review (D20): `aerolvm`. No binary of
   that name exists today; the string is only a containerd namespace and an
   AWS cluster tag.

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
- The `code` MCP toolset (`run_code`), deferred at eng review (D1): `exec`
  covers it, and it fails on images without the interpreter. Add on demand.
- The `lifecycle` MCP toolset (`sandbox_get` / `start` / `stop` /
  `snapshot`), deferred at eng review (D2). The CLI keeps these verbs; the
  idle-destroy default covers cost. Add on demand.

## Eng review record (/plan-eng-review, 2026-10-04)

**Target:** `plans/mcp-server-and-agent-cli.md` (this file), PR #578, branch
`feat/mcp-server-agent-cli-plan`. Sections 1–10 above are the plan as reviewed;
amendments from approved decisions are applied in place and listed here.

### Scope record

feature answers: D1 = A (defer the `code` toolset / `run_code`), D2 = A (defer
the `lifecycle` MCP toolset: sandbox_get / start / stop / snapshot; the CLI
keeps its start/stop/snapshot verbs); structure: A, original arrangement (D3:
`cmd/aerolvm` + `internal/agenttools` + `internal/agentmcp`); accepted scope:
Phases 1–2 as written, minus the `code` and `lifecycle` MCP toolsets (both
moved to §10 NOT in scope); pending remedies: R1–R3 (Scope Challenge findings).

Scope Challenge result: scope reduced per recommendation (D1, D2). Later
answers added scope: per-owner names (D4, rolled out with no gate per D8/D9),
auto-generated names (D5), recreate notice (D6), stop-then-destroy idle policy
(D7), WASM exec path (D10), isolate guard (D11).

## Decision ledger

### R1: get-or-create when a name is held by a sandbox this token cannot see
Finding: Scope Challenge #1, P1, confidence 9/10, internal/store/store.go:377 (`CREATE UNIQUE INDEX IF NOT EXISTS idx_sandboxes_name ON sandboxes(name) WHERE name <> '';`) + internal/service/owner_scope.go:47-55 (`scopedGet` → `enforceOwner`); reviewer: Claude (plan-eng-review).
Plan baseline: §5.4 step 3 "On 409 ... go back to step 1" (unbounded); §5.6 "A name owned by another tenant must return an empty list". Original proposal, not yet approved.
Runtime evidence: the name index is global across owners; GET is owner-scoped. With a tenant token, a name held by another tenant yields scoped GET = empty and POST = 409, every iteration. The open-source PAT is unscoped, so single-operator installs never hit it.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R1 behaviour on 409 + empty scoped GET | loop back to step 1 (unbounded) | one re-check, then error `name_taken` ("name in use by a sandbox this token cannot see; choose another name") | cannot occur: names unique per owner |
| Name uniqueness scope | global (store.go:377) | unchanged, global | per owner: index on (owner_ref, name), owner-scoped `ResolveSandboxIDByName` and cluster placement-by-name |
| Server work | T2 (`?name=` lookup) | T2 only | T2 + store index migration + Raft FSM name-index change (fragile areas: regression tests + PR call-out) |
| Docs / `mcp config` | example uses `--sandbox my-agent` | recommend unique pinned names; document `name_taken` | no change needed |
| Tests | none planned for this case | agenttools test: 409 + empty scoped GET → `name_taken`, exactly 2 GETs + 1 POST | store, FSM and cluster tests for per-owner names |
| R2, R3, R4 | pending | pending | pending |

Question D4:
D4 — What should get-or-create do when another tenant already holds the name?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: Sandbox names are unique across the whole fleet (internal/store/store.go:377), but a tenant can only see its own sandboxes (owner_scope.go:47). If tenant B asks for `my-agent` and tenant A already has it, B's lookup finds nothing and B's create gets "name taken". The plan's get-or-create (§5.4) then retries forever. Only managed multi-tenant installs are affected; a single-operator install has one unscoped token.
Stakes if we pick wrong: as written, an MCP user in a managed install picks a common name and every tool call hangs in a retry loop. The heavier fix touches the store index and the Raft name index, two of the repo's fragile areas.
Recommendation: A because it stops the loop with a clear, actionable error now. B is a real product change to the fragile store and Raft paths, so it deserves its own plan (offered later as a TODO).
Completeness: A=7/10, B=10/10
Pros / cons:
A) Fail with `name_taken` (recommended)
  ✅ No loop: one re-check after the 409, then an error telling the user to pick another name
  ✅ No server change beyond T2; testable offline (human: ~2h / CC: ~10 min)
  ❌ Common names still collide across tenants in managed installs; the 409 still reveals that a name exists
B) Make names unique per owner
  ✅ Removes the collision and the cross-tenant 409 existence leak at the root
  ✅ Every tenant can use natural names like `my-agent`
  ❌ Store index migration plus a Raft FSM name-index change: fragile areas, regression tests, Daytona semantics change (human: ~1 week / CC: ~3h)
Net: a clear error now and a separate plan for per-tenant names, against doing the store and Raft change inside this plan.
Header: D4 name clash
Options:
A) Fail with name_taken (recommended)
One re-check after a 409; if the scoped GET is still empty, return error `name_taken` telling the user to choose another name. Docs and `mcp config` recommend unique pinned names. Test: 409 + empty scoped GET → `name_taken` after exactly 2 GETs + 1 POST. No server change beyond T2. Human ~2h / CC ~10 min.
B) Per-owner unique names
Change the name index to (owner_ref, name) and owner-scope ResolveSandboxIDByName and the cluster placement-by-name lookup, with store, FSM and cluster regression tests and PR call-outs. Removes the collision and the 409 leak. Human ~1 week / CC ~3h.

State: approved
Actual answer: B) Per-owner unique names (user answer to D4, 2026-10-04)
Accepted scope: names unique per owner. The store index becomes (owner_ref, name) WHERE name <> ''. `ResolveSandboxIDByName` and the cluster placement-by-name lookup (FSM `nameIndex`, internal/cluster/fsm.go:380-386) are keyed and scoped by owner. Store, FSM and cluster regression tests next to the changed files; PR call-outs per CLAUDE.md hard rules 5–6 (fragile store and cluster areas). Plan amended in §4 (new task T2b), §5.4, §5.6, §7 and §8.
History: none

### R2: retry-safe create when the caller gives no name
Finding: Scope Challenge #2, P1, confidence 9/10, sdk/go/internal/apiclient/client.go:886-946. `doWithRetry` retries every method; `isTransientTransportError` matches `"EOF"`, `"timeout"`, `"connection reset"` and `context.DeadlineExceeded`; `isRetryableStatusCode` matches 421/429/502/503/504. Reviewer: Claude (plan-eng-review).
Plan baseline: §5.4 proposes auto-generated names for unnamed creates; §9 Q2 left it open ("is making every agent-created sandbox named acceptable?"). Original proposal, not yet approved.
Runtime evidence: `POST /v1/sandboxes` is retried on post-send transport errors and gateway 5xx. A response lost after the server created the sandbox makes the SDK send a second POST, which creates a second sandbox when no name is set. Per-owner names (R1/D4) keep a 409 on the retried POST resolvable to the caller's own sandbox.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R2 unnamed CLI/MCP create | open (§9 Q2) | CLI generates `agent-<12 random base32>` before the first attempt; SDK retries land on 409 → GET → the same sandbox | send no name; a lost response can duplicate | send no name; agenttools sets SDK `MaxRetries=-1` for the create call only |
| Duplicate sandboxes under a lost response | possible | none | possible | none from the SDK; the agent may still retry the whole tool call |
| Tests | none | agenttools: fake server creates, then drops the connection; assert one sandbox, same ID returned | none | agenttools: no retry on create; error surfaces |
| SDK retry bug for other SDK users | pre-existing | unchanged (TODO question later) | unchanged | unchanged |
| R1 (approved, D4) | per-owner names | per-owner names | per-owner names | per-owner names |
| R3, R4 | pending | pending | pending | pending |

Question D5:
D5 — How should the CLI and MCP make an unnamed create safe to retry?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); D4 made names unique per owner.
ELI10: The Go SDK retries a create when the connection drops or a gateway returns 502/503/504 (sdk/go/internal/apiclient/client.go:886-946). If the server already made the sandbox and only the reply was lost, the retry makes a second one. That costs money and leaves an orphan the agent never sees. Giving every create a name chosen before the first attempt turns the retry into "already exists", which the CLI resolves to the same sandbox.
Stakes if we pick wrong: agents on flaky networks silently pile up duplicate billed sandboxes, or every transient blip becomes a hard error the agent then retries itself.
Recommendation: A because it makes every CLI/MCP create exactly-once with no server change, using the per-owner names from D4.
Completeness: A=10/10, B=3/10, C=5/10
Pros / cons:
A) Auto-generate a name (recommended)
  ✅ Exactly one sandbox per create even when replies are lost, with SDK retries kept
  ✅ No server change; one offline test proves it (human: ~2h / CC: ~10 min)
  ❌ Every agent-created sandbox gets a visible `agent-…` name the user didn't choose
B) Leave unnamed creates as they are
  ✅ No generated names; matches what SDK users get today
  ✅ Zero work in this plan
  ❌ A lost reply creates a duplicate billed sandbox the agent never learns about
C) Turn off SDK retries for create only
  ✅ No generated names, and the SDK itself never duplicates
  ✅ Small change in agenttools (human: ~1h / CC: ~5 min)
  ❌ Transient blips become errors; agents retry the whole call and can still duplicate
Net: exactly-once creates at the cost of generated names, against keeping names user-chosen and accepting duplicates or extra failures.
Header: D5 retry-safe
Options:
A) Auto-generate a name (recommended)
CLI/MCP creates without a name get `agent-<12 random base32>`, generated before the first attempt; a retried POST that gets 409 resolves to the same sandbox via GET-by-name. Test: fake server creates then drops the connection; assert exactly one sandbox and the same ID returned. Resolves §9 Q2. Human ~2h / CC ~10 min.
B) Leave unnamed creates as-is
CLI/MCP send no name when the caller gives none; SDK retries can duplicate a sandbox after a lost reply. Document it. No work.
C) No SDK retries on create
CLI/MCP send no name; agenttools disables SDK retries (MaxRetries=-1) for the create call only, so transient failures surface as errors. Test: create is attempted once. Human ~1h / CC ~5 min.

State: approved
Actual answer: A) Auto-generate a name (user answer to D5, 2026-10-04)
Accepted scope: CLI/MCP creates without a name get `agent-<12 random base32>`, generated before the first attempt. SDK retries stay on; a retried POST that gets 409 resolves to the same sandbox via GET-by-name. agenttools test: the fake server creates the sandbox and then drops the connection; assert exactly one sandbox exists and the same ID is returned. Resolves §9 Q2. The other-SDK retry bug is unchanged and goes to the TODO stage.
History: none

### R3: a pinned sandbox that was destroyed and silently recreated
Finding: Scope Challenge #3, P2, confidence 8/10. internal/service/service.go:5551 (`if l.DestroyIfIdleFor > 0 && idle >= l.DestroyIfIdleFor { return lifecycleDestroy }`) + plan §5.3 pinned mode (`--create-if-missing`, default `destroy_if_idle_for` 1h). Reviewer: Claude (plan-eng-review).
Plan baseline: §5.3 says a host restart "reattaches to the same sandbox" and that the lifecycle TTL is the cleanup guarantee. It does not say what the model is told when the pinned sandbox is gone and gets recreated. Original proposal, not yet approved.
Runtime evidence: idle is measured from `LastActiveAt`, which every toolbox call bumps (`ToolboxTarget` → `TouchSandbox`, service.go:4174). A long-lived host such as Claude Desktop that sits idle past the TTL loses the sandbox. The next call 404s, and `--create-if-missing` creates a new empty sandbox under the same name. Nothing tells the model that earlier files are gone.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R3 pinned sandbox gone after a successful earlier call | silent recreate (implied) | recreate, and the tool result says so: `sandbox_recreated: true` plus a one-line notice; the CLI prints a stderr warning | no recreate after the first create in this process: tool error "pinned sandbox no longer exists"; the user restarts the MCP server | silent recreate |
| Cached ID / resolution | unspecified | dropped on 404, re-resolved by name | dropped on 404 | unspecified |
| Tests | none | agentmcp: pinned, first call creates; fake API 404s the ID; next call recreates, and the result has `sandbox_recreated: true` and the notice once | agentmcp: 404 after first create → error, no POST | none |
| R4 default idle policy | pending | pending | pending | pending |
| R1 (D4), R2 (D5) | approved | unchanged | unchanged | unchanged |

Question D6:
D6 — What should the model hear when its pinned sandbox disappears and gets recreated?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); D4 per-owner names and D5 auto-names are approved.
ELI10: In pinned mode the MCP server makes one sandbox and reuses it. If the sandbox is destroyed while the chat sits idle (the idle timer at internal/service/service.go:5551), the next tool call quietly creates a fresh, empty one with the same name. The model still thinks the files it wrote an hour ago are there, so it runs `pytest`, gets "no such file" and goes in circles.
Stakes if we pick wrong: the agent wastes turns debugging missing files and the user can't tell why. Failing hard instead makes the user restart the MCP server for something the server could explain.
Recommendation: A because it keeps the session working and tells the model exactly what happened, in one line it can act on.
Completeness: A=10/10, B=7/10, C=3/10
Pros / cons:
A) Recreate and say so (recommended)
  ✅ The session keeps working, and the model learns its earlier files are gone
  ✅ One small, testable branch in the pinned resolver (human: ~3h / CC: ~15 min)
  ❌ The model can still lose work silently if it ignores the notice
B) Error instead of recreating
  ✅ Nothing changes without the user knowing
  ✅ Simplest rule: one create per server process
  ❌ The user must restart the MCP server; the chat stalls until they do
C) Leave it silent
  ✅ No work
  ✅ Nothing in the tool results changes
  ❌ The model debugs files that no longer exist, wasting turns and money
Net: keep the session alive and tell the model, against stopping until the user restarts the server, or saying nothing.
Header: D6 recreate
Options:
A) Recreate and say so (recommended)
On a 404 for the pinned sandbox after an earlier successful call, drop the cached ID, recreate by name, and return `sandbox_recreated: true` plus a one-line notice that earlier files are gone; the CLI prints a stderr warning. Test in agentmcp: pinned, first call creates, fake API 404s the ID, next call recreates, and the result carries the flag and the notice once. Human ~3h / CC ~15 min.
B) Error instead of recreating
After the first create in a process, a 404 on the pinned sandbox returns a tool error "pinned sandbox no longer exists; restart the MCP server to create a fresh one" and never recreates. Test: 404 → error, no POST. Human ~2h / CC ~10 min.
C) Leave it silent
Recreate silently as implied today. No work, no test.

State: approved
Actual answer: A) Recreate and say so (user answer to D6, 2026-10-04)
Accepted scope: on a 404 for the pinned sandbox after an earlier successful call, drop the cached ID, recreate by name, and return `sandbox_recreated: true` plus a one-line notice that earlier files are gone. The CLI prints a stderr warning. agentmcp test: pinned mode, the first call creates; the fake API 404s the ID; the next call recreates, and its result carries the flag and the notice exactly once.
History: none

### R4: default idle policy for MCP-created sandboxes
Finding: Scope Challenge #4, P2, confidence 7/10, plan §5.3 "Cleanup": "MCP-created sandboxes get a default `lifecycle.destroy_if_idle_for` of 1h". Reviewer: Claude (plan-eng-review).
Plan baseline: destroy after 1h idle, `--keep` opts out. Original proposal, not yet approved.
Runtime evidence: `Lifecycle` supports `StopIfIdleFor` and `DestroyIfIdleFor` together (pkg/models/types.go:307-311). Validate requires destroy not to fire before stop. A toolbox call on a stopped sandbox does not auto-start it: `ToolboxTarget` (internal/service/service.go:4173) fails with "sandbox container IP is not available". D6 makes a recreate visible but does not bring the lost files back.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R4 default lifecycle for MCP-created sandboxes | `destroy_if_idle_for: 1h` | unchanged: `destroy_if_idle_for: 1h` | `stop_if_idle_for: 30m` + `destroy_if_idle_for: 24h` |
| Behaviour after a 2h break | sandbox destroyed; D6 recreates an empty one and says so | same | sandbox stopped; the next call starts it again with files intact |
| New client logic | none | none | agenttools: if the resolved sandbox is `stopped`, call Start (idempotent) before the tool runs |
| Cost while idle | none after 1h | none after 1h | stopped sandbox holds disk for up to 24h |
| Tests | none | none | agentmcp: stopped pinned sandbox → one Start, then the tool runs; created sandboxes carry the 30m/24h lifecycle |
| `--keep` / configurable value | yes | yes | yes |
| R1 (D4), R2 (D5), R3 (D6) | approved | unchanged | unchanged |

Question D7:
D7 — Should MCP-created sandboxes be destroyed after 1h idle, or stopped first and destroyed after 24h?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); D6 makes a recreate visible to the model.
ELI10: The plan auto-deletes an MCP sandbox after one idle hour so abandoned chats don't bill forever. A coding agent's work (cloned repo, installed packages, edits) lives in that sandbox, so a lunch break wipes it out. The server already supports "stop when idle, delete much later" (pkg/models/types.go:307). A stopped sandbox costs only disk, and starting it again brings everything back. The catch: a tool call on a stopped sandbox doesn't wake it today (service.go:4173), so the MCP layer would start it first.
Stakes if we pick wrong: with 1h destroy, users return from a break to an empty sandbox and have to redo setup. With stop-then-destroy, idle sandboxes hold disk for a day and the first call after a break waits for a start.
Recommendation: B because a lost workspace costs the user much more than a day of disk, and the start-on-demand branch is small.
Completeness: A=7/10, B=10/10
Pros / cons:
A) Keep destroy after 1h idle
  ✅ Simplest; the plan as written, nothing new to build or test
  ✅ No disk held by idle agent sandboxes past one hour
  ❌ Any break over an hour wipes the agent's workspace; D6 only reports the loss
B) Stop at 30m, destroy at 24h (recommended)
  ✅ Work survives breaks; the next call restarts the sandbox with files intact
  ✅ Small change: one start-if-stopped branch plus a test (human: ~3h / CC: ~15 min)
  ❌ Idle sandboxes hold disk for up to 24h, and the first call after a break pays a start
Net: a day of disk and one restart delay, against losing the workspace on every break longer than an hour.
Header: D7 idle policy
Options:
A) Keep destroy after 1h idle
MCP-created sandboxes keep the plan's default `destroy_if_idle_for: 1h` (`--keep` and the value stay configurable). No new logic or tests.
B) Stop at 30m, destroy at 24h (recommended)
MCP-created sandboxes default to `stop_if_idle_for: 30m` + `destroy_if_idle_for: 24h`. agenttools calls Start when the resolved pinned sandbox is `stopped`, before running the tool. agentmcp test: stopped sandbox → exactly one Start, then the tool runs; created sandboxes carry the 30m/24h lifecycle. Human ~3h / CC ~15 min.

State: approved
Actual answer: B) Stop at 30m, destroy at 24h (user answer to D7, 2026-10-04)
Accepted scope: MCP-created sandboxes default to `stop_if_idle_for: 30m` + `destroy_if_idle_for: 24h`; `--keep` and both values stay configurable. agenttools calls Start when the resolved pinned sandbox is `stopped`, before running the tool. agentmcp test: a stopped sandbox gets exactly one Start and then the tool runs; created sandboxes carry the 30m/24h lifecycle.
History: the AskUserQuestion option label was sent shortened as "Stop 30m, destroy 24h (recommended)"; its description was identical to the saved option B, so the commitments match.

### R5: switching the Raft name index to per-owner during a rolling upgrade
Finding: Section 1 (Architecture), P1, confidence 8/10. internal/cluster/fsm.go:2026-2034 `validateNameUniqueLocked` (`if owner, ok := f.nameIndex[name]; ok && owner != sandboxID { return fmt.Errorf("%w: %q is held by %s", ErrNameConflict, name, owner) }`) runs inside Raft apply at fsm.go:857, 1257, 1316, 1923, 1990. Reviewer: Claude (plan-eng-review).
Plan baseline: R1/D4 approved per-owner names, including the FSM `nameIndex` keyed by (owner, name), with FSM regression tests and a PR call-out. How the switch rolls out across a running cluster is unspecified.
Runtime evidence: Raft needs every replica to reach the same result for the same command. internal/cluster has no FSM/feature version gating (search for snapshot/fsm/cluster version symbols found none). Gossip `nodeMeta` carries no version and is capped at 512 bytes (gossip.go:18-25). Placements already carry the tenant `OwnerRef` (cluster.go:403-405), and the index is rebuilt from placements on Restore (fsm.go:385). During a rolling upgrade, an old replica rejects a cross-owner duplicate name that new replicas accept. The replicas then disagree on whether that placement exists. If an old node later leads, the missing placement is the reconcile/owner-watcher hazard seen in UC-20.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R5 rollout of per-owner FSM names | user (D8): support both, backward compatible, no gates | the proposer writes an owner-qualified key into the Raft command's `Spec.Name` (and `Placement.Name`): `owner:<base64url(owner_ref)>/<name>` for tenant sandboxes; operator sandboxes (owner_ref "") keep plain names. Old and new replicas index identical strings. | same owner-qualified key |
| Gate | none (D8) | none | none |
| Mixed-version divergence | — | none: every replica derives the key with the existing `specName` (fsm.go:1880) from the same bytes | none |
| Legacy tenant sandboxes with plain names | — | still found by name: lookup tries the qualified key, then the plain key filtered by `OwnerRef` | found by ID only |
| Reserved prefix | — | new nodes reject user names starting with `owner:` | same |
| Decode for display | — | new code turns the key back into the user name wherever it reads `Spec.Name` (failover recreate, list, Daytona) | same |
| Upgrade-window caveats (documented) | — | an old node that recreates or lists a new tenant sandbox shows the encoded name until it upgrades; an owner can get a legacy and a new sandbox with one name if created via old and new nodes in the window (lookup prefers the qualified key); failover onto an old node can hit its global store index | same, without the legacy lookup |
| Tests | — | mixed-version determinism (a legacy-mode FSM and a new FSM apply one command sequence and end with identical `nameIndex`), encode/decode round trip, reserved-prefix rejection, legacy lookup fallback, Daytona resolution | determinism, round trip, prefix rejection |
| R6, R7 | pending | pending | pending |

Question D9:
D9 — Confirm the gate-free, backward-compatible design for per-owner names in the cluster.
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); in D8 you asked to "support both and make it backward compatible but without any gates".
ELI10: Old nodes check names using whatever string sits in the sandbox spec's Name field (internal/cluster/fsm.go:1880, `specName`). If the node that accepts the create writes the owner into that string, for example `owner:QUJD/my-agent`, every node compares the same text. Old and new nodes then agree without any switch. Operator sandboxes keep plain names, so both styles live side by side. New code turns the encoded string back into `my-agent` for display. Old nodes can't do that, so during the upgrade window they may show the encoded name.
Stakes if we pick wrong: without the legacy lookup, every tenant sandbox created before the upgrade stops resolving by name, and Daytona users who address sandboxes by name break.
Recommendation: A because it is the version of your answer that keeps existing tenant names working.
Completeness: A=10/10, B=6/10
Pros / cons:
A) Owner-qualified key + legacy lookup (recommended)
  ✅ No gate, and old and new replicas always agree because they compare identical strings
  ✅ Existing tenant sandboxes keep resolving by name after the upgrade
  ❌ Old nodes show encoded names during the window; a same-owner duplicate is possible in the window (human: ~3 days / CC: ~1h)
B) Owner-qualified key, no legacy lookup
  ✅ No gate, same agreement guarantee, and a bit less code
  ✅ One lookup path to test and reason about
  ❌ Tenant sandboxes created before the upgrade can only be found by ID, which breaks name-based Daytona calls
Net: one fallback lookup path, against breaking name lookups for every pre-upgrade tenant sandbox.
Header: D9 compat key
Options:
A) Owner-qualified key + legacy (recommended)
Proposer writes `owner:<base64url(owner_ref)>/<name>` into the Raft command's `Spec.Name` and `Placement.Name` for tenant sandboxes; operator sandboxes keep plain names; no gate. New code decodes for display everywhere it reads Spec.Name and rejects user names with the `owner:` prefix. Name lookup tries the qualified key, then the plain key filtered by OwnerRef. Upgrade-window caveats documented. Tests: mixed-version determinism, round trip, prefix rejection, legacy fallback, Daytona. PR call-out on replay and leader-change impact. Human ~3 days / CC ~1h.
B) Owner-qualified key, no legacy
Same key scheme, no gate, decode and prefix rejection; pre-upgrade tenant sandboxes are found by ID only. Tests: determinism, round trip, prefix rejection. Human ~2 days / CC ~45 min.

State: approved
Actual answer: A) Owner-qualified key + legacy lookup (user answer to D9, 2026-10-04), confirming the D8 free-text answer "support both and make it backward compatible but without any gates."
Accepted scope: no gate. For tenant sandboxes, the proposer writes `owner:<base64url(owner_ref)>/<name>` into the Raft command's `Spec.Name` and `Placement.Name`; operator sandboxes (owner_ref "") keep plain names. New code decodes the key back to the user name everywhere it reads `Spec.Name` (failover recreate, list, Daytona) and rejects user names that start with `owner:`. Name lookup tries the qualified key, then the plain key filtered by `OwnerRef`. Upgrade-window caveats are documented. Tests: mixed-version determinism (a legacy-mode FSM and a new FSM apply one command sequence and end with identical `nameIndex`), encode/decode round trip, reserved-prefix rejection, legacy lookup fallback, Daytona resolution. PR call-out on replay and leader-change impact.
History: D8 (superseded, kept verbatim below). Rebuilt before sending once: option A first said voters report support "in its authenticated capacity heartbeat", but capacity leases are pulled only from sandbox-owning roles (capacity_lease.go:489), so the mechanism was changed to each voter's cluster-internal mTLS endpoint.

<details><summary>D8 brief (superseded)</summary>

D8 comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R5 rollout of per-owner FSM names | unspecified | gated: the FSM keeps global checks until a Raft-applied, one-way `activate_per_owner_names` command; the leader accepts it only after every voter, asked over its cluster-internal mTLS endpoint, reports the `per_owner_names` capability | no gating; release notes and Ansible require stopping all nodes and upgrading together | per-owner names in the single-node store only; the cluster FSM stays global for now, and cluster get-or-create returns `name_taken` after one re-check |
| Mixed-version divergence | possible | none (old rules until every voter supports the new ones) | possible if an operator rolls nodes one at a time | none (FSM unchanged) |
| D4 coverage | full (approved) | full | full | single-node only; narrows D4 in cluster mode |
| New code | — | activation command + an internal capabilities endpoint on every member + snapshot carries the flag | release-note and Ansible change | `name_taken` path in cluster mode |
| Tests | FSM tests (D4) | + mixed-version apply determinism, activation refused while an old voter is present, flag survives snapshot/restore, restore rebuilds the per-owner index | FSM tests (D4) only | store tests + a cluster `name_taken` test |
| R6, R7 | pending | pending | pending | pending |

Question D8:
D8 — How do we roll out per-owner names in the cluster's Raft state without old and new nodes disagreeing?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); D4 approved per-owner names, including the cluster name index.
ELI10: In a cluster, every server node replays the same log of "place sandbox X named Y" and must reach the same answer. The name check runs inside that replay (internal/cluster/fsm.go:2026). During a rolling upgrade, some nodes run old code and some run new. Old nodes reject a name another tenant already uses; new nodes accept it. They then disagree about whether the sandbox exists. If an old node becomes leader, a running sandbox can look orphaned and get cleaned up (the UC-20 kind of bug). Nothing today stops mixed-version replay from diverging: there is no version gate, and gossip has no version field.
Stakes if we pick wrong: a routine rolling upgrade could split the cluster's view of which sandboxes exist and destroy live tenant sandboxes.
Recommendation: A because it is the only option that keeps rolling upgrades safe and still delivers D4 in cluster mode.
Completeness: A=10/10, B=5/10, C=6/10
Pros / cons:
A) Gate behind a Raft-applied switch (recommended)
  ✅ Old and new nodes always agree: the new rule only starts after every voter supports it
  ✅ Gives the cluster a reusable pattern for future FSM rule changes, which it lacks today
  ❌ More code in the fragile cluster package: activation command, capabilities endpoint, tests (human: ~3 days / CC: ~1h)
B) Require a stop-all upgrade
  ✅ No gating code; FSM change as approved in D4
  ✅ Simple to explain in release notes
  ❌ One operator doing the usual rolling upgrade (Ansible) can diverge the cluster and destroy live sandboxes
C) Per-owner in single-node only for now
  ✅ Zero FSM risk in this plan; cluster rules stay exactly as today
  ✅ Single-node users get per-owner names immediately
  ❌ Narrows D4: managed (cluster) tenants still collide and get `name_taken`
Net: some careful cluster code now, against an upgrade-time divergence risk or leaving cluster tenants with the collision.
Header: D8 FSM rollout
Options:
A) Gate behind a Raft switch (recommended)
The FSM keeps global name checks until a Raft-applied, one-way `activate_per_owner_names` command; the leader accepts it only after every voter, asked over its cluster-internal mTLS endpoint (every member has one; capacity leases skip server-only voters, capacity_lease.go:489), reports the `per_owner_names` capability; the flag is stored in the snapshot. Tests: mixed-version apply determinism, activation refused while an old voter is present, flag survives snapshot/restore, restore rebuilds the per-owner index. PR call-out on split-brain, replay and leader-change impact. Human ~3 days / CC ~1h.
B) Require a stop-all upgrade
No gating code. Release notes and Ansible playbooks require stopping all nodes and upgrading together for this release; FSM tests from D4 only. Human ~2h / CC ~10 min.
C) Per-owner in single-node only
Per-owner store index ships; the cluster FSM keeps global names, and cluster-mode get-or-create returns `name_taken` after one re-check. Narrows D4 to single-node. Tests: store tests + a cluster `name_taken` test. Human ~4h / CC ~20 min.

State: pending
Actual answer: unanswered
Accepted scope: none
History: rebuilt before sending. Option A first said voters report support "in its authenticated capacity heartbeat", but capacity leases are pulled only from sandbox-owning roles (capacity_lease.go:489 `!CanOwnSandboxRole(m.Role)`), so server-only voters never report. The mechanism now asks each voter's cluster-internal mTLS endpoint.

</details>

### R6: exec on WASM sandboxes (no streaming exec there)
Finding: Section 1 (Architecture), P1, confidence 9/10. internal/runtime/wasm/toolhost/exec_stream.go:21 returns "streaming exec is not supported on the wasm runtime; use POST /process/execute"; toolhost/host.go:68 serves `POST /process/execute`. Reviewer: Claude (plan-eng-review).
Plan baseline: §5.3 "`exec` uses `ExecStream` with ring buffers instead of buffered `Exec`"; §5.5 exit info from `ExecStreamHandle.Wait()`. Original proposal, not yet approved.
Runtime evidence: every CLI `exec` and MCP `exec` against a WASM sandbox would fail. Buffered toolbox exec reads all output into memory (`io.ReadAll(stdout)`, cmd/toolboxd/main.go:622-628; the WASM host has its own executor, toolhost/exec.go:12). The resolved sandbox object (fetched by resolution anyway) carries its runtime.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R6 exec path per runtime | always ExecStream | by the resolved sandbox's runtime: WASM → buffered `POST /process/execute`, everything else → ExecStream | always buffered `POST /process/execute` | always ExecStream; WASM gets a clear "not supported" error |
| Memory bound on the buffered path | — | the response body is read with a 4 MiB limit; a larger body returns error `output_too_large` (suggest redirecting output to a file), because a cut JSON body can't be decoded; within the limit, the usual head/tail truncation applies | same 4 MiB limit and `output_too_large`, for every runtime | — |
| CLI live output / `-i` / `-t` | yes | yes off WASM; on WASM `-i`/`-t` fail with a clear error | no live output, no stdin, no TTY anywhere | yes off WASM |
| Tests | — | agenttools: WASM sandbox uses buffered exec (no WebSocket dial); a body over 4 MiB → `output_too_large`; a body under it with long stdout → head/tail `truncated: true`; `-t` on WASM → clear error | buffered path + limit tests | WASM → clear error |
| R7 | pending | pending | pending | pending |

Question D10:
D10 — How should `exec` work on WASM sandboxes, which don't support streaming exec?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: The plan runs every command through the live-streaming exec channel. WASM sandboxes refuse that channel ("streaming exec is not supported on the wasm runtime", toolhost/exec_stream.go:21) and only offer the plain request/response exec. As written, `aerolvm exec` and the MCP `exec` tool would fail on every WASM sandbox. We already know each sandbox's runtime when we look it up, so we can pick the right channel per sandbox.
Stakes if we pick wrong: WASM, one of the five runtimes and the fastest to create, would be unusable from the CLI and MCP, or every user would lose live output to make WASM work.
Recommendation: A because it keeps live streaming where it exists and still works on WASM, with memory bounded on both paths.
Completeness: A=10/10, B=7/10, C=4/10
Pros / cons:
A) Pick the channel by runtime (recommended)
  ✅ Exec works on all shell-capable runtimes, with live output where the runtime supports it
  ✅ A 4 MiB response limit keeps the plain path's memory bounded (human: ~4h / CC: ~20 min)
  ❌ Two exec code paths to test; WASM users get no live output or stdin
B) Always use the plain request/response exec
  ✅ One code path, and it works on every runtime that has a shell
  ✅ Simplest to test and reason about
  ❌ No live output, no `-i` stdin and no TTY for anyone, which hurts the CLI the most
C) Streaming only; WASM gets an error
  ✅ Simplest; no second path
  ✅ The error message names the fix (use the SDK or the API)
  ❌ The CLI and MCP don't work on WASM sandboxes at all
Net: one extra code path, against dropping live output everywhere or dropping WASM.
Header: D10 WASM exec
Options:
A) Pick channel by runtime (recommended)
Resolution already returns the sandbox; WASM → buffered `POST /process/execute`, response read with a 4 MiB limit (larger → error `output_too_large`, suggest redirecting to a file; within it, head/tail truncation); every other runtime → ExecStream. On WASM, `-i`/`-t` fail with a clear error. Tests: WASM uses buffered exec with no WebSocket dial; body over 4 MiB → `output_too_large`; long stdout under it → `truncated: true`; `-t` on WASM → clear error. Human ~4h / CC ~20 min.
B) Always buffered exec
Every exec uses `POST /process/execute`, response read with a 4 MiB limit (larger → `output_too_large`; within it, head/tail truncation); no live output, `-i` or `-t` anywhere. Tests: buffered path + limit. Human ~3h / CC ~15 min.
C) Streaming only, WASM errors
Keep ExecStream for all; on WASM return a clear "streaming exec is not supported on wasm sandboxes" error. Test: WASM → clear error. Human ~1h / CC ~5 min.

State: approved
Actual answer: A) Pick channel by runtime (user answer to D10, 2026-10-04)
Accepted scope: exec picks its channel from the resolved sandbox's runtime. WASM uses buffered `POST /process/execute`, with the response read under a 4 MiB limit: a larger body returns `output_too_large` (suggest redirecting output to a file); within the limit, head/tail truncation applies. Every other runtime uses ExecStream. On WASM, `-i`/`-t` fail with a clear error. agenttools tests: WASM uses buffered exec with no WebSocket dial; a body over 4 MiB → `output_too_large`; long stdout under the limit → `truncated: true`; `-t` on WASM → clear error.
History: rebuilt before sending. The first draft said the body is "capped at 4 MiB before decoding, then head/tail truncation", but a cut JSON body can't be decoded, so a body over the limit now returns `output_too_large`.

### R7: isolate sandboxes created or targeted through the CLI and MCP
Finding: Section 1 (Architecture), P2, confidence 9/10. internal/runtime/isolate/exec.go:36: `http.Error(w, "isolate runtime does not support this toolbox endpoint (no shell/filesystem; use exec as invoke-handler)", http.StatusNotImplemented)`; exec there "invoke[s] the sandbox's fetch handler" (exec.go:38-40). Reviewer: Claude (plan-eng-review).
Plan baseline: §5.2 `aerolvm create --runtime R` and §5.3 `sandbox_create(runtime?)` accept any runtime. Original proposal, not yet approved.
Runtime evidence: on an isolate sandbox, every file tool returns 501, and `exec` runs the Worker's fetch handler, not a shell command. A model that picks `runtime: isolate` gets a sandbox where nearly every MCP tool fails or behaves unlike its description.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R7 MCP `sandbox_create` runtime values | any runtime | every runtime except `isolate` (schema enum) | any runtime |
| CLI `create --runtime isolate` | allowed | allowed (operators and SDK users know the model) | allowed |
| Tools on an isolate sandbox (pinned or by ref) | raw 501 / fetch-handler output | clear error before the call: "isolate sandboxes have no shell or filesystem; use the SDK's invoke" | raw 501 / fetch-handler output; documented |
| Tests | — | tools/list golden shows the enum without `isolate`; a file tool and exec against an isolate sandbox → clear error, no toolbox call | none |
| R1–R6 | approved | unchanged | unchanged |

Question D11:
D11 — Should the MCP server keep models away from isolate sandboxes, which have no shell or filesystem?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: Isolate sandboxes are JavaScript Workers: no shell, no filesystem. Their toolbox returns "not supported" for file calls, and "exec" means "call the Worker's handler" (internal/runtime/isolate/exec.go:36). If a model creates one through MCP because "isolate" sounds safe, read_file, write_file and list_files all fail, and exec does something the tool description doesn't describe.
Stakes if we pick wrong: models waste turns on a sandbox where the tools can't work, and users read it as the MCP server being broken.
Recommendation: A because the MCP tools assume a shell and filesystem, so the schema shouldn't offer a runtime that has neither.
Completeness: A=10/10, B=5/10
Pros / cons:
A) Hide isolate from MCP, clear errors (recommended)
  ✅ Models can't pick a runtime the tools don't work on
  ✅ An isolate sandbox reached by ref gets one clear error instead of a raw 501 (human: ~2h / CC: ~10 min)
  ❌ MCP users can't drive isolate sandboxes at all until an isolate-specific tool exists
B) Allow it and document
  ✅ No special cases in the code
  ✅ Advanced users can still reach isolate via MCP
  ❌ Models will pick it and fail; the raw 501 text doesn't tell them what to do instead
Net: a small special case for clear behaviour, against an open schema that models will misuse.
Header: D11 isolate
Options:
A) Hide isolate, clear errors (recommended)
The MCP `sandbox_create` runtime enum excludes `isolate`; the CLI still allows `--runtime isolate`. Any CLI/MCP file or exec call against an isolate sandbox returns "isolate sandboxes have no shell or filesystem; use the SDK's invoke" before calling the toolbox. Tests: tools/list golden shows the enum without isolate; file tool and exec on an isolate sandbox → clear error, no toolbox call. Human ~2h / CC ~10 min.
B) Allow it and document
Any runtime stays creatable from MCP; tools on isolate sandboxes return the toolbox's 501 or fetch-handler output; documented in mcp.mdx. No tests.

State: approved
Actual answer: A) Hide isolate, clear errors (user answer to D11, 2026-10-04)
Accepted scope: the MCP `sandbox_create` runtime enum excludes `isolate`; the CLI still allows `--runtime isolate`. Any CLI/MCP file or exec call against an isolate sandbox returns "isolate sandboxes have no shell or filesystem; use the SDK's invoke" before calling the toolbox. Tests: the tools/list golden shows the enum without `isolate`; a file tool and exec against an isolate sandbox return the clear error with no toolbox call.
History: none

### R8: resolving `<id-or-name>` references
Finding: Section 2 (Code quality), P3, confidence 8/10. internal/service/service.go:6239-6245 `generateSandboxID` returns `"sb-" + hex.EncodeToString(buf)` (8 random bytes). Names are only trimmed on create (`Name: strings.TrimSpace(req.Name)`, service.go:1904, 2205), so a name may look like an ID. Plan §5.2 rule 6: "Resolution tries the ID first and falls back to the name lookup (§5.6) on 404." Reviewer: Claude (plan-eng-review).
Plan baseline: try the ID first, then the name on 404 (accepted as written in the scope record).
Runtime evidence: under the plan rule, every name reference costs a failed ID GET before the name lookup (two round trips; in cluster mode the ID GET can also be forwarded). An ID-shaped name is shadowed by a same-owner sandbox whose ID equals it. D9 already adds create-time name validation (the reserved `owner:` prefix).
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R8 resolution rule | ID first, name on 404 | by shape: refs matching `^sb-[0-9a-f]{16}$` are IDs only; anything else is a name only | unchanged: ID first, name on 404 |
| Round trips per name ref | 2 | 1 | 2 |
| Create-time name validation | `owner:` prefix rejected (D9) | also reject names matching the ID shape | `owner:` prefix only |
| Existing sandboxes whose name looks like an ID | resolvable by ID; by name only if no ID matches | resolvable by ID only | unchanged |
| Tests | ID→name fallback (plan §8) | table test of the shape router; create rejects ID-shaped names | fallback test as planned |
| R1–R7 | approved | unchanged | unchanged |

Question D12:
D12 — Should `<id-or-name>` references be resolved by their shape instead of trying the ID first?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: Sandbox IDs always look like `sb-` plus 16 hex characters (internal/service/service.go:6239). The plan resolves any reference by trying it as an ID first and, on "not found", as a name. So every name lookup makes two requests, and a sandbox named like an ID can be hidden by a real ID. If we route by shape and refuse new names that look like IDs, every reference takes one request and can't be ambiguous.
Stakes if we pick wrong: every agent tool call that uses a name pays an extra round trip (forwarded across nodes in cluster mode), and a rare ID-shaped name can resolve to the wrong sandbox.
Recommendation: A because it halves name lookups and removes the ambiguity, at the cost of one validation rule that D9 already opens.
Completeness: A=10/10, B=7/10
Pros / cons:
A) Route by shape (recommended)
  ✅ One request per reference instead of two for every name
  ✅ No ambiguity: IDs and names can't be confused (human: ~2h / CC: ~10 min)
  ❌ A pre-existing sandbox whose name looks like an ID can only be reached by its ID
B) Keep ID-then-name fallback
  ✅ No new validation rule; any existing name keeps working
  ✅ Already in the plan as written
  ❌ Two requests per name reference, and an ID-shaped name can be shadowed
Net: one request and no ambiguity, against keeping exotic ID-shaped names reachable by name.
Header: D12 ref shape
Options:
A) Route by shape (recommended)
Refs matching `^sb-[0-9a-f]{16}$` resolve as IDs only; all other refs resolve as names only (one request). Creates also reject names matching the ID shape, next to the D9 `owner:` prefix check. Tests: table test of the shape router; create rejects ID-shaped names. Human ~2h / CC ~10 min.
B) Keep ID-then-name fallback
Resolution tries the ID first, then the name on 404, as in plan §5.2 rule 6. No new validation. Tests as planned.

State: approved
Actual answer: A) Route by shape (user answer to D12, 2026-10-04)
Accepted scope: refs matching `^sb-[0-9a-f]{16}$` resolve as IDs only; all other refs resolve as names only (one request). Creates also reject names matching the ID shape, next to the D9 `owner:` prefix check. Tests: a table test of the shape router; create rejects ID-shaped names.
History: none

### R9: LLM eval of the MCP tool descriptions
Finding: Section 3 (Tests), P2, confidence 7/10, plan §5.3 tool table and result shape. Tool names, descriptions and notices are text a model reads, so they behave like a prompt. Reviewer: Claude (plan-eng-review).
Plan baseline: §8 tests the tools/list golden (schema stability) and tool behaviour with a fake API. Nothing checks whether a model actually picks the right tool or reacts to truncation, `name_taken`-style errors or the D6 recreate notice. Original proposal: no eval.
Runtime evidence: no eval harness for agents exists in the repo (integration-tests/ drives the API, not a model). Unit tests can't catch "the description is misleading".
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R9 model-in-the-loop verification | none | tag-gated eval (`-tags=agenteval`, operator-run, never in `make test` or CI): Claude drives `aerolvm mcp` against a single-node local sandboxd through 5 scripted tasks with pass criteria | none; rely on the tools/list golden + unit tests |
| Tasks | — | (1) create + exec + read output; (2) write then read a file; (3) start a dev server with `start_process` + `expose_port` and fetch the URL; (4) recover after a D6 recreate notice; (5) exec on a WASM sandbox | — |
| Cost | — | API spend per run (operator-run, like the integration suite) | none |
| When it runs | — | before changing any tool name, description or notice text, and before release | — |
| R1–R8 | approved | unchanged | unchanged |

Question D13:
D13 — Add a small model-in-the-loop eval for the MCP tool descriptions?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: The MCP server's tool names and descriptions are effectively a prompt: they decide whether a model picks `exec` or `start_process`, whether it notices `truncated: true`, and whether it acts on the "sandbox was recreated" notice. Unit tests prove the tools work; they can't prove a model uses them well. A small eval runs Claude against a local sandboxd through five scripted tasks. It is gated behind a build tag and run by hand like the AWS integration suite, so `make test` and CI never pay for it.
Stakes if we pick wrong: without it, a confusing description ships and agents misuse the tools, which looks like "the MCP server is flaky". With it, each run costs API money and needs a key.
Recommendation: A because tool text is the product surface agents see, and five tasks run by hand catch the worst wording mistakes for a few dollars.
Completeness: A=10/10, B=7/10
Pros / cons:
A) Add a tag-gated eval (recommended)
  ✅ Catches misleading tool text before users do, on the exact flows this plan adds
  ✅ Kept out of `make test` and CI; run on demand and before release (human: ~1 day / CC: ~30 min)
  ❌ API spend per run, needs a key, and model output varies, so pass criteria must be loose
B) No eval
  ✅ No API cost or key management
  ✅ Fully deterministic test suite
  ❌ Description and notice wording is never checked against a real model
Net: a few dollars per run and some flakiness, against shipping tool text no model has tried.
Header: D13 tool eval
Options:
A) Add a tag-gated eval (recommended)
Add `-tags=agenteval` tests (operator-run, never in `make test` or CI): Claude drives `aerolvm mcp` against a single-node local sandboxd through 5 tasks: create+exec, write/read file, start_process+expose_port+fetch, recover after a recreate notice, exec on WASM. Loose pass criteria per task. Run before changing tool text and before release. Human ~1 day / CC ~30 min.
B) No eval
Rely on the tools/list golden and unit tests; tool text is reviewed by hand only.

State: approved
Actual answer: A) Add a tag-gated eval (user answer to D13, 2026-10-04)
Accepted scope: `-tags=agenteval` tests, operator-run and never in `make test` or CI. Claude drives `aerolvm mcp` against a single-node local sandboxd through 5 tasks: create+exec, write/read file, start_process+expose_port+fetch, recover after a recreate notice, exec on WASM. Loose pass criteria per task. Run before changing tool text and before release.
History: none

### R10: memory use of `read_file` and `cp` on large files
Finding: Section 4 (Performance), P1, confidence 9/10. sdk/go/pkg/microvm/client.go:471-476 `UploadFile(ctx, targetPath string, data []byte)` / `DownloadFile(ctx, targetPath string) ([]byte, error)`; the internal DownloadFile ends with `return io.ReadAll(response.Body)` (sdk/go/internal/apiclient/client.go ~672). Reviewer: Claude (plan-eng-review).
Plan baseline: §5.3 `read_file` returns at most 2,000 lines / 256 KiB per call (wraps `DownloadFile`); §5.2 `aerolvm cp` (docker-cp form). Original proposal, not yet approved.
Runtime evidence: both directions hold the whole file in memory. `read_file` on a 2 GB log allocates 2 GB in the MCP process to return 256 KiB; `cp` of a multi-GB dataset can OOM the CLI. The scale is the file size, which is unbounded. `internal/agenttools` can't reach the SDK's `internal/apiclient` (Go internal-package rule), so streaming needs public Go SDK methods.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R10 file transfer path | whole file in memory | stream: Go SDK gains `DownloadFileStream(ctx, path) (io.ReadCloser, error)` and `UploadFileStream(ctx, path, io.Reader)`; `cp` streams both ways; `read_file` reads window + 1 byte, then closes the body | keep `[]byte`; `cp` refuses files over 256 MiB with a clear error; `read_file` windows server-side via `exec` (`sed -n`/`head -c`) | as planned |
| Peak memory, 2 GB file | 2 GB | ~256 KiB (read_file) / a fixed buffer (cp) | 256 MiB cap (cp); `exec`-sized (read_file) | 2 GB |
| SDK surface | — | two Go-only methods on existing endpoints; other SDKs unchanged (no new endpoint) | none | none |
| Runtime dependence | — | none (toolbox endpoints) | `read_file` needs a shell with `sed`/`head`; fails on WASM images without them | none |
| Tests | — | apiclient: streaming upload (multipart via io.Pipe) and download; agenttools: `read_file` on a large fake body reads at most window + 1 bytes; `cp` of a 64 MiB fake file stays under a fixed allocation bound | cap error test; exec-window test | none |
| R1–R9 | approved | unchanged | unchanged | unchanged |

Question D14:
D14 — How should `read_file` and `cp` handle large files without loading them whole into memory?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: The Go SDK's download reads the entire file into memory (`io.ReadAll`, sdk/go/internal/apiclient/client.go ~672), and its upload takes the whole file as one byte slice (sdk/go/pkg/microvm/client.go:471). The MCP `read_file` tool only returns 256 KiB, but as planned it would still download the whole file first, so a 2 GB log costs 2 GB of RAM. `aerolvm cp` has the same problem in both directions. Streaming fixes both; the CLI can't reach the SDK's internal HTTP client, so the SDK needs two public streaming methods.
Stakes if we pick wrong: an agent that reads a big log or copies a dataset blows up the MCP process or the CLI, mid-task, on the user's laptop.
Recommendation: A because it bounds memory for every file size and runtime, using the toolbox endpoints that already exist.
Completeness: A=10/10, B=6/10, C=3/10
Pros / cons:
A) Stream through new Go SDK methods (recommended)
  ✅ Memory stays at the window or a fixed buffer, whatever the file size
  ✅ Works on every runtime with a toolbox; no shell tools needed (human: ~1 day / CC: ~30 min)
  ❌ Grows the Go SDK's public API by two methods that the other four SDKs don't get
B) Cap cp, window read_file via exec
  ✅ No SDK change
  ✅ Simple, clear error for oversized copies
  ❌ `cp` can't move files over 256 MiB, and `read_file` breaks on images without `sed`/`head` (including WASM)
C) Keep whole-file transfers
  ✅ No work
  ✅ Matches the current SDK behaviour exactly
  ❌ A big file can exhaust the MCP or CLI process's memory
Net: two Go SDK methods, against a copy-size limit and shell-tool dependence, or unbounded memory.
Header: D14 large files
Options:
A) Stream via Go SDK (recommended)
Go SDK gains `DownloadFileStream(ctx, path) (io.ReadCloser, error)` and `UploadFileStream(ctx, path, io.Reader)` on the existing toolbox endpoints (Go only; other SDKs unchanged). `cp` streams both ways; `read_file` reads window + 1 byte, then closes. Tests: streaming upload/download in apiclient; read_file on a large fake body reads ≤ window+1 bytes; cp of a 64 MiB fake file stays under a fixed allocation bound. Human ~1 day / CC ~30 min.
B) Cap cp, exec-window read_file
Keep `[]byte` methods. `cp` refuses files over 256 MiB with a clear error; `read_file` windows server-side via `exec` (`sed -n` / `head -c`). Tests: cap error; exec windowing. Human ~3h / CC ~15 min.
C) Keep whole-file transfers
No change; document that large files load fully into memory.

State: approved
Actual answer: A) Stream via Go SDK (user answer to D14, 2026-10-04)
Accepted scope: the Go SDK gains `DownloadFileStream(ctx, path) (io.ReadCloser, error)` and `UploadFileStream(ctx, path, io.Reader)` on the existing toolbox endpoints (Go only; the other SDKs are unchanged). `cp` streams both ways; `read_file` reads window + 1 byte, then closes the body. Tests: streaming upload and download in apiclient; `read_file` on a large fake body reads at most window + 1 bytes; `cp` of a 64 MiB fake file stays under a fixed allocation bound.
History: none

### R11: size of `sandbox_list` results in the model's context
Finding: Section 4 (Performance), P2, confidence 7/10. pkg/api/clusterlist/list.go:36-38 `DefaultPageLimit = 100`, `MaxPageLimit = 500`; `ParsePageParams` reads `limit` (list.go:668-688). The Go SDK's `ListPageWithOptions(ctx, tags, includeEnv, pageToken)` sends no `limit`. Plan §5.3 `sandbox_list(tags?, page_token?)` wraps `ListPage`. Reviewer: Claude (plan-eng-review).
Plan baseline: return the SDK's `[]*Sandbox` (full `models.Sandbox`) for one page. Original proposal, not yet approved.
Runtime evidence: one page is 100 full sandbox objects (ports, mounts, lifecycle, tags and more), all of it fed into the model's context on every list call. The size is roughly 100 × object size; the exact bytes per object are unmeasured.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R11 MCP `sandbox_list` payload | full objects, 100 per page | compact rows {id, name, status, runtime, created_at, tags}, server default 100 per page, `next_page_token` passed through | compact rows as in A, 20 per page via a new Go SDK `WithLimit(n)` list option; `next_page_token` passed through | full objects, 100 per page |
| SDK change | — | none | Go SDK `WithLimit(n)` ListOption (sends `limit`) | none |
| CLI `aerolvm list --json` | full objects | unchanged (full objects) | unchanged, plus `--limit` | unchanged |
| Tests | — | agentmcp: list result rows carry only the compact fields; token passthrough | as A + apiclient sends `limit=20`; page holds ≤ 20 rows | none |
| R1–R10 | approved | unchanged | unchanged | unchanged |

Question D15:
D15 — How much should the MCP `sandbox_list` tool return per call?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: Everything a tool returns goes straight into the model's context window. As planned, `sandbox_list` returns 100 full sandbox objects per page (the server default, pkg/api/clusterlist/list.go:36), each carrying ports, mounts, lifecycle and tags the model rarely needs. Returning a few key fields per sandbox shrinks that a lot. The server already accepts a page size; the Go SDK just doesn't send one yet.
Stakes if we pick wrong: on a busy account, every list call floods the model's context, pushing out the actual task and costing tokens.
Recommendation: B because a one-option SDK change lets the tool return 20 compact rows, and the extra effort is a few minutes.
Completeness: A=8/10, B=10/10, C=4/10
Pros / cons:
A) Compact rows, server page size
  ✅ Much smaller payload with no SDK change
  ✅ The CLI keeps full objects for scripts
  ❌ Still up to 100 rows per call on large accounts
B) Compact rows, 20 per page (recommended)
  ✅ Smallest predictable payload: at most 20 compact rows per call
  ✅ The `WithLimit` option also gives the CLI a `--limit` flag (human: ~2h / CC: ~10 min)
  ❌ One more Go SDK option that the other four SDKs don't have yet
C) Full objects as planned
  ✅ No work; the model sees everything about each sandbox
  ✅ Same shape as the CLI's JSON
  ❌ Large list payloads in context on every call
Net: a tiny SDK option for the smallest payload, against 5x more rows without it, or full objects.
Header: D15 list size
Options:
A) Compact rows, server page size
MCP `sandbox_list` returns {id, name, status, runtime, created_at, tags} per row, the server's default 100 per page, with `next_page_token`. No SDK change; CLI unchanged. Test: rows carry only the compact fields; token passthrough. Human ~1h / CC ~5 min.
B) Compact rows, 20 per page (recommended)
As A, but 20 rows per page via a new Go SDK `WithLimit(n)` list option that sends `limit`; the CLI gains `--limit`. Tests: as A + apiclient sends `limit=20`, page ≤ 20 rows. Human ~2h / CC ~10 min.
C) Full objects as planned
MCP `sandbox_list` returns full sandbox objects, 100 per page. No work.

State: approved
Actual answer: B) Compact rows, 20 per page (user answer to D15, 2026-10-04)
Accepted scope: MCP `sandbox_list` returns compact rows {id, name, status, runtime, created_at, tags}, 20 per page, via a new Go SDK `WithLimit(n)` list option that sends `limit`, with `next_page_token` passed through. The CLI gains `--limit`. Tests: rows carry only the compact fields; token passthrough; apiclient sends `limit=20`; a page holds at most 20 rows.
History: none

### R12: TODO: SDK create retries can duplicate unnamed sandboxes (all SDKs)
Finding: Scope Challenge #2 follow-up, P2, confidence 8/10. sdk/go/internal/apiclient/client.go:886-946 (`doWithRetry` retries every method on transport errors and 502/503/504). Retry logic also exists in sdk/typescript/src/internal/client.ts, sdk/python/microvm/client.py and sdk/java/.../MicroVMConfig.java (not inspected in detail). Reviewer: Claude (plan-eng-review).
Plan baseline: D5 made CLI/MCP creates retry-safe with auto-generated names. Plain SDK users are untouched.
Runtime evidence: Go verified. The other SDKs carry retry code, and their behaviour on a non-idempotent POST is unverified.
Proposed TODO (repo TODOS.md style):

    ## SDK create retries can duplicate unnamed sandboxes (all SDKs)
    - **What:** the Go SDK retries `POST /v1/sandboxes` on post-send transport
      errors ("EOF", "timeout", "connection reset", DeadlineExceeded) and on
      502/503/504 (sdk/go/internal/apiclient/client.go:886-946). Without a
      name, a lost reply creates a second sandbox. The TS, Python and Java SDKs
      have retry code too; check them.
    - **Why:** duplicate billed sandboxes that the caller never sees. The CLI
      and MCP avoid it with auto-generated names (plans/mcp-server-and-agent-cli.md
      §5.4, eng review D5); plain SDK users don't.
    - **Start:** decide between (a) no retry for non-idempotent POSTs after the
      request may have been sent and (b) a create idempotency key (server +
      5 SDKs). Add a test per SDK: a fake server creates, then drops the
      connection, and exactly one sandbox must exist.
    - **Depends on:** none.

Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| R12 SDK duplicate-on-retry | untracked | add the TODO above to TODOS.md | skip | fix it in this plan for all 5 SDKs |
| Plan scope | D5 covers CLI/MCP only | unchanged | unchanged | grows: 5 SDKs + possibly a server idempotency key |
| R1–R11 | approved | unchanged | unchanged | unchanged |

Question D16:
D16 — Track the SDK duplicate-on-retry bug as a TODO?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: While checking create retries (D5), I confirmed the Go SDK retries a create after a dropped connection or a gateway 5xx (sdk/go/internal/apiclient/client.go:886). Without a name, that can create a second sandbox. D5 protects the CLI and MCP, but anyone calling the SDKs directly is still exposed, and the other SDKs have retry code that may do the same. It belongs to the SDKs, not to this plan.
Stakes if we pick wrong: skipping it leaves a silent duplicate-billing bug for every SDK user; building it here roughly doubles this plan's SDK work.
Recommendation: A because it is a real bug with its own design choice (stop retrying vs. an idempotency key) that deserves its own PR.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Add to TODOS.md (recommended)
  ✅ The bug is recorded with the exact code location and a test recipe
  ✅ Keeps this plan focused on the CLI and MCP
  ❌ SDK users stay exposed until someone picks it up
B) Skip
  ✅ No bookkeeping
  ✅ D5 already protects the new CLI and MCP paths
  ❌ The bug is forgotten, and SDK users keep getting silent duplicates
C) Build it now in this plan
  ✅ Fixes the bug for every SDK user in the same release
  ✅ The test recipe is already known
  ❌ Adds 5-SDK work and an unmade design choice (human: ~3 days / CC: ~1h)
Net: tracking it separately, against forgetting it or folding a separate SDK design into this plan.
Header: D16 TODO
Options:
A) Add to TODOS.md (recommended)
Append the TODO above to TODOS.md in the repo's existing style; no SDK change in this plan.
B) Skip
Do not record it; D5 covers the CLI and MCP only.
C) Build it now in this plan
Add a Phase 1 task that makes create retry-safe in all 5 SDKs (design choice made at implementation), with a lost-reply test per SDK. Human ~3 days / CC ~1h.

State: approved
Actual answer: A) Add to TODOS.md (user answer to D16, 2026-10-04)
Accepted scope: append the TODO above to TODOS.md in the repo's existing style; no SDK change in this plan.
History: none

### R13: §9 Q1, the shape of the v1 name lookup (T2)
Finding: Plan §9 open question 1, marked "decide at eng review". pkg/api/v1/routes.go registers per-sandbox routes as `GET /v1/sandboxes/{id}` wrapped by `clusterForwardWrap`, which forwards by sandbox ID. Reviewer: Claude (plan-eng-review).
Plan baseline: §5.6 proposes `?name=` on `GET /v1/sandboxes`, returning a 0- or 1-element list (recommended in §9, not yet approved).
Runtime evidence: after D12, an ID-shaped ref is never a name, so letting `/{id}` accept names would no longer be ambiguous. But `clusterForwardWrap` forwards by ID; accepting names there would need a name → owner lookup inside the wrapper used by every per-sandbox route.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R13 lookup shape | open | `GET /v1/sandboxes?name=<n>` → 0- or 1-element list; cluster: placement-by-name, no fan-out | `GET /v1/sandboxes/{id-or-name}`; `clusterForwardWrap` resolves non-ID refs to an owner first |
| Routes touched | — | the list handler only | the forwarding wrapper shared by all per-sandbox routes |
| SDK parity (T2) | five SDKs get get-by-name | five SDKs pass `name` to list | five SDKs accept a name in get |
| R1–R12 | approved | unchanged | unchanged |

Question D17:
D17 — How should the v1 API look up a sandbox by name?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: The CLI and MCP need "find my sandbox called X". The plan adds a `?name=` filter to the existing list call, which returns zero or one sandbox. The alternative lets the single-sandbox URL accept a name as well as an ID. That is neater to call, but every per-sandbox route in a cluster is forwarded by ID (pkg/api/v1/routes.go, `clusterForwardWrap`), so that wrapper would need a name lookup in front of all of them.
Stakes if we pick wrong: the second option changes the forwarding path for every per-sandbox route in cluster mode, one of the repo's fragile areas, just to save a query parameter.
Recommendation: A because it touches one handler, keeps cluster forwarding untouched, and is purely additive to a soft-frozen v1.
Completeness: A=10/10, B=9/10
Pros / cons:
A) `?name=` filter on list (recommended)
  ✅ One handler changes; cluster forwarding for every other route stays as is
  ✅ Purely additive, so a soft-frozen v1 is fine (human: ~4h / CC: ~20 min, as T2)
  ❌ Callers get a list back and must take its single element
B) Names accepted on `/{id}`
  ✅ One URL for both IDs and names; slightly nicer for callers
  ✅ Unambiguous now that D12 reserves the ID shape
  ❌ Adds a name lookup to the forwarding wrapper shared by every per-sandbox route (fragile cluster path)
Net: a small change to one handler, against a neater URL that routes every per-sandbox call through a new lookup.
Header: D17 name API
Options:
A) `?name=` filter on list (recommended)
Add `?name=<n>` to `GET /v1/sandboxes`, returning a 0- or 1-element owner-scoped list; cluster mode uses placement-by-name with no fan-out. Five SDKs pass `name` to list (T2). As in §5.6.
B) Names accepted on `/{id}`
`GET /v1/sandboxes/{id-or-name}`: `clusterForwardWrap` resolves non-ID refs (per D12) to an owner before forwarding; five SDKs accept a name in get. Regression tests on the forwarding wrapper.

State: approved
Actual answer: A) `?name=` filter on list (user answer to D17, 2026-10-04)
Accepted scope: add `?name=<n>` to `GET /v1/sandboxes`, returning a 0- or 1-element owner-scoped list; cluster mode uses placement-by-name with no fan-out. Five SDKs pass `name` to list (T2). As in §5.6.
History: none

### R14: §9 Q3, docs hard rule for `cli.mdx` / `mcp.mdx`
Finding: Plan §9 open question 3. CLAUDE.md "Hard rules → Documentation": "Every new docs page must cover all five SDK languages with matching `syncKey="lang"` tab order" and "No raw HTTP / curl examples". Reviewer: Claude (plan-eng-review).
Plan baseline: §9 proposes tabs keyed by MCP client (`syncKey="mcp-client"`), plus a required "Same thing from the SDK" five-language section, as a documented exception. Not yet approved.
Runtime evidence: CLI commands and MCP client config are shell and JSON by nature; neither is an SDK-language example or raw HTTP. The rule's purpose (no curl, SDK parity) still holds if each page also shows the SDK equivalent.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R14 docs for CLI/MCP | rule requires five SDK tabs on every new page | documented exception for `cli.mdx` and `mcp.mdx`: shell/JSON blocks, client tabs `syncKey="mcp-client"`, plus a required "Same thing from the SDK" section with the five-language `syncKey="lang"` tabs; CLAUDE.md's hard rule names the exception | no docs-site pages; CLI/MCP docs live in `cmd/aerolvm/README.md` |
| CLAUDE.md change | — | one sentence naming the two pages as the exception | none |
| Discoverability | — | in the docs sidebar (`docs/src/content.config.ts`) | only in the repo |
| R1–R13 | approved | unchanged | unchanged |

Question D18:
D18 — Allow a documented exception to the five-SDK docs rule for the CLI and MCP pages?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: The repo's docs rule says every new page shows its examples in all five SDK languages. The CLI page is shell commands, and the MCP page is client config like `claude mcp add ...`. Neither has an SDK-language form. The proposal: those two pages get tabs per MCP client, plus a required section showing the same task in the five SDKs, and CLAUDE.md names them as the exception so the rule stays clear for everything else.
Stakes if we pick wrong: without an exception, the pages either break a hard rule or move out of the docs site where users won't find them.
Recommendation: A because it keeps the rule's intent (no curl, SDK parity) and puts the pages where users look.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Documented exception (recommended)
  ✅ CLI and MCP docs live in the docs sidebar next to everything else
  ✅ The SDK-equivalent section keeps five-language parity on both pages
  ❌ The hard rule gains its first named exception, which future pages may try to cite
B) Keep them off the docs site
  ✅ The hard rule stays absolute, with no exceptions
  ✅ README docs sit next to the code they describe
  ❌ Users browsing the docs site never find the CLI or MCP setup
Net: one named exception, against hiding the feature's docs from the docs site.
Header: D18 docs rule
Options:
A) Documented exception (recommended)
`cli.mdx` and `mcp.mdx` use shell/JSON blocks with client tabs (`syncKey="mcp-client"`) and a required "Same thing from the SDK" section with five-language `syncKey="lang"` tabs; no curl. Register both in `docs/src/content.config.ts`; add one sentence to CLAUDE.md naming the two pages as the exception.
B) Keep them off the docs site
No docs-site pages; CLI and MCP docs live in `cmd/aerolvm/README.md`. The hard rule is unchanged.

State: approved
Actual answer: A) Documented exception (user answer to D18, 2026-10-04)
Accepted scope: `cli.mdx` and `mcp.mdx` use shell/JSON blocks with client tabs (`syncKey="mcp-client"`) and a required "Same thing from the SDK" section with five-language `syncKey="lang"` tabs; no curl. Both are registered in `docs/src/content.config.ts`. One sentence is added to CLAUDE.md naming the two pages as the exception (at implementation, task T7/T11).
History: none

### R15: §9 Q4, stdin forwarding default for `aerolvm exec`
Finding: Plan §9 open question 4; §5.2 rule 8. Reviewer: Claude (plan-eng-review).
Plan baseline: stdin is forwarded only with `-i` (docker semantics), recommended in §9 but not yet approved.
Runtime evidence: E2B's `sandbox exec` pipes stdin automatically (e2b.dev/docs/cli/exec-command). Agent harnesses often give child processes a non-TTY stdin that never reaches EOF. If stdin is forwarded automatically, any remote command that reads stdin waits until `--timeout`.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R15 stdin forwarding | open | only with `-i` | automatic when stdin is not a TTY (E2B style); `--no-stdin` turns it off |
| Agent harness with an open, never-EOF stdin | — | the command runs normally | a stdin-reading command hangs until `--timeout` (124) |
| `echo x \| aerolvm exec sb -- cat` | — | needs `-i` | works without a flag |
| Tests | stdin only with `-i` (plan §8) | as planned | auto-forward on a non-TTY; `--no-stdin` disables it |
| R1–R14 | approved | unchanged | unchanged |

Question D19:
D19 — Should `aerolvm exec` forward stdin only with `-i`, or automatically like E2B?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: With E2B, `echo data | e2b sandbox exec ...` just works, because stdin is always piped in. The catch is that agent tools such as a coding agent's shell often start commands with an open stdin that never ends. If we always forward stdin, any command in the sandbox that reads it (`cat`, `python -`, some installers) sits waiting until the timeout. Docker makes you say `-i` to forward stdin, and agents already know that convention.
Stakes if we pick wrong: auto-forwarding makes agent commands hang for the full timeout in some harnesses; requiring `-i` makes piped input need a flag.
Recommendation: A because a hang is far worse for an agent than a flag it already knows from docker.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) Only with `-i` (recommended)
  ✅ Never hangs because of an open stdin from the harness
  ✅ Matches docker exec, which agents already know
  ❌ `echo x | aerolvm exec sb -- cat` needs `-i`, unlike E2B
B) Automatic on non-TTY stdin
  ✅ Piped input works with no flag, like E2B
  ✅ Familiar to users coming from E2B
  ❌ Stdin-reading commands hang until timeout under harnesses with an open stdin
Net: an explicit flag, against hangs in agent harnesses.
Header: D19 stdin
Options:
A) Only with `-i` (recommended)
Stdin is forwarded only when `-i` is given (docker semantics), as in §5.2 rule 8. Test: stdin is not read without `-i`.
B) Automatic on non-TTY stdin
Forward stdin whenever it is not a TTY; `--no-stdin` turns it off. Tests: auto-forward on a non-TTY; `--no-stdin` disables it.

State: approved
Actual answer: B) Automatic on non-TTY stdin (user answer to D19, 2026-10-04)
Accepted scope: forward stdin whenever it is not a TTY; `--no-stdin` turns it off; `-i` forces forwarding on a TTY. Tests: auto-forward on a non-TTY; `--no-stdin` disables it. Reconciliation with D10 (required for D10's "exec works on WASM"): on WASM sandboxes, automatic forwarding is skipped because buffered exec has no stdin; an explicit `-i` still fails with the D10 error. Docs (cli.mdx) tell users to pass `--no-stdin` if their harness leaves stdin open. MCP `exec` has no stdin, so it is unaffected.
History: none

### R16: §9 Q6, binary name
Finding: Plan §9 open question 6. Reviewer: Claude (plan-eng-review).
Plan baseline: `aerolvm`, proposed in §5.1 and not yet approved.
Runtime evidence: no binary named `aerolvm` exists. The string is used only as the containerd namespace (scripts/install.sh:936 `SB_CONTAINERD_NAMESPACE=aerolvm`, Terraform/locals.tf:291) and the default AWS cluster tag (Ansible/inventory/aws_ec2.yml:14), neither of which clashes with a command on PATH. The Go module and Python package are `microvm`; the TS package is `@aerol-ai/aerolvm-sdk`; the local install dir is `~/.aerolvm`.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| R16 binary name | open | `aerolvm` | `microvm` |
| Matches | — | product name, TS package, `~/.aerolvm` | Go module path, Python package |
| Clash risk on PATH | — | none found | generic word; other tools use it |
| R1–R15 | approved | unchanged | unchanged |

Question D20:
D20 — What should the CLI binary be called?
Project/branch/task: reviewing plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578).
ELI10: Agents and users will type this name and put it into MCP configs, so it should be unique and obviously ours. `aerolvm` matches the product, the npm package and the `~/.aerolvm` install directory, and nothing installs a binary by that name today (it is only a containerd namespace and an AWS tag). `microvm` matches the Go module and Python package, but it is a generic word other tools also use.
Stakes if we pick wrong: a generic name can collide with another tool on someone's PATH, and renaming after people have written MCP configs breaks them.
Recommendation: A because it is unique, matches the product name, and has no clash on PATH.
Note: options differ in kind, not coverage — no completeness score.
Pros / cons:
A) `aerolvm` (recommended)
  ✅ Unique and clearly ours; matches the product, the npm package and `~/.aerolvm`
  ✅ No existing binary or PATH clash found in the repo's install paths
  ❌ Differs from the Go module and Python package name (`microvm`)
B) `microvm`
  ✅ Matches the Go module path and the Python package
  ✅ Short and descriptive
  ❌ Generic word; more likely to collide with other tools on a user's PATH
Net: a unique product name, against matching the Go/Python package name.
Header: D20 bin name
Options:
A) `aerolvm` (recommended)
Ship the binary as `aerolvm` (cmd/aerolvm), as written in the plan.
B) `microvm`
Ship the binary as `microvm` (cmd/microvm); update the plan, docs and `mcp config` snippets.

State: approved
Actual answer: A) `aerolvm` (user answer to D20, 2026-10-04)
Accepted scope: ship the binary as `aerolvm` (cmd/aerolvm), as written in the plan.
History: none

Approval readiness: PASS. Checked: scope D1 (A), D2 (A), D3 (A); R1/D4 B; R2/D5 A; R3/D6 A; R4/D7 B; R5/D8 free text + D9 A; R6/D10 A; R7/D11 A; R8/D12 A; R9/D13 A; R10/D14 A; R11/D15 B; R12/D16 A; R13/D17 A; R14/D18 A; R15/D19 B; R16/D20 A. The required-proof tests and the CRITICAL regression list added in Section 3 carry forward behaviour approved by the scope record ("Phases 1–2 as written") and by D9 (operator names stay plain).

## Review body (/plan-eng-review, 2026-10-04)

### NOT in scope (decided at this review)
- `code` MCP toolset (`run_code`): deferred (D1). `exec` covers it, and it fails on images without the interpreter.
- `lifecycle` MCP toolset: deferred (D2). The CLI keeps start/stop/snapshot.
- Fixing SDK duplicate-on-retry for plain SDK users: tracked in TODOS.md (D16), not built here.
- An FSM activation gate: rejected in favour of an owner-qualified key with no gate (D8/D9).
- An isolate-specific MCP tool (`invoke`): not proposed. Isolate is hidden from MCP (D11).

### What already exists (reused, not rebuilt)
- Go SDK (`sdk/go/pkg/microvm`): create, list, exec, sessions, files, expose, retries. CGO-free and in the root module. Extended only by `WithLimit` (D15) and file streams (D14).
- Toolbox endpoints (`cmd/toolboxd/main.go`, WASM `toolhost/host.go`): `/process/execute`, `/process/exec/stream`, `/files*`, `/process/session*`.
- Lifecycle timers (`pkg/models/types.go:307`): stop/destroy-if-idle, used for MCP defaults (D7).
- Name uniqueness: the store index (`store.go:377`) and the FSM `nameIndex` keyed via `specName` (`fsm.go:1880`). T2b reuses `specName` unchanged (D9).
- List paging (`pkg/api/clusterlist/list.go:36-38, 668`): `limit` and `page_token` already served.
- Daytona `resolveSandbox` (`pkg/api/daytona/handlers.go:826`) is server-side and can't be shared with the client binary (different deployment boundary). agenttools has its own resolver (D12).

### Diagrams

Component flow:
```
 Agent host                                   AerolVM
 ┌───────────────────────────────┐
 │ shell tool ─► aerolvm <verb>  │──┐
 │ MCP client ─stdio─► aerolvm mcp│─┤ internal/agentmcp: toolsets, pinned / read-only,
 └───────────────────────────────┘  │   isolate hidden (D11), compact list (D15)
                                    ▼
             internal/agenttools: resolve-by-shape (D12) · getOrCreate + auto-name (D4/D5)
                                  exec: stream | WASM buffered ≤4 MiB (D10) · file streams (D14)
                                    │  Go SDK (+WithLimit, +File*Stream) over HTTPS, SB_PAT_TOKEN
                                    ▼
   sandboxd /v1 ─ clusterForwardWrap ─► owner node ─ toolbox proxy ─► toolboxd | wasm toolhost
       │ GET /v1/sandboxes?name= (T2, D17)
       └─► single-node: store (owner_ref, name) | cluster: FSM placement-by-name, owner-qualified key (D9)
```

Get-or-create (CLI and MCP):
```
create(name?)
  name := given ?: "agent-" + rand12                        (D5)
  reject if name ~ ^sb-[0-9a-f]{16}$ or starts "owner:"     (D12, D9)
  GET /v1/sandboxes?name=name ── hit ──► {created:false}  (warn if spec differs)
        │ miss
  POST {name, lifecycle (MCP: stop 30m / destroy 24h, D7)}
        ├─ 201 ───────────────► {created:true}
        ├─ 409 ─► GET ?name= ─► the same owner's sandbox (per-owner names, D4) ─► {created:false}
        └─ EOF / 5xx ─► SDK retry with the same name ─► 201 or 409 (as above)
```

Pinned MCP sandbox:
```
[unresolved] ─first tool call─► resolve(name)
   ├─ started ──────────────────────────────► [ready]
   ├─ stopped ─► Start (D7) ────────────────► [ready]
   ├─ 404 + --create-if-missing ─► single-flight create ─► [ready]
   └─ 404 otherwise ─► isError "pinned sandbox not found"
[ready] ─tool call gets 404─► drop cache, recreate ─► result.sandbox_recreated=true (D6) ─► [ready]
[ready] ─stdin EOF / SIGTERM with --ephemeral─► Destroy (best effort; lifecycle TTL is the backstop)
```

FSM name key (D9):
```
proposer:  owner_ref=""  → Spec.Name = "my-agent"                (operator: plain, global)
           owner_ref="A" → Spec.Name = "owner:<b64url(A)>/my-agent"
apply (old or new replica): specName(Spec) → nameIndex[key]      identical bytes ⇒ identical result
lookup(A, "my-agent"): qualified key, else plain key where OwnerRef == A (legacy)
```

Inline diagrams to add at implementation: the getOrCreate flow in `internal/agenttools/create.go`, and the name-key encode/decode rule beside the encoder in `internal/cluster`.

### Failure modes

| Path | Realistic failure | Covered by | User sees |
|---|---|---|---|
| exec stream | WebSocket drops mid-command | exit 125 + stderr error (§5.2 rule 5) | clear error; the remote command may keep running (documented) |
| exec on WASM | output larger than 4 MiB | `output_too_large` test (D10) | clear error suggesting redirect to a file |
| read_file | multi-GB file | window + 1 byte read test (D14) | first window plus a continuation offset |
| create | reply lost after the server created the sandbox | lost-reply test (D5) | same sandbox, `created:false` |
| create | tenant name collision | per-owner names (D4) | none: each tenant has its own namespace |
| rolling upgrade | old and new replicas diverge on names | mixed-version determinism test (D9) | none |
| pinned sandbox | destroyed after idle | recreate-notice test (D6) | the model is told its files are gone |
| pinned sandbox | stopped after idle | start-then-run test (D7) | the first call waits for a start |
| `?name=` in cluster | leader or control plane unavailable | error-code mapping test | retryable `isError` / exit 1 |
| MCP stdout | a library writes to stdout | stdout-hygiene test | none (the protocol stays clean) |
| config / debug | token printed | `mcp config` + `--debug` redaction tests | none |
| `--ephemeral` | destroy fails on exit | lifecycle TTL backstop | silent, but bounded by the 24h destroy |

Critical gaps (no test, no handling and silent): **0**.

### Worktree parallelization strategy

| Step | Modules touched | Depends on |
|------|----------------|------------|
| S1 per-owner names + `?name=` (T1, T2) | pkg/api/v1, internal/service, internal/store, internal/cluster, pkg/api/daytona, pkg/models, sdk/* (list `name`) | — |
| S2 Go SDK extensions (T3) | sdk/go | — |
| S3 tool layer (T4, T5) | internal/agenttools | S2 |
| S4 CLI (T7) | cmd/aerolvm | S3 |
| S5 MCP (T6) | internal/agentmcp, cmd/aerolvm (mcp entry) | S3 |
| S6 release + install (plan T6) | .github/workflows, scripts | — |
| S7 docs + CLAUDE.md exception (T10) | docs/, CLAUDE.md | S4, S5 |
| S8 tests, integration UCs, agenteval (T8, T9) | integration-tests/, all new packages | S1, S4, S5 |

- Lane A: S1 (server).
- Lane B: S2 → S3 → S4 + S5 (S4 and S5 share `cmd/aerolvm`, so coordinate them or run them in sequence).
- Lane C: S6.
- Order: launch A, B and C together; merge all three; then S7 and S8.
- Conflicts: `sdk/go` is touched by S1 (list `name`) and S2. Sequence those two or rebase S2 on S1.
- Repo policy: one stacked PR per task; merge nothing until the stack is green.

## Implementation Tasks
Synthesized from this review's findings. Each task derives from a specific finding above. Run with Claude Code or Codex; checkbox as you ship.

- [ ] **T1 (P1, human: ~1 week / CC: ~3h)**: server: per-owner names with an owner-qualified FSM key and no gate, plus name validation
  - Surfaced by: Scope Challenge R1 (D4); Architecture R5 (D8/D9); Code quality R8 (D12)
  - Files: internal/store/store.go, internal/service/facade_state.go, internal/service/service.go, internal/cluster/ (proposer encode, decode, lookup fallback), pkg/api/daytona/handlers.go, pkg/models/types.go
  - Verify: `go test ./internal/store/... ./internal/cluster/... ./internal/service/... ./pkg/api/daytona/...`, including the CRITICAL regression list and the mixed-version determinism test
- [ ] **T2 (P1, human: ~4h / CC: ~20min)**: server + SDKs: `GET /v1/sandboxes?name=` with no cluster fan-out; five SDKs pass `name`
  - Surfaced by: §9 Q1 (D17)
  - Files: pkg/api/v1/handlers.go, pkg/api/v1/cluster_handler.go, sdk/{go,typescript,python,rust,java}
  - Verify: handler, tenant-scope and no-fan-out tests; per-SDK test commands from CLAUDE.md
- [ ] **T3 (P1, human: ~1 day / CC: ~30min)**: Go SDK: `DownloadFileStream`, `UploadFileStream`, `WithLimit`
  - Surfaced by: Performance R10 (D14), R11 (D15)
  - Files: sdk/go/pkg/microvm/client.go, sdk/go/internal/apiclient/client.go
  - Verify: `go test ./sdk/go/...` (streaming upload/download; `limit=20` sent)
- [ ] **T4 (P1, human: ~4h / CC: ~20min)**: agenttools: exec channel by runtime with a 4 MiB limit; isolate guard
  - Surfaced by: Architecture R6 (D10), R7 (D11)
  - Files: internal/agenttools/exec.go, internal/agenttools/resolve.go
  - Verify: `go test ./internal/agenttools/...` (WASM: no WebSocket dial; `output_too_large`; isolate error)
- [ ] **T5 (P1, human: ~3h / CC: ~15min)**: agenttools: get-or-create with auto-names; shape-based resolution
  - Surfaced by: Scope Challenge R2 (D5); Code quality R8 (D12)
  - Files: internal/agenttools/create.go, internal/agenttools/resolve.go
  - Verify: lost-reply test (one sandbox, same ID); shape router table test
- [ ] **T6 (P2, human: ~1 day / CC: ~30min)**: MCP: recreate notice, stop/start lifecycle default, compact list, isolate enum
  - Surfaced by: R3 (D6), R4 (D7), R11 (D15), R7 (D11)
  - Files: internal/agentmcp/, cmd/aerolvm (mcp entry)
  - Verify: `go test ./internal/agentmcp/...`; tools/list golden
- [ ] **T7 (P2, human: ~4h / CC: ~20min)**: CLI: automatic stdin on a non-TTY, `--no-stdin`, WASM skip
  - Surfaced by: §9 Q4 (D19), reconciled with D10
  - Files: cmd/aerolvm (exec verb)
  - Verify: `go test ./cmd/aerolvm/...`
- [ ] **T8 (P2, human: ~1 day / CC: ~30min)**: tests: Section 3 required-proof tests and the CRITICAL regression gate
  - Surfaced by: Test review (coverage diagram GAP→NEW rows)
  - Files: internal/agenttools/*_test.go, internal/agentmcp/*_test.go, cmd/aerolvm/*_test.go, pkg/api/v1/*_test.go
  - Verify: `make test`; coverage at ~85% or above per package (`/maintain-coverage`)
- [ ] **T9 (P2, human: ~1 day / CC: ~30min)**: eval: `-tags=agenteval` harness with 5 tasks
  - Surfaced by: Test review R9 (D13)
  - Files: integration-tests/ (or a new agenteval dir behind the tag)
  - Verify: an operator run against a local single-node sandboxd
- [ ] **T10 (P2, human: ~1h / CC: ~5min)**: docs: CLAUDE.md exception sentence; `cli.mdx`/`mcp.mdx` structure
  - Surfaced by: §9 Q3 (D18)
  - Files: CLAUDE.md, docs/src/content/docs/cli.mdx, docs/src/content/docs/mcp.mdx, docs/src/content.config.ts
  - Verify: `make docs-build`

### Unresolved decisions
None. Every choice raised in this review has an answer (D1–D20).

### Completion summary
- Step 0: Scope Challenge: scope reduced per recommendation (D1, D2); 4 findings (R1–R4), all resolved
- Architecture Review: 4 issues found (R5, R6, R7, missing diagrams)
- Code Quality Review: 1 issue found (R8); 1 suppressed
- Test Review: diagram produced, 8 gaps identified (7 required-proof, 1 eval)
- Performance Review: 2 issues found (R10, R11)
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 1 item proposed to user (accepted, added)
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 0 in this review
- Outside voice: codex, unavailable (preflight `model_unusable`; the probe failed with "Module not found .../resolve-codex-generation-model.ts" after the gstack upgrade; native fallback unavailable, since this session has no TaskOutput tool)
- Parallelization: 3 lanes, 3 parallel / 2 sequential follow-on steps
- Lake Score: 12/13 (every scored answer picked the 10/10 option except D8, which was answered in free text and then confirmed as the 10/10 option in D9)

### Suppressed findings (appendix)
- [P3] (confidence: 4/10) plan §5.3 `edit_file`: read → unique-match replace → write isn't atomic, so a concurrent writer's change can be lost. Suppressed because agent sessions are effectively single-writer and the toolbox has no conditional write to build on.

## CEO review (/plan-ceo-review, 2026-10-04)

**Target:** this plan as amended by the eng review (D1–D21). **Depth:**
implementation-ready (the plan already names interfaces and tests). **Working
plan:** this file.

### 0A. Premise
- **Real problem:** coding agents can't use AerolVM without someone first
  writing SDK code. Competitors are one config line away:
  - E2B: `e2b sandbox exec` and an MCP server.
  - Daytona: `daytona mcp init`.
  - Fly Sprites: a remote MCP at `https://sprites.dev/mcp` plus a Claude Code
    plugin.
  - People asked for an MCP server in the Cloudflare Sandbox and Sprites
    threads.
- **Target outcome:** an agent goes from nothing to running code in an AerolVM
  sandbox in one step, and AerolVM shows up wherever agents look for
  sandboxes.
- **Do-nothing cost:** AerolVM drops out of every evaluation whose first test
  is "does it work from Claude Code / Cursor?". Its create-latency lead (the
  WASM and isolate p50s in memory) never gets measured.
- **Direct or proxy:** the plan fixes the pain directly for local agents (CLI
  and stdio MCP). Hosted agents (claude.ai, ChatGPT connectors, Claude
  Desktop without a local install) need the remote MCP, which is Phase 4 and
  gated. Sprites leads with exactly that.
- **Roadmap alignment:** ROADMAP.md (Oct 2026 – Oct 2027) doesn't mention an
  agent interface. It says "A change to this direction is a pull request that
  updates this file." The plan doesn't conflict with the "will not" list:
  - it adds no sixth SDK language;
  - agent sandboxes stop after 30m idle and are destroyed after 24h (D7), so
    they are not long-lived workspaces.

### 0B. Existing code leverage
See plan §2 and the eng review's "What already exists": the Go SDK, toolbox
endpoints, lifecycle timers, the name index, list paging and the in-repo
release pipeline.
- **Unverified possible stopgap:** the E2B SDK works against the `/e2b`
  facade with `E2B_API_URL`, `E2B_SANDBOX_URL` and `E2B_API_KEY`
  (docs/src/content/docs/using-e2b-sdk.mdx:11-16). E2B's own MCP server
  depends on its code-interpreter template, which nobody has verified on
  AerolVM, so it isn't counted as a path.
- **Nothing is rebuilt that could be refactored:** the CLI/MCP is a new
  client of existing endpoints.

### 0C. Dream state
```
  CURRENT STATE                    THIS PLAN                          12-MONTH IDEAL
  agents need SDK code;     --->   aerolvm CLI + stdio MCP;     --->  any agent, local or hosted, gets an
  no CLI, no MCP;                  per-owner names; bounded           AerolVM sandbox in one step (URL paste
  E2B SDK via env vars             output/memory; agent-safe          or one install); listed where agents
                                   lifecycle; remote MCP gated        look (MCP registry, Claude Code plugin);
                                                                      capabilities disclosed progressively;
                                                                      agent-created sandboxes capped and
                                                                      attributable; self-hosters get the same
```
The plan moves toward the ideal for local agents. It doesn't yet cover hosted
agents, discoverability (registry or plugin listing), progressive disclosure,
or per-session caps.

### 0F/0G. Selective expansion (mode: SELECTIVE EXPANSION, user answer to CEO D1)

**HOLD checks.**
- The plan is past 8 files and 2 new units, but every deferrable item already
  has an answer from the eng review: D1 and D2 deferred toolsets, and D4, D13
  and D17 kept their scope.
- No new deferrals are proposed. Invariants are kept: no local-filesystem MCP
  tools, and no gate on the name change.

**10x check.** Today an agent can't reach AerolVM at all. The plan makes it one
config line for local agents. 10x would be any agent, local or hosted,
reaching a sandbox in one step, with AerolVM's sub-second create showing up in
the agent's own loop. Because remote, plugin and registry listing all reuse
`internal/agentmcp`, they cost roughly 2x the Phase 2 effort.

**Platform potential.** One tool registry can serve stdio, a remote endpoint,
a Claude Code plugin and a registry listing. The D13 agent eval can double as
a public "agent task latency" benchmark.

**Delight scan** (adjacent small items):
- a per-session create cap (C4)
- a provenance tag (C6)
- a ROADMAP line (C5)
- a plugin and skill (C2)
- a registry listing (C3)
- `aerolvm mcp doctor` (checks URL, token and reachability, and prints the
  fix)

**Cherry-pick list.** 10 candidates in total. The top 6 (C1–C6) are asked one at
a time. Available on request:
- `aerolvm mcp doctor`
- file reads returned as MCP resources
- an in-sandbox `llm.txt`
- running Claude Code inside an AerolVM sandbox

### 0H. Document approval
- CEO summary: ~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-10-04-mcp-server-and-agent-cli.md.
- Spec review: unavailable. The reviewer subagent wasn't launched, because this
  session doesn't spawn agents unless the user asks. Metrics were recorded
  (iterations 0, score null).
- Approved as-is: CEO D8 answer A (user, 2026-10-04).

### 0I. Temporal interrogation

| When | What the implementer needs or will hit | Human / CC+gstack |
|---|---|---|
| Hour 1, foundations | Three units (`cmd/aerolvm`, `internal/agenttools`, `internal/agentmcp`, D3). Pin `modelcontextprotocol/go-sdk` v1.7.x. Stacked PRs off `main`, one per task, merged only when the stack is green. `pr-review.md` applies to T1, T2 and Phase 2b (pkg/api, store, cluster). The D9 key rule is `owner:<base64url(owner_ref)>/<name>` for tenant sandboxes and plain names for operators. | ~1 day / ~15 min |
| Hours 2–3, core logic | **Decode choke point:** failover passes the replicated spec into `Service.RecreateSandbox` (internal/service/service.go:1302), via owner_watcher.go:152-161, client.go:619-622 and agent.go:550. Decode the D9 key once in `RecreateSandbox` before the store write, and in name lookup and list rendering. Don't scatter decode calls. Runtime detection for D10/D11 reads the resolved sandbox's runtime field. | ~2 days / ~30 min |
| Hours 4–5, integration | **Proposer encode point:** the owner-qualified key must be written where the Raft place/reserve command's `Spec` is built (the cluster create path), never inside apply. Phase 2b `/mcp`: mount outside `/v1` but behind the same bearer middleware; validate `Origin`; use the go-sdk stateless handler; the in-process transport streams through `io.Pipe`. Release matrix adds `aerolvm` for linux/darwin/windows × amd64/arm64 (CGO=0); `subject-path: dist/*` attests the new binaries automatically. | ~3 days / ~1h |
| Hour 6+, polish and tests | 85% coverage per new package (`/maintain-coverage`); the CRITICAL regression list (§8); the plugin CI check (C2); `mcp-publisher validate` in release (C3); the D13 agent eval run by hand against a local sandboxd; docs exception (D18) and the ROADMAP bullet (C5). | ~3 days / ~1h |

No feasibility blockers. No new choices are pending: the decode and encode
points above implement the approved D9 contract.

### CEO decision ledger

| ID and owner | Contract and evidence | Current | Proposed | Status | Exact approval and scope |
|---|---|---|---|---|---|
| C1 server/agentmcp | Remote MCP. Evidence: Sprites ships `https://sprites.dev/mcp` (fly.io/blog/sprites-mcp). Plan §5.7 kept it for Phase 4 behind a demand checkpoint. | Phase 2b in this plan | — | approved | CEO D2 answer A (user, 2026-10-04): build stateless `/mcp` behind `SB_MCP_ENABLED` (default false), bearer auth only, D10 buffered exec path for every runtime; reuses internal/agentmcp and the auth middleware; handler test + integration UC. OAuth stays deferred (Phase 4). |
| C2 packaging | Claude Code plugin + skill. Evidence: Sprites' plugin pairs MCP with progressive skill disclosure ("Dumping thirty tool descriptions into a context window is a bad way to teach anything"). | in this plan (§5.8) | — | approved | CEO D3 answer A (user, 2026-10-04): `.claude-plugin/marketplace.json` + `plugins/aerolvm/` (plugin.json registering `aerolvm mcp`, short skills/aerolvm/SKILL.md for the CLI); CI check that the manifests parse and the skill only names real verbs. |
| C3 release | Official MCP Registry listing. Evidence: registry.modelcontextprotocol.io takes a `server.json` via `mcp-publisher`; it points at npm / PyPI / NuGet / OCI / GitHub Releases artifacts. | in this plan (Phase 3) | — | approved | CEO D4 answer A (user, 2026-10-04): Phase 3 `server.json` (`io.github.aerol-ai/aerolvm`) pointing at the npm package; release step runs `mcp-publisher validate` and `publish` with GitHub OIDC. |
| C4 agentmcp | Per-session create cap. Evidence: Sprites defaults to a five-sprite cap. Unpinned MCP mode had no cap (§5.3). | in this plan (§5.3) | — | approved | CEO D5 answer A (user, 2026-10-04): unpinned `aerolvm mcp` allows at most 5 successful creates per process (`--max-creates N`, 0 = unlimited); the 6th returns an isError telling the model to destroy a sandbox or raise the limit; pinned recreates and 409-resolved creates don't count; remote /mcp has no session cap; agentmcp tests. |
| C5 docs | ROADMAP.md alignment. Evidence: ROADMAP.md: "A change to this direction is a pull request that updates this file"; it names no agent interface. | in this plan (§4 T7) | — | approved | CEO D6 answer A (user, 2026-10-04): one "What the project will do" bullet in ROADMAP.md for the `aerolvm` CLI and MCP server (local stdio + bearer remote endpoint) as the agent interface over the existing API, in the same stacked PR as the docs task. |
| C6 agenttools | Provenance tag on CLI/MCP-created sandboxes. Evidence: sandboxes carry `Tags` and list filters by tag (`WithTags`). | in this plan (§5.4) | — | approved | CEO D7 answer A (user, 2026-10-04): CLI creates add `aerolvm.created_by=cli`; MCP creates (stdio and remote) add `aerolvm.created_by=mcp`, merged with user tags (user wins on conflict); MCP `sandbox_list` stays unfiltered by default; agenttools test. |
| CF1 server/agentmcp (Section 1) | Remote /mcp configuration. Evidence: stdio options are process flags (§5.3 `--sandbox`, `--toolsets`, `--read-only`); Phase 2b is stateless (§5.7), so it has no process to carry them. | URL query parameters (§5.7) | — | approved | CEO D9 answer A (user, 2026-10-04): `/mcp` accepts `sandbox`, `create_if_missing`, `image`, `runtime`, `toolsets`, `read_only` as query parameters with the stdio flags' names and validation, parsed per request; token stays in Authorization; handler tests (each param maps to the stdio config; invalid → 400 naming the param) + tools/list golden for `?sandbox=x&read_only=1`. |
| CF2 server/agentmcp (Section 1) | Remote unpinned mode has no create brake. Evidence: the C4 cap counts creates per process; remote /mcp is stateless; the open-source `Admitter` is a no-op (pkg/controlplane/controlplane.go:127, 273). | remote requires `sandbox=` (§5.7) | — | approved | CEO D10 answer A (user, 2026-10-04): `/mcp` without `sandbox=` returns 400 "remote MCP requires ?sandbox=<name>"; fleet tools never registered remotely; stdio keeps unpinned with the C4 cap; handler + tools/list tests. |
| CF3 toolboxd/agenttools (Section 2) | Cancelled exec leaves the remote process running. Evidence: cmd/toolboxd/exec_stream.go runs `exec.Command("/bin/sh", "-c", start.Command)`; on WebSocket read error the pump only closes stdin, then waits on the child. | kill on drop (§5.5) | — | approved | CEO D11 answer B (user, 2026-10-04): toolboxd kills the command's process group when the WebSocket closes or errors before the exit message; agenttools also sends KILL on cancellation; sessions unaffected; toolboxd drop test (`sleep 300`, drop WS, group gone within 2s; normal exit still sends exit) + agenttools cancel test. |
| CF5 agenttools (Section 4) | New CLI against an old server resolves the wrong sandbox. Evidence: pkg/api/v1/handlers.go:168-183 `parseTagFilter` reads only `tag.` keys; the list handler otherwise reads only `ids`; an unknown `name` parameter is ignored and a full page comes back. | verify each result (§5.6) | — | approved | CEO D12 answer A (user, 2026-10-04): accept a `?name=` response only if ≤1 row and that row's name equals the request; else `server_unsupported` naming the URL and the fix; applies to every name resolution incl. get-or-create; fake-old-server tests (no follow-up exec/destroy). |
| CF6 server/observability (Section 8) | Remote /mcp has no tool-level observability. Evidence: §5.7 specifies none; existing seams are internal/observability/expvar.go (`CollectAerolVMExpvars`), trace.go (OTEL), setup/grafana d1–d11, setup/runbooks/. | full launch observability (§5.7) | — | approved | CEO D13 answer A (user, 2026-10-04): expvar `aerolvm_mcp` (calls by tool × outcome, latency by tool) via `CollectAerolVMExpvars`; one structured log line + OTEL span per tool call (tool, sandbox_id, owner_ref, outcome, duration_ms; never args/outputs); Grafana "Remote MCP" panel row; Prometheus alert >20% errors for 10m; setup/runbooks/remote-mcp.md; handler test of counter + log line. |
| CF7 store (Section 9) | Downgrade after T2b can brick boot. Evidence: internal/store/store.go:377 `CREATE UNIQUE INDEX IF NOT EXISTS idx_sandboxes_name ON sandboxes(name) WHERE name <> '';`; store.go:691-694 aborts open on any failing schema statement; sqlite3 probe confirmed name-only IF NOT EXISTS (reused name → exit 0; new name → `UNIQUE constraint failed`, exit 19). | reuse `idx_sandboxes_name` (§5.6) | — | approved | CEO D14 answer A (user, 2026-10-04): keep `idx_sandboxes_name`; startup migration reads its definition from sqlite_master and, if global, drops and recreates it as (owner_ref, name) WHERE name <> '' in one transaction; older binaries skip it and boot; store test runs the OLD schema list against a migrated DB with duplicate names. |

CEO approval readiness: PASS. Checked: C1 (D2 A), C2 (D3 A), C3 (D4 A), C4 (D5 A), C5 (D6 A), C6 (D7 A), CF1 (D9 A), CF2 (D10 A), CF3 (D11 B), CF5 (D12 A), CF6 (D13 A), CF7 (D14 A). Admin answers, not remedy approvals: mode D1 = SELECTIVE EXPANSION; document approval D8 = A. Required proofs added without a question: D9 decode fallback for legacy `owner:` names; C1 remote live UC (C1 scope says "integration UC"). No deferrals or rejections.

## Answered decision C1 (CEO D2: A, Add to this plan's scope)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Remote `/mcp` endpoint on sandboxd | pending (C1); plan §5.7 | Phase 4, gated on demand + its own eng review | built in this plan, Phase 2b, behind `SB_MCP_ENABLED` (default false) | stays Phase 4; TODOS.md entry with the trigger "first managed customer asks for no-install MCP" | stays the Phase 4 sketch, no TODO |
| Auth | §5.7 | bearer, OAuth via `pkg/controlplane` later | bearer only via the existing middleware; OAuth stays deferred | unchanged | unchanged |
| Exec on remote | eng D10 | — | buffered `/process/execute` path from D10 (4 MiB limit) for every runtime, because WebSocket hijack can't run in-process | — | — |
| Clients served | — | local only (stdio) | + Claude Code `--transport http --header`, Cursor, VS Code with a header; NOT claude.ai/ChatGPT connectors (they need OAuth) | local only | local only |
| Effort / risk | — | — | L / medium (new pkg/api route, stateless, default-off) | S / low | S / low |
| Eng-review rows R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D2 — C1: Pull the remote MCP endpoint forward from the gated Phase 4 into this plan?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review in SELECTIVE EXPANSION mode.
ELI10: Fly's Sprites lets you paste one URL into an MCP client and go. Our plan ships a local binary first and keeps a sandboxd-hosted `/mcp` URL for a later, gated Phase 4. Building it now with plain bearer-token auth (the existing API token) would let Claude Code, Cursor and VS Code connect with no install. It would NOT reach claude.ai or ChatGPT connectors: those need OAuth, which is the expensive part and stays deferred either way.
Stakes: pulling it in adds a new API route and a third front end to a solo-maintained plan, mostly for clients that can already run the local binary. Leaving it out means managed users must install `aerolvm` to use MCP at all.
Recommendation: B because the clients a bearer-only endpoint serves can already run the local binary, while the no-install audience (claude.ai, ChatGPT) needs OAuth, which neither option builds.
Note: options differ in kind, not coverage — no completeness score.
Header: C1 remote MCP
A) Add to this plan's scope
Build Phase 4's stateless `/mcp` now behind `SB_MCP_ENABLED` (default false), with bearer auth only and the D10 buffered exec path for every runtime. Effort L, risk medium, reuses internal/agentmcp and the auth middleware; verified by a handler test plus an integration UC.
✅ Claude Code, Cursor and VS Code connect to a URL with no binary to install or update
✅ Managed users get MCP without version drift between their CLI and the server
❌ A new pkg/api route and front end now, before any user has asked for it, and still no claude.ai/ChatGPT reach
B) Defer to TODOS.md (recommended)
Keep Phase 4 gated; add a TODOS.md entry with the trigger "first managed customer asks for no-install MCP" and note that OAuth is the real unlock. Effort S, risk low, zero implementation work now; reuse is unchanged.
✅ This plan stays focused on the local path that serves every MCP client that can run a binary
✅ The trigger and the OAuth dependency are written down, so the decision isn't lost
❌ Managed users must install the `aerolvm` binary to use MCP until Phase 4 ships
C) Skip
Leave §5.7 as an untracked sketch; no TODO. Effort S, risk low, zero implementation work.
✅ No bookkeeping, and the plan text already describes the design
✅ Nothing changes in this plan's scope or tasks
❌ No trigger is recorded, so the remote endpoint may never get revisited

## Answered decision C2 (CEO D3: A, Add to this plan's scope)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Claude Code plugin | pending (C2) | none; users run `aerolvm mcp config claude-code` (§5.3) | `.claude-plugin/marketplace.json` at the repo root + `plugins/aerolvm/` with `plugin.json` registering `aerolvm mcp` and a `skills/aerolvm/SKILL.md` | TODOS.md entry | none |
| Skill content | — | — | short: when to reach for a sandbox, the core CLI verbs (`create`, `exec`, `cp`, `expose`, `destroy`), `--json`, `--no-stdin`, pinned MCP mode; points to `aerolvm <verb> --help` for detail (progressive disclosure) | — | — |
| Install path for users | — | binary + `claude mcp add …` | `/plugin marketplace add aerol-ai/microvm` then `/plugin install aerolvm` (binary still required on PATH) | unchanged | unchanged |
| Tests | — | — | CI check that `plugin.json` and `marketplace.json` parse and that the skill names only verbs that exist in `aerolvm --help` | — | — |
| Effort / risk | — | — | S / low | S / low | S / low |
| C1 (approved), R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D3 — C2: Ship a Claude Code plugin (MCP config + a CLI skill) from this repo?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review in SELECTIVE EXPANSION mode; C1 added the remote endpoint.
ELI10: Fly found that dumping every tool into the model's context teaches it badly, so their Claude Code plugin pairs the MCP server with a short skill that the agent loads only when it needs a sandbox. We can ship the same from this repo: a plugin that registers `aerolvm mcp` and a one-page skill teaching the CLI verbs. Users would install it with two slash commands instead of copying config.
Stakes: without it, setup stays a copy-paste of `mcp config` output, and the agent learns the CLI only from `--help`; with it, there is one more artifact to keep in sync with the CLI's verbs.
Recommendation: A because it is small, makes setup two commands, and a CI check keeps the skill honest about which verbs exist.
Note: options differ in kind, not coverage — no completeness score.
Header: C2 plugin
A) Add to this plan's scope (recommended)
Add `.claude-plugin/marketplace.json` and `plugins/aerolvm/` (plugin.json registering `aerolvm mcp`, plus a short skills/aerolvm/SKILL.md for the CLI) with a CI check that the manifests parse and the skill only names real verbs. Effort S, risk low, reuses the CLI and `mcp config`; verified by that CI check.
✅ Two slash commands set up both the MCP server and the CLI know-how in Claude Code
✅ Progressive disclosure: the skill loads only when the agent needs a sandbox, keeping context small
❌ One more artifact that must track CLI verbs, and the binary still has to be on PATH
B) Defer to TODOS.md
Record the plugin idea in TODOS.md for after the CLI ships. Effort S, risk low, zero implementation work now.
✅ Plugin format can settle after real users try the CLI
✅ Nothing new to maintain in this plan
❌ Setup stays a copy-paste, and the agent learns the CLI only from --help
C) Skip
No plugin. Effort S, risk low, zero implementation work.
✅ No extra artifact to keep in sync
✅ `mcp config` already covers setup for every client
❌ Misses the Claude Code plugin directory as a discovery channel

## Answered decision C3 (CEO D4: A, Add to this plan's scope)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Official MCP Registry entry | pending (C3) | none | Phase 3: `server.json` (name `io.github.aerol-ai/aerolvm`) pointing at the Phase 3 npm package, published by a release-workflow step (`mcp-publisher` with GitHub OIDC) | TODOS.md entry | none |
| Package the entry points at | §4 Phase 3 (npm package with per-platform binaries) | npm planned in Phase 3 | the same npm package; no new bundle format | — | — |
| Tests / checks | — | — | `mcp-publisher validate` in CI on every release-workflow run | — | — |
| Effort / risk | — | — | S / low | S / low | S / low |
| C1, C2 (approved), R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D4 — C3: List `aerolvm mcp` in the official MCP Registry when the npm package ships?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review in SELECTIVE EXPANSION mode; C1 and C2 accepted.
ELI10: MCP clients and directories pull from the official registry at registry.modelcontextprotocol.io. Getting listed means writing a small `server.json` and running `mcp-publisher publish`. The registry entry has to point at a package it understands, like npm. This plan already ships an npm package in Phase 3, so the listing can ride on it with one extra release step.
Stakes: without a listing, AerolVM doesn't appear where agent users and directory sites look for MCP servers; with it, there's one more release step that can fail.
Recommendation: A because it reuses the npm package Phase 3 already builds, so a new discovery channel costs one release step.
Note: options differ in kind, not coverage — no completeness score.
Header: C3 registry
A) Add to this plan's scope (recommended)
In Phase 3, add `server.json` (`io.github.aerol-ai/aerolvm`) pointing at the npm package and a release-workflow step that runs `mcp-publisher validate` and `publish` with GitHub OIDC. Effort S, risk low, reuses the Phase 3 npm package; verified by validate in CI.
✅ AerolVM appears in the official registry and the directories that mirror it
✅ Rides on the npm package already planned; no new packaging format
❌ One more release step that can fail and that depends on the registry staying stable
B) Defer to TODOS.md
Record the registry listing in TODOS.md for after Phase 3 ships. Effort S, risk low, zero implementation work now.
✅ Release workflow stays as is for this plan
✅ Listing can wait until the npm package has real users
❌ No registry presence when the npm package launches
C) Skip
No registry listing. Effort S, risk low, zero implementation work.
✅ Nothing extra to maintain
✅ Users can still add the server by hand
❌ Misses the main discovery channel for MCP servers

## Answered decision C4 (CEO D5: A, Add to this plan's scope)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Creates per MCP server process (unpinned mode) | pending (C4); §5.3 | unlimited | at most 5 successful creates per process (`--max-creates N`, 0 = unlimited); the 6th returns `isError` "create limit reached for this session; destroy a sandbox or raise --max-creates" | TODOS.md entry | unlimited |
| Pinned mode | §5.3, D6 | one sandbox; recreate after loss | unchanged; a recreate does not count against the cap | unchanged | unchanged |
| Remote `/mcp` (C1) | approved | stateless, no session | the cap doesn't apply (no process session); the managed build's per-owner create-admission gate (`pkg/controlplane` `Admitter`) still applies; the open-source build has no per-tenant limit | unchanged | unchanged |
| Retried or idempotent create (D5 409 → existing sandbox) | approved | — | does not count against the cap | — | — |
| Tests | — | — | agentmcp: 5 creates succeed, the 6th returns the error without a POST; a 409 → existing sandbox doesn't count; `--max-creates 0` lifts the cap | — | — |
| Effort / risk | — | — | S / low | S / low | S / low |
| C1–C3 (approved), R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D5 — C4: Cap how many sandboxes one MCP session can create?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review in SELECTIVE EXPANSION mode; C1–C3 accepted.
ELI10: In unpinned mode the model can call `sandbox_create` as often as it likes. A confused or prompt-injected model could loop and create dozens of billed sandboxes before anyone notices. Sprites caps an MCP session at five. We can do the same: five creates per `aerolvm mcp` process by default, with a flag to raise or remove it. Pinned mode is unaffected. The remote endpoint has no session, so only the managed build's per-owner admission gate (pkg/controlplane `Admitter`) applies there; the open-source build has no per-tenant limit.
Stakes: without a cap, one bad loop can run up a bill; with it, a legitimate agent that needs more than five sandboxes must be started with a higher limit.
Recommendation: A because a stuck model creating sandboxes is a real cost risk, and the cap is a few lines with a clear error and an off switch.
Note: options differ in kind, not coverage — no completeness score.
Header: C4 create cap
A) Add to this plan's scope (recommended)
Unpinned `aerolvm mcp` allows at most 5 successful creates per process (`--max-creates N`, 0 = unlimited); the 6th returns an isError telling the model to destroy a sandbox or raise the limit. Pinned recreates and 409-resolved creates don't count; remote /mcp has no session cap (only the managed build's per-owner admission gate applies). Effort S, risk low; verified by agentmcp tests.
✅ A looping or injected model can't create more than five billed sandboxes per session
✅ Clear error text tells the model and the user exactly how to proceed
❌ Agents that genuinely need many sandboxes must be started with --max-creates
B) Defer to TODOS.md
Record the cap in TODOS.md; unpinned mode stays unlimited for now. Effort S, risk low, zero implementation work now.
✅ No new flag or error path in this plan
✅ Can be tuned later from real usage
❌ A runaway session can create unlimited sandboxes until the idle lifecycle cleans them up
C) Skip
No cap; rely on the idle lifecycle (D7) and, in the managed build, the per-owner admission gate. Effort S, risk low, zero implementation work.
✅ Simplest behaviour for agents that fan out
✅ The managed build's per-owner admission gate (pkg/controlplane Admitter) can already refuse creates
❌ Self-hosted operators have no per-session brake

History: rebuilt before sending. The first draft said "server-side tenant quotas" exist; the repo has only the per-owner create-admission gate (pkg/controlplane/controlplane.go:127 `Admitter`), a no-op in the open-source build.

## Answered decision C5 (CEO D6: A, Add to this plan's scope)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| ROADMAP.md direction | pending (C5); ROADMAP.md: "A change to this direction is a pull request that updates this file" | no agent interface listed | add one "What the project will do" bullet: ship the `aerolvm` CLI and MCP server (local stdio + bearer remote endpoint) as the agent interface over the existing API; landed in the same stacked PR as T10 (docs) | TODOS.md entry | none |
| "Will not" list | ROADMAP.md | unchanged | unchanged (no sixth SDK language; agent sandboxes aren't long-lived workspaces) | unchanged | unchanged |
| Effort / risk | — | — | S / low | S / low | S / low |
| C1–C4 (approved), R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D6 — C5: Add the CLI + MCP to ROADMAP.md as part of this plan?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review in SELECTIVE EXPANSION mode; C1–C4 accepted.
ELI10: The repo's ROADMAP.md says what AerolVM will and won't do through October 2027, and states that a change in direction is a pull request that updates it. The roadmap doesn't mention any agent interface today. Shipping a CLI, a local MCP server and a remote MCP endpoint is a new direction, so by the roadmap's own rule it should get one line there.
Stakes: without the line, the roadmap understates what the project commits to maintaining, and contributors reading it won't know the agent interface is supported.
Recommendation: A because the roadmap's own rule asks for it and it is one sentence.
Note: options differ in kind, not coverage — no completeness score.
Header: C5 roadmap
A) Add to this plan's scope (recommended)
Add one "What the project will do" bullet to ROADMAP.md: ship the `aerolvm` CLI and MCP server (local stdio and a bearer-auth remote endpoint) as the agent interface over the existing API, in the same stacked PR as the docs task (T10). Effort S, risk low, zero code; verified by review.
✅ Follows the roadmap's own rule that a direction change updates the file
✅ Tells contributors and users the agent interface is supported, not experimental
❌ Commits the project to maintaining the CLI/MCP through October 2027
B) Defer to TODOS.md
Record the roadmap update in TODOS.md for after the CLI ships. Effort S, risk low, zero implementation work now.
✅ The roadmap changes only once the feature actually exists
✅ No public commitment before first users try it
❌ The roadmap and the shipped product disagree until someone remembers
C) Skip
Leave ROADMAP.md unchanged. Effort S, risk low, zero implementation work.
✅ No new long-term commitment in writing
✅ Nothing to keep in sync
❌ Breaks the roadmap's own rule for direction changes

## Answered decision C6 (CEO D7: A, Add to this plan's scope)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Provenance tag on create | pending (C6); `CreateSandboxRequest.Tags` (pkg/models/types.go) | no tag | CLI creates add `aerolvm.created_by=cli`; MCP creates (stdio and remote) add `aerolvm.created_by=mcp`; merged with user tags, user tags win on conflict | TODOS.md entry | none |
| MCP `sandbox_list` default (D15) | approved | compact rows, 20/page, all of the caller's sandboxes | unchanged (the tag is available as a filter, not applied by default) | unchanged | unchanged |
| Tests | — | — | agenttools: create request carries the tag; a user-supplied `aerolvm.created_by` is kept | — | — |
| Effort / risk | — | — | S / low | S / low | S / low |
| C1–C5 (approved), R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D7 — C6: Tag sandboxes created by the CLI and MCP with where they came from?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review in SELECTIVE EXPANSION mode; C1–C5 accepted.
ELI10: Sandboxes already carry free-form tags, and list can filter by tag. If every CLI- or MCP-created sandbox gets a tag like `aerolvm.created_by=mcp`, operators can see how much usage comes from agents, find and clean up agent sandboxes in one filter, and the agent itself can list only its own kind. A user's own tag of the same name wins.
Stakes: without it, agent-created sandboxes look like any other, so cleanup and usage questions need guesswork; with it, every agent sandbox carries one extra tag.
Recommendation: A because it is one map entry per create, and it answers "how much do agents use this?" from day one.
Note: options differ in kind, not coverage — no completeness score.
Header: C6 tag
A) Add to this plan's scope (recommended)
CLI creates add `aerolvm.created_by=cli`; MCP creates (stdio and remote) add `aerolvm.created_by=mcp`, merged with user tags (user wins on conflict). MCP `sandbox_list` stays unfiltered by default. Effort S, risk low, reuses existing tags; verified by an agenttools test.
✅ Operators can filter, count and clean up agent-created sandboxes with existing tag filters
✅ Answers how much usage comes from agents without new telemetry
❌ One more tag on every agent sandbox that users may see in listings
B) Defer to TODOS.md
Record the tag in TODOS.md for later. Effort S, risk low, zero implementation work now.
✅ No change to what the CLI sends today
✅ Tag naming can be decided with real usage data
❌ Sandboxes created before it ships can't be told apart later
C) Skip
No provenance tag. Effort S, risk low, zero implementation work.
✅ Nothing extra in listings
✅ Users keep full control of their tags
❌ Agent usage and cleanup stay invisible to operators

## Answered decision CF1 (CEO D9: A, URL query parameters)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| How a remote client sets options | pending (CF1); §5.7, C1 | unspecified | URL query parameters on `/mcp`: `sandbox`, `create_if_missing`, `image`, `runtime`, `toolsets`, `read_only`; same names and validation as the stdio flags; parsed on every request (stateless) | no options: remote serves the `core` toolset, unpinned, read-write | request headers (`X-Aerolvm-Sandbox`, `X-Aerolvm-Toolsets`, …) |
| Client support | — | — | every MCP client accepts a URL | — | only clients that let users set headers (Claude Code `--header`, VS Code); Cursor and others vary |
| Secrets in the URL | §6 token handling | token only in `Authorization` | unchanged: options aren't secrets; the token stays in the header | unchanged | unchanged |
| Pinned lazy create across nodes | D4/D5 | — | name-keyed get-or-create makes concurrent first calls on different nodes converge on one sandbox | n/a | same as A |
| Tests | — | — | handler: each parameter maps to the same registry config as the stdio flag; invalid values → 400 with the parameter name; tools/list golden for `?sandbox=x&read_only=1` | none | header-parsing tests |
| Effort / risk | — | — | S / low | S / low | S / low |
| CF2 (remote unpinned policy) | pending | pending | pending | pending | pending |
| C1–C6, eng R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D9 — CF1: How does a remote MCP client choose pinned mode, toolsets and read-only?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review Section 1; C1 added the remote `/mcp`.
ELI10: With the local server you pick options with flags: `aerolvm mcp --sandbox my-agent --read-only`. The remote endpoint you added in C1 is a URL with no process to pass flags to, and the plan never says how a remote client picks those options. So it would get one fixed default, which can't be pinned to one sandbox or made read-only. Putting the same options in the URL (`/mcp?sandbox=my-agent&read_only=1`) works in every MCP client, because they all accept a URL. Headers would work only in clients that let you set them.
Stakes: without a way to set options, remote users lose pinned and read-only mode, the two safety modes, and get full access to every sandbox their token can see.
Recommendation: A because a URL is the one thing every MCP client lets you configure, and it brings the remote endpoint to parity with the local flags.
Note: options differ in kind, not coverage — no completeness score.
Header: CF1 remote opts
A) URL query parameters (recommended)
`/mcp` accepts `sandbox`, `create_if_missing`, `image`, `runtime`, `toolsets` and `read_only` as query parameters with the same names and validation as the stdio flags, parsed per request. The token stays in the Authorization header. Effort S, risk low; verified by handler tests and a tools/list golden for a pinned read-only URL.
✅ Works in every MCP client, since all of them accept a URL
✅ Remote gets the same pinned and read-only safety modes as stdio
❌ Option values appear in client config files and server access logs (no secrets, but visible)
B) No remote options
Remote `/mcp` always serves the core toolset, unpinned and read-write. Effort S, risk low, zero extra work.
✅ Simplest endpoint; nothing to parse or validate
✅ Fewest test cases
❌ No pinned or read-only mode remotely: the model can touch every sandbox the token sees
C) Request headers
Options travel as `X-Aerolvm-*` headers parsed per request. Effort S, risk low; verified by header-parsing tests.
✅ Keeps option values out of URLs and access logs
✅ Same option set as stdio
❌ Only clients that let users set custom headers can use it

## Answered decision CF2 (CEO D10: A, Remote requires pinned)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Remote unpinned mode | pending (CF2); CF1 (approved), C4 (approved) | allowed; `sandbox=` optional | not allowed: `/mcp` without `sandbox=` returns 400 "remote MCP requires ?sandbox=<name>"; `sandbox_create`, `sandbox_list` and `sandbox_destroy` are never registered remotely | allowed; the only brake is the managed build's per-owner admission gate | allowed only when the operator sets `SB_MCP_ALLOW_UNPINNED=true` (default false); otherwise as A |
| Unpinned via stdio | eng §5.3, C4 | allowed with the 5-create cap | unchanged | unchanged | unchanged |
| Tests | — | — | handler: no `sandbox=` → 400; tools/list for a remote URL never contains the fleet tools | none | flag off → 400; flag on → fleet tools listed |
| Effort / risk | — | — | S / low | S / low | S / low |
| CF1, C1–C6, eng R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D10 — CF2: Should remote MCP clients be limited to pinned mode (one named sandbox per URL)?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review Section 1; CF1 put options in the URL.
ELI10: The local server caps a session at five sandbox creates (C4) because it can count them in one process. The remote endpoint has no session to count, and the open-source build has no per-tenant limit (the control-plane admission check is a no-op there). So a remote client in unpinned mode can create sandboxes without any brake. Requiring `?sandbox=<name>` makes each remote URL one pinned sandbox: the model can't create, list or destroy anything else, which is also the safest mode against prompt injection.
Stakes: allowing unpinned remotely means a looping or injected model can create unlimited billed sandboxes on a self-hosted install; requiring pinned means remote users who want many sandboxes must use the local binary.
Recommendation: A because the remote endpoint can't enforce C4's cap, and pinned mode is the safe default the plan already recommends.
Note: options differ in kind, not coverage — no completeness score.
Header: CF2 unpinned
A) Remote requires pinned (recommended)
`/mcp` without `sandbox=` returns 400 "remote MCP requires ?sandbox=<name>"; fleet tools (`sandbox_create`, `sandbox_list`, `sandbox_destroy`) are never registered remotely. Stdio keeps unpinned mode with the C4 cap. Effort S, risk low; verified by handler and tools/list tests.
✅ No unbounded creates through the remote endpoint on any build
✅ Each remote URL can touch exactly one sandbox, limiting prompt-injection damage
❌ Remote users who want several sandboxes must use several URLs or the local binary
B) Allow unpinned remotely
Remote clients may omit `sandbox=` and get the fleet tools; only the managed build's per-owner admission gate limits creates. Effort S, risk low, zero extra work.
✅ Remote matches stdio's unpinned flexibility
✅ No extra validation path
❌ Self-hosted installs have no brake on a looping remote session
C) Unpinned behind an operator flag
Unpinned remote mode works only when the operator sets `SB_MCP_ALLOW_UNPINNED=true` (default false); otherwise as A. Effort S, risk low; verified by flag-on and flag-off tests.
✅ Safe by default, and operators who want it can turn it on
✅ Fits the repo's default-off pattern for risky features
❌ One more flag to document and test

## Answered decision CF3 (CEO D11: B, Kill on drop in toolboxd)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Exec stream dropped before the command exits | pending (CF3); cmd/toolboxd/exec_stream.go | process keeps running; only stdin closes | client-side only: agenttools sends `Signal("KILL")` before closing on any cancellation (CLI SIGINT/SIGTERM, MCP `notifications/cancelled`, ctx done); an abrupt client death still orphans the process | toolboxd kills the command's process group when the WebSocket closes or errors before the exit message is sent; agenttools also sends KILL on cancellation | no change; document that a cancelled exec keeps running |
| Who benefits | — | — | only aerolvm CLI/MCP | every exec-stream caller (all five SDKs, CLI, MCP), including abrupt client death | — |
| Existing behaviour change | exec-stream API | — | none | a disconnected exec now dies; long-running work belongs in sessions (`/sessions`), which are unaffected | none |
| Release surface | — | — | CLI only | toolboxd (in-guest agent) ships with images/templates; old sandboxes keep old behaviour until they run a new toolboxd | none |
| Tests | — | — | agenttools: cancellation sends KILL then closes | toolboxd: start `sleep 300`, drop the WS, assert the process group is gone within 2s; a normal exit still sends the exit message; agenttools KILL-on-cancel test | none |
| Effort / risk | — | — | S / low | M / medium | S / low |
| CF1, CF2, C1–C6, eng R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D11 — CF3: What should happen to a running command when its exec stream is cancelled or dropped?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review Section 2.
ELI10: When an agent runs `aerolvm exec sb -- npm test` and then gets killed (harness timeout, Ctrl-C, or the MCP client cancels the call), the connection to the sandbox drops. Today the sandbox's agent only closes the command's input and keeps it running (cmd/toolboxd/exec_stream.go), so the test suite or a runaway loop keeps burning CPU with nothing attached and no way to reach it. Fixing it in the sandbox agent covers every client, including one that dies too suddenly to say anything. Fixing it only in the CLI is smaller but misses sudden deaths.
Stakes: orphaned processes pile up in agent sandboxes, eating CPU and memory and confusing the next command that the model runs.
Recommendation: B because the leak lives in toolboxd, and fixing it there covers every SDK and sudden client death; long-running work already has sessions.
Completeness: A=7/10, B=10/10, C=3/10
Header: CF3 exec cancel
A) Client-side kill only
agenttools sends `Signal("KILL")` before closing the stream on any cancellation (CLI SIGINT/SIGTERM, MCP cancel, ctx done). Effort S, risk low; verified by an agenttools test. Abrupt client death still orphans the process.
✅ No change to toolboxd or existing SDK behaviour
✅ Covers the common cancellation paths in the CLI and MCP
❌ A client killed with SIGKILL, or any other SDK user, still leaves orphans
B) Kill on drop in toolboxd (recommended)
toolboxd kills the command's process group when the WebSocket closes or errors before the exit message; agenttools also sends KILL on cancellation. Effort M, risk medium (in-guest agent change; sessions unaffected); verified by a toolboxd drop test and the agenttools cancel test.
✅ Fixes the leak at its source for every SDK, the CLI and MCP
✅ Covers sudden client death, which no client-side fix can
❌ Changes existing exec-stream behaviour, and old sandboxes keep the leak until their toolboxd updates
C) Leave it and document
No change; docs say a cancelled exec keeps running and suggest sessions for long work. Effort S, risk low, zero implementation work.
✅ No behaviour change anywhere
✅ Nothing new to test
❌ Agent sandboxes keep accumulating orphaned processes

## Answered decision CF5 (CEO D12: A, Verify each result)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Name lookup response check | pending (CF5); D17 contract "0- or 1-element owner-scoped list" | client trusts the server | agenttools accepts a `?name=` response only when it has at most 1 row and that row's name equals the requested name; otherwise error `server_unsupported`: "sandboxd at <url> does not support name lookup (needs a release with T2); use the sandbox ID or upgrade" | version gate: the CLI reads the server version first and refuses name refs below the T2 release | no check |
| Extra requests | — | — | none | one version read per process (cached) | none |
| Guards server bugs too | — | — | yes (any wrong row is rejected) | no (trusts a new server's result) | no |
| Applies to | — | — | every name resolution (CLI verbs, stdio MCP, remote /mcp, D5 get-or-create) | CLI and stdio MCP | — |
| Tests | — | — | agenttools: fake old server returns 3 sandboxes for `?name=x` → `server_unsupported`, no follow-up call (no exec/destroy); 1 row with a different name → `server_unsupported`; 0 rows → not_found; 1 matching row → used | version-gate tests | none |
| Effort / risk | — | — | S / low | S / low | S / low |
| CF1–CF3, C1–C6, eng R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D12 — CF5: How should the CLI protect against an older sandboxd that ignores `?name=`?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review Section 4.
ELI10: The name lookup works by adding `?name=my-agent` to the list call. Today's server ignores parameters it doesn't know (it reads only `tag.*` and `ids`, pkg/api/v1/handlers.go:168), so an older server answers with a whole page of sandboxes. A new CLI that trusts "this list has zero or one result" would take the first one, so `aerolvm destroy my-agent` could destroy a different sandbox. Users will mix CLI and server versions, especially self-hosters.
Stakes: without a check, a version mismatch silently runs commands against, or destroys, the wrong sandbox.
Recommendation: A because checking the returned row's name costs nothing, needs no extra request, and also catches server bugs.
Completeness: A=10/10, B=8/10, C=2/10
Header: CF5 old server
A) Verify each result (recommended)
agenttools accepts a `?name=` response only if it has at most 1 row and that row's name equals the request; anything else is `server_unsupported` naming the URL and the fix (use the ID or upgrade). Applies to every name resolution, including get-or-create. Effort S, risk low; verified by fake-old-server tests (no exec/destroy is sent).
✅ A version mismatch fails loudly before any command touches a sandbox
✅ No extra request, and it also rejects wrong rows from a buggy server
❌ Users of an older server must use sandbox IDs until they upgrade
B) Version gate
The CLI reads the server version first and refuses name refs below the T2 release. Effort S, risk low; verified by version-gate tests.
✅ A clear "upgrade your server" message up front
✅ One cached version read per process
❌ Trusts any new server's response, and dev builds without a proper version string get wrongly refused or allowed
C) No check
Trust the 0-or-1 contract. Effort S, risk low, zero work.
✅ Nothing to build
✅ Correct against servers that have T2
❌ Against an older server, commands can hit or destroy the wrong sandbox

## Answered decision CF6 (CEO D13: A, Full launch observability)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Metrics for remote /mcp | pending (CF6) | none | expvar map `aerolvm_mcp`: calls by tool × outcome (`ok`, `tool_error`, `api_error`, `bad_request`, `unauthorized`) + latency sum/count by tool, exported through `CollectAerolVMExpvars` | same expvar map | none |
| Per-call log + trace | — | API route logs only | one structured log line per tool call (tool, sandbox_id, owner_ref, outcome, duration_ms; never arguments or outputs) + an OTEL span per tool call | same log line + span | none |
| Dashboard + alert + runbook | prime directive: dashboards, alerts, runbooks are launch scope | none | a "Remote MCP" panel row in setup/grafana (calls, error ratio, p95 latency by tool); a Prometheus alert when the error ratio is over 20% for 10m; setup/runbooks/remote-mcp.md (auth failures, 5xx spike, slow tools, turning `SB_MCP_ENABLED` off) | none | none |
| Stdio MCP / CLI | §5.3 | logs to stderr, `--debug` | unchanged (local, no telemetry) | unchanged | unchanged |
| Tests | — | — | handler test: one tool call increments the right counter and emits one log line without arguments | same | none |
| Effort / risk | — | — | M / low | S / low | S / low |
| CF1–CF3, CF5, C1–C6, eng R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D13 — CF6: What observability should the remote MCP endpoint ship with?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review Section 8; C1 added the remote `/mcp`.
ELI10: The remote endpoint you added runs inside sandboxd, but the plan gives it no metrics, no per-call log and no dashboard. If agents start failing through it, an operator can see API requests but not which MCP tool failed, for which sandbox, or how slow it was. The repo already exports expvar metrics, OTEL traces and Grafana dashboards (internal/observability, setup/grafana), so the endpoint can plug into those: counters and latency per tool, one log line per call (never the command text or output), a dashboard panel, an alert and a runbook.
Stakes: without it, the first remote-MCP incident is debugged from generic API logs, with no way to tell which tool or sandbox is failing.
Recommendation: A because dashboards, alerts and runbooks are launch scope for a new server endpoint, and every piece reuses an existing seam.
Completeness: A=10/10, B=7/10, C=3/10
Header: CF6 observ
A) Full launch observability (recommended)
expvar `aerolvm_mcp` (calls by tool × outcome, latency by tool) via `CollectAerolVMExpvars`; one structured log line + OTEL span per tool call (tool, sandbox_id, owner_ref, outcome, duration_ms; never args/outputs); a Grafana "Remote MCP" panel row, a Prometheus alert at >20% errors for 10m, and setup/runbooks/remote-mcp.md. Effort M, risk low; verified by a handler test of counter + log line.
✅ Operators see which tool, sandbox and tenant is failing or slow from day one
✅ Reuses expvar, OTEL, Grafana and the runbook folder already in the repo
❌ More launch work: a panel, an alert and a runbook to keep current
B) Metrics and logs only
The same expvar map, log line and span, with no dashboard, alert or runbook. Effort S, risk low; verified by the same handler test.
✅ The data exists for anyone who goes looking
✅ Less to maintain than A
❌ Nobody is alerted, and there's no runbook for the first incident
C) Nothing new
Rely on existing API route logs and traces. Effort S, risk low, zero work.
✅ No new code or dashboards
✅ The in-process API calls are already logged per route
❌ No way to tell which MCP tool or sandbox is failing

## Answered decision CF7 (CEO D14: A, Reuse the index name)
Commitment comparison:

| Commitment | Source/approval or pending | Current | A | B | C |
|---|---|---|---|---|---|
| Name of the per-owner unique index (T2b, D4) | pending (CF7); D4 approved the (owner_ref, name) index without naming it | unspecified | keep the name `idx_sandboxes_name`. A startup migration reads its definition from `sqlite_master`; if it is still the global `(name)` form, it drops and recreates `idx_sandboxes_name ON sandboxes(owner_ref, name) WHERE name <> ''` in one transaction. An older binary's `CREATE UNIQUE INDEX IF NOT EXISTS idx_sandboxes_name …` is then a no-op, so it still boots | new index name; release notes say downgrading below the T2b release is unsupported once tenants share a name | new index name, no note |
| Downgraded binary | — | — | boots. Its name lookup may pick another tenant's row, which owner scoping turns into a 404; documented as degraded behaviour | fails to boot once duplicates exist ("run schema statement") | fails to boot, undocumented |
| Tests | — | — | store: migrate an old DB → index definition contains owner_ref; two owners with the same name; then run the OLD schema statement list against that DB and assert the open succeeds | migration test only | migration test only |
| Effort / risk | — | — | S / low | S / low | S / low |
| D4 (approved) | approved | (owner_ref, name) per-owner uniqueness | unchanged | unchanged | unchanged |
| CF1–CF6, C1–C6, eng R1–R16 | approved | unchanged | unchanged | unchanged | unchanged |

Question: D14 — CF7: How should T2b's new name index stay safe if an operator rolls back to an older release?
Project: plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578), CEO review Section 9; D4 made names unique per owner.
ELI10: On startup the store runs a list of "create index if it doesn't exist" statements and refuses to start if any fails (internal/store/store.go:691). Today's list includes the global "names are unique" index (store.go:377). T2b replaces it with a per-owner index. If the new index gets a new name, an operator who rolls back to the previous release starts the old binary, which tries to create the global index again. Once two tenants share a name, that fails and the daemon won't boot. If the new index keeps the old name, the old binary sees the index already exists, skips it, and starts.
Stakes: the standard "roll back the release" move during an incident would leave the node down until someone hand-edits SQLite.
Recommendation: A because reusing the index name costs a small migration and keeps rollback a one-step operation.
Completeness: A=10/10, B=6/10, C=2/10
Header: CF7 rollback
A) Reuse the index name (recommended)
Keep `idx_sandboxes_name`. A startup migration reads its definition from sqlite_master and, if it's still the global form, drops and recreates it as (owner_ref, name) WHERE name <> '' in one transaction. An older binary then skips it and boots. Effort S, risk low; verified by a store test that runs the old schema list against a migrated DB with duplicate names.
✅ Rolling back the release still boots the daemon
✅ No operator action needed during an incident
❌ A downgraded node's name lookup can 404 for one of two same-named tenants until re-upgraded
B) New name, document no-downgrade
Create the per-owner index under a new name and state in release notes that downgrading below the T2b release is unsupported once tenants share a name. Effort S, risk low; verified by a migration test.
✅ A clean, self-describing index name
✅ The limitation is written down
❌ Rollback during an incident can leave a node unable to boot
C) New name, no note
Create the per-owner index under a new name with no rollback guidance. Effort S, risk low.
✅ Simplest migration
✅ No release-note work
❌ A rollback can brick boot with no warning

## CEO review body (/plan-ceo-review, 2026-10-04)

### NOT in scope (CEO review)
- Deferred this review: none.
- Rejected this review: none.
- Not proposed (available on request): `aerolvm mcp doctor`; file reads
  returned as MCP resources; an in-sandbox `llm.txt`; running Claude Code
  inside an AerolVM sandbox.
- Still out of scope from the eng review: the `code` and `lifecycle` MCP
  toolsets (eng D1, D2); OAuth for claude.ai/ChatGPT connectors (Phase 4); the
  rest of §10.

### What already exists (additions to the eng review list)
- `internal/observability` (expvar `CollectAerolVMExpvars`, OTEL `trace.go`),
  `setup/grafana` d1–d11 and `setup/runbooks/`: reused for CF6.
- The `pkg/controlplane` `Admitter` (per-owner create admission; a no-op in
  open source): the remote endpoint's only server-side create brake. That
  gap is why CF2 makes remote pinned-only.
- Sessions (`/sessions`): the supported home for long-running work, unaffected
  by CF3.
- `CreateSandboxRequest.Tags` and list tag filters: carry the C6 provenance tag.

### Dream state delta
```
  12-MONTH IDEAL                                  AFTER THIS PLAN
  any agent, local or hosted, one step       ->   local (CLI, stdio, plugin) and remote clients that take a
                                                  bearer header; claude.ai/ChatGPT still need Phase 4 OAuth
  listed where agents look                   ->   Claude Code plugin (C2) + MCP Registry via npm (C3)
  progressive disclosure                     ->   plugin skill (C2); tools/list stays small (toolsets)
  agent sandboxes capped and attributable    ->   C4 cap (stdio), pinned-only remote (CF2), provenance tag
                                                  (C6), per-tool metrics (CF6)
  self-hosters get the same                  ->   yes: every piece runs against a self-hosted sandboxd
```
Remaining gap to the ideal: OAuth for hosted connectors (Phase 4), and the
on-request items.

### Error & Rescue Registry
| Codepath | Failure | Class | Rescued | Action | User sees |
|---|---|---|---|---|---|
| agenttools.resolve | old server ignores `?name=` | server_unsupported | Y (CF5) | reject unless ≤1 row with a matching name | "sandboxd … does not support name lookup; use the ID or upgrade" |
| agenttools.resolve | not found | not_found | Y | isError + next-step hint | actionable |
| agenttools.getOrCreate | 409 / lost reply | conflict / transport | Y (D4/D5) | GET by name → same sandbox | transparent |
| agenttools.exec (stream) | client cancelled or died | ctx canceled / WS drop | Y (CF3) | KILL on cancel; toolboxd kills the group on drop | exit 125/124; no orphan |
| agenttools.exec (WASM) | body > 4 MiB | output_too_large | Y (D10) | error suggesting a redirect | actionable |
| agentmcp create cap | 6th create | create_limit | Y (C4) | isError naming `--max-creates` | actionable |
| agentmcp pinned | gone / stopped | recreated / start | Y (D6/D7) | recreate + notice / Start | notice or start delay |
| sandboxd `/mcp` | bad Origin / param / missing `sandbox=` / bad token | 403 / 400 / 400 / 401 | Y (§5.7, CF1, CF2) | HTTP error naming the cause | client error |
| `/mcp` tool call | any outcome | — | Y (CF6) | counter + log line + span | visible on the panel and alert |
| T2 `?name=` (cluster) | control plane unavailable | 503 | Y | retryable mapping | retry hint |
| T2b decode | legacy name already starting `owner:` | decode | Y (required proof) | fall back to the plain name | none |
| store migration | downgrade after T2b | schema statement | Y (CF7) | index name reused; old statement is a no-op | node boots |
| release `mcp-publisher` | registry or auth failure | step failure | Y (C3) | step fails after assets publish | red workflow; release stays up |
| plugin CI | skill names a removed verb | CI failure | Y (C2) | PR blocked | red CI |

### Failure Modes Registry
```
  CODEPATH              | FAILURE MODE                  | RESCUED? | TEST? | USER SEES?            | LOGGED?
  ----------------------|-------------------------------|----------|-------|-----------------------|--------
  resolve (CF5)         | old server, full page         | Y        | Y     | server_unsupported    | Y (stderr/isError)
  exec stream (CF3)     | client death mid-command      | Y        | Y     | process killed        | Y (toolboxd)
  remote /mcp (CF2)     | unpinned request              | Y        | Y     | 400                   | Y (CF6)
  remote /mcp (CF6)     | tool error spike              | Y        | Y     | alert >20%/10m        | Y
  store (CF7)           | rollback with dup names       | Y        | Y     | node boots            | n/a
  T2b decode            | legacy "owner:" name          | Y        | Y     | plain name            | n/a
  create cap (C4)       | runaway loop (stdio)          | Y        | Y     | create_limit          | Y
  publish (C3)          | registry down                 | Y        | Y     | red release step      | Y (CI)
```
CRITICAL GAPS: 0. CF5 was one and is now rescued and tested.

### Scope Expansion Decisions
CEO summary: ~/.gstack/projects/aerol-ai-microvm/ceo-plans/2026-10-04-mcp-server-and-agent-cli.md
- Accepted: C1 bearer remote `/mcp` (Phase 2b), C2 Claude Code plugin, C3 MCP
  Registry entry, C4 5-create cap, C5 ROADMAP bullet, C6 provenance tag.
- Deferred: none.
- Skipped: none.

### Diagrams
1. **System architecture.** This supersedes the eng-review component flow,
   which predates the remote endpoint. Updated for eng re-review D1, where the
   remote handler is its own `pkg/api` package.
```
  shell (Claude Code, Codex, CI)   local MCP client (+ Claude Code plugin, C2)   remote MCP client (bearer)
          │ aerolvm <verb>                 │ stdio: aerolvm mcp                     │ POST /mcp?sandbox=…  (CF1/CF2)
          ▼                                ▼                                        ▼
     cmd/aerolvm ───────────────► internal/agentmcp ◄──────────────── pkg/api/<mcp> handler (re-review D1)
          │                (toolsets, pinned, cap C4,          Origin/Host check · SB_MCP_ENABLED · metrics CF6
          │                 isolate D11, notices D6/RR2,       in-process RoundTripper via io.Pipe
          │                 shared Options.Validate CF1)                │
          ▼                                ▼                            ▼
     internal/agenttools: resolve-by-shape D12 + verify CF5 · getOrCreate D4/D5 + tag C6
                          exec stream|buffered D10 + KILL on cancel CF3 · file streams D14
          │ Go SDK (+WithLimit, +File*Stream)
          ▼
   sandboxd /v1 ── auth ── clusterForwardWrap ──► owner ── toolbox proxy ──► toolboxd (ping 30s RR1,
       │ ?name= (T2)                                                         kill on drop CF3)
       └─► store idx_sandboxes_name (owner_ref,name) CF7 | FSM nameIndex owner-qualified key D9
```
2. **Data flow with shadow paths:**
```
  ref ─► shape router (D12) ─► id ─► GET /sandboxes/{id} ─────────────────────► sandbox
                           └─► name ─► GET ?name= ─► verify rows (CF5) ─┬─ 1 match ─► sandbox
                                                                       ├─ 0 rows ──► not_found / create (D5, tag C6, cap C4)
                                                                       └─ else ────► server_unsupported (no action sent)
```
3. **State machine (pinned sandbox, stdio or remote per request):**
```
  [resolve] ─► started ─► [run tool]
      │──────► stopped ─► Start (D7) ─► [run tool]
      │──────► 404 + create_if_missing ─► get-or-create ─► [run tool] (+ sandbox_recreated after a prior success, D6)
      └──────► 404 otherwise ─► isError
  remote: no sandbox= ─► 400 (CF2)      invalid param ─► 400 (CF1)
```
4. **Error flow (exec cancel, CF3):**
```
  client cancel ─► agenttools sends KILL ─► close WS
  client dies   ─────────────────────────► WS drops ─► toolboxd kills process group ─► no orphan
```
5. **Deployment sequence:**
```
  T1/T2 server (per-owner names, ?name=, CF7 migration) ─► toolboxd (CF3) in images
  ─► CLI + stdio MCP (Phases 1–2) ─► /mcp behind SB_MCP_ENABLED (2b) ─► npm + registry (Phase 3)
```
6. **Rollback flowchart:**
```
  /mcp misbehaves ─► SB_MCP_ENABLED=false ─► restart (no data change)
  CLI bug ─► install the previous aerolvm binary
  server bug after T2b ─► old binary boots (CF7); name lookups may 404 for one of two same-named tenants;
                          FSM keys stay deterministic (D9)
  toolboxd bug ─► previous image/template
```

### Stale Diagram Audit
- The eng-review "Component flow" diagram in this file predates C1 and doesn't
  show `/mcp`. The CEO Section 1 diagram supersedes it.
- DESIGN.md (actors and actions; a table, not ASCII) has no action for remote
  MCP. Update it with the C1 task.

## Implementation Tasks (CEO review)
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship. These add
to the eng review's T1–T10.

- [ ] **CT1 (P1, human: ~1 week / CC: ~2h)**: server: remote `/mcp` Phase 2b with URL options, pinned-only and launch observability
  - Surfaced by: C1 (D2), CF1 (D9), CF2 (D10), CF6 (D13)
  - Files: pkg/api (new mcp route + handler), internal/agentmcp, internal/observability, setup/grafana, setup/prometheus (alert), setup/runbooks/remote-mcp.md, DESIGN.md
  - Verify: handler tests (params → config, 400s, tools/list without fleet tools, counter + log line); integration UC on cluster-3-mixed from a non-owner node
- [ ] **CT2 (P1, human: ~1 day / CC: ~30min)**: toolboxd + agenttools: kill on stream drop; KILL on cancel
  - Surfaced by: CF3 (D11)
  - Files: cmd/toolboxd/exec_stream.go, internal/agenttools/exec.go
  - Verify: toolboxd drop test (`sleep 300`, process group gone within 2s); agenttools cancel test
- [ ] **CT3 (P1, human: ~2h / CC: ~10min)**: agenttools: verify `?name=` results
  - Surfaced by: CF5 (D12)
  - Files: internal/agenttools/resolve.go
  - Verify: fake-old-server tests (3 rows → server_unsupported, no follow-up call)
- [ ] **CT4 (P1, human: ~3h / CC: ~15min)**: store: per-owner index keeps the name `idx_sandboxes_name`; in-place migration
  - Surfaced by: CF7 (D14)
  - Files: internal/store/store.go
  - Verify: store test runs the OLD schema list against a migrated DB with cross-owner duplicates and the open succeeds
- [ ] **CT5 (P2, human: ~2h / CC: ~10min)**: agentmcp: 5-create cap for unpinned stdio
  - Surfaced by: C4 (D5)
  - Files: internal/agentmcp, cmd/aerolvm (flag)
  - Verify: agentmcp cap tests
- [ ] **CT6 (P2, human: ~1h / CC: ~5min)**: agenttools: provenance tag on create
  - Surfaced by: C6 (D7)
  - Files: internal/agenttools/create.go
  - Verify: agenttools tag test
- [ ] **CT7 (P2, human: ~3h / CC: ~15min)**: packaging: Claude Code plugin + skill + CI check
  - Surfaced by: C2 (D3)
  - Files: .claude-plugin/marketplace.json, plugins/aerolvm/, .github/workflows (check)
  - Verify: the CI check parses the manifests and fails on an unknown verb
- [ ] **CT8 (P2, human: ~2h / CC: ~10min)**: release: MCP Registry entry in Phase 3
  - Surfaced by: C3 (D4)
  - Files: server.json, .github/workflows/release.yml
  - Verify: `mcp-publisher validate` in CI
- [ ] **CT9 (P2, human: ~15min / CC: ~2min)**: docs: ROADMAP.md bullet
  - Surfaced by: C5 (D6)
  - Files: ROADMAP.md
  - Verify: review
- [ ] **CT10 (P2, human: ~1h / CC: ~5min)**: cluster/service: decode fallback for legacy `owner:` names
  - Surfaced by: Section 2 registry (required proof of D9)
  - Files: internal/cluster (decode helper), internal/service/service.go (`RecreateSandbox` decode choke point)
  - Verify: unit test: a malformed `owner:` name decodes to itself

### Unresolved Decisions
None. Every CEO-review question (D1–D14) has an answer.

### Completion Summary
```
  +====================================================================+
  |            MEGA PLAN REVIEW — COMPLETION SUMMARY                   |
  +====================================================================+
  | Mode selected        | SELECTIVE EXPANSION                         |
  | System Audit         | ROADMAP lacks agent interface; old servers  |
  |                      | ignore ?name=; exec stream orphans procs;   |
  |                      | index migration aborts boot on failure      |
  | Step 0               | SELECTIVE EXPANSION; C1–C6 accepted         |
  | Section 1  (Arch)    | 2 issues found (CF1, CF2)                   |
  | Section 2  (Errors)  | 14 error paths mapped, 2 GAPS (CF3; D9 proof)|
  | Section 3  (Security)| 9 threats reviewed, 0 High unmitigated      |
  | Section 4  (Data/UX) | 6 edge cases mapped, 1 unhandled (CF5)      |
  | Section 5  (Quality) | 0 issues found (2 notes)                    |
  | Section 6  (Tests)   | Diagram produced, 2 gaps (required proofs)  |
  | Section 7  (Perf)    | 0 issues found                              |
  | Section 8  (Observ)  | 1 gap found (CF6)                           |
  | Section 9  (Deploy)  | 1 risk flagged (CF7)                        |
  | Section 10 (Future)  | Reversibility: 3–5/5, debt items: 3         |
  | Section 11 (Design)  | SKIPPED (no UI scope)                       |
  +--------------------------------------------------------------------+
  | NOT in scope         | written (4 not-proposed items)              |
  | What already exists  | written                                     |
  | Dream state delta    | written                                     |
  | Error/rescue registry| 14 rows, 0 CRITICAL GAPS                    |
  | Failure modes        | 8 total, 0 CRITICAL GAPS                    |
  | TODOS.md updates     | 0 items proposed                            |
  | Scope proposals      | 6 proposed, 6 accepted (SEL)                |
  | CEO plan             | written                                     |
  | Outside voice        | codex, unavailable (probe module missing)   |
  | Lake Score           | 4/4 recommendations chose complete option   |
  | Diagrams produced    | 6 (arch, data flow, state, error, deploy,   |
  |                      | rollback)                                   |
  | Stale diagrams found | 2 (eng component flow, DESIGN.md actions)   |
  | Unresolved decisions | 0                                           |
  +====================================================================+
```

## Eng re-review record (/plan-eng-review, 2026-10-04, after the CEO review)

**Target:** `plans/mcp-server-and-agent-cli.md` (this file), PR #578. Scope
under review: everything the CEO review added (C1–C6, CF1–CF3, CF5–CF7). The
eng D1–D21 decisions stand unless reopened here with new evidence.

### Scope record (re-review)
feature answers: no cuts proposed; the CEO additions were accepted minutes
earlier and no new evidence argues against them. structure: A, original
arrangement (re-review D1): the remote `/mcp` handler gets its own package under
`pkg/api`, which calls `internal/agentmcp` for the registry. accepted scope:
the plan as amended by the CEO review. pending remedies: none at scope time.

Scope Challenge result: scope accepted as-is.

### Factual corrections (no behaviour change)
- **Toolboxd delivery (§5.5, CF3 note).** Toolboxd is not shipped "with
  images". containerd/docker/gVisor bind-mount it read-only from the host's
  `SB_TOOLBOX_BINARY_PATH` (internal/runtime/containerd/lifecycle.go:613). A
  host upgrade therefore reaches every new sandbox, while running sandboxes
  keep the old process until restart. Firecracker injects it at cold boot
  (internal/runtime/firecracker/coldboot_agent.go), and existing snapshots
  and templates keep the old copy until they are rebuilt.
- **Origin validation (§5.7).** Since go-sdk v1.4.0 (CVE-2026-34742),
  DNS-rebinding protection is automatic only for localhost binds. sandboxd
  binds a public interface, so the explicit `Origin`/`Host` check in §5.7
  stays. Use go-sdk's allowed-hosts and allowed-origins options rather than
  custom code [Layer 1].
- **Stale comment.** cmd/toolboxd/exec_stream.go:88 says "the read pump uses
  pong handling for liveness", but no ping or pong handling exists in toolboxd,
  the SDK or the API. See finding RR1.

## Decision ledger (re-review)

### RR1: keepalive for exec streams now that a drop kills the command
Finding: Section 1 (re-review), P1, confidence 7/10. cmd/toolboxd/exec_stream.go:88-89 (`// Future reads: no deadline; the read pump uses pong handling for liveness.` / `_ = conn.SetReadDeadline(time.Time{})`); no `SetPongHandler`, `PingMessage` or `WriteControl` in cmd/toolboxd, sdk/go/internal/apiclient or pkg/api/v1. pkg/daemon/daemon.go:928-932 sets only `IdleTimeout: 2 * time.Minute`, which doesn't apply to hijacked WebSockets. Reviewer: Claude (plan-eng-review, re-review).
Plan baseline: CEO CF3 (D11: B) approved: "toolboxd kills the command's process group when the WebSocket closes or errors before the exit message". No keepalive is specified.
Runtime evidence: there's no keepalive on exec streams today. Intermediaries in front of `/v1` (ingress proxy, cloud load balancers, CDN proxies) commonly close idle WebSockets after ~60–100s. Which ones sit in front of a given deployment is unknown. Under CF3, an idle close of a silent long command kills the command. Before CF3, the command kept running.
Comparison grid:

| Choice | Current | A | B | C |
|---|---|---|---|---|
| RR1 exec-stream liveness | none | toolboxd sends a WebSocket ping every 30s on exec streams; gorilla clients answer pongs by default; read deadline = 90s, extended on every pong or message; kill-on-drop fires only on close, read error or deadline expiry | none; CF3 as approved; docs warn that idle proxies can end silent commands | toolboxd kills on drop only when the start message sets `kill_on_disconnect: true` (agenttools sets it); other SDK callers keep today's behaviour |
| CF3 coverage | approved: every exec-stream caller | unchanged | unchanged | narrowed to aerolvm CLI/MCP (reopens CF3) |
| Silent 10-minute command behind a 60s idle proxy | output lost; process orphaned | runs to completion; pings keep the path alive | killed at ~60s | CLI/MCP: killed at ~60s; other SDKs: orphaned |
| Stale comment at exec_stream.go:88 | wrong | made true by the implementation | corrected to say there's no liveness check | corrected |
| Tests | — | toolboxd: a silent `sleep 120` with a fake 60s-idle proxy completes; with pongs suppressed, the process is killed after the 90s deadline | none | toolboxd: flag on → kill on drop; flag off → no kill |
| Effort / risk | — | S / low | S / low | S / low |
| CF3 and the other approved rows | approved | unchanged | unchanged | CF3 narrowed |

Question D2:
D2 — RR1: Exec streams have no keepalive; now that a dropped stream kills the command, what keeps long silent commands alive?
Project/branch/task: eng re-review of plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); the CEO review approved kill-on-drop (CF3).
ELI10: CF3 makes the sandbox agent kill a command when its live connection drops, so cancelled commands don't linger. But nothing on that connection ever sends a keepalive (cmd/toolboxd/exec_stream.go:88 claims a pong check that doesn't exist). Proxies and load balancers often close a connection that has been quiet for about a minute. So a command that prints nothing for a while, like `sleep 600 && make`, would get its connection closed by a proxy and then killed by CF3. A ping every 30 seconds keeps the path open and still lets a real drop be detected within 90 seconds.
Stakes: without a keepalive, CF3 turns proxy idle timeouts into killed builds and tests that look like random agent failures.
Recommendation: A because it keeps CF3's protection and stops idle proxies from killing healthy long commands, for a few lines in toolboxd.
Completeness: A=10/10, B=4/10, C=6/10
Header: RR1 keepalive
Options:
A) Ping every 30s (recommended)
toolboxd sends a WebSocket ping every 30s on exec streams (gorilla clients auto-pong); the read deadline is 90s and extends on every pong or message; kill-on-drop fires only on close, read error or deadline expiry. Fixes the stale comment. Tests: a silent `sleep 120` behind a fake 60s-idle proxy completes; with pongs suppressed, the process dies after the deadline. Human ~3h / CC ~15 min.
B) No keepalive, document
Keep CF3 as approved with no pings; docs warn that idle proxies can end silent commands and suggest sessions for long work. Correct the stale comment. Human ~30 min / CC ~5 min.
C) Kill-on-drop opt-in
toolboxd kills on drop only when the start message sets `kill_on_disconnect: true` (agenttools sets it); other SDK callers keep today's behaviour. Narrows CF3. Tests: flag on/off. Human ~2h / CC ~10 min.

State: approved
Actual answer: A) Ping every 30s (user answer to re-review D2, 2026-10-04)
Accepted scope: toolboxd sends a WebSocket ping every 30s on exec streams (gorilla clients auto-pong); the read deadline is 90s and extends on every pong or message; kill-on-drop (CF3) fires only on close, read error or deadline expiry. The stale comment at exec_stream.go:88 is fixed by the implementation. Tests: a silent `sleep 120` behind a fake 60s-idle proxy completes; with pongs suppressed, the process dies after the deadline.
History: none

### RR2: telling the model about a fresh sandbox on the stateless remote endpoint
Finding: Section 1 (re-review), P2, confidence 8/10. Eng D6 accepted scope: "on a 404 for the pinned sandbox after an earlier successful call, drop the cached ID, recreate by name, and return `sandbox_recreated: true`". Remote `/mcp` is stateless (§5.7) and pinned-only (CF2), so no process remembers an earlier call. Reviewer: Claude (plan-eng-review, re-review).
Plan baseline: D6 covers stdio. For remote `create_if_missing` (CF1), nothing is said about notices.
Runtime evidence: under D7, an idle remote-pinned sandbox is destroyed after 24h. The next remote call creates a new empty one through get-or-create (D4/D5), and the model isn't told.
Comparison grid:

| Choice | Current | A | B |
|---|---|---|---|
| RR2 remote lazy create notice | silent | every remote lazy create returns `sandbox_created: true` plus a one-line notice: "this is a newly created sandbox; files from any earlier session are not present" | silent (as now) |
| First-ever remote call | silent | also carries the notice (harmless; it's true) | silent |
| Stdio D6 | approved | unchanged | unchanged |
| Tests | — | /mcp handler: a `create_if_missing` call that creates → result has `sandbox_created: true` and the notice; a call on an existing sandbox → no flag | none |
| Effort / risk | — | S / low | S / low |
| RR1 (approved), CEO rows, eng R1–R16 | approved | unchanged | unchanged |

Question D3:
D3 — RR2: The remote endpoint can't tell a first call from a recreate; should it announce every new sandbox it creates?
Project/branch/task: eng re-review of plans/mcp-server-and-agent-cli.md on feat/mcp-server-agent-cli-plan (PR #578); D6 added a recreate notice for the local server.
ELI10: Locally, the MCP server remembers it already made a sandbox, so if that sandbox disappears it can tell the model "this is a fresh one; your old files are gone" (D6). The remote endpoint keeps no memory between requests, so it can't tell a first call from a recreate after the 24-hour idle cleanup. It would silently hand the model an empty sandbox. The simple fix is to announce every sandbox the remote endpoint creates, which is always true and covers the recreate case.
Stakes: a remote agent that comes back the next day gets an empty sandbox, assumes its files are there, and wastes turns debugging.
Recommendation: A because it is the only stateless way to give remote users D6's protection, and the notice is accurate even on the first call.
Completeness: A=10/10, B=4/10
Header: RR2 notice
Options:
A) Announce every remote create (recommended)
Every remote lazy create returns `sandbox_created: true` plus "this is a newly created sandbox; files from any earlier session are not present". Calls on an existing sandbox carry no flag. Test in the /mcp handler. Human ~1h / CC ~5 min.
B) Keep remote silent
Remote creates stay silent; only stdio has D6's notice. Document the difference. No work.

State: approved
Actual answer: A) Announce every remote create (user answer to re-review D3, 2026-10-04)
Accepted scope: every remote lazy create returns `sandbox_created: true` plus "this is a newly created sandbox; files from any earlier session are not present"; calls on an existing sandbox carry no flag; /mcp handler test.
History: none

Re-review approval readiness: PASS. Checked: structure D1 = A (original arrangement, separate `pkg/api` package); RR1 (D2 A); RR2 (D3 A). Factual corrections (toolboxd delivery, go-sdk Origin note, stale comment, missing architecture diagram) change no behaviour and need no approval. Required proofs added without a question carry forward approved behaviour: the Origin/Host check (§5.7) and `io.Pipe` streaming (C1 note); the shared `Options.Validate()` implements CF1's "same names and validation".

## Eng re-review body (/plan-eng-review, 2026-10-04)

### NOT in scope (re-review)
- Nothing deferred or rejected in this re-review.
- A remote-specific agent-eval task: not added. Remote shares the stdio tool
  registry, so the D13 eval covers the tool text.

### What already exists (reused by the re-review remedies)
- gorilla/websocket's default ping handler answers pings with pongs on every
  client that reads the stream (the SDK read loop does), so RR1 needs no client
  change.
- go-sdk's allowed-hosts and allowed-origins options handle the `/mcp`
  Origin/Host check [Layer 1].

### Failure modes (new rows)
| Path | Realistic failure | Covered by | User sees |
|---|---|---|---|
| exec stream behind an idle proxy | silent command for 10 min | RR1 pings + 90s deadline; test | command completes |
| exec stream, real drop | network gone | RR1 deadline → CF3 kill; test | exit 125; no orphan |
| remote pinned after 24h idle | sandbox destroyed and recreated | RR2 notice; test | model told files are gone |
| `/mcp` from a browser page | DNS-rebinding attempt | Origin/Host check; test | 403 |
| `/mcp` large tool output | body over 4 MiB | `io.Pipe` + limit; test | `output_too_large`; sandboxd memory bounded |

Critical gaps: **0**.

### Worktree parallelization strategy (whole plan, eng + CEO + re-review)

| Step | Modules touched | Depends on |
|------|----------------|------------|
| S1 per-owner names, `?name=`, index migration, decode (T1, T2, CT4, CT10) | internal/store, internal/service, internal/cluster, pkg/api/v1, pkg/api/daytona, pkg/models | — |
| S2 Go SDK (T3) | sdk/go | — |
| S3 tool layer (T4, T5, CT3, CT6) | internal/agenttools | S2 |
| S4 CLI (T7) + MCP stdio (T6, CT5) | cmd/aerolvm, internal/agentmcp | S3 |
| S5 remote `/mcp` (CT1, RR2) | pkg/api (new mcp package), internal/agentmcp, internal/observability, setup/ | S4 |
| S6 toolboxd keepalive + kill on drop (CT2, RR1) | cmd/toolboxd | — |
| S7 release, plugin, registry (plan T6, CT7, CT8) | .github/workflows, scripts, .claude-plugin, plugins/ | S4 |
| S8 docs, ROADMAP, CLAUDE.md exception (T10, CT9) | docs/, ROADMAP.md, CLAUDE.md | S4, S5 |
| S9 integration UCs, agent eval, required proofs (T8, T9) | integration-tests/, all new packages | S1, S5, S6 |

- Lane A: S1 (server).
- Lane B: S2 → S3 → S4 → S5 (agentmcp is shared with S4, so they run in
  sequence).
- Lane C: S6 (toolboxd, independent).
- Lane D: S7 after S4.
- Order: launch A + B + C together. Merge A and C. When B reaches S4, start D.
  Then S8 and S9.
- Conflicts: `sdk/go` is shared by S1 (list `name`) and S2; `internal/agentmcp`
  by S4 and S5.

## Implementation Tasks (eng re-review)
Synthesized from this review's findings. Each task derives from a specific
finding above. Run with Claude Code or Codex; checkbox as you ship. These add
to eng T1–T10 and CEO CT1–CT10.

- [ ] **RT1 (P1, human: ~3h / CC: ~15min)**: toolboxd: exec-stream keepalive (30s ping, 90s deadline) under kill-on-drop
  - Surfaced by: Section 1 RR1 (re-review D2)
  - Files: cmd/toolboxd/exec_stream.go
  - Verify: silent `sleep 120` behind a fake 60s-idle proxy completes; with pongs suppressed, killed after the deadline
- [ ] **RT2 (P2, human: ~1h / CC: ~5min)**: remote MCP: announce every lazy create (`sandbox_created`)
  - Surfaced by: Section 1 RR2 (re-review D3)
  - Files: pkg/api (mcp package), internal/agentmcp
  - Verify: /mcp handler test (create → flag + notice; existing → no flag)
- [ ] **RT3 (P2, human: ~2h / CC: ~10min)**: remote MCP required proofs: Origin/Host and `io.Pipe` streaming tests
  - Surfaced by: Section 3 (required proof of §5.7 and the C1 note)
  - Files: pkg/api (mcp package) tests
  - Verify: bad Origin → 403, no Origin → allowed; headers arrive before the handler finishes; a body over 4 MiB is never fully buffered
- [ ] **RT4 (P2, human: ~1h / CC: ~5min)**: agentmcp: one `Options.Validate()` shared by stdio flags and remote query params
  - Surfaced by: Section 2 (required by CF1 under re-review D1)
  - Files: internal/agentmcp, cmd/aerolvm, pkg/api (mcp package)
  - Verify: a table test where the same input gives the same result through both parsers

### Unresolved decisions
None. Re-review D1–D3 are all answered.

### Completion summary
- Step 0: Scope Challenge: scope accepted as-is (no cuts; structure D1 = original arrangement); 3 factual corrections
- Architecture Review: 2 issues found (RR1, RR2)
- Code Quality Review: 1 issue found (missing architecture diagram, fixed)
- Test Review: diagram produced, 2 gaps identified (Origin and `io.Pipe` required proofs, added)
- Performance Review: 0 issues found
- NOT in scope: written
- What already exists: written
- TODOS.md updates: 0 items proposed to user
- Failure modes: 0 critical gaps flagged
- Unresolved decisions: 0 in this review
- Outside voice: codex, unavailable (gstack probe can't load its resolver module; no native fallback without a TaskOutput tool)
- Parallelization: 4 lanes, 3 parallel at launch / 2 sequential follow-on steps
- Lake Score: 2/2

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 1 | CLEAR | 6 proposals, 6 accepted, 0 deferred |
| Outside Review | codex via `/plan-eng-review` (×2) and `/plan-ceo-review` | Independent 2nd opinion | 3 | unavailable | preflight model_unusable every time (gstack probe can't load its resolver module); no completed external review |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 2 | ISSUES OPEN | 5 issues, 0 critical gaps (re-review of the CEO additions; all resolved in D1–D3) |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |
| DX Review | `/plan-devex-review` | Developer experience gaps | 0 | — | — |

- **OUTSIDE COVERAGE:** codex, plan-review phase, unavailable on all three attempts: eng (2026-10-03T23:08Z), CEO (2026-10-04T00:07Z) and the eng re-review (2026-10-04T00:36Z). The gstack probe fails with `Module not found "/../scripts/resolve-codex-generation-model.ts"`, and no native fallback ran because there's no TaskOutput tool. This is missing coverage, not a clean result.
- **VERDICT:** CEO CLEARED. Eng Review is not CLEAR: the re-review found 5 issues, all now resolved and covering the CEO additions, so the log records issues_open; eng review required. A further eng pass that finds nothing would clear it.

NO UNRESOLVED DECISIONS
