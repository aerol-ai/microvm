# Agent eval for the aerolvm MCP tools

Checks that Claude can actually use the tools `aerolvm mcp` offers. A unit
test proves a tool works when called correctly; this proves a model calls it
correctly from its name, description and notices alone.

Run it before you change a tool name, a tool description or a notice's
wording, and before a release. It calls the Anthropic API, so it is never part
of `make test` or CI.

## Tasks

Each task checks the sandbox afterwards, not only what the model answered.

1. **Create and exec:** create a named sandbox, run a command, report the
   output.
2. **Write then read:** write a file in a pinned sandbox and read it back.
3. **Dev server:** start a server that keeps running with `start_process`,
   publish it with `expose_port`, and fetch it. Without a reachable URL (a
   local install with no domain), the harness checks the server from inside
   the sandbox.
4. **Recover after a recreate:** the harness destroys the pinned sandbox
   between two turns. The next tool result must carry the recreate notice,
   and the model must say so and restore the file.
5. **Exec on WASM:** WASM has no streaming exec. Skipped unless
   `AEROLVM_EVAL_WASM_IMAGE` names a module the sandboxd can run.

## Run

Point it at a local single-node sandboxd ([Local Setup](../../docs/src/content/docs/getting-started/local-setup.md)):

```sh
export SB_API_URL=http://127.0.0.1:21212 SB_PAT_TOKEN=<token> ANTHROPIC_API_KEY=<key>
go test -tags=agenteval -count=1 -v ./integration-tests/agenteval/
```

| Variable | Default | Meaning |
|---|---|---|
| `AEROLVM_EVAL_MODEL` | `claude-opus-5-5` | Model to evaluate |
| `AEROLVM_EVAL_IMAGE` | `python:3.12-alpine` | Image for tasks 1-4 |
| `AEROLVM_EVAL_WASM_IMAGE` | unset | Module ref for task 5 |
| `AEROLVM_EVAL_WASM_COMMAND` | `echo hello-wasm` | Command for task 5 |
| `AEROLVM_EVAL_WASM_EXPECT` | `hello-wasm` | Text task 5's answer must contain |

The harness builds `aerolvm` from this checkout, so it grades the tool text
you are about to ship. `-v` prints every tool call and answer. Read the
transcripts as well as the verdict: a task that passed after five failed
calls means a description needs work.

`loop_test.go` checks the agent loop itself offline, against a scripted model
and the fake sandboxd, and does run in `make test`.
