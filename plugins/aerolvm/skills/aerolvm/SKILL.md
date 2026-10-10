---
name: aerolvm
description: Use when work should run in an isolated AerolVM sandbox instead of on this machine, such as untrusted or generated code, a different OS image or toolchain, a long-running dev server you need a public URL for, or a clean environment to reproduce a bug. Covers the aerolvm CLI and the aerolvm MCP tools.
---

# AerolVM sandboxes

An AerolVM sandbox is an isolated Linux machine (a container, gVisor, a
Firecracker microVM, or a WASM module) on the user's sandboxd. Reach for one
when a command should not run on this machine: code you did not write, a
toolchain or image this machine lacks, a server that needs a public URL, or a
clean environment.

The `aerolvm` MCP tools (sandbox_create, exec, read_file, ...) and the
`aerolvm` CLI do the same things. Use the MCP tools when they are available.
Use the CLI through Bash for what they don't cover: copying files to or from
this machine (`cp`) and streaming a long command's output.

## Core CLI verbs

```sh
aerolvm create --name build-box --image python:3.12 --destroy-if-idle 2h
aerolvm exec build-box -- pytest -q
aerolvm exec build-box --cwd /app --timeout 15m -- "npm ci && npm test"
aerolvm cp ./data.csv build-box:/work/data.csv
aerolvm cp build-box:/work/report.html ./report.html
aerolvm exec build-box --background -- npm run dev -- --port 3000
aerolvm expose build-box 3000
aerolvm destroy build-box
```

- `create` is safe to retry. It is keyed by `--name`, and a name that exists
  returns that sandbox instead of making another one.
- A sandbox is addressed by name or by ID (`sb-` plus 16 hex digits).
- `exec` exits with the command's own exit code: 124 on `--timeout`, 125 if
  aerolvm itself failed.
- `expose` prints the public URL, and repeating it returns the same URL.
- Destroy what you created when you are done with it. `stop` keeps the files.

## Habits that keep agents out of trouble

- Pass `--json` (or set `AEROLVM_OUTPUT=json`) to get one JSON document on
  stdout. Errors go to stderr as `{"error":{"code":...}}`.
- Pass `--no-stdin` to `exec` when your shell leaves stdin open. Otherwise a
  command that reads stdin waits until `--timeout`.
- Give `exec` one quoted string to run a shell pipeline:
  `aerolvm exec box -- "make test | tail -50"`.
- Run `aerolvm <verb> --help` for a verb's flags, examples and JSON shape.
  It is written for agents and is shorter than any docs page.
- If a command fails with `not logged in`, ask the user to run
  `aerolvm login` themselves; it asks for their API token, which you should
  not handle.
- `aerolvm shell <sandbox>` is for a person at a terminal and refuses to run
  without one. Use `exec` yourself; suggest `aerolvm shell build-box` when the
  user wants to look around inside a sandbox.

## Pinned MCP mode

`aerolvm mcp --sandbox NAME --create-if-missing` gives the model a single
sandbox. The sandbox argument disappears from every tool, the
create/list/destroy tools are not offered, and the sandbox is created on
first use. `aerolvm mcp config claude-code --sandbox NAME --create-if-missing`
prints the command that registers it.
