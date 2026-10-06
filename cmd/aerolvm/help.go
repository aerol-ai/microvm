package main

// Help is written for models first (§5.2 rule 9): short, one or two real
// examples per verb, and the JSON shape named. Keep it that way; agents read
// `aerolvm <verb> --help` instead of docs.

const overviewHead = `aerolvm drives AerolVM sandboxes from a shell or an AI agent.

Usage: aerolvm <command> [flags] [args]

Commands:
`

const overviewTail = `
Sandboxes are addressed as <id-or-name>: sb-<16 hex> is an ID, anything else
is a name (names are unique per account).

Environment:
  SB_API_URL       sandboxd URL (default http://127.0.0.1:21212)
  SB_PAT_TOKEN     API token (required)
  AEROLVM_OUTPUT   set to "json" to make --json the default

Output: stdout is data, stderr is everything else. With --json, errors are
{"error":{"code":"not_found","message":"...","http_status":404,"retryable":false}}
on stderr.

Exit codes: 0 ok, 1 error, 2 usage. exec returns the command's own code,
128+n if a signal killed it, 124 on --timeout, 125 if aerolvm itself failed.

Run "aerolvm <command> --help" for a command's flags and examples.
`

const createHelp = `Create a sandbox, or return the existing one with the same name.

Usage: aerolvm create [--name N] [--image I] [flags]

Create is safe to retry: it is keyed by name, and with no --name a name
(agent-<random>) is chosen before the first attempt. If the name exists,
that sandbox is returned and nothing is created.

Flags:
  --name N             sandbox name, unique in your account
  --image I            container image, or the module for --runtime wasm
  --runtime R          docker, gvisor, firecracker or wasm
  --cpu C              CPU cores (fractions allowed)
  --memory-mb M        memory in MiB
  --env K=V            environment variable (repeatable)
  --tag K=V            label (repeatable); aerolvm.created_by=cli is added
  --stop-if-idle D     stop after this long idle, e.g. 30m (files are kept)
  --destroy-if-idle D  destroy after this long idle, e.g. 24h
  --block-network      no outbound network
  --allow-host H       allow outbound to only these destinations (repeatable
                       or comma list): a host, *.domain, host:port or CIDR
  --json               print the sandbox as JSON, plus "created": true|false

Examples:
  aerolvm create --name build-box --image python:3.12 --destroy-if-idle 2h
  id=$(aerolvm create --image node:22 --json | jq -r .id)
  aerolvm create --image python:3.12 --allow-host pypi.org --allow-host '*.pythonhosted.org'
`

const listHelp = `List sandboxes, one page at a time.

Usage: aerolvm list [--tag K=V]... [--limit N] [--page-token T]

Flags:
  --tag K=V        only sandboxes with this label (repeatable, all must match)
  --limit N        rows per page (server default 100, max 500)
  --page-token T   continue from the token a previous page printed
  --json           print {"sandboxes":[...],"next_page_token":"..."}

Examples:
  aerolvm list --tag aerolvm.created_by=cli
  aerolvm list --limit 20 --json
`

const getHelp = `Show one sandbox.

Usage: aerolvm get <sandbox>

  --json   print the sandbox object

Example:
  aerolvm get build-box --json
`

const execHelp = `Run a command in a sandbox and stream its output.

Usage: aerolvm exec <sandbox> [flags] -- <command> [args...]

One argument after -- runs as a shell command line ("make test | tail");
several are quoted and joined. Exit code: the command's own, 128+n if a
signal killed it, 124 on --timeout, 125 if aerolvm itself failed.

Stdin is forwarded when it is not a terminal (echo x | aerolvm exec sb -- cat).
Some agent harnesses leave stdin open forever; pass --no-stdin there or a
command that reads stdin waits until --timeout. WASM sandboxes have no
streaming exec: stdin is not forwarded there and -i/-t are refused.

Flags:
  --cwd D          working directory
  --env K=V        environment variable (repeatable)
  --timeout D      kill the command after D (e.g. 10m) and exit 124
  -i               forward stdin even when it is a terminal
  --no-stdin       never forward stdin
  -t               allocate a terminal (only when stdout is a terminal)
  --background     start the command as a background session and print its
                   session ID; read its output with "aerolvm logs"
  --json           print {"exit_code","stdout","stderr",...} at the end
                   instead of streaming (output keeps its head and tail)

Examples:
  aerolvm exec build-box -- pytest -q
  aerolvm exec build-box --cwd /app --timeout 15m -- "npm ci && npm test"
  aerolvm exec build-box --background -- npm run dev
`

const logsHelp = `Print the output of a background command started with exec --background.

Usage: aerolvm logs <sandbox> <session-id> [--follow]

  --follow   keep printing until the command exits (Ctrl-C detaches;
             the command keeps running)

Example:
  aerolvm logs build-box ses-1 --follow
`

const cpHelp = `Copy a file between this machine and a sandbox.

Usage: aerolvm cp <src> <dst>

A sandbox path is <sandbox>:<path>. "-" is stdin (as src) or stdout (as dst).
Files stream; size doesn't matter. Directories are not supported yet (use
tar through exec).

Examples:
  aerolvm cp ./data.csv build-box:/work/data.csv
  aerolvm cp build-box:/work/report.html ./report.html
  aerolvm cp build-box:/var/log/app.log - | tail
`

const lsHelp = `List a directory in a sandbox.

Usage: aerolvm ls <sandbox>:<path>

  --json   print {"path","entries":[{"name","is_dir","size",...}]}

Example:
  aerolvm ls build-box:/work
`

const exposeHelp = `Publish a sandbox port and print its URL. Repeating it returns the same URL.

Usage: aerolvm expose <sandbox> <port> [--tcp]

  --tcp    raw TCP instead of HTTP; prints host:port
  --json   print {"protocol","public_url","host","host_port"}

Example:
  aerolvm exec build-box --background -- npm run dev -- --port 3000
  aerolvm expose build-box 3000
`

const startHelp = `Start stopped sandboxes.

Usage: aerolvm start <sandbox>...
`

const stopHelp = `Stop sandboxes. Files are kept; "aerolvm start" resumes them.

Usage: aerolvm stop <sandbox>...
`

const destroyHelp = `Destroy sandboxes. A sandbox that is already gone counts as destroyed.

Usage: aerolvm destroy <sandbox>...

There is no --all: name each sandbox.
`

const snapshotHelp = `Snapshot a sandbox's filesystem as an image other sandboxes can start from.

Usage: aerolvm snapshot <sandbox> <name>

Example:
  aerolvm snapshot build-box deps-installed
  aerolvm create --image deps-installed
`

const healthHelp = `Check that sandboxd is reachable and the token works.

Usage: aerolvm health [--json]
`

const versionHelp = `Print the aerolvm version.

Usage: aerolvm version [--json]
`
