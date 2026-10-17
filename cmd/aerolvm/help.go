package main

// Help is written for models first (§5.2 rule 9): short, one or two real
// examples per verb, and the JSON shape named. Keep it that way; agents read
// `aerolvm <verb> --help` instead of docs.

const overviewHead = `aerolvm drives AerolVM sandboxes from a terminal, a script or an AI agent.

Usage: aerolvm <command> [flags] [args]

Sign in once:              aerolvm login
Get a shell in a sandbox:  aerolvm shell <sandbox>
`

const overviewTail = `
Sandboxes are addressed as <id-or-name>: sb-<16 hex> is an ID, anything else
is a name (names are unique per account).

Environment (these override "aerolvm login"):
  SB_API_URL       sandboxd URL (default: your login, else http://127.0.0.1:21212)
  SB_PAT_TOKEN     API token (required unless you ran "aerolvm login")
  SB_API_TOKEN     the same as SB_PAT_TOKEN; SB_PAT_TOKEN wins if both are set
  SB_TEAM          the team to act for, when your sign-in has several
  AEROLVM_OUTPUT   set to "json" to make --json the default

Output: stdout is data, stderr is everything else. With --json, errors are
{"error":{"code":"not_found","message":"...","http_status":404,"retryable":false}}
on stderr.

Exit codes: 0 ok, 1 error, 2 usage. exec and shell return the remote
command's own code (128+n if a signal killed it) and 125 if aerolvm itself
failed; exec returns 124 on --timeout.

Run "aerolvm <command> --help" for a command's flags and examples.
`

const shellHelp = `Open an interactive shell in a sandbox.

Usage: aerolvm shell [<sandbox>] [--session NAME | --new]

You get a login shell (bash, or sh when the image has no bash). It keeps
running when you leave without exiting: Ctrl-] detaches, and so does
closing the terminal or losing the network. Run the same command again to
get back in, with the shell's recent output. exit or Ctrl-D ends it.

With no <sandbox>, aerolvm lists the sandboxes you can open a shell in and
asks for a number. Everyone who opens the same session shares one shell,
like tmux; an SSH login to the sandbox lands in the same "default" one.

shell needs a terminal; scripts and agents use "aerolvm exec". WASM and
isolate sandboxes have no shell. A stopped sandbox is started first.
Exit code: the shell's own, 0 after a detach, 125 if aerolvm itself failed.

Flags:
  --session NAME   open the shell with this name, or start one under it,
                   instead of the shared "default" shell
  --new            start a separate shell; when you detach, aerolvm prints
                   the --session name that reopens it

Examples:
  aerolvm shell build-box
  aerolvm shell
  aerolvm shell build-box --new
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

For an interactive shell, use "aerolvm shell" instead.

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
  -t               allocate a terminal (only when stdout is a terminal);
                   -it is -i and -t together, as in docker exec
  --background     start the command as a background session and print its
                   session ID; read its output with "aerolvm logs"
  --json           print {"exit_code","stdout","stderr",...} at the end
                   instead of streaming (output keeps its head and tail)

Examples:
  aerolvm exec build-box -- pytest -q
  aerolvm exec build-box --cwd /app --timeout 15m -- "npm ci && npm test"
  aerolvm exec build-box -it -- htop
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

Says which credentials it used: SB_PAT_TOKEN or the saved login.
`

const loginHelp = `Sign in to sandboxd and save the login, so commands work without
SB_API_URL and SB_PAT_TOKEN.

Usage: aerolvm login [<url>] [--sso] [--device] [--issuer NAME] [--team TEAM]
       aerolvm login [<url>] --token-stdin [--team TEAM]

Asks for the URL (default: SB_API_URL, your last login, or the local
setup's http://127.0.0.1:21212). A bare host gets https://, or http:// for
localhost. Logging in again replaces the saved login.

When sandboxd offers single sign-on, login opens your browser to sign in
with your company account (asking which one when there are several). Over
SSH, --device prints a URL and a code to enter on any device instead. The
login renews itself while your provider allows; when it can't, sign in
again with "aerolvm login --sso <url>". Otherwise login asks for an API
token, with typing hidden, and checks it against sandboxd.

The login is saved readable only by you in ~/.config/aerolvm/config.json
($XDG_CONFIG_HOME/aerolvm when set, %AppData%\aerolvm on Windows).
SB_PAT_TOKEN (or SB_API_TOKEN) in the environment still wins over it, and
the saved credential is only ever sent to the URL it was saved for.

Flags:
  --sso                   sign in with single sign-on; fail if it isn't offered
  --device                sign in with a code on another device (SSH sessions)
  --issuer NAME           the sign-in provider, when sandboxd offers several
  --team TEAM             the team to act for when you belong to several; sent
                          with every request (SB_TEAM overrides it)
  --client-secret-stdin   read the provider app's client secret from stdin and
                          save it with the login (Google desktop apps need one;
                          your AerolVM admin hands it out)
  --token-stdin           read an API token from stdin instead (scripts, CI)
  --json                  print {"api_url","config_path","server_version"}

Examples:
  aerolvm login https://sandbox.example.com
  aerolvm login https://sandbox.example.com --device
  aerolvm login https://sandbox.example.com --team payments
  aerolvm login https://sandbox.example.com --token-stdin < token.txt
`

const whoamiHelp = `Show who sandboxd takes you for: your name, role, team, how you signed in
and when that expires.

Usage: aerolvm whoami [--explain] [--json]

With a sign-in that matches no access rule, whoami says so and lists the
groups your sign-in carried, so you can tell your admin what to add.

Flags:
  --explain   also show which access rule (binding) gave you this role, and
              the claims of your own sign-in it was matched against
  --json      print sandboxd's answer: {"principal":{"kind","id","name"},
              "role","team","expires_at"}, plus "explain" with --explain

Examples:
  aerolvm whoami
  aerolvm whoami --explain
`

const authHelp = `Print a fresh bearer token for scripts and SDKs.

Usage: aerolvm auth token [--json]

Prints the credential aerolvm would send, on stdout: your SSO login's ID
token (renewed first when it is about to expire), the saved API token, or
SB_PAT_TOKEN. An ID token lasts about an hour; run it again for a new one.

Flags:
  --json   print {"api_url","token","expires_at"}

Examples:
  SB_PAT_TOKEN=$(aerolvm auth token) python agent.py
`

const tokenHelp = `Create, list and revoke scoped API tokens (avm_...) for services and CI.

Usage: aerolvm token create --name N --role R --team T --expires-in D
       aerolvm token list
       aerolvm token revoke <token-id>

A token acts with one role (viewer, runner, auditor or admin) on one team,
or on every team with --team '*'. auditor and admin need --team '*'. Every
token expires; --expires-in takes days (90d) or a duration (720h), up to
the server's SB_TOKEN_MAX_TTL. sandboxd needs SB_IDENTITY_ENABLED=true to
accept the tokens it mints.

create prints the token on stdout. It is shown this once and sandboxd keeps
only its hash: store it now. A name is unique in its team, so running the
same create twice fails the second time (exit 1, http_status 409); revoke
the first and create it again if its token was lost.

revoke takes the token id (tok_...) or the token itself. It succeeds also
when the token is already gone. Other nodes stop accepting it within
seconds.

create and revoke need an admin; list needs an auditor or admin.

Flags (create):
  --name N         1 to 64 characters of A-Z, a-z, 0-9, '.', '_' and '-'
  --role R         viewer, runner, auditor or admin
  --team T         a team name (a-z, 0-9, '-'), or '*' for every team
  --expires-in D   lifetime, e.g. 90d
  --json           print the created token object, token included
                   (list: {"tokens":[...]}; revoke: {"revoked":"tok_..."})

Examples:
  aerolvm token create --name ci-deploy --role runner --team payments --expires-in 90d
  aerolvm token create --name prom-scrape --role viewer --team '*' --expires-in 90d --json
  aerolvm token list
  aerolvm token revoke tok_7Hq2aBcDeFgH
`

const accessHelp = `Review who holds access and what they did with it: the evidence for a
quarterly access review (SOC 2 CC6.2/6.3).

Usage: aerolvm access review --since <when> (--export s3://<bucket>[/<prefix>] | --export-dir <dir>)
                             [--format md|csv] [--witness s3://<bucket>[/<prefix>]]

access review joins the token list (GET /v1/tokens, which needs an auditor or
admin) with the audit export into one report:

  - every token: name, role, team, creator, expiry, its last recorded action
    and its calls by kind;
  - every token created or revoked in the window, and who did it;
  - every other principal the records name (people, the operator token,
    nodes, daemon subsystems, sandbox SSH keys): last action, calls by kind;
  - refused credentials (401s) by source address;
  - each node's verdict and what its records cover.

Flags on rows: admin, admin_grant (a token minted with the admin role),
expired (not yet swept), expiring (within 30 days), revoked, not_listed (a
token that acted but is gone), no_recorded_action (no api record names the
token in the window), denied (403s), refused (401s) and rate_limited (calls
the audit flood budget summarized). Plain reads leave a record only with
SB_AUDIT_API_RECORDS=all; the report says what the records show, so
no_recorded_action is not read as "unused".

The export is read the way audit verify reads it, so every record counted
links into its node's chain. A tampered batch fails the review: nothing is
printed on stdout and the verdict goes to stderr (exit 1). INCOMPLETE
evidence prints the report with a warning (exit 3), and so does an export
with no batches (exit 3, no report).

Flags:
  --since T         window start: an RFC3339 time, a duration (2160h) or days
                    (90d). Required
  --export URL      the S3 audit export (SB_AUDIT_EXPORT_S3_*)
  --export-dir D    batches saved from a webhook or bus receiver, laid out as
                    D/node=<id>/YYYY/MM/DD/<batch>.jsonl
  --format F        md (default) or csv
  --witness URL     also check the witnessed heads, as audit verify does;
                    nodes then come from the witness
  --max-lag D       how long a head may wait for its records (default 15m)
  --region R        AWS region for the buckets
  --endpoint URL    S3-compatible endpoint
  --path-style      path-style S3 addressing
  --json            print the report as JSON instead

Markdown special characters in names are escaped, and a CSV cell that starts
with =, +, - or @ gets a leading ' so a spreadsheet does not run it.

Examples:
  aerolvm access review --export s3://acme-audit/audit --since 90d > access-review.md
  aerolvm access review --export-dir ./audit-export --since 2026-07-01T00:00:00Z --format csv > review.csv
`

const logoutHelp = `Forget the saved login. The token only leaves this machine; it keeps
working on sandboxd until an operator revokes it.

Usage: aerolvm logout [--json]
`

const versionHelp = `Print the aerolvm version.

Usage: aerolvm version [--json]
`

const auditHelp = `Verify nodes' audit logs against the heads their S3 witness locked, or
search them for what a caller did.

Usage: aerolvm audit verify --witness s3://<bucket>[/<prefix>] --since <when>
                            (--export s3://<bucket>[/<prefix>] | --export-dir <dir>)
                            [--local <node-id>=<secrets.jsonl>]... [--node <id>]...
       aerolvm audit search --since <when> (--export ... | --export-dir <dir>)
                            [--caller <id-or-name>] [--kind <kind>] [--sandbox <id>]
                            [--result <result>] [--until <when>] [--witness ...]
                            [--local ...] [--node <id>]... [--limit N]

audit verify

Checks that every head the witness recorded since --since links to the next
one through the audit records, in the order they were witnessed. Records
come from the off-node export, then from a copy of the node's local log for
records not exported yet. Run it anywhere but the node you are auditing.

Results, per node and overall (the worst wins):
  PASS        every head in the window links to the next one (exit 0)
  FAIL        a head is forged or rolled back, a link is missing, the export
              forks, or a head key was hidden (exit 1; also used when the
              check cannot run)
  INCOMPLETE  nothing contradicts the witness, but heads newer than the
              evidence have waited longer than --max-lag (exit 3)

Flags:
  --witness URL     the witness bucket and prefix (SB_AUDIT_WITNESS_S3_*)
  --since T         window start: an RFC3339 time, a duration (720h) or days
                    (30d). Required; keep exports at least this long
  --export URL      the S3 audit export (SB_AUDIT_EXPORT_S3_*)
  --export-dir D    batches saved from a webhook or bus receiver, laid out as
                    D/node=<id>/YYYY/MM/DD/<batch>.jsonl
  --local N=PATH    a copy of node N's secrets.jsonl (repeatable; a bare PATH
                    works with exactly one --node)
  --node ID         check only this node (repeatable; default: every node in
                    the witness)
  --max-lag D       how long a head may wait for its records (default 15m)
  --region R        AWS region for both buckets
  --endpoint URL    S3-compatible endpoint
  --path-style      path-style S3 addressing
  --json            print the full report as JSON

Credentials come from the standard AWS chain and need read access only.

audit search

Prints every record in the window that matches the filters, then each node's
verdict. The records are read the way audit verify reads them, so every one
printed links into its node's chain; with --witness the heads are checked
too, without it only the links. Exit codes are audit verify's.

  --caller C        the caller's id (tok_..., operator, system:lifecycle) or
                    display name (an email, ignoring case)
  --kind K          api, secret_open, egress, auth_denied, ...
  --sandbox ID      records about one sandbox
  --result R        ok, denied, error (api records); success, failure
  --until T         window end, same forms as --since (default: now)
  --limit N         print at most N matches (default 1000, 0 = all); the
                    walk and the verdict always cover the whole window
  --witness URL     also check the witnessed heads, as audit verify does
  --node, --local, --export, --export-dir, --since, --max-lag, --region,
  --endpoint, --path-style, --json   as for audit verify

Examples:
  aerolvm audit verify --witness s3://acme-witness/witness/ --since 30d \
      --export s3://acme-audit/audit
  aerolvm audit verify --witness s3://acme-witness --since 2026-10-01T00:00:00Z \
      --export-dir ./audit --node node-1 --local ./node-1-secrets.jsonl
  aerolvm audit search --export s3://acme-audit/audit --caller ana@acme.com --since 7d
  aerolvm audit search --export-dir ./audit --kind api --result denied --since 30d
`
