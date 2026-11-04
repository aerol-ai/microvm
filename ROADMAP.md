# Roadmap

This roadmap says what AerolVM intends to do, and not do, from October 2026 through October 2027. It is a direction, not a delivery schedule. Dates inside the year can move. A change to this direction is a pull request that updates this file.

## What the project will do

- Keep the open-source daemon (`sandboxd`), the in-sandbox agent (`toolboxd`), the docs, and the five SDKs: TypeScript, Python, Go, Rust, and Java. A user-facing API change updates each SDK that exposes that API.
- Keep both ways of running it: self-host on your own Linux host (install script, Ansible, or Terraform), and the managed multi-tenant service.
- Keep the current runtimes. OCI sandboxes stay on containerd by default. gVisor, Firecracker, WASM, and the V8 isolate runtime stay available. The isolate runtime stays off unless the operator turns it on.
- Keep single-node installs on SQLite, with no external database required. Cluster mode stays optional: Raft for placement and SWIM gossip for membership.
- Keep the `/e2b` and `/daytona` HTTP facades working for callers that already use those SDKs against AerolVM.
- Ship `aerolvm`, a CLI and MCP server, as the interface AI agents use to drive sandboxes: locally over stdio, and from sandboxd's opt-in `/mcp` endpoint with the same bearer tokens. It is a client of the existing API, not a second API.
- Ship security fixes on the newest minor release line, as [SUPPORT.md](SUPPORT.md) describes.

## What the project will not do

- It will not drop self-hosting, and it will not require an Aerol account to run the open-source daemon.
- It will not require Kubernetes. `sandboxd` will not become a Kubernetes workload, and sandboxes will not become Kubernetes objects, during this year.
- It will not replace SQLite with a mandatory external database for a single-node install.
- It will not backport security fixes onto an older minor line.
- It will not add a sixth first-party SDK language.
- It will not change the license away from MIT.
- It will not become a general-purpose IDE or a long-lived developer workspace product. The Daytona facade is a compatibility layer for existing SDK callers, not a promise to match every Daytona workspace feature.
- It will not make the V8 isolate runtime the default.
