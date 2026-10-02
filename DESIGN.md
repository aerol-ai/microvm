# Actors and actions

This is the design of a released AerolVM node: who acts, and what each actor can cause the system to do. The daemon is `sandboxd`. `toolboxd` is the agent inside a sandbox. Caddy terminates TLS and routes HTTP and TCP. A cluster is optional; with cluster mode off, peer actions do not run.

## Actors

| Actor | What it is | What it holds |
| :--- | :--- | :--- |
| Operator | The person who installs and configures the host. | Host access, the API token, and the daemon environment. In the open-source build the token holder is trusted as the host operator. |
| API client | An SDK or any HTTPS caller. | The API token. |
| Sandbox guest | Code running inside one sandbox. | That sandbox's filesystem, network namespace, and resource limits. Not the host, the API token, or another tenant's sandbox. |
| Preview or TCP client | A browser or TCP client that was given a published address. | The preview URL or the TLS address. No API token. |
| SSH client | A client using the sandbox's Ed25519 key. | That one sandbox's key. |
| Cluster peer | Another `sandboxd` process, only when cluster mode is on. | Raft membership and the cluster forwarding credential. |
| External storage | An S3, NFS, SSHFS, or rclone service the operator attached. | The credentials the operator sealed into the mount. |

## Actions

| Actor | Action | What carries it out |
| :--- | :--- | :--- |
| Operator | Install `sandboxd`, `toolboxd`, and Caddy. Configure TLS, runtimes, and cluster membership. | `install.sh`, `cluster-init.sh`, `cluster-join.sh`, and the daemon environment. |
| Operator | Reconcile drifted host state. Build an image. | `POST /v1/admin/reconcile`, `POST /v1/images/build`. |
| API client | Create, list, start, stop, and destroy a sandbox. Set env, tags, and resource limits. | `POST/GET /v1/sandboxes` and the per-sandbox lifecycle routes. The Daytona (`/daytona`) and E2B (`/e2b`) facades call the same service layer. |
| API client | Run a command, open a PTY session, and read or write files. | The API forwards to `toolboxd` inside the sandbox. |
| API client | Publish an HTTP preview or a TCP/TLS port. Take and restore a snapshot. Attach external storage. | The service layer records the intent in SQLite and programs Caddy, the runtime, or the mount manager. |
| API client | Read capacity and the secret-audit log. | `GET /v1/capacity`, `GET /v1/sandboxes/{id}/audit`. |
| Sandbox guest | Compute, open outbound connections, and use the files and mounts it was given. | The runtime: containerd (default), gVisor, Firecracker, WASM, or the V8 isolate. |
| Sandbox guest | Ask the host to run a process, touch the filesystem, or record session output. | `toolboxd`, which the daemon placed in that sandbox. The guest does not talk to Caddy's admin socket or to SQLite. |
| Preview or TCP client | Open the published HTTP or TCP service. | Caddy routes `<sandbox-id>.<domain>` (HTTP) or `<sandbox-id>-<port>.<domain>` (TCP) to the sandbox. |
| SSH client | Open a shell in one sandbox. | The SSH gateway checks the per-sandbox Ed25519 key and connects only to that sandbox. |
| Cluster peer | Replicate placement, exchange membership and capacity, and forward an API call to the node that owns the sandbox. | Raft for placement state, SWIM for membership, and the cross-node HTTP proxy. A node that is not the owner does not apply the mutation locally. |
| External storage | Serve the objects or files the mount names. | The host mount manager. The guest sees the mounted tree. The remote service never receives the API token. |

SQLite (WAL, one writer in the daemon) stores sandbox rows, exposed-port intents, the TCP host-port pool, and sealed secrets. It is not an actor. No other process opens that database.
