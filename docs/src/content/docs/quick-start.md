---
title: Quick Start
---

**AerolVM** is open-source infrastructure for running isolated code environments.
Self-host it or run it as managed multi-tenant SaaS. Each sandbox is a fully
isolated compute unit — OCI containers on containerd, gVisor, Firecracker
microVMs, WASM modules, or V8 isolates — with its own network policy and
allocated resources.

Warm create latency (server-side) ranges from **~4ms** (V8 isolate) through
**~34ms** (Firecracker warm pool) and **~189ms** (default OCI on containerd)
depending on runtime. See the
[README benchmark table](https://github.com/aerol-ai/microvm#create-latency-live-uc-94)
for the latest UC-94 numbers.

Agents and developers interact with sandboxes programmatically using the AerolVM
SDKs, API, and CLI. Operations span sandbox lifecycle management, filesystem
operations, process and code execution, and runtime configuration. Stateful
environment snapshots enable persistent agent operations across sessions.

## Runtimes

| Runtime | Status | Use case |
|---|---|---|
| OCI (`runtime: "docker"` on **containerd**) | ✅ | Fast OCI images, broadest compatibility (default engine) |
| gVisor | ✅ | User-space kernel isolation for untrusted code (`--with-gvisor`) |
| Firecracker | ✅ | Hardware microVM isolation; warm pool ~34ms server create |
| WebAssembly | ✅ | WASI modules; resident host ~22ms warm create |
| Isolate (V8 / workerd) | ✅ (off by default) | JS/TS `fetch` handlers; **~4ms** warm server create (`--with-isolate`) |

Kata Containers is not implemented — create requests with `runtime: "kata"`
return not-implemented. The default API runtime is `docker` (OCI); production
hosts run it on the **containerd** engine (`SB_CONTAINER_ENGINE=containerd`).
Enable the other runtimes in server config or installer flags as needed.

## Use Cases

- **AI code execution** - run LLM-generated code safely in isolated environments
- **CI / ephemeral build agents** - spin up a fresh environment per job, destroy when done
- **Interactive developer environments** - persistent workspaces with SSH, port previews, and file sync
- **Data processing pipelines** - attach cloud storage, run transforms, and extract results
- **Edge-style JS handlers** - deploy a V8 isolate with per-sandbox egress, no container image

## Next Steps

- [Server Setup](/getting-started) - self-host AerolVM on your own infrastructure
- [Create Sandbox](/sandboxes) - lifecycle states, parameters, and configuration options
- [Environment](/environment) - image selection, env vars, and resource limits
- [Streaming Exec](/exec-streaming) - stream stdout/stderr live and use interactive PTY sessions
- [Sessions](/sessions) - persistent terminal sessions that survive reconnects
- [WebAssembly Sandboxes](/wasm-sandbox) - create and run WASI modules with durable checkpoints
- [Isolate Sandboxes](/isolate-sandbox) - push a JS/TS fetch handler as a V8 isolate
