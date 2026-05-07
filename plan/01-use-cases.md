# Use Cases: sandbox-library

## What is sandbox-library?

A self-hosted, standalone Go service that turns any bare-metal Linux server into a sandbox farm. It bundles Daytona's Docker-management logic (runner) with Caddy's reverse proxy to give every sandbox a globally-reachable HTTPS URL — with zero dependency on the Daytona cloud API.

---

## Use Cases

### UC-01 — Install on bare metal with a single command

**Actor:** DevOps engineer / platform team  
**Trigger:** Wants to turn a fresh Ubuntu/Debian server into a sandbox host  
**Flow:**
```bash
curl -sSL https://get.aerol.ai | bash -s -- --domain sandbox.aerol.ai
```
The script installs Docker, Caddy, and the `sandboxd` binary, writes a systemd unit, and starts everything.  
**Outcome:** Server is ready to accept sandbox creation requests within ~2 minutes.

---

### UC-02 — Create a sandbox via REST API

**Actor:** AI agent, backend service, developer  
**Trigger:** POST request to the sandbox-server API  
**Flow:**
```bash
curl -X POST http://localhost:8080/v1/sandboxes \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"image": "ubuntu:22.04", "cpu": 2, "memory": 2048}'
```
**Outcome:**
- A Docker container is created and started.
- A Caddy route is added: `https://<sandbox-id>.sandbox.aerol.ai → container:toolbox-port`.
- Response includes the sandbox ID and public URL.

---

### UC-03 — Create a sandbox via Go SDK

**Actor:** Go application / AI agent built in Go  
**Trigger:** SDK call in application code  
**Flow:**
```go
client := sandbox.NewClient("http://localhost:8080", os.Getenv("API_TOKEN"))
sb, err := client.Create(ctx, sandbox.CreateOptions{
    Image:   "python:3.12",
    CPU:     2,
    MemoryMB: 4096,
    Env:     map[string]string{"APP_ENV": "test"},
})
fmt.Println(sb.PublicURL) // https://abc123.sandbox.aerol.ai
```
**Outcome:** Sandbox created with a typed Go API.

---

### UC-04 — Execute commands inside a sandbox

**Actor:** AI agent, CI pipeline  
**Trigger:** Command execution request (forwarded to Daytona toolbox daemon inside the container)  
**Flow:**
```go
result, err := sb.Exec(ctx, "python3 -c 'print(42)'")
fmt.Println(result.Stdout) // 42
```
Or via REST:
```bash
curl -X POST https://<sandbox-id>.sandbox.aerol.ai/toolbox/process/execute \
  -d '{"command": "ls -la /workspace"}'
```
**Outcome:** Command runs inside the container and returns stdout/stderr.

---

### UC-05 — Upload and download files to/from a sandbox

**Actor:** AI agent, developer  
**Trigger:** File operation via SDK or REST  
**Flow:**
```go
sb.UploadFile(ctx, "/workspace/script.py", fileBytes)
data, _ := sb.DownloadFile(ctx, "/workspace/output.csv")
```
Or via REST (proxied through Caddy → toolbox daemon):
```bash
curl -X POST https://<sandbox-id>.sandbox.aerol.ai/toolbox/files/upload \
  --form file=@script.py
```
**Outcome:** Files are written to / read from the container filesystem.

---

### UC-06 — Expose a specific container port publicly

**Actor:** Developer building a web app inside a sandbox  
**Trigger:** Port registration request  
**Flow:**
```go
url, err := sb.ExposePort(ctx, 3000)
// Returns https://<sandbox-id>-3000.sandbox.aerol.ai
```
Or by request (Caddy route: `<sandbox-id>-<port>.sandbox.aerol.ai → container:<port>`).  
**Outcome:** Any HTTP/WS traffic to the returned URL reaches the container.

---

### UC-07 — SSH into a running sandbox

**Actor:** Developer, AI agent  
**Trigger:** SSH connection  
**Flow:**
```bash
ssh <sandbox-id>@ssh.sandbox.aerol.ai -p 2220
```
SSH gateway inside `sandboxd` authenticates via sandbox ID and proxies into the container's SSH daemon (run by the Daytona toolbox daemon).  
**Outcome:** Interactive terminal session inside the sandbox.

---

### UC-08 — Stop and restart a sandbox

**Actor:** Platform scheduler, AI agent  
**Trigger:** SDK or REST call  
**Flow:**
```go
sb.Stop(ctx)
// later...
sb.Start(ctx)
```
**Outcome:** Container is stopped/started. Caddy routes are preserved. State persisted in SQLite.

---

### UC-09 — Destroy a sandbox and reclaim resources

**Actor:** AI agent, garbage collector job  
**Trigger:** SDK or REST call  
**Flow:**
```go
sb.Destroy(ctx)
```
**Outcome:** Container removed, Caddy route deleted, SQLite record purged.

---

### UC-10 — Set resource limits (CPU / memory / disk)

**Actor:** Platform operator, AI agent  
**Trigger:** Create options or resize request  
**Flow:**
```go
client.Create(ctx, sandbox.CreateOptions{
    CPU:      4,
    MemoryMB: 8192,
    DiskGB:   20,
})
// or after creation:
sb.Resize(ctx, sandbox.ResizeOptions{CPU: 2})
```
**Outcome:** Docker cgroup limits applied to the container.

---

### UC-11 — Pass environment variables to a sandbox

**Actor:** AI agent, CI pipeline  
**Trigger:** Create request with env map  
**Flow:**
```go
client.Create(ctx, sandbox.CreateOptions{
    Image: "node:20",
    Env: map[string]string{
        "DATABASE_URL": "postgres://...",
        "SECRET":       "hunter2",
    },
})
```
**Outcome:** Env vars available inside the container.

---

### UC-12 — Use a custom Docker image

**Actor:** AI infrastructure team  
**Trigger:** Create request specifying a registry image  
**Flow:**
```go
client.Create(ctx, sandbox.CreateOptions{
    Image: "ghcr.io/myorg/my-sandbox:latest",
    Registry: &sandbox.RegistryAuth{
        Username: "myuser",
        Password: os.Getenv("GHCR_TOKEN"),
        Server:   "ghcr.io",
    },
})
```
**Outcome:** Image pulled (with auth if needed), container started.

---

### UC-13 — Run many sandboxes concurrently

**Actor:** AI orchestration layer  
**Trigger:** Parallel SDK/REST calls  
**Flow:** Multiple goroutines / services each call `Create` simultaneously.  
**Outcome:** Each gets an isolated container and unique public URL. Server handles concurrency safely.

---

### UC-14 — List and inspect sandboxes

**Actor:** Dashboard, monitoring tool  
**Trigger:** GET request  
**Flow:**
```go
sandboxes, _ := client.List(ctx)
info, _      := client.Get(ctx, sandboxID)
```
**Outcome:** Returns running status, public URL, resource usage, created-at timestamp.

---

### UC-15 — Network isolation (block egress)

**Actor:** Security-conscious platform  
**Trigger:** Create option  
**Flow:**
```go
client.Create(ctx, sandbox.CreateOptions{
    NetworkBlockAll: true,
})
```
**Outcome:** iptables rules prevent the container from reaching the internet (matches Daytona's `netrules` logic).

---

### UC-16 — Works with bare IP address (no domain)

**Actor:** Developer testing on a VPS without a domain  
**Trigger:** Install script run with `--no-domain`  
**Flow:** Caddy serves over HTTP on port 80; public URL is `http://<server-ip>/<sandbox-id>/`.  
**Outcome:** Sandboxes reachable without DNS setup.

---

### UC-17 — Health check and observability

**Actor:** Monitoring system, ops team  
**Trigger:** GET `/health`  
**Flow:**
```bash
curl http://localhost:8080/health
# {"status":"ok","sandboxes":12,"docker":"ok","caddy":"ok"}
```
**Outcome:** Shows service health, container count, Docker/Caddy connectivity.

---

### UC-18 — Automatic TLS via Let's Encrypt

**Actor:** Caddy (automatic)  
**Trigger:** Wildcard DNS `*.sandbox.aerol.ai → server IP` configured by operator  
**Flow:** First request to `https://<guid>.sandbox.aerol.ai` triggers Caddy's ACME flow.  
**Outcome:** TLS cert issued and renewed automatically; zero manual cert management.

---

### UC-19 — Sandbox auto-stop on idle

**Actor:** Platform resource manager  
**Trigger:** Configurable idle timeout  
**Flow:** `sandboxd` monitors container activity; stops containers idle for > N minutes.  
**Outcome:** Unused containers freed automatically.

---

### UC-20 — State survives `sandboxd` restart

**Actor:** Operator, systemd service restarter  
**Trigger:** `sandboxd` process restart  
**Flow:** On startup, `sandboxd` reads SQLite, re-syncs Docker container states, and re-registers Caddy routes.  
**Outcome:** No sandbox state is lost across restarts.
