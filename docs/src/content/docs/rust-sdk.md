---
title: Rust SDK
---

The Rust SDK lives under `sdk/rust`, publishes as `aerolvm-sdk`, and is imported in code as `aerolvm_sdk`.

## Install

```bash
cargo add aerolvm-sdk
```

## Create A Client

```rust
use aerolvm_sdk::Client;

let client = Client::new(
    Some("https://sandbox.example.com"),
    Some("your-token"),
)?;
```

If you pass `None`, the client falls back to `SB_API_URL`, `SB_PAT_TOKEN`, and then `http://127.0.0.1:8080` for the base URL.

## Create And Use A Sandbox

```rust
use aerolvm_sdk::{Client, CreateOptions, Lifecycle};

let client = Client::new(Some("https://sandbox.example.com"), Some("your-token"))?;

let mut sandbox = client.create(CreateOptions {
    image: "ghcr.io/aerol-ai/ubuntu:22.04".to_string(),
    cpu: Some(1),
    memory_mb: Some(1024),
    disk_gb: Some(10),
    env: None,
    os_user: None,
    network_block_all: None,
    registry: None,
    container_command: None,
    mounts: None,
    lifecycle: Some(Lifecycle {
        stop_if_idle_for: 3_600_000_000_000,
        destroy_at_age: 86_400_000_000_000,
        ..Default::default()
    }),
})?;

let result = sandbox.exec(aerolvm_sdk::ExecRequest {
    command: "echo hello from rust".to_string(),
    work_dir: None,
    env: None,
    timeout_seconds: None,
})?;

println!("{}", result.stdout);
println!("{:?}", sandbox.data.public_url);
println!("{:?}", sandbox.data.ssh_public_key);
println!("{:?}", sandbox.ssh_private_key); // returned only by create()
```

The Rust wrapper stores the API record on `sandbox.data`, while the create-only private key is available separately as `sandbox.ssh_private_key`.

## Streaming Exec And Sessions

```rust
use std::sync::Arc;

let handle = sandbox.exec_stream(aerolvm_sdk::ExecStreamOptions {
    command: "bash".to_string(),
    tty: true,
    cols: Some(120),
    rows: Some(40),
    on_stdout: Some(Arc::new(|chunk| {
        print!("{}", String::from_utf8_lossy(&chunk))
    })),
    ..Default::default()
})?;

handle.write_string("echo streamed\n")?;
println!("{:?}", handle.wait()?);
```

```rust
let session = sandbox.create_session(aerolvm_sdk::CreateSessionOptions {
    name: Some("shell".to_string()),
    command: Some("bash".to_string()),
    work_dir: Some("/workspace".to_string()),
    pty: Some(true),
    cols: Some(120),
    rows: Some(40),
    ..Default::default()
})?;

let attached = sandbox.attach_session(&session.id, aerolvm_sdk::SessionAttachOptions {
    cols: Some(120),
    rows: Some(40),
    on_stdout: Some(Arc::new(|chunk| {
        print!("{}", String::from_utf8_lossy(&chunk))
    })),
    ..Default::default()
})?;

attached.write_string("echo attached\n")?;
println!("{:?}", attached.wait()?);
```

## Additional Helpers

- `client.health()` returns the daemon, Docker, Caddy, and SSH gateway status.
- `client.mounts(id)` returns redacted mount specs.
- `sandbox.upload_file()` and `sandbox.download_file()` transfer file contents.
- `sandbox.expose_port()` and `sandbox.unexpose_port()` manage public URLs.
- `sandbox.session_log()` and `sandbox.session_recording()` return raw `Vec<u8>` payloads.

HTTP calls are blocking. The crate spins up an internal Tokio runtime only for the WebSocket-backed streaming helpers.