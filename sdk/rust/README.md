# Aerol.ai MicroVM Rust SDK

A Rust client for the Aerol.ai MicroVM sandbox API.

## Install

```bash
cargo add aerolvm-sdk
```

## Usage

```rust
use aerolvm_sdk::{Client, CreateOptions, Lifecycle};

let client = Client::new(Some("http://127.0.0.1:8080"), Some("your-pat-token"))?;
let health = client.health()?;
println!("health = {:?}", health);

let sandbox = client.create(CreateOptions {
	image: "ghcr.io/aerol-ai/ubuntu:22.04".to_string(),
	cpu: None,
	memory_mb: None,
	disk_gb: None,
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
println!("ssh public key = {:?}", sandbox.data.ssh_public_key);
println!("ssh private key = {:?}", sandbox.ssh_private_key); // only returned by create()
println!("ssh gateway = {:?}", health.ssh_gateway);

let mut sandbox = sandbox;
sandbox.update_lifecycle(Lifecycle {
	stop_if_idle_for: 7_200_000_000_000,
	destroy_at_age: 172_800_000_000_000,
	..Default::default()
})?;
```

## Example

```bash
cargo run --example create_sandbox -- http://127.0.0.1:8080 your-pat-token ghcr.io/aerol-ai/ubuntu:22.04
```

## Streaming exec

```rust
use std::sync::Arc;

let handle = sandbox.exec_stream(aerolvm_sdk::ExecStreamOptions {
	command: "bash".to_string(),
	tty: true,
	cols: Some(120),
	rows: Some(40),
	on_stdout: Some(Arc::new(|chunk| print!("{}", String::from_utf8_lossy(&chunk)))),
	..Default::default()
})?;

handle.write_string("echo hello\n")?;
let result = handle.wait()?;
println!("{:?}", result);
```

## Sessions

```rust
use std::sync::Arc;

let session = sandbox.create_session(aerolvm_sdk::CreateSessionOptions {
	name: Some("shell".to_string()),
	command: Some("bash".to_string()),
	work_dir: Some("/workspace".to_string()),
	pty: Some(true),
	cols: Some(120),
	rows: Some(40),
	..Default::default()
})?;

println!("session = {:?}", session);
println!("sessions = {:?}", sandbox.list_sessions()?);
println!("log = {}", String::from_utf8_lossy(&sandbox.session_log(&session.id)?));

let handle = sandbox.attach_session(&session.id, aerolvm_sdk::SessionAttachOptions {
	cols: Some(120),
	rows: Some(40),
	on_stdout: Some(Arc::new(|chunk| print!("{}", String::from_utf8_lossy(&chunk)))),
	..Default::default()
})?;

handle.write_string("echo attached\n")?;
println!("{:?}", handle.wait()?);
```
