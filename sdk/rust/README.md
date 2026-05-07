# Aerol.ai MicroVM Rust SDK

A Rust client for the Aerol.ai MicroVM sandbox API.

## Usage

```rust
use microvm_sdk::{Client, CreateOptions};

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
})?;
println!("ssh public key = {:?}", sandbox.data.ssh_public_key);
println!("ssh private key = {:?}", sandbox.ssh_private_key); // only returned by create()
```

## Example

```bash
cargo run --example create_sandbox -- http://127.0.0.1:8080 your-pat-token ghcr.io/aerol-ai/ubuntu:22.04
```

## Streaming exec

```rust
use std::sync::Arc;

let handle = sandbox.exec_stream(microvm_sdk::ExecStreamOptions {
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

let session = sandbox.create_session(microvm_sdk::CreateSessionOptions {
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

let handle = sandbox.attach_session(&session.id, microvm_sdk::SessionAttachOptions {
	cols: Some(120),
	rows: Some(40),
	on_stdout: Some(Arc::new(|chunk| print!("{}", String::from_utf8_lossy(&chunk)))),
	..Default::default()
})?;

handle.write_string("echo attached\n")?;
println!("{:?}", handle.wait()?);
```
