# Aerol.ai MicroVM Rust SDK

A Rust client for the Aerol.ai MicroVM sandbox API.

## Usage

```rust
use microvm_sdk::{Client, CreateOptions};

let client = Client::new(Some("http://127.0.0.1:8080"), Some("your-pat-token"))?;
let health = client.health()?;
println!("health = {:?}", health);
```

## Example

```bash
cargo run --example create_sandbox -- http://127.0.0.1:8080 your-pat-token ghcr.io/aerol-ai/ubuntu:22.04
```
