use aerolvm_sdk::{Client, CreateOptions};
use std::env;

fn main() {
    let api_url = env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:21212".to_owned());
    let pat_token = env::args().nth(2).expect("PAT token is required");
    let image = env::args().nth(3).expect("Image is required");

    let client = Client::new(Some(&api_url), Some(&pat_token)).expect("failed to create client");
    let health = client.health().expect("health check failed");
    println!("health = {:#?}", health);

    let sandbox = client
        .create(CreateOptions {
            image,
            cpu: Some(1),
            memory_mb: Some(1024),
            disk_gb: Some(10),
            env: None,
            os_user: None,
            network_block_all: None,
            network_bytes_in_limit: None,
            network_bytes_out_limit: None,
            registry: None,
            container_command: None,
            mounts: None,
            lifecycle: None,
            failover: None,
            runtime: None,
            gpus: None,
            custom_domains: None,
            durability: None,
        })
        .expect("sandbox creation failed");

    println!("sandbox = {:#?}", sandbox.data);
    println!("open {}", sandbox.data.public_url);
}
