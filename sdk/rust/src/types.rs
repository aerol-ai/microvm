use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegistryAuth {
    pub server: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateOptions {
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<u32>,
    #[serde(rename = "memory_mb", skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    #[serde(rename = "disk_gb", skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "os_user", skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
    #[serde(rename = "network_block_all", skip_serializing_if = "Option::is_none")]
    pub network_block_all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryAuth>,
    #[serde(rename = "container_command", skip_serializing_if = "Option::is_none")]
    pub container_command: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResizeOptions {
    pub cpu: Option<u32>,
    #[serde(rename = "memory_mb", skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u32>,
    #[serde(rename = "disk_gb", skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExposedPort {
    #[serde(rename = "sandbox_id")]
    pub sandbox_id: String,
    pub port: u16,
    #[serde(rename = "public_url")]
    pub public_url: String,
    #[serde(rename = "created_at")]
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Sandbox {
    pub id: String,
    pub image: String,
    pub status: String,
    #[serde(rename = "public_url")]
    pub public_url: String,
    #[serde(rename = "container_id")]
    pub container_id: Option<String>,
    #[serde(rename = "container_ip")]
    pub container_ip: Option<String>,
    pub cpu: u32,
    #[serde(rename = "memory_mb")]
    pub memory_mb: u32,
    #[serde(rename = "disk_gb")]
    pub disk_gb: u32,
    #[serde(rename = "os_user")]
    pub os_user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "network_block_all")]
    pub network_block_all: bool,
    #[serde(rename = "toolbox_enabled")]
    pub toolbox_enabled: bool,
    #[serde(rename = "exposed_ports", skip_serializing_if = "Option::is_none")]
    pub exposed_ports: Option<Vec<ExposedPort>>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
    #[serde(rename = "last_active_at")]
    pub last_active_at: String,
    #[serde(rename = "last_error", skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(rename = "container_command", skip_serializing_if = "Option::is_none")]
    pub container_command: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
    pub sandboxes: u32,
    pub docker: String,
    pub caddy: String,
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecRequest {
    pub command: String,
    #[serde(rename = "workdir", skip_serializing_if = "Option::is_none")]
    pub work_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::HashMap<String, String>>,
    #[serde(rename = "timeout_seconds", skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "exit_code")]
    pub exit_code: i32,
    #[serde(rename = "duration_ms")]
    pub duration_ms: i64,
}
