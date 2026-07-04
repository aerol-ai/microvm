mod image;
mod types;

use std::fmt;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;

use futures_util::{SinkExt, StreamExt};
use reqwest::blocking::{
    multipart::{Form, Part},
    Client as HttpClient,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

pub use image::Image;
pub use types::CreateSandboxResponse;
use types::{CustomDomainListWire, ExposePortResponseWire};
pub use types::{
    AddCustomDomainOptions, BuildImageOptions, BuildImagePushOptions, BuildImageResult,
    CloneGeneration, ClientConfig, CreateOptions, CreateSessionOptions, CreateTemplateOptions,
    CreateWasmModuleOptions,
    CustomDomain,
    CustomDomainDnsRecords,
    CustomDomainStatus, DnsRecord, ExecExitInfo, ExecRequest, ExecResult, ExposeOptions,
    ExposeProtocol, ExposeResult, ExposedPort, Failover, HealthStatus, IngressTarget, Lifecycle,
    MountSpec, MountSpecRedacted, MountType, NetworkUsage, PlatformVolumeMount,
    RegisterSnapshotOptions, RegistryAuth,
    ResizeOptions, RetryConfig, Sandbox as SandboxData, SandboxSnapshot, Session, SessionList,
    SessionStatus, SetNetworkLimitsOptions, Template, TemplatePushState, TemplateStatus,
    UpdateLifecycleOptions, WasmModule, WasmModuleStatus, PushWasmModuleOptions,
    PushWasmModuleResponse,
};

const DEFAULT_API_URL: &str = "http://127.0.0.1:21212";
const STREAM_PREFIX_STDOUT: u8 = 0x01;
const STREAM_PREFIX_STDERR: u8 = 0x02;

pub type StreamCallback = Arc<dyn Fn(Vec<u8>) + Send + Sync + 'static>;
pub type ErrorCallback = Arc<dyn Fn(String) + Send + Sync + 'static>;
pub type ExitCallback = Arc<dyn Fn(ExecExitInfo) + Send + Sync + 'static>;

#[derive(Default)]
pub struct ExecStreamOptions {
    pub command: String,
    pub workdir: Option<String>,
    pub env: Option<std::collections::HashMap<String, String>>,
    pub tty: bool,
    pub cols: Option<u16>,
    pub rows: Option<u16>,
    pub on_stdout: Option<StreamCallback>,
    pub on_stderr: Option<StreamCallback>,
    pub on_error: Option<ErrorCallback>,
}

#[derive(Default)]
pub struct SessionAttachOptions {
    pub on_stdout: Option<StreamCallback>,
    pub on_stderr: Option<StreamCallback>,
    pub on_exit: Option<ExitCallback>,
    pub on_error: Option<ErrorCallback>,
    pub cols: Option<u16>,
    pub rows: Option<u16>,
}

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    MissingToken,
    Api(String),
    WebSocket(WebSocketError),
    Http(http::Error),
    SerdeJson(serde_json::Error),
    ChannelClosed,
    Runtime(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reqwest(err) => write!(f, "HTTP error: {}", err),
            Error::MissingToken => write!(
                f,
                "PAT token is required. Set SB_PAT_TOKEN or pass pat_token."
            ),
            Error::Api(message) => write!(f, "API error: {}", message),
            Error::WebSocket(err) => write!(f, "WebSocket error: {}", err),
            Error::Http(err) => write!(f, "HTTP request build error: {}", err),
            Error::SerdeJson(err) => write!(f, "JSON error: {}", err),
            Error::ChannelClosed => write!(f, "stream control channel is closed"),
            Error::Runtime(err) => write!(f, "runtime error: {}", err),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Reqwest(err)
    }
}

impl From<WebSocketError> for Error {
    fn from(err: WebSocketError) -> Self {
        Error::WebSocket(err)
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Error::Http(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::SerdeJson(err)
    }
}

/// Wire version of the sandbox daemon API the [`Client`] speaks.
///
/// Today only [`ApiVersion::V1`] exists. The Rust SDK package version and the
/// API wire version evolve independently — bumping the SDK does not move the
/// wire version. When v2 lands, a new variant is added here without removing
/// `V1`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ApiVersion {
    V1,
}

impl ApiVersion {
    /// URL prefix for routes at this version. Mirrors the constants exposed
    /// by `pkg/api/v1/dto.go::PathPrefix` on the server.
    pub fn path_prefix(self) -> &'static str {
        match self {
            ApiVersion::V1 => api_v1::PATH_PREFIX,
        }
    }
}

impl Default for ApiVersion {
    fn default() -> Self {
        ApiVersion::V1
    }
}

/// v1 wire constants. Mirrors `microvm/_internal/api/v1/paths.py` in the
/// Python SDK and `sdk/go/internal/apiclient/v1/paths.go` in the Go SDK.
mod api_v1 {
    pub const PATH_PREFIX: &str = "/v1";
}

#[derive(Clone, Debug)]
pub struct Client {
    api_url: String,
    pat_token: String,
    api_version: ApiVersion,
    inner: HttpClient,
    retry_config: RetryConfig,
}

#[derive(Clone, Debug)]
pub struct Sandbox {
    pub client: Client,
    pub data: SandboxData,
    pub ssh_private_key: Option<String>,
}

pub struct ExecStreamHandle {
    control_tx: UnboundedSender<ControlMessage>,
    done_rx: mpsc::Receiver<Result<ExecExitInfo, Error>>,
}

pub struct SessionAttachHandle {
    control_tx: UnboundedSender<ControlMessage>,
    done_rx: mpsc::Receiver<Result<ExecExitInfo, Error>>,
}

enum ControlMessage {
    Binary(Vec<u8>),
    Text(String),
}

#[derive(Serialize)]
struct ExecStreamStartRequest {
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    workdir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    env: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    tty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rows: Option<u16>,
}

#[derive(serde::Deserialize)]
struct ExecStreamServerMessage {
    #[serde(rename = "type")]
    kind: String,
    code: Option<i32>,
    signal: Option<String>,
    message: Option<String>,
}

#[derive(Serialize)]
struct SessionSignalRequest {
    signal: String,
}

#[derive(Serialize)]
struct SessionResizeRequest {
    cols: u16,
    rows: u16,
}

impl ExecStreamHandle {
    pub fn write(&self, data: &[u8]) -> Result<(), Error> {
        self.control_tx
            .send(ControlMessage::Binary(data.to_vec()))
            .map_err(|_| Error::ChannelClosed)
    }

    pub fn write_string(&self, data: &str) -> Result<(), Error> {
        self.write(data.as_bytes())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), Error> {
        self.send_text(
            serde_json::json!({ "type": "resize", "cols": cols, "rows": rows }).to_string(),
        )
    }

    pub fn signal(&self, name: &str) -> Result<(), Error> {
        self.send_text(serde_json::json!({ "type": "signal", "signal": name }).to_string())
    }

    pub fn close(&self) -> Result<(), Error> {
        self.send_text(serde_json::json!({ "type": "close" }).to_string())
    }

    pub fn wait(self) -> Result<ExecExitInfo, Error> {
        self.done_rx.recv().map_err(|_| Error::ChannelClosed)?
    }

    fn send_text(&self, payload: String) -> Result<(), Error> {
        self.control_tx
            .send(ControlMessage::Text(payload))
            .map_err(|_| Error::ChannelClosed)
    }
}

impl SessionAttachHandle {
    pub fn write(&self, data: &[u8]) -> Result<(), Error> {
        self.control_tx
            .send(ControlMessage::Binary(data.to_vec()))
            .map_err(|_| Error::ChannelClosed)
    }

    pub fn write_string(&self, data: &str) -> Result<(), Error> {
        self.write(data.as_bytes())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), Error> {
        self.send_text(
            serde_json::json!({ "type": "resize", "cols": cols, "rows": rows }).to_string(),
        )
    }

    pub fn signal(&self, name: &str) -> Result<(), Error> {
        self.send_text(serde_json::json!({ "type": "signal", "signal": name }).to_string())
    }

    pub fn close(&self) -> Result<(), Error> {
        self.send_text(serde_json::json!({ "type": "close" }).to_string())
    }

    pub fn wait(self) -> Result<ExecExitInfo, Error> {
        self.done_rx.recv().map_err(|_| Error::ChannelClosed)?
    }

    fn send_text(&self, payload: String) -> Result<(), Error> {
        self.control_tx
            .send(ControlMessage::Text(payload))
            .map_err(|_| Error::ChannelClosed)
    }
}

impl Sandbox {
    fn new(client: Client, data: SandboxData) -> Self {
        Sandbox {
            client,
            data,
            ssh_private_key: None,
        }
    }

    fn new_with_ssh_private_key(
        client: Client,
        data: SandboxData,
        ssh_private_key: Option<String>,
    ) -> Self {
        Sandbox {
            client,
            data,
            ssh_private_key,
        }
    }

    pub fn refresh(&mut self) -> Result<&Self, Error> {
        let updated = self.client.get(&self.data.id)?;
        self.data = updated.data;
        Ok(self)
    }

    pub fn exec(&self, request: ExecRequest) -> Result<ExecResult, Error> {
        self.client.exec(&self.data.id, request)
    }

    /// Read this sandbox's clone-generation token (changes on
    /// resume-from-snapshot). Read-only; does not reseed in-guest PRNGs.
    pub fn clone_generation(&self) -> Result<CloneGeneration, Error> {
        self.client.clone_generation(&self.data.id)
    }

    pub fn exec_stream(&self, options: ExecStreamOptions) -> Result<ExecStreamHandle, Error> {
        self.client.exec_stream(&self.data.id, options)
    }

    pub fn create_session(&self, options: CreateSessionOptions) -> Result<Session, Error> {
        self.client.create_session(&self.data.id, options)
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, Error> {
        self.client.list_sessions(&self.data.id)
    }

    pub fn get_session(&self, session_id: &str) -> Result<Session, Error> {
        self.client.get_session(&self.data.id, session_id)
    }

    pub fn delete_session(&self, session_id: &str) -> Result<(), Error> {
        self.client.delete_session(&self.data.id, session_id)
    }

    pub fn signal_session(&self, session_id: &str, signal: &str) -> Result<(), Error> {
        self.client
            .signal_session(&self.data.id, session_id, signal)
    }

    pub fn resize_session(&self, session_id: &str, cols: u16, rows: u16) -> Result<(), Error> {
        self.client
            .resize_session(&self.data.id, session_id, cols, rows)
    }

    pub fn session_log(&self, session_id: &str) -> Result<Vec<u8>, Error> {
        self.client.session_log(&self.data.id, session_id)
    }

    pub fn session_recording(&self, session_id: &str) -> Result<Vec<u8>, Error> {
        self.client.session_recording(&self.data.id, session_id)
    }

    pub fn attach_session(
        &self,
        session_id: &str,
        options: SessionAttachOptions,
    ) -> Result<SessionAttachHandle, Error> {
        self.client
            .attach_session(&self.data.id, session_id, options)
    }

    pub fn upload_file(&self, target_path: &str, data: Vec<u8>) -> Result<(), Error> {
        self.client.upload_file(&self.data.id, target_path, data)
    }

    pub fn download_file(&self, target_path: &str) -> Result<Vec<u8>, Error> {
        self.client.download_file(&self.data.id, target_path)
    }

    /// Publish a sandbox container port. Pass [`ExposeOptions::default()`] (or
    /// [`ExposeOptions::http()`]) for the historical HTTP routing, or
    /// [`ExposeOptions::tcp()`] / [`ExposeOptions::tls()`] for the caddy-l4
    /// surfaces. The returned [`ExposeResult`] is a discriminated enum —
    /// pattern-match on it to read the variant-specific fields.
    pub fn expose_port(&self, port: u16, options: ExposeOptions) -> Result<ExposeResult, Error> {
        self.client.expose_port(&self.data.id, port, options)
    }

    pub fn unexpose_port(&self, port: u16) -> Result<(), Error> {
        self.client.unexpose_port(&self.data.id, port)
    }

    /// Attach a custom hostname to this sandbox. Returns the post-add list
    /// of bindings (sorted by hostname). Idempotent: calling with an
    /// already-registered hostname returns the existing list — but re-adding
    /// with a different `port` returns 409 (detach first).
    pub fn add_custom_domain(
        &self,
        hostname: &str,
        options: Option<AddCustomDomainOptions>,
    ) -> Result<Vec<CustomDomain>, Error> {
        self.client
            .add_custom_domain(&self.data.id, hostname, options)
    }

    /// List all custom hostnames currently bound to this sandbox.
    pub fn list_custom_domains(&self) -> Result<Vec<CustomDomain>, Error> {
        self.client.list_custom_domains(&self.data.id)
    }

    /// Detach a custom hostname from this sandbox. Idempotent: 204 on success
    /// regardless of whether the hostname was registered.
    pub fn remove_custom_domain(&self, hostname: &str) -> Result<(), Error> {
        self.client.remove_custom_domain(&self.data.id, hostname)
    }

    /// Fetch the ready-to-paste DNS records for every custom hostname
    /// attached to this sandbox, along with the underlying [`IngressTarget`]
    /// they resolve to. Returns an empty `records` list when no domains are
    /// attached; the `target` is populated either way so callers can render
    /// instructions before the first attach.
    pub fn custom_domain_dns(&self) -> Result<CustomDomainDnsRecords, Error> {
        self.client.custom_domain_dns(&self.data.id)
    }

    pub fn start(&mut self) -> Result<&Self, Error> {
        let updated = self.client.start(&self.data.id)?;
        self.data = updated.data;
        Ok(self)
    }

    pub fn stop(&mut self) -> Result<&Self, Error> {
        let updated = self.client.stop(&self.data.id)?;
        self.data = updated.data;
        Ok(self)
    }

    pub fn create_snapshot(&self, name: &str) -> Result<SandboxSnapshot, Error> {
        self.client.create_snapshot(&self.data.id, name)
    }

    pub fn destroy(self) -> Result<(), Error> {
        self.client.destroy(&self.data.id)
    }

    pub fn resize(&mut self, options: ResizeOptions) -> Result<&Self, Error> {
        let updated = self.client.resize(&self.data.id, options)?;
        self.data = updated.data;
        Ok(self)
    }

    pub fn update_lifecycle(&mut self, lifecycle: Lifecycle) -> Result<&Self, Error> {
        let updated = self.client.update_lifecycle(&self.data.id, lifecycle)?;
        self.data = updated.data;
        Ok(self)
    }

    pub fn get_network_usage(&self) -> Result<NetworkUsage, Error> {
        self.client.get_network_usage(&self.data.id)
    }

    pub fn set_network_limits(&self, opts: SetNetworkLimitsOptions) -> Result<NetworkUsage, Error> {
        self.client.set_network_limits(&self.data.id, opts)
    }
}

impl Client {
    pub fn new(api_url: Option<&str>, pat_token: Option<&str>) -> Result<Self, Error> {
        Self::with_api_version(api_url, pat_token, ApiVersion::default())
    }

    /// Construct a client pinned to a specific wire version. Use this if you
    /// need to test against a non-default version explicitly; otherwise
    /// [`Client::new`] picks the SDK's default ("v1" today).
    pub fn with_api_version(
        api_url: Option<&str>,
        pat_token: Option<&str>,
        api_version: ApiVersion,
    ) -> Result<Self, Error> {
        Self::with_config(ClientConfig {
            api_url: api_url.map(String::from),
            pat_token: pat_token.map(String::from),
            retry: None,
        }, api_version)
    }

    pub fn with_config(
        config: ClientConfig,
        api_version: ApiVersion,
    ) -> Result<Self, Error> {
        let token = config.pat_token
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                std::env::var("SB_PAT_TOKEN")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            });

        let pat_token = token.ok_or(Error::MissingToken)?;
        let api_url = config.api_url
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .or_else(|| {
                std::env::var("SB_API_URL")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| value.trim().trim_end_matches('/').to_string())
            })
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());

        Ok(Client {
            api_url,
            pat_token,
            api_version,
            inner: HttpClient::new(),
            retry_config: config.retry.unwrap_or_default(),
        })
    }

    /// URL prefix for the active wire version (e.g. `"/v1"`).
    fn version_prefix(&self) -> &'static str {
        self.api_version.path_prefix()
    }

    pub fn create(&self, opts: CreateOptions) -> Result<Sandbox, Error> {
        let raw = self.do_json::<CreateOptions, CreateSandboxResponse>(
            Method::POST,
            &format!("{}/sandboxes", self.version_prefix()),
            Some(&opts),
        )?;
        Ok(Sandbox::new_with_ssh_private_key(
            self.clone(),
            raw.sandbox,
            raw.ssh_private_key,
        ))
    }

    pub fn build_image(&self, image: &Image) -> Result<String, Error> {
        Ok(self
            .build_image_with_options(image, &BuildImageOptions::default())?
            .image)
    }

    /// Build an `Image` and optionally push the result to a remote registry.
    /// Push credentials are forwarded to the daemon as a one-shot
    /// `X-Registry-Auth` header on the underlying push call and are never
    /// persisted server-side.
    pub fn build_image_with_options(
        &self,
        image: &Image,
        options: &BuildImageOptions,
    ) -> Result<BuildImageResult, Error> {
        #[derive(Serialize)]
        struct BuildImageRequest<'a> {
            dockerfile_content: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            push: Option<BuildImagePushBody<'a>>,
        }

        #[derive(Serialize)]
        struct BuildImagePushBody<'a> {
            registry: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            tag: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            server: Option<&'a str>,
            username: &'a str,
            password: &'a str,
        }

        #[derive(serde::Deserialize)]
        struct BuildImageResponse {
            image: String,
            #[serde(default)]
            pushed: Option<String>,
        }

        if let Some(message) = image.validation_error() {
            return Err(Error::Api(message.to_string()));
        }

        let push_body = if let Some(push) = options.push.as_ref() {
            let registry = push.registry.trim();
            if registry.is_empty() {
                return Err(Error::Api(
                    "push.registry is required when push is set".to_string(),
                ));
            }
            if push.username.is_empty() || push.password.is_empty() {
                return Err(Error::Api(
                    "push.username and push.password are required when push is set".to_string(),
                ));
            }
            Some(BuildImagePushBody {
                registry,
                tag: push.tag.as_deref().filter(|s| !s.is_empty()),
                server: push.server.as_deref().filter(|s| !s.is_empty()),
                username: push.username.as_str(),
                password: push.password.as_str(),
            })
        } else {
            None
        };

        let path = format!("{}/images/build", self.version_prefix());
        let response = self
            .inner
            .request(Method::POST, self.full_url(&path))
            .bearer_auth(&self.pat_token)
            .json(&BuildImageRequest {
                dockerfile_content: image.dockerfile(),
                push: push_body,
            })
            .send()?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            let _ = response.text();
            return Err(Error::Api(format!(
                "this daemon does not support Image builds (POST {} is not registered) — pass a string image reference (e.g. \"ubuntu:22.04\") instead, or upgrade the daemon",
                path,
            )));
        }
        let response = self.handle_response(response)?;
        let payload: BuildImageResponse = response.json().map_err(Error::Reqwest)?;
        Ok(BuildImageResult {
            image: payload.image,
            pushed: payload.pushed.filter(|s| !s.is_empty()),
        })
    }

    pub fn create_with_image(
        &self,
        image: &Image,
        mut opts: CreateOptions,
    ) -> Result<Sandbox, Error> {
        opts.image = self.build_image(image)?;
        self.create(opts)
    }

    pub fn list(&self) -> Result<Vec<Sandbox>, Error> {
        self.list_with_tags(&std::collections::HashMap::new())
    }

    /// Lists sandboxes filtered by tag. Every key/value pair in `tags` must
    /// be present on a sandbox's `tags` map for it to be returned (AND
    /// semantics on the server). Wire format is `?tag.<key>=<value>`; both
    /// key and value are percent-encoded. Passing an empty map is identical
    /// to calling [`Client::list`].
    pub fn list_with_tags(
        &self,
        tags: &std::collections::HashMap<String, String>,
    ) -> Result<Vec<Sandbox>, Error> {
        let mut path = format!("{}/sandboxes", self.version_prefix());
        path.push_str(&build_tag_query(tags));
        let raw = self.do_json::<(), Vec<SandboxData>>(Method::GET, &path, None)?;
        Ok(raw
            .into_iter()
            .map(|item| Sandbox::new(self.clone(), item))
            .collect())
    }

    pub fn get(&self, id: &str) -> Result<Sandbox, Error> {
        let raw = self.do_json::<(), SandboxData>(
            Method::GET,
            &format!("{}/sandboxes/{}", self.version_prefix(), id),
            None,
        )?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn start(&self, id: &str) -> Result<Sandbox, Error> {
        let raw = self.do_json::<(), SandboxData>(
            Method::POST,
            &format!("{}/sandboxes/{}/start", self.version_prefix(), id),
            None,
        )?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn stop(&self, id: &str) -> Result<Sandbox, Error> {
        let raw = self.do_json::<(), SandboxData>(
            Method::POST,
            &format!("{}/sandboxes/{}/stop", self.version_prefix(), id),
            None,
        )?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn create_snapshot(&self, id: &str, name: &str) -> Result<SandboxSnapshot, Error> {
        #[derive(Serialize)]
        struct CreateSnapshotRequest<'a> {
            name: &'a str,
        }

        self.do_json::<CreateSnapshotRequest<'_>, SandboxSnapshot>(
            Method::POST,
            &format!("{}/sandboxes/{}/snapshot", self.version_prefix(), id),
            Some(&CreateSnapshotRequest { name }),
        )
    }

    pub fn register_snapshot(
        &self,
        opts: RegisterSnapshotOptions,
    ) -> Result<SandboxSnapshot, Error> {
        #[derive(Serialize)]
        struct RegisterSnapshotRequest<'a> {
            name: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            image: Option<&'a str>,
            #[serde(rename = "dockerfile_content", skip_serializing_if = "Option::is_none")]
            dockerfile_content: Option<&'a str>,
            #[serde(rename = "context_hashes", skip_serializing_if = "Option::is_none")]
            context_hashes: Option<&'a [String]>,
            #[serde(skip_serializing_if = "Option::is_none")]
            entrypoint: Option<&'a [String]>,
            #[serde(rename = "region_id", skip_serializing_if = "Option::is_none")]
            region_id: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            cpu: Option<f64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            gpu: Option<f64>,
            #[serde(rename = "memory_mb", skip_serializing_if = "Option::is_none")]
            memory_mb: Option<u32>,
            #[serde(rename = "disk_gb", skip_serializing_if = "Option::is_none")]
            disk_gb: Option<u32>,
        }

        let name = opts.name.trim();
        if name.is_empty() {
            return Err(Error::Api("name is required".to_string()));
        }

        let image = opts
            .image
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let dockerfile_content = opts
            .dockerfile_content
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        match (&image, &dockerfile_content) {
            (None, None) => {
                return Err(Error::Api(
                    "image or dockerfile_content is required".to_string(),
                ))
            }
            (Some(_), Some(_)) => {
                return Err(Error::Api(
                    "image and dockerfile_content are mutually exclusive".to_string(),
                ))
            }
            _ => {}
        }

        let region_id = opts
            .region_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        self.do_json::<RegisterSnapshotRequest<'_>, SandboxSnapshot>(
            Method::POST,
            &format!("{}/snapshots", self.version_prefix()),
            Some(&RegisterSnapshotRequest {
                name,
                image: image.as_deref(),
                dockerfile_content: dockerfile_content.as_deref(),
                context_hashes: if opts.context_hashes.is_empty() {
                    None
                } else {
                    Some(opts.context_hashes.as_slice())
                },
                entrypoint: if opts.entrypoint.is_empty() {
                    None
                } else {
                    Some(opts.entrypoint.as_slice())
                },
                region_id: region_id.as_deref(),
                cpu: opts.cpu,
                gpu: opts.gpu,
                memory_mb: opts.memory_mb,
                disk_gb: opts.disk_gb,
            }),
        )
    }

    pub fn register_snapshot_from_image(
        &self,
        name: &str,
        image: &Image,
        mut opts: RegisterSnapshotOptions,
    ) -> Result<SandboxSnapshot, Error> {
        if let Some(message) = image.validation_error() {
            return Err(Error::Api(message.to_string()));
        }
        opts.name = name.to_string();
        opts.image = None;
        opts.dockerfile_content = Some(image.dockerfile().to_string());
        self.register_snapshot(opts)
    }

    pub fn destroy(&self, id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!("{}/sandboxes/{}", self.version_prefix(), id),
            None,
        )
    }

    /// Register a Firecracker rootfs template. Returns immediately with a
    /// `status = TemplateStatus::Pending` row; poll [`Client::get_template`]
    /// until the row reaches `Ready` (fast-boot available) or
    /// `ReadyNoSnapshot` (cold boot only).
    ///
    /// Idempotent when `opts.id` is supplied: a duplicate id returns 409 so a
    /// retried CI step does not register two rows for the same logical
    /// template.
    pub fn create_template(&self, opts: CreateTemplateOptions) -> Result<Template, Error> {
        if opts.image.trim().is_empty() {
            return Err(Error::Api("image is required".to_string()));
        }
        self.do_json::<CreateTemplateOptions, Template>(
            Method::POST,
            &format!("{}/templates", self.version_prefix()),
            Some(&opts),
        )
    }

    pub fn list_templates(&self) -> Result<Vec<Template>, Error> {
        self.do_json::<(), Vec<Template>>(
            Method::GET,
            &format!("{}/templates", self.version_prefix()),
            None,
        )
    }

    pub fn get_template(&self, id: &str) -> Result<Template, Error> {
        self.do_json::<(), Template>(
            Method::GET,
            &format!("{}/templates/{}", self.version_prefix(), id),
            None,
        )
    }

    pub fn delete_template(&self, id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!("{}/templates/{}", self.version_prefix(), id),
            None,
        )
    }

    /// Register a WASM module in the host catalogue. Resolution is synchronous —
    /// the returned row is typically already `WasmModuleStatus::Ready`.
    pub fn create_wasm_module(&self, opts: CreateWasmModuleOptions) -> Result<WasmModule, Error> {
        if opts.module_ref.trim().is_empty() {
            return Err(Error::Api("module_ref is required".to_string()));
        }
        self.do_json::<CreateWasmModuleOptions, WasmModule>(
            Method::POST,
            &format!("{}/wasm-modules", self.version_prefix()),
            Some(&opts),
        )
    }

    pub fn list_wasm_modules(&self) -> Result<Vec<WasmModule>, Error> {
        self.do_json::<(), Vec<WasmModule>>(
            Method::GET,
            &format!("{}/wasm-modules", self.version_prefix()),
            None,
        )
    }

    pub fn get_wasm_module(&self, id: &str) -> Result<WasmModule, Error> {
        self.do_json::<(), WasmModule>(
            Method::GET,
            &format!("{}/wasm-modules/{}", self.version_prefix(), id),
            None,
        )
    }

    pub fn delete_wasm_module(&self, id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!("{}/wasm-modules/{}", self.version_prefix(), id),
            None,
        )
    }

    /// Upload a compiled core-wasip1 module to the registry under your own
    /// credentials and get back the `oci://` ref to use as `module_ref` on a
    /// later `create`. The daemon validates and forwards the bytes; it never
    /// stores them.
    pub fn push_wasm_module(
        &self,
        opts: PushWasmModuleOptions,
    ) -> Result<PushWasmModuleResponse, Error> {
        if opts.name.trim().is_empty() {
            return Err(Error::Api("name is required".to_string()));
        }
        if opts.registry_token.trim().is_empty() {
            return Err(Error::Api("registry_token is required".to_string()));
        }
        let tag = if opts.tag.trim().is_empty() {
            "latest"
        } else {
            opts.tag.as_str()
        };
        let path = format!(
            "{}/wasm-modules/push?name={}&tag={}",
            self.version_prefix(),
            urlencoding::encode(&opts.name),
            urlencoding::encode(tag),
        );
        let url = self.full_url(&path);
        let mut builder = self
            .inner
            .post(&url)
            .bearer_auth(&self.pat_token)
            .header("Content-Type", "application/octet-stream")
            .header("X-Registry-Token", &opts.registry_token)
            .body(opts.module);
        if !opts.registry_username.trim().is_empty() {
            builder = builder.header("X-Registry-Username", &opts.registry_username);
        }
        let response = self.handle_response(builder.send()?)?;
        response.json().map_err(Error::Reqwest)
    }

    /// Re-run the snapshot phase against an existing template. Idempotent
    /// under concurrent retry: the daemon's CAS collapses N parallel calls
    /// for the same ready template into one rebuild kick. Returns the row
    /// in its post-transition state (typically `Unhealthy`); poll
    /// [`Client::get_template`] to observe the transition back to `Ready`.
    ///
    /// Returns an [`Error::Api`] wrapping a 412 response when the template
    /// is in a state where rebuild is unsafe (build in flight) or
    /// unsupported (`ReadyNoSnapshot`, `Failed` — those need
    /// delete+recreate today).
    pub fn rebuild_template(&self, id: &str) -> Result<Template, Error> {
        self.do_json::<(), Template>(
            Method::POST,
            &format!("{}/templates/{}/rebuild", self.version_prefix(), id),
            None,
        )
    }

    pub fn resize(&self, id: &str, opts: ResizeOptions) -> Result<Sandbox, Error> {
        let raw = self.do_json::<ResizeOptions, SandboxData>(
            Method::POST,
            &format!("{}/sandboxes/{}/resize", self.version_prefix(), id),
            Some(&opts),
        )?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn update_lifecycle(&self, id: &str, lifecycle: Lifecycle) -> Result<Sandbox, Error> {
        let raw = self.do_json::<Lifecycle, SandboxData>(
            Method::PUT,
            &format!("{}/sandboxes/{}/lifecycle", self.version_prefix(), id),
            Some(&lifecycle),
        )?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn reconcile(&self) -> Result<(), Error> {
        self.do_json::<(), serde_json::Value>(
            Method::POST,
            &format!("{}/admin/reconcile", self.version_prefix()),
            None,
        )
        .map(|_| ())
    }

    pub fn health(&self) -> Result<HealthStatus, Error> {
        self.do_json::<(), HealthStatus>(Method::GET, "/health", None)
    }

    pub fn mounts(&self, id: &str) -> Result<Vec<MountSpecRedacted>, Error> {
        #[derive(serde::Deserialize)]
        struct MountList {
            mounts: Vec<MountSpecRedacted>,
        }

        let raw = self.do_json::<(), MountList>(
            Method::GET,
            &format!("{}/sandboxes/{}/mounts", self.version_prefix(), id),
            None,
        )?;
        Ok(raw.mounts)
    }

    /// Read a sandbox's clone-generation token. The token changes whenever the
    /// sandbox is resumed from a snapshot, so a change signals "this is a
    /// clone." Read-only — the SDK cannot reseed a process inside the guest;
    /// see the "Randomness in cloned sandboxes" docs for the in-guest pattern.
    pub fn clone_generation(&self, id: &str) -> Result<CloneGeneration, Error> {
        self.do_json::<(), CloneGeneration>(
            Method::GET,
            &format!(
                "{}/sandboxes/{}/toolbox/clone-generation",
                self.version_prefix(),
                id
            ),
            None,
        )
    }

    pub fn get_network_usage(&self, id: &str) -> Result<NetworkUsage, Error> {
        self.do_json::<(), NetworkUsage>(
            Method::GET,
            &format!("{}/sandboxes/{}/network/usage", self.version_prefix(), id),
            None,
        )
    }

    pub fn set_network_limits(
        &self,
        id: &str,
        opts: SetNetworkLimitsOptions,
    ) -> Result<NetworkUsage, Error> {
        self.do_json::<SetNetworkLimitsOptions, NetworkUsage>(
            Method::PATCH,
            &format!("{}/sandboxes/{}/network/limits", self.version_prefix(), id),
            Some(&opts),
        )
    }

    pub fn exec(&self, id: &str, request: ExecRequest) -> Result<ExecResult, Error> {
        self.do_json::<ExecRequest, ExecResult>(
            Method::POST,
            &format!(
                "{}/sandboxes/{}/toolbox/process/execute",
                self.version_prefix(),
                id
            ),
            Some(&request),
        )
    }

    pub fn create_session(&self, id: &str, opts: CreateSessionOptions) -> Result<Session, Error> {
        self.do_json::<CreateSessionOptions, Session>(
            Method::POST,
            &format!("{}/sandboxes/{}/sessions", self.version_prefix(), id),
            Some(&opts),
        )
    }

    pub fn list_sessions(&self, id: &str) -> Result<Vec<Session>, Error> {
        let raw = self.do_json::<(), SessionList>(
            Method::GET,
            &format!("{}/sandboxes/{}/sessions", self.version_prefix(), id),
            None,
        )?;
        Ok(raw.sessions)
    }

    pub fn get_session(&self, id: &str, session_id: &str) -> Result<Session, Error> {
        self.do_json::<(), Session>(
            Method::GET,
            &format!(
                "{}/sandboxes/{}/sessions/{}",
                self.version_prefix(),
                id,
                session_id
            ),
            None,
        )
    }

    pub fn delete_session(&self, id: &str, session_id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!(
                "{}/sandboxes/{}/sessions/{}",
                self.version_prefix(),
                id,
                session_id
            ),
            None,
        )
    }

    pub fn signal_session(&self, id: &str, session_id: &str, signal: &str) -> Result<(), Error> {
        self.do_json::<SessionSignalRequest, ()>(
            Method::POST,
            &format!(
                "{}/sandboxes/{}/sessions/{}/signal",
                self.version_prefix(),
                id,
                session_id
            ),
            Some(&SessionSignalRequest {
                signal: signal.to_string(),
            }),
        )
    }

    pub fn resize_session(
        &self,
        id: &str,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<(), Error> {
        self.do_json::<SessionResizeRequest, ()>(
            Method::POST,
            &format!(
                "{}/sandboxes/{}/sessions/{}/resize",
                self.version_prefix(),
                id,
                session_id
            ),
            Some(&SessionResizeRequest { cols, rows }),
        )
    }

    pub fn session_log(&self, id: &str, session_id: &str) -> Result<Vec<u8>, Error> {
        let url = self.full_url(&format!(
            "{}/sandboxes/{}/sessions/{}/log",
            self.version_prefix(),
            id,
            session_id
        ));
        let response = self
            .inner
            .request(Method::GET, &url)
            .bearer_auth(&self.pat_token)
            .send()?;
        self.handle_response(response)?
            .bytes()
            .map_err(Error::Reqwest)
            .map(|bytes| bytes.to_vec())
    }

    pub fn session_recording(&self, id: &str, session_id: &str) -> Result<Vec<u8>, Error> {
        let url = self.full_url(&format!(
            "{}/sandboxes/{}/sessions/{}/recording",
            self.version_prefix(),
            id,
            session_id
        ));
        let response = self
            .inner
            .request(Method::GET, &url)
            .bearer_auth(&self.pat_token)
            .send()?;
        self.handle_response(response)?
            .bytes()
            .map_err(Error::Reqwest)
            .map(|bytes| bytes.to_vec())
    }

    pub fn attach_session(
        &self,
        id: &str,
        session_id: &str,
        options: SessionAttachOptions,
    ) -> Result<SessionAttachHandle, Error> {
        let (control_tx, control_rx) = unbounded_channel();
        let (done_tx, done_rx) = mpsc::channel();
        let api_url = self.api_url.clone();
        let pat_token = self.pat_token.clone();
        let api_version = self.api_version;
        let sandbox_id = id.to_string();
        let session_id = session_id.to_string();

        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build();
            let result = match runtime {
                Ok(runtime) => runtime.block_on(run_session_attach(
                    api_url,
                    api_version,
                    pat_token,
                    sandbox_id,
                    session_id,
                    options,
                    control_rx,
                )),
                Err(err) => Err(Error::Runtime(err)),
            };
            let _ = done_tx.send(result);
        });

        Ok(SessionAttachHandle {
            control_tx,
            done_rx,
        })
    }

    pub fn exec_stream(
        &self,
        id: &str,
        options: ExecStreamOptions,
    ) -> Result<ExecStreamHandle, Error> {
        if options.command.trim().is_empty() {
            return Err(Error::Api("command is required".to_string()));
        }

        let (control_tx, control_rx) = unbounded_channel();
        let (done_tx, done_rx) = mpsc::channel();
        let api_url = self.api_url.clone();
        let pat_token = self.pat_token.clone();
        let api_version = self.api_version;
        let sandbox_id = id.to_string();

        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build();
            let result = match runtime {
                Ok(runtime) => runtime.block_on(run_exec_stream(
                    api_url,
                    api_version,
                    pat_token,
                    sandbox_id,
                    options,
                    control_rx,
                )),
                Err(err) => Err(Error::Runtime(err)),
            };
            let _ = done_tx.send(result);
        });

        Ok(ExecStreamHandle {
            control_tx,
            done_rx,
        })
    }

    pub fn upload_file(&self, id: &str, target_path: &str, data: Vec<u8>) -> Result<(), Error> {
        let file_name = Path::new(target_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file");

        let form = Form::new()
            .text("path", target_path.to_string())
            .part("file", Part::bytes(data).file_name(file_name.to_string()));

        self.do_multipart(
            &format!(
                "{}/sandboxes/{}/toolbox/files/upload",
                self.version_prefix(),
                id
            ),
            form,
        )
    }

    pub fn download_file(&self, id: &str, target_path: &str) -> Result<Vec<u8>, Error> {
        let url = self.full_url(&format!(
            "{}/sandboxes/{}/toolbox/files/download?path={}",
            self.version_prefix(),
            id,
            urlencoding::encode(target_path)
        ));
        let response = self
            .inner
            .request(Method::GET, &url)
            .bearer_auth(&self.pat_token)
            .send()?;
        self.handle_response(response)?
            .bytes()
            .map_err(Error::Reqwest)
            .map(|bytes| bytes.to_vec())
    }

    pub fn expose_port(
        &self,
        id: &str,
        port: u16,
        options: ExposeOptions,
    ) -> Result<ExposeResult, Error> {
        let protocol_str = match options.protocol {
            ExposeProtocol::Http => "http",
            ExposeProtocol::Tcp => "tcp",
            ExposeProtocol::Tls => "tls",
        };
        let body = if matches!(options.protocol, ExposeProtocol::Http) {
            None
        } else {
            Some(serde_json::json!({"protocol": protocol_str}))
        };
        let wire = self.do_json::<Value, ExposePortResponseWire>(
            Method::POST,
            &format!("{}/sandboxes/{}/ports/{}", self.version_prefix(), id, port),
            body.as_ref(),
        )?;
        match wire.protocol.as_str() {
            "tcp" => Ok(ExposeResult::Tcp {
                url: wire.public_url,
                host: wire.host.unwrap_or_default(),
                host_port: wire.host_port.unwrap_or(0),
            }),
            "tls" => Ok(ExposeResult::Tls {
                url: wire.public_url,
            }),
            "http" | "" => Ok(ExposeResult::Http {
                url: wire.public_url,
            }),
            other => Err(Error::Api(format!("unknown expose protocol: {}", other))),
        }
    }

    pub fn unexpose_port(&self, id: &str, port: u16) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!("{}/sandboxes/{}/ports/{}", self.version_prefix(), id, port),
            None,
        )
    }

    /// Register a custom hostname against `id`. Returns the post-add list of
    /// bindings, sorted by hostname server-side. The hostname is forwarded
    /// verbatim — the server lowercases and validates it. `options.port`, if
    /// set to a non-zero value, pins the container port traffic dials.
    pub fn add_custom_domain(
        &self,
        id: &str,
        hostname: &str,
        options: Option<AddCustomDomainOptions>,
    ) -> Result<Vec<CustomDomain>, Error> {
        let mut body = serde_json::json!({ "hostname": hostname });
        if let Some(opts) = options {
            if let Some(port) = opts.port {
                if port != 0 {
                    body.as_object_mut()
                        .expect("body is object")
                        .insert("target_port".to_string(), Value::from(port));
                }
            }
        }
        let wire = self.do_json::<Value, CustomDomainListWire>(
            Method::POST,
            &format!("{}/sandboxes/{}/custom-domains", self.version_prefix(), id),
            Some(&body),
        )?;
        Ok(wire.custom_domains)
    }

    /// Fetch the current list of custom hostnames bound to `id`.
    pub fn list_custom_domains(&self, id: &str) -> Result<Vec<CustomDomain>, Error> {
        let wire = self.do_json::<(), CustomDomainListWire>(
            Method::GET,
            &format!("{}/sandboxes/{}/custom-domains", self.version_prefix(), id),
            None,
        )?;
        Ok(wire.custom_domains)
    }

    /// Detach a custom hostname from `id`. The hostname is URL-encoded into
    /// the path. Idempotent: returns Ok on 204 regardless of prior state.
    pub fn remove_custom_domain(&self, id: &str, hostname: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!(
                "{}/sandboxes/{}/custom-domains/{}",
                self.version_prefix(),
                id,
                urlencoding::encode(hostname),
            ),
            None,
        )
    }

    /// Cluster-wide ingress target advertised for DNS planning. Mirrors
    /// `GET /v1/ingress/dns`. Returns an [`IngressTarget`] with `source =
    /// "unknown"` when no ingress node has yet gossiped a public address —
    /// callers should treat that as unusable rather than guessing.
    pub fn dns_target(&self) -> Result<IngressTarget, Error> {
        self.do_json::<(), IngressTarget>(
            Method::GET,
            &format!("{}/ingress/dns", self.version_prefix()),
            None,
        )
    }

    /// Ready-to-paste DNS records for every custom hostname currently bound
    /// to `id`, plus the [`IngressTarget`] they were composed against. The
    /// records list may be empty (no custom domains attached) but `target`
    /// is always populated.
    pub fn custom_domain_dns(&self, id: &str) -> Result<CustomDomainDnsRecords, Error> {
        self.do_json::<(), CustomDomainDnsRecords>(
            Method::GET,
            &format!(
                "{}/sandboxes/{}/custom-domains/dns",
                self.version_prefix(),
                id
            ),
            None,
        )
    }

    fn full_url(&self, path: &str) -> String {
        format!("{}{}", self.api_url, path)
    }

    fn do_json<T: Serialize, U: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        payload: Option<&T>,
    ) -> Result<U, Error> {
        let max_retries = self.retry_config.max_retries.unwrap_or(3);
        let base_delay = self.retry_config.base_delay_ms.unwrap_or(200);
        let max_delay = self.retry_config.max_delay_ms.unwrap_or(5000);

        let mut attempt = 0;
        loop {
            let url = self.full_url(path);
            let mut builder = self
                .inner
                .request(method.clone(), &url)
                .bearer_auth(&self.pat_token);
            if let Some(body) = payload {
                builder = builder.json(body);
            }

            match builder.send() {
                Ok(response) => {
                    let status = response.status();
                    if (status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status == reqwest::StatusCode::BAD_GATEWAY
                        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                        || status == reqwest::StatusCode::GATEWAY_TIMEOUT)
                        && attempt < max_retries
                    {
                        // Fall through to retry logic
                    } else {
                        let response = self.handle_response(response)?;
                        if response.status() == reqwest::StatusCode::NO_CONTENT {
                            return serde_json::from_str("null").map_err(Error::SerdeJson);
                        }
                        return response.json().map_err(Error::Reqwest);
                    }
                }
                Err(err) => {
                    if attempt >= max_retries || !err.is_request() && !err.is_connect() && !err.is_timeout() {
                        return Err(Error::Reqwest(err));
                    }
                }
            }

            let delay_ms = std::cmp::min(base_delay * (1 << attempt), max_delay);
            // Add jitter
            let jitter = 1.0 + (rand::random::<f64>() - 0.5) * 0.5;
            let sleep_duration = std::time::Duration::from_millis((delay_ms as f64 * jitter) as u64);
            std::thread::sleep(sleep_duration);
            attempt += 1;
        }
    }

    fn do_multipart(&self, path: &str, form: Form) -> Result<(), Error> {
        let url = self.full_url(path);
        let response = self
            .inner
            .post(&url)
            .bearer_auth(&self.pat_token)
            .multipart(form)
            .send()?;
        self.handle_response(response).map(|_| ())
    }

    fn handle_response(
        &self,
        response: reqwest::blocking::Response,
    ) -> Result<reqwest::blocking::Response, Error> {
        if response.status().is_success() {
            Ok(response)
        } else {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            if let Ok(value) = serde_json::from_str::<Value>(&body) {
                if let Some(message) = value.get("error").and_then(|entry| entry.as_str()) {
                    return Err(Error::Api(format!("{}: {}", status, message)));
                }
            }
            Err(Error::Api(format!("{}: {}", status, body)))
        }
    }
}

async fn run_exec_stream(
    api_url: String,
    api_version: ApiVersion,
    pat_token: String,
    sandbox_id: String,
    options: ExecStreamOptions,
    mut control_rx: tokio::sync::mpsc::UnboundedReceiver<ControlMessage>,
) -> Result<ExecExitInfo, Error> {
    let ws_url = websocket_url(
        &api_url,
        &format!(
            "{}/sandboxes/{}/toolbox/process/exec/stream",
            api_version.path_prefix(),
            urlencoding::encode(&sandbox_id)
        ),
    )?;
    let mut request = ws_url.into_client_request().map_err(Error::WebSocket)?;
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {}", pat_token))
            .map_err(|err| Error::Api(format!("invalid auth header: {}", err)))?,
    );

    let (stream, _) = connect_async(request)
        .await
        .map_err(|err| decorate_ws_handshake("exec stream", err))?;
    let (mut write, mut read) = stream.split();

    let start = ExecStreamStartRequest {
        command: options.command.clone(),
        workdir: options.workdir.clone(),
        env: options.env.clone(),
        tty: options.tty,
        cols: options.cols,
        rows: options.rows,
    };
    write
        .send(Message::Text(serde_json::to_string(&start)?.into()))
        .await?;

    loop {
        tokio::select! {
            Some(control) = control_rx.recv() => {
                match control {
                    ControlMessage::Binary(data) => write.send(Message::Binary(data.into())).await?,
                    ControlMessage::Text(text) => write.send(Message::Text(text.into())).await?,
                }
            }
            message = read.next() => {
                match message {
                    Some(Ok(Message::Binary(payload))) => {
                        if payload.is_empty() {
                            continue;
                        }
                        let stream_kind = payload[0];
                        let chunk = payload[1..].to_vec();
                        match stream_kind {
                            STREAM_PREFIX_STDOUT => {
                                if let Some(callback) = &options.on_stdout {
                                    callback(chunk);
                                }
                            }
                            STREAM_PREFIX_STDERR => {
                                if let Some(callback) = &options.on_stderr {
                                    callback(chunk);
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        let payload: ExecStreamServerMessage = serde_json::from_str(text.as_ref())?;
                        if payload.kind == "exit" {
                            return Ok(ExecExitInfo {
                                code: payload.code.unwrap_or(0),
                                signal: payload.signal,
                            });
                        }
                        if payload.kind == "error" {
                            let message = payload.message.unwrap_or_else(|| "stream error".to_string());
                            if let Some(callback) = &options.on_error {
                                callback(message.clone());
                            }
                            return Err(Error::Api(message));
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Err(Error::Api("stream closed before exit".to_string())),
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(Error::WebSocket(err)),
                }
            }
        }
    }
}

async fn run_session_attach(
    api_url: String,
    api_version: ApiVersion,
    pat_token: String,
    sandbox_id: String,
    session_id: String,
    options: SessionAttachOptions,
    mut control_rx: tokio::sync::mpsc::UnboundedReceiver<ControlMessage>,
) -> Result<ExecExitInfo, Error> {
    let ws_url = websocket_url(
        &api_url,
        &format!(
            "{}/sandboxes/{}/sessions/{}/attach",
            api_version.path_prefix(),
            urlencoding::encode(&sandbox_id),
            urlencoding::encode(&session_id)
        ),
    )?;
    let mut request = ws_url.into_client_request().map_err(Error::WebSocket)?;
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Bearer {}", pat_token))
            .map_err(|err| Error::Api(format!("invalid auth header: {}", err)))?,
    );

    let (stream, _) = connect_async(request)
        .await
        .map_err(|err| decorate_ws_handshake("session attach", err))?;
    let (mut write, mut read) = stream.split();

    if let (Some(cols), Some(rows)) = (options.cols, options.rows) {
        if cols > 0 && rows > 0 {
            write
                .send(Message::Text(
                    serde_json::json!({ "type": "resize", "cols": cols, "rows": rows })
                        .to_string()
                        .into(),
                ))
                .await?;
        }
    }

    loop {
        tokio::select! {
            Some(control) = control_rx.recv() => {
                match control {
                    ControlMessage::Binary(data) => write.send(Message::Binary(data.into())).await?,
                    ControlMessage::Text(text) => write.send(Message::Text(text.into())).await?,
                }
            }
            message = read.next() => {
                match message {
                    Some(Ok(Message::Binary(payload))) => {
                        if payload.is_empty() {
                            continue;
                        }
                        let stream_kind = payload[0];
                        let chunk = payload[1..].to_vec();
                        match stream_kind {
                            STREAM_PREFIX_STDOUT => {
                                if let Some(callback) = &options.on_stdout {
                                    callback(chunk);
                                }
                            }
                            STREAM_PREFIX_STDERR => {
                                if let Some(callback) = &options.on_stderr {
                                    callback(chunk);
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        let payload: ExecStreamServerMessage = serde_json::from_str(text.as_ref())?;
                        if payload.kind == "exit" {
                            let exit = ExecExitInfo {
                                code: payload.code.unwrap_or(0),
                                signal: payload.signal,
                            };
                            if let Some(callback) = &options.on_exit {
                                callback(exit.clone());
                            }
                            return Ok(exit);
                        }
                        if payload.kind == "error" {
                            let message = payload.message.unwrap_or_else(|| "session error".to_string());
                            if let Some(callback) = &options.on_error {
                                callback(message.clone());
                            }
                            return Err(Error::Api(message));
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Err(Error::Api("session stream closed before exit".to_string())),
                    Some(Ok(_)) => {}
                    Some(Err(err)) => return Err(Error::WebSocket(err)),
                }
            }
        }
    }
}

// decorate_ws_handshake unwraps tungstenite's Http error variant so the
// caller sees the actual status + body the server returned (e.g.
// "status=502, body=\"toolbox unavailable\"") instead of just
// "Http error: 502 Bad Gateway".
// Renders the tag filter as the server's `?tag.<key>=<value>` wire format.
// The `tag.` prefix is literal — parseTagFilter on the server inspects the
// decoded query key — so only the user-supplied key and value get
// percent-encoded. An empty map returns "" so the URL is byte-identical to
// the pre-filter call (no stray trailing "?"). Map iteration order is
// unspecified; the server treats every `tag.*` pair as an AND clause so the
// emitted order does not affect the response.
fn build_tag_query(tags: &std::collections::HashMap<String, String>) -> String {
    if tags.is_empty() {
        return String::new();
    }
    let mut out = String::from("?");
    let mut first = true;
    for (key, value) in tags {
        if !first {
            out.push('&');
        }
        first = false;
        out.push_str("tag.");
        out.push_str(&urlencoding::encode(key));
        out.push('=');
        out.push_str(&urlencoding::encode(value));
    }
    out
}

fn decorate_ws_handshake(label: &str, err: WebSocketError) -> Error {
    match err {
        WebSocketError::Http(response) => {
            let status = response.status();
            let body = response.into_body().unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body);
            let trimmed = body_str.trim();
            if trimmed.is_empty() {
                Error::Api(format!(
                    "{} websocket handshake failed: status={}",
                    label, status
                ))
            } else {
                Error::Api(format!(
                    "{} websocket handshake failed: status={}, body={:?}",
                    label, status, trimmed
                ))
            }
        }
        other => Error::WebSocket(other),
    }
}

fn websocket_url(base_url: &str, path: &str) -> Result<String, Error> {
    let mut parsed = reqwest::Url::parse(&format!("{}{}", base_url.trim_end_matches('/'), path))
        .map_err(|err| Error::Api(format!("invalid API URL: {}", err)))?;
    match parsed.scheme() {
        "http" => {
            let _ = parsed.set_scheme("ws");
        }
        "https" => {
            let _ = parsed.set_scheme("wss");
        }
        "ws" | "wss" => {}
        other => return Err(Error::Api(format!("unsupported API URL scheme: {}", other))),
    }
    Ok(parsed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread;
    use tokio_tungstenite::accept_async;

    fn spawn_json_server(body: String) -> (String, std::sync::mpsc::Receiver<String>) {
        spawn_response_server("200 OK", "application/json", body.into_bytes())
    }

    fn spawn_response_server(
        status_line: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener address");
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let status_line = status_line.to_string();
        let content_type = content_type.to_string();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("server should accept");
            let request = read_http_request(&mut stream);
            request_tx.send(request).expect("request should be sent");

            let response = format!(
                "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status_line,
                content_type,
                body.len(),
            );
            stream
                .write_all(response.as_bytes())
                .expect("response should write");
            stream.write_all(&body).expect("response body should write");
        });

        (format!("http://{}", addr), request_rx)
    }

    fn spawn_create_with_image_server() -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener address");
        let (request_tx, request_rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("server should accept");
                let request = read_http_request(&mut stream);
                request_tx
                    .send(request.clone())
                    .expect("request should be sent");

                let body = if request.starts_with("POST /v1/images/build HTTP/1.1\r\n") {
                    serde_json::json!({ "image": "aerolvm-build/abc123:latest" })
                        .to_string()
                        .into_bytes()
                } else if request.starts_with("POST /v1/sandboxes HTTP/1.1\r\n") {
                    serde_json::json!({
                        "id": "sb-from-image",
                        "image": "aerolvm-build/abc123:latest",
                        "status": "started",
                        "public_url": "https://sb-from-image.example.com",
                        "cpu": 2,
                        "memory_mb": 2048,
                        "disk_gb": 20,
                        "os_user": "root",
                        "network_block_all": false,
                        "toolbox_enabled": true,
                        "exposed_ports": [],
                        "created_at": "2026-05-07T10:00:00Z",
                        "updated_at": "2026-05-07T10:00:00Z",
                        "last_active_at": "2026-05-07T10:00:00Z"
                    })
                    .to_string()
                    .into_bytes()
                } else {
                    panic!("unexpected request: {}", request);
                };

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("response should write");
                stream.write_all(&body).expect("response body should write");
            }
        });

        (format!("http://{}", addr), request_rx)
    }

    fn spawn_session_attach_server() -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener address");
        listener
            .set_nonblocking(true)
            .expect("listener should be non-blocking");
        let (control_tx, control_rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("tokio listener should build");
                let (stream, _) = listener.accept().await.expect("server should accept");
                let ws_stream = accept_async(stream).await.expect("websocket should accept");
                let (mut write, mut read) = ws_stream.split();

                for _ in 0..4 {
                    match read.next().await {
                        Some(Ok(Message::Text(text))) => {
                            control_tx
                                .send(text.to_string())
                                .expect("text control should send");
                        }
                        Some(Ok(Message::Binary(payload))) => {
                            control_tx
                                .send(format!("binary:{}", String::from_utf8_lossy(&payload)))
                                .expect("binary control should send");
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => panic!("websocket read failed: {}", err),
                        None => panic!("websocket closed early"),
                    }
                }

                write
                    .send(Message::Binary(
                        [vec![STREAM_PREFIX_STDOUT], b"hello".to_vec()]
                            .concat()
                            .into(),
                    ))
                    .await
                    .expect("stdout frame should send");
                write
                    .send(Message::Binary(
                        [vec![STREAM_PREFIX_STDERR], b"warn".to_vec()]
                            .concat()
                            .into(),
                    ))
                    .await
                    .expect("stderr frame should send");
                write
                    .send(Message::Text(
                        serde_json::json!({ "type": "exit", "code": 0, "signal": "TERM" })
                            .to_string()
                            .into(),
                    ))
                    .await
                    .expect("exit frame should send");
            });
        });

        (format!("http://{}", addr), control_rx)
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut header_end = None;
        let mut content_length = 0usize;

        loop {
            let mut chunk = [0u8; 1024];
            let read = stream.read(&mut chunk).expect("request should read");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);

            if header_end.is_none() {
                if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    let end = pos + 4;
                    header_end = Some(end);
                    let headers = String::from_utf8_lossy(&buffer[..end]);
                    for line in headers.lines() {
                        if let Some(value) = line.split_once(':') {
                            if value.0.eq_ignore_ascii_case("content-length") {
                                content_length = value.1.trim().parse::<usize>().unwrap_or(0);
                            }
                        }
                    }
                }
            }

            if let Some(end) = header_end {
                if buffer.len() >= end + content_length {
                    break;
                }
            }
        }

        String::from_utf8_lossy(&buffer).to_string()
    }

    fn minimal_create_options() -> CreateOptions {
        CreateOptions {
            image: "ubuntu:22.04".to_string(),
            cpu: None,
            memory_mb: None,
            disk_gb: None,
            env: None,
            os_user: None,
            network_block_all: None,
            network_allow_out: None,
            network_deny_out: None,
            allow_public_traffic: None,
            mask_request_host: None,
            network_bytes_in_limit: None,
            network_bytes_out_limit: None,
            registry: None,
            container_command: None,
            mounts: None,
            platform_volumes: None,
            lifecycle: None,
            failover: None,
            runtime: None,
            gpus: None,
            custom_domains: None,
            durability: None,
            module_ref: None,
        }
    }

    fn request_json_body(request: &str) -> serde_json::Value {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).expect("request body should be valid JSON")
    }

    #[test]
    fn create_options_omits_allow_public_traffic_when_unset() {
        let opts = minimal_create_options();
        let value = serde_json::to_value(&opts).expect("serialize create options");
        assert!(value.get("allow_public_traffic").is_none());
    }

    #[test]
    fn create_options_serializes_selective_egress() {
        let mut opts = minimal_create_options();
        opts.network_allow_out = Some(vec!["1.1.1.0/24".to_string(), "8.8.8.8/32".to_string()]);
        opts.allow_public_traffic = Some(false);
        let value = serde_json::to_value(&opts).expect("serialize create options");
        assert_eq!(
            value["network_allow_out"],
            serde_json::json!(["1.1.1.0/24", "8.8.8.8/32"])
        );
        assert_eq!(value["allow_public_traffic"], serde_json::json!(false));
        // network_deny_out is None, so skip_serializing_if omits it entirely.
        assert!(value.get("network_deny_out").is_none());
    }

    #[test]
    fn create_options_serializes_platform_volumes() {
        let mut opts = minimal_create_options();
        opts.platform_volumes = Some(vec![
            PlatformVolumeMount {
                name: "data".to_string(),
                path: "/workspace".to_string(),
                read_only: None,
            },
            PlatformVolumeMount {
                name: "cache".to_string(),
                path: "/cache".to_string(),
                read_only: Some(true),
            },
        ]);
        let value = serde_json::to_value(&opts).expect("serialize create options");
        assert_eq!(value["platform_volumes"][0]["name"], serde_json::json!("data"));
        assert_eq!(
            value["platform_volumes"][0]["path"],
            serde_json::json!("/workspace")
        );
        // read_only is None on the first => omitted; Some(true) on the second.
        assert!(value["platform_volumes"][0].get("read_only").is_none());
        assert_eq!(
            value["platform_volumes"][1]["read_only"],
            serde_json::json!(true)
        );
        // Unset by default => skip_serializing_if omits the field.
        let plain = serde_json::to_value(minimal_create_options()).expect("serialize");
        assert!(plain.get("platform_volumes").is_none());
    }

    #[test]
    fn create_options_serializes_mask_request_host() {
        let mut opts = minimal_create_options();
        opts.mask_request_host = Some("localhost".to_string());
        let value = serde_json::to_value(&opts).expect("serialize create options");
        assert_eq!(value["mask_request_host"], serde_json::json!("localhost"));
        // Unset by default => skip_serializing_if omits it.
        let plain = serde_json::to_value(minimal_create_options()).expect("serialize");
        assert!(plain.get("mask_request_host").is_none());
    }

    #[test]
    fn new_client_uses_environment_defaults() {
        std::env::set_var("SB_PAT_TOKEN", "env-pat");
        std::env::set_var("SB_API_URL", "https://sandbox.example.com/");

        let client = Client::new(None, None).expect("client should build");

        assert_eq!(client.pat_token, "env-pat");
        assert_eq!(client.api_url, "https://sandbox.example.com");
    }

    #[test]
    fn websocket_url_switches_schemes() {
        let ws = websocket_url(
            "https://sandbox.example.com",
            "/v1/sandboxes/sb/toolbox/process/exec/stream",
        )
        .expect("ws url");
        assert_eq!(
            ws,
            "wss://sandbox.example.com/v1/sandboxes/sb/toolbox/process/exec/stream"
        );
    }

    #[test]
    fn create_returns_ssh_key_material() {
        let body = serde_json::json!({
            "id": "sb-create",
            "image": "ubuntu:22.04",
            "status": "started",
            "public_url": "https://sb-create.example.com",
            "cpu": 2,
            "memory_mb": 2048,
            "disk_gb": 20,
            "os_user": "root",
            "network_block_all": false,
            "toolbox_enabled": true,
            "ssh_public_key": "ssh-ed25519 AAAA sandbox",
            "ssh_private_key": "PRIVATE",
            "exposed_ports": [],
            "created_at": "2026-05-07T10:00:00Z",
            "updated_at": "2026-05-07T10:00:00Z",
            "last_active_at": "2026-05-07T10:00:00Z"
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sandbox = client
            .create(minimal_create_options())
            .expect("create should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let request_lower = request.to_ascii_lowercase();

        assert!(
            request.starts_with("POST /v1/sandboxes HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert!(
            request_lower.contains("authorization: bearer pat-token"),
            "missing bearer auth: {}",
            request
        );
        assert_eq!(
            sandbox.data.ssh_public_key.as_deref(),
            Some("ssh-ed25519 AAAA sandbox")
        );
        assert_eq!(sandbox.ssh_private_key.as_deref(), Some("PRIVATE"));
    }

    #[test]
    fn image_builder_emits_expected_dockerfile() {
        let image = Image::base("alpine")
            .run_command("apk add curl")
            .run_command_group(["apk add bash", "echo ready"])
            .env([("FOO", "bar"), ("PATH", "/opt/bin:/usr/bin")])
            .workdir("/app")
            .user("nobody")
            .expose(8080)
            .entrypoint(["/bin/sh", "-c"])
            .cmd(["echo", "hi"]);

        assert_eq!(
            image.dockerfile(),
            "FROM alpine\nRUN apk add curl\nRUN apk add bash && echo ready\nENV FOO=bar PATH=/opt/bin:/usr/bin\nWORKDIR /app\nUSER nobody\nEXPOSE 8080\nENTRYPOINT [\"/bin/sh\",\"-c\"]\nCMD [\"echo\",\"hi\"]\n"
        );
    }

    #[test]
    fn image_builder_tracks_invalid_inputs() {
        assert!(Image::base("   ").validation_error().is_some());
        assert!(Image::from_dockerfile("   ").validation_error().is_some());
        assert!(Image::base("alpine")
            .workdir(" ")
            .validation_error()
            .is_some());
        assert!(Image::base("alpine").user(" ").validation_error().is_some());
        assert!(Image::base("alpine").expose(0).validation_error().is_some());
        assert!(Image::base("alpine")
            .expose(70_000)
            .validation_error()
            .is_some());
    }

    #[test]
    fn create_with_image_builds_then_creates() {
        let (url, request_rx) = spawn_create_with_image_server();

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sandbox = client
            .create_with_image(
                &Image::base("ubuntu:22.04")
                    .run_commands(["apt-get update", "apt-get install -y curl"]),
                minimal_create_options(),
            )
            .expect("create_with_image should succeed");

        let build_request = request_rx.recv().expect("build request should be captured");
        let create_request = request_rx
            .recv()
            .expect("create request should be captured");

        assert!(
            build_request.starts_with("POST /v1/images/build HTTP/1.1\r\n"),
            "unexpected request: {}",
            build_request
        );
        assert_eq!(
            request_json_body(&build_request),
            serde_json::json!({
                "dockerfile_content": "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\n"
            })
        );
        assert_eq!(
            request_json_body(&create_request),
            serde_json::json!({
                "image": "aerolvm-build/abc123:latest"
            })
        );
        assert_eq!(sandbox.data.id, "sb-from-image");
    }

    #[test]
    fn build_image_with_options_forwards_push_directive() {
        let (url, request_rx) = spawn_json_server(
            serde_json::json!({
                "image": "aerolvm-build/abc123:latest",
                "pushed": "ghcr.io/x/y:v1"
            })
            .to_string(),
        );
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");

        let result = client
            .build_image_with_options(
                &Image::base("alpine"),
                &BuildImageOptions {
                    push: Some(BuildImagePushOptions {
                        registry: "ghcr.io/x/y".to_string(),
                        tag: Some("v1".to_string()),
                        server: Some("ghcr.io".to_string()),
                        username: "u".to_string(),
                        password: "p".to_string(),
                    }),
                },
            )
            .expect("build_image_with_options should succeed");

        assert_eq!(result.image, "aerolvm-build/abc123:latest");
        assert_eq!(result.pushed.as_deref(), Some("ghcr.io/x/y:v1"));

        let request = request_rx.recv().expect("request should be received");
        assert_eq!(
            request_json_body(&request),
            serde_json::json!({
                "dockerfile_content": "FROM alpine\n",
                "push": {
                    "registry": "ghcr.io/x/y",
                    "tag": "v1",
                    "server": "ghcr.io",
                    "username": "u",
                    "password": "p"
                }
            })
        );
    }

    #[test]
    fn build_image_with_options_rejects_missing_credentials() {
        // Validation must happen client-side: no listener — if any HTTP call
        // leaks, reqwest will surface a connect error and the asserts on the
        // returned Validation message will fail.
        let client = Client::new(Some("http://127.0.0.1:1"), Some("pat-token"))
            .expect("client should build");

        let cases: &[(BuildImagePushOptions, &str)] = &[
            (
                BuildImagePushOptions {
                    registry: String::new(),
                    tag: None,
                    server: None,
                    username: "u".to_string(),
                    password: "p".to_string(),
                },
                "registry",
            ),
            (
                BuildImagePushOptions {
                    registry: "ghcr.io/x/y".to_string(),
                    tag: None,
                    server: None,
                    username: String::new(),
                    password: "p".to_string(),
                },
                "username",
            ),
            (
                BuildImagePushOptions {
                    registry: "ghcr.io/x/y".to_string(),
                    tag: None,
                    server: None,
                    username: "u".to_string(),
                    password: String::new(),
                },
                "password",
            ),
        ];

        for (push, want_substr) in cases {
            let err = client
                .build_image_with_options(
                    &Image::base("alpine"),
                    &BuildImageOptions {
                        push: Some(push.clone()),
                    },
                )
                .expect_err("must reject missing credentials");
            let msg = err.to_string();
            assert!(
                msg.contains(want_substr),
                "expected error containing {want_substr:?}, got {msg:?}"
            );
        }
    }

    #[test]
    fn build_image_maps_404_to_actionable_error() {
        let (url, _request_rx) = spawn_response_server(
            "404 Not Found",
            "text/plain",
            b"404 page not found\n".to_vec(),
        );

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let err = client
            .build_image(&Image::base("alpine"))
            .expect_err("build_image should fail");

        assert!(err.to_string().contains("does not support Image builds"));
        assert!(err.to_string().contains("string image reference"));
    }

    #[test]
    fn create_sends_nested_lifecycle_body() {
        let body = serde_json::json!({
            "id": "sb-lifecycle-create",
            "image": "ubuntu:22.04",
            "status": "started",
            "public_url": "https://sb-lifecycle-create.example.com",
            "cpu": 2,
            "memory_mb": 2048,
            "disk_gb": 20,
            "os_user": "root",
            "network_block_all": false,
            "toolbox_enabled": true,
            "exposed_ports": [],
            "created_at": "2026-05-07T10:00:00Z",
            "updated_at": "2026-05-07T10:00:00Z",
            "last_active_at": "2026-05-07T10:00:00Z",
            "lifecycle": {
                "stop_if_idle_for": 3600000000000u64,
                "destroy_at_age": 86400000000000u64
            },
            "failover": { "policy": "recreate" }
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sandbox = client
            .create(CreateOptions {
                lifecycle: Some(Lifecycle {
                    stop_if_idle_for: 3600000000000,
                    destroy_at_age: 86400000000000,
                    ..Default::default()
                }),
                failover: Some(Failover {
                    policy: "recreate".to_string(),
                }),
                ..minimal_create_options()
            })
            .expect("create should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let body = request_json_body(&request);

        assert_eq!(
            body,
            serde_json::json!({
                "image": "ubuntu:22.04",
                "lifecycle": {
                    "stop_if_idle_for": 3600000000000u64,
                    "destroy_at_age": 86400000000000u64
                },
                "failover": { "policy": "recreate" }
            })
        );
        assert_eq!(
            sandbox.data.lifecycle,
            Lifecycle {
                stop_if_idle_for: 3600000000000,
                destroy_if_idle_for: 0,
                stop_at_age: 0,
                destroy_at_age: 86400000000000,
                serverless: false,
            }
        );
        assert_eq!(
            sandbox.data.failover,
            Some(Failover {
                policy: "recreate".to_string()
            })
        );
    }

    #[test]
    fn update_lifecycle_sends_flat_body_and_maps_response() {
        let body = serde_json::json!({
            "id": "sb-lifecycle-update",
            "image": "ubuntu:22.04",
            "status": "started",
            "public_url": "https://sb-lifecycle-update.example.com",
            "cpu": 2,
            "memory_mb": 2048,
            "disk_gb": 20,
            "os_user": "root",
            "network_block_all": false,
            "toolbox_enabled": true,
            "exposed_ports": [],
            "created_at": "2026-05-07T10:00:00Z",
            "updated_at": "2026-05-07T11:00:00Z",
            "last_active_at": "2026-05-07T10:30:00Z",
            "lifecycle": {
                "stop_if_idle_for": 7200000000000u64,
                "destroy_at_age": 172800000000000u64
            }
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sandbox = client
            .update_lifecycle(
                "sb-lifecycle-update",
                Lifecycle {
                    stop_if_idle_for: 7200000000000,
                    destroy_at_age: 172800000000000,
                    ..Default::default()
                },
            )
            .expect("update lifecycle should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let body = request_json_body(&request);

        assert!(
            request.starts_with("PUT /v1/sandboxes/sb-lifecycle-update/lifecycle HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(
            body,
            serde_json::json!({
                "stop_if_idle_for": 7200000000000u64,
                "destroy_at_age": 172800000000000u64
            })
        );
        assert_eq!(
            sandbox.data.lifecycle,
            Lifecycle {
                stop_if_idle_for: 7200000000000,
                destroy_if_idle_for: 0,
                stop_at_age: 0,
                destroy_at_age: 172800000000000,
                serverless: false,
            }
        );
    }

    #[test]
    fn create_round_trips_serverless_lifecycle_flag() {
        let body = serde_json::json!({
            "id": "sb-serverless",
            "image": "ubuntu:22.04",
            "status": "started",
            "public_url": "https://sb-serverless.example.com",
            "cpu": 1,
            "memory_mb": 1024,
            "disk_gb": 10,
            "os_user": "root",
            "network_block_all": false,
            "toolbox_enabled": true,
            "exposed_ports": [],
            "created_at": "2026-05-24T10:00:00Z",
            "updated_at": "2026-05-24T10:00:00Z",
            "last_active_at": "2026-05-24T10:00:00Z",
            "lifecycle": {
                "stop_if_idle_for": 300000000000u64,
                "serverless": true
            }
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sandbox = client
            .create(CreateOptions {
                lifecycle: Some(Lifecycle {
                    stop_if_idle_for: 300000000000,
                    serverless: true,
                    ..Default::default()
                }),
                ..minimal_create_options()
            })
            .expect("create should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let wire = request_json_body(&request);

        assert_eq!(
            wire,
            serde_json::json!({
                "image": "ubuntu:22.04",
                "lifecycle": {
                    "stop_if_idle_for": 300000000000u64,
                    "serverless": true
                }
            })
        );
        assert!(sandbox.data.lifecycle.serverless);
    }

    #[test]
    fn create_snapshot_sends_name_and_maps_response() {
        let body = serde_json::json!({
            "name": "snapshots/demo:v1",
            "image": "snapshots/demo:v1",
            "image_id": "sha256:snap-1",
            "source_sandbox_id": "sb-1",
            "created_at": "2026-05-14T10:00:00Z"
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let snapshot = client
            .create_snapshot("sb-1", "snapshots/demo:v1")
            .expect("create snapshot should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let body = request_json_body(&request);

        assert!(
            request.starts_with("POST /v1/sandboxes/sb-1/snapshot HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(body, serde_json::json!({"name": "snapshots/demo:v1"}));
        assert_eq!(snapshot.name, "snapshots/demo:v1");
        assert_eq!(snapshot.image_id.as_deref(), Some("sha256:snap-1"));
        assert_eq!(snapshot.source_sandbox_id, "sb-1");
    }

    #[test]
    fn register_snapshot_sends_image_path_and_maps_response() {
        let body = serde_json::json!({
            "name": "py-base",
            "image": "python:3.12-slim",
            "image_id": "sha256:snap-2",
            "source_sandbox_id": "",
            "created_at": "2026-05-15T10:00:00Z",
            "region_id": "us",
            "cpu": 2.0,
            "gpu": 1.0,
            "memory_mb": 4096,
            "disk_gb": 10
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let snapshot = client
            .register_snapshot(RegisterSnapshotOptions {
                name: "py-base".to_string(),
                image: Some("python:3.12-slim".to_string()),
                region_id: Some("us".to_string()),
                cpu: Some(2.0),
                gpu: Some(1.0),
                memory_mb: Some(4096),
                disk_gb: Some(10),
                ..Default::default()
            })
            .expect("register snapshot should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let body = request_json_body(&request);

        assert!(
            request.starts_with("POST /v1/snapshots HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(
            body,
            serde_json::json!({
                "name": "py-base",
                "image": "python:3.12-slim",
                "region_id": "us",
                "cpu": 2.0,
                "gpu": 1.0,
                "memory_mb": 4096,
                "disk_gb": 10
            })
        );
        assert_eq!(snapshot.image_id.as_deref(), Some("sha256:snap-2"));
        assert_eq!(snapshot.region_id.as_deref(), Some("us"));
        assert_eq!(snapshot.cpu, Some(2.0));
        assert_eq!(snapshot.gpu, Some(1.0));
        assert_eq!(snapshot.memory_mb, Some(4096));
        assert_eq!(snapshot.disk_gb, Some(10));
    }

    #[test]
    fn register_snapshot_from_image_sends_dockerfile_path() {
        let body = serde_json::json!({
            "name": "built",
            "image": "snapshots/built:resolved",
            "image_id": "sha256:snap-3",
            "source_sandbox_id": "",
            "created_at": "2026-05-15T10:00:00Z",
            "entrypoint": ["/bin/sh", "-c", "echo hi"]
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let snapshot = client
            .register_snapshot_from_image(
                "built",
                &Image::base("debian:bookworm-slim").run_command("apt-get update"),
                RegisterSnapshotOptions {
                    entrypoint: vec![
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        "echo hi".to_string(),
                    ],
                    ..Default::default()
                },
            )
            .expect("register snapshot from image should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let body = request_json_body(&request);

        assert!(
            request.starts_with("POST /v1/snapshots HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        let dockerfile = body
            .get("dockerfile_content")
            .and_then(|value| value.as_str())
            .expect("dockerfile_content should be present");
        assert!(dockerfile.contains("FROM debian:bookworm-slim"));
        assert!(dockerfile.contains("RUN apt-get update"));
        assert!(body.get("image").is_none());
        assert_eq!(
            body.get("entrypoint"),
            Some(&serde_json::json!(["/bin/sh", "-c", "echo hi"]))
        );
        assert_eq!(snapshot.image, "snapshots/built:resolved");
        assert_eq!(snapshot.entrypoint, vec!["/bin/sh", "-c", "echo hi"]);
    }

    #[test]
    fn register_snapshot_validates_input_before_sending() {
        let client = Client::new(Some("http://127.0.0.1:1"), Some("pat-token"))
            .expect("client should build");

        let missing_name = client
            .register_snapshot(RegisterSnapshotOptions {
                image: Some("alpine".to_string()),
                ..Default::default()
            })
            .expect_err("missing name should fail");
        assert!(missing_name.to_string().contains("name is required"));

        let missing_payload = client
            .register_snapshot(RegisterSnapshotOptions {
                name: "x".to_string(),
                ..Default::default()
            })
            .expect_err("missing image/dockerfile should fail");
        assert!(missing_payload
            .to_string()
            .contains("image or dockerfile_content is required"));

        let both_set = client
            .register_snapshot(RegisterSnapshotOptions {
                name: "x".to_string(),
                image: Some("alpine".to_string()),
                dockerfile_content: Some("FROM busybox".to_string()),
                ..Default::default()
            })
            .expect_err("mutually exclusive fields should fail");
        assert!(both_set.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn mounts_returns_redacted_mount_specs() {
        let body = serde_json::json!({
            "mounts": [
                {
                    "type": "s3",
                    "target": "/workspace",
                    "source": "s3://bucket/prefix",
                    "options": { "region": "us-east-1" },
                    "read_only": true,
                    "has_credentials": true
                }
            ]
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let mounts = client.mounts("sb-1").expect("mounts should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("GET /v1/sandboxes/sb-1/mounts HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(
            mounts,
            vec![MountSpecRedacted {
                mount_type: MountType::S3,
                target: "/workspace".to_string(),
                source: "s3://bucket/prefix".to_string(),
                options: Some(std::collections::HashMap::from([(
                    String::from("region"),
                    String::from("us-east-1")
                )])),
                read_only: true,
                has_credentials: true,
            }]
        );
    }

    #[test]
    fn clone_generation_reads_token_via_toolbox_proxy() {
        let body = serde_json::json!({
            "generation": "2d0d8c69",
            "resumed_at": 1700000000000000000i64
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let gen = client
            .clone_generation("sb-1")
            .expect("clone_generation should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("GET /v1/sandboxes/sb-1/toolbox/clone-generation HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(gen.generation, "2d0d8c69");
        assert_eq!(gen.resumed_at, 1700000000000000000);
    }

    #[test]
    fn get_network_usage_maps_response_shape() {
        let body = serde_json::json!({
            "sandbox_id": "sb-1",
            "bytes_in": 1024,
            "bytes_out": 2048,
            "bytes_in_limit": 1048576,
            "bytes_out_limit": 0,
            "quota_exceeded": false,
            "last_sampled_at": "2026-05-15T10:00:00Z"
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let usage = client
            .get_network_usage("sb-1")
            .expect("get_network_usage should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("GET /v1/sandboxes/sb-1/network/usage HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(usage.bytes_in, 1024);
        assert_eq!(usage.bytes_out_limit, 0);
        assert!(!usage.quota_exceeded);
    }

    #[test]
    fn get_network_usage_handles_absent_last_sampled_at() {
        let body = serde_json::json!({
            "sandbox_id": "sb-fresh",
            "bytes_in": 0,
            "bytes_out": 0,
            "bytes_in_limit": 0,
            "bytes_out_limit": 0,
            "quota_exceeded": false
        })
        .to_string();
        let (url, _rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let usage = client
            .get_network_usage("sb-fresh")
            .expect("get_network_usage should succeed");
        assert_eq!(usage.last_sampled_at, None);
    }

    #[test]
    fn set_network_limits_sends_patch_with_provided_fields_only() {
        let body = serde_json::json!({
            "sandbox_id": "sb-1",
            "bytes_in": 0,
            "bytes_out": 0,
            "bytes_in_limit": 4096,
            "bytes_out_limit": 0,
            "quota_exceeded": false,
            "last_sampled_at": "2026-05-15T10:00:00Z"
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let usage = client
            .set_network_limits(
                "sb-1",
                SetNetworkLimitsOptions {
                    network_bytes_in_limit: Some(4096),
                    network_bytes_out_limit: None,
                },
            )
            .expect("set_network_limits should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let body = request_json_body(&request);

        assert!(
            request.starts_with("PATCH /v1/sandboxes/sb-1/network/limits HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(body, serde_json::json!({"network_bytes_in_limit": 4096}));
        assert_eq!(usage.bytes_in_limit, 4096);
    }

    #[test]
    fn health_maps_ssh_gateway_status() {
        let body = serde_json::json!({
            "status": "degraded",
            "sandboxes": 1,
            "docker": "ok",
            "caddy": "ok",
            "ssh_gateway": "disabled",
            "version": "dev"
        })
        .to_string();
        let (url, _request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let health = client.health().expect("health should succeed");

        assert_eq!(health.ssh_gateway, "disabled");
    }

    #[test]
    fn create_session_sends_expected_body() {
        let body = serde_json::json!({
            "id": "ses-1",
            "name": "default",
            "argv": ["sh", "-c", "bash"],
            "workdir": "/workspace",
            "pty": true,
            "status": "running",
            "exit_code": 0,
            "created_at": "2026-05-07T10:05:00Z",
            "started_at": "2026-05-07T10:05:01Z",
            "recording": true,
            "bytes": 0,
            "attached": 1
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let session = client
            .create_session(
                "sb-1",
                CreateSessionOptions {
                    name: Some("default".to_string()),
                    command: Some("bash".to_string()),
                    work_dir: Some("/workspace".to_string()),
                    pty: Some(true),
                    cols: Some(120),
                    rows: Some(40),
                    ..Default::default()
                },
            )
            .expect("create session should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let request_lower = request.to_ascii_lowercase();

        assert!(
            request.starts_with("POST /v1/sandboxes/sb-1/sessions HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert!(
            request_lower.contains("authorization: bearer pat-token"),
            "missing bearer auth: {}",
            request
        );
        assert!(
            request.contains("\"command\":\"bash\""),
            "missing command: {}",
            request
        );
        assert!(
            request.contains("\"workdir\":\"/workspace\""),
            "missing workdir: {}",
            request
        );
        assert_eq!(session.status, SessionStatus::Running);
        assert_eq!(
            session.argv,
            vec!["sh".to_string(), "-c".to_string(), "bash".to_string()]
        );
    }

    #[test]
    fn list_sessions_parses_response() {
        let body = serde_json::json!({
            "sessions": [
                {
                    "id": "ses-1",
                    "name": "default",
                    "argv": ["bash"],
                    "pty": true,
                    "status": "running",
                    "exit_code": 0,
                    "created_at": "2026-05-07T10:05:00Z",
                    "started_at": "2026-05-07T10:05:01Z",
                    "recording": true,
                    "bytes": 12,
                    "attached": 1
                }
            ]
        })
        .to_string();
        let (url, _request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sessions = client
            .list_sessions("sb-1")
            .expect("list sessions should succeed");

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name, "default");
        assert_eq!(sessions[0].status, SessionStatus::Running);
    }

    #[test]
    fn delete_session_accepts_no_content() {
        let (url, request_rx) =
            spawn_response_server("204 No Content", "application/json", Vec::new());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        client
            .delete_session("sb-1", "ses-1")
            .expect("delete session should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("DELETE /v1/sandboxes/sb-1/sessions/ses-1 HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
    }

    #[test]
    fn session_log_returns_bytes() {
        let (url, _request_rx) =
            spawn_response_server("200 OK", "text/plain", b"session log".to_vec());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let body = client
            .session_log("sb-1", "ses-1")
            .expect("session log should succeed");

        assert_eq!(body, b"session log".to_vec());
    }

    #[test]
    fn attach_session_streams_and_signals() {
        let (url, control_rx) = spawn_session_attach_server();
        let stdout_chunks = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let stderr_chunks = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let error_messages = Arc::new(Mutex::new(Vec::<String>::new()));
        let exits = Arc::new(Mutex::new(Vec::<ExecExitInfo>::new()));

        let stdout_capture = Arc::clone(&stdout_chunks);
        let stderr_capture = Arc::clone(&stderr_chunks);
        let error_capture = Arc::clone(&error_messages);
        let exit_capture = Arc::clone(&exits);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let handle = client
            .attach_session(
                "sb-1",
                "ses-1",
                SessionAttachOptions {
                    cols: Some(120),
                    rows: Some(40),
                    on_stdout: Some(Arc::new(move |chunk| {
                        stdout_capture.lock().expect("stdout lock").push(chunk)
                    })),
                    on_stderr: Some(Arc::new(move |chunk| {
                        stderr_capture.lock().expect("stderr lock").push(chunk)
                    })),
                    on_error: Some(Arc::new(move |message| {
                        error_capture.lock().expect("error lock").push(message)
                    })),
                    on_exit: Some(Arc::new(move |info| {
                        exit_capture.lock().expect("exit lock").push(info)
                    })),
                },
            )
            .expect("attach session should succeed");

        handle
            .write_string("pwd\n")
            .expect("stdin write should succeed");
        handle.resize(100, 30).expect("resize should succeed");
        handle.signal("INT").expect("signal should succeed");
        let result = handle.wait().expect("attach should exit cleanly");

        assert_eq!(
            result,
            ExecExitInfo {
                code: 0,
                signal: Some("TERM".to_string())
            }
        );
        assert_eq!(
            stdout_chunks.lock().expect("stdout lock").clone(),
            vec![b"hello".to_vec()]
        );
        assert_eq!(
            stderr_chunks.lock().expect("stderr lock").clone(),
            vec![b"warn".to_vec()]
        );
        assert!(error_messages.lock().expect("error lock").is_empty());
        assert_eq!(
            exits.lock().expect("exit lock").clone(),
            vec![ExecExitInfo {
                code: 0,
                signal: Some("TERM".to_string())
            }]
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                &control_rx
                    .recv()
                    .expect("initial resize should be captured")
            )
            .expect("initial resize should parse"),
            serde_json::json!({ "type": "resize", "cols": 120, "rows": 40 })
        );
        assert_eq!(
            control_rx.recv().expect("stdin should be captured"),
            "binary:pwd\n"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&control_rx.recv().expect("resize should be captured"))
                .expect("resize should parse"),
            serde_json::json!({ "type": "resize", "cols": 100, "rows": 30 })
        );
        assert_eq!(
            serde_json::from_str::<Value>(&control_rx.recv().expect("signal should be captured"))
                .expect("signal should parse"),
            serde_json::json!({ "type": "signal", "signal": "INT" })
        );
    }

    // Mirrors pkg/api/v1/list_filter_test.go: list_with_tags must render every
    // tag as `?tag.<k>=<v>`, which is the prefix the server's parseTagFilter
    // keys on. The check is on the request line rather than parsed URL params
    // because the test server captures the raw HTTP request.
    #[test]
    fn list_with_tags_renders_tag_prefix_on_wire() {
        let (url, request_rx) = spawn_json_server("[]".to_string());
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let mut tags = std::collections::HashMap::new();
        tags.insert("user_id".to_string(), "alice".to_string());
        client
            .list_with_tags(&tags)
            .expect("list_with_tags should succeed");
        let request = request_rx.recv().expect("request should be captured");
        assert!(
            request.starts_with("GET /v1/sandboxes?tag.user_id=alice HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
    }

    // URL-encoding is delegated to urlencoding::encode in build_tag_query.
    // This pins that both keys and values with reserved characters survive
    // the round trip via the server's url.Values decode (which percent-
    // decodes both sides before the `tag.` prefix check).
    #[test]
    fn list_with_tags_url_encodes_keys_and_values() {
        let (url, request_rx) = spawn_json_server("[]".to_string());
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let mut tags = std::collections::HashMap::new();
        tags.insert("user/id".to_string(), "alice bob".to_string());
        client
            .list_with_tags(&tags)
            .expect("list_with_tags should succeed");
        let request = request_rx.recv().expect("request should be captured");
        // urlencoding crate encodes space as %20 (not '+'), slash as %2F.
        assert!(
            request.starts_with("GET /v1/sandboxes?tag.user%2Fid=alice%20bob HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
    }

    // Backward-compat: list() and list_with_tags(&empty) must produce the
    // pre-filter URL byte-for-byte — no stray trailing "?" — so fixtures and
    // request matchers in downstream code keep working.
    #[test]
    fn list_without_tags_omits_query_string() {
        let (url, request_rx) = spawn_json_server("[]".to_string());
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        client.list().expect("list should succeed");
        let request = request_rx.recv().expect("request should be captured");
        assert!(
            request.starts_with("GET /v1/sandboxes HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );

        let (url2, request_rx2) = spawn_json_server("[]".to_string());
        let client2 = Client::new(Some(&url2), Some("pat-token")).expect("client should build");
        client2
            .list_with_tags(&std::collections::HashMap::new())
            .expect("list_with_tags should succeed");
        let request2 = request_rx2.recv().expect("request should be captured");
        assert!(
            request2.starts_with("GET /v1/sandboxes HTTP/1.1\r\n"),
            "unexpected request: {}",
            request2
        );
    }

    // Custom-domains: POST returns 201 with the post-add list envelope, body
    // is `{"hostname": "..."}`, hostname is forwarded verbatim (server
    // lowercases). Mirrors the TS/Python/Go SDK tests for the same endpoint.
    #[test]
    fn add_custom_domain_posts_hostname_and_returns_list() {
        let body = serde_json::json!({
            "custom_domains": [
                {
                    "hostname": "api.acme.com",
                    "status": "pending_dns",
                    "created_at": "2026-05-24T10:00:00Z",
                    "updated_at": "2026-05-24T10:00:00Z"
                }
            ]
        })
        .to_string();
        let (url, request_rx) =
            spawn_response_server("201 Created", "application/json", body.into_bytes());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let domains = client
            .add_custom_domain("sb-1", "api.acme.com", None)
            .expect("add_custom_domain should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("POST /v1/sandboxes/sb-1/custom-domains HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(
            request_json_body(&request),
            serde_json::json!({"hostname": "api.acme.com"})
        );
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].hostname, "api.acme.com");
        assert_eq!(domains[0].status, CustomDomainStatus::PendingDns);
        assert!(domains[0].last_error.is_none());
        assert_eq!(domains[0].target_port, 0);
    }

    #[test]
    fn add_custom_domain_forwards_target_port() {
        let body = serde_json::json!({
            "custom_domains": [
                {
                    "hostname": "api.acme.com",
                    "status": "pending_dns",
                    "target_port": 3333,
                    "created_at": "2026-05-24T10:00:00Z",
                    "updated_at": "2026-05-24T10:00:00Z"
                }
            ]
        })
        .to_string();
        let (url, request_rx) =
            spawn_response_server("201 Created", "application/json", body.into_bytes());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let domains = client
            .add_custom_domain(
                "sb-1",
                "api.acme.com",
                Some(AddCustomDomainOptions::with_port(3333)),
            )
            .expect("add_custom_domain should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert_eq!(
            request_json_body(&request),
            serde_json::json!({"hostname": "api.acme.com", "target_port": 3333})
        );
        assert_eq!(domains[0].target_port, 3333);
    }

    #[test]
    fn add_custom_domain_omits_target_port_when_zero() {
        let (url, request_rx) = spawn_response_server(
            "201 Created",
            "application/json",
            br#"{"custom_domains":[]}"#.to_vec(),
        );

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        client
            .add_custom_domain(
                "sb-1",
                "api.acme.com",
                Some(AddCustomDomainOptions::with_port(0)),
            )
            .expect("add_custom_domain should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert_eq!(
            request_json_body(&request),
            serde_json::json!({"hostname": "api.acme.com"})
        );
    }

    #[test]
    fn list_custom_domains_returns_envelope_contents() {
        let body = serde_json::json!({
            "custom_domains": [
                {
                    "hostname": "a.acme.com",
                    "status": "ready",
                    "created_at": "2026-05-24T10:00:00Z",
                    "updated_at": "2026-05-24T10:00:00Z"
                },
                {
                    "hostname": "b.acme.com",
                    "status": "failed",
                    "last_error": "no DNS",
                    "created_at": "2026-05-24T10:00:00Z",
                    "updated_at": "2026-05-24T10:00:00Z"
                }
            ]
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let domains = client
            .list_custom_domains("sb-1")
            .expect("list_custom_domains should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("GET /v1/sandboxes/sb-1/custom-domains HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(domains.len(), 2);
        assert_eq!(domains[0].status, CustomDomainStatus::Ready);
        assert_eq!(domains[1].status, CustomDomainStatus::Failed);
        assert_eq!(domains[1].last_error.as_deref(), Some("no DNS"));
    }

    // 204 No Content is the success path for DELETE — `do_json` already
    // handles that case for `Result<(), Error>`. Hostname must be URL-encoded
    // into the path so dots, hyphens, and uppercase survive intact.
    #[test]
    fn remove_custom_domain_url_encodes_and_accepts_no_content() {
        let (url, request_rx) =
            spawn_response_server("204 No Content", "application/json", Vec::new());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        client
            .remove_custom_domain("sb-1", "API.Acme.com")
            .expect("remove_custom_domain should succeed");
        let request = request_rx.recv().expect("request should be captured");

        // urlencoding::encode preserves unreserved chars (letters, digits,
        // '-', '_', '.', '~') so this hostname round-trips verbatim. The
        // assertion still pins the encoded path so a regression that drops
        // the helper or swaps in a stricter encoder is caught.
        assert!(
            request.starts_with(
                "DELETE /v1/sandboxes/sb-1/custom-domains/API.Acme.com HTTP/1.1\r\n"
            ),
            "unexpected request: {}",
            request
        );
    }

    // 409 Conflict is the documented response when the hostname is already
    // bound to a different sandbox. We just need to confirm it surfaces as an
    // Api error carrying the server-supplied JSON `error` field — that's the
    // contract handle_response promises for any 4xx.
    #[test]
    fn add_custom_domain_surfaces_409_conflict() {
        let body = serde_json::json!({ "error": "hostname already in use" })
            .to_string()
            .into_bytes();
        let (url, _request_rx) = spawn_response_server("409 Conflict", "application/json", body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let err = client
            .add_custom_domain("sb-1", "taken.acme.com", None)
            .expect_err("add_custom_domain should fail on 409");

        let message = err.to_string();
        assert!(
            message.contains("409"),
            "expected status in error: {}",
            message
        );
        assert!(
            message.contains("hostname already in use"),
            "expected server message in error: {}",
            message
        );
    }

    // 412 Precondition Failed is what the server returns when the cluster
    // hasn't finished bootstrapping TLS-on-demand yet. Same propagation path
    // as 409 — we lock in the status code passes through.
    #[test]
    fn add_custom_domain_surfaces_412_precondition() {
        let body = serde_json::json!({ "error": "tls-on-demand not ready" })
            .to_string()
            .into_bytes();
        let (url, _request_rx) =
            spawn_response_server("412 Precondition Failed", "application/json", body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let err = client
            .add_custom_domain("sb-1", "api.acme.com", None)
            .expect_err("add_custom_domain should fail on 412");

        let message = err.to_string();
        assert!(
            message.contains("412"),
            "expected status in error: {}",
            message
        );
        assert!(
            message.contains("tls-on-demand not ready"),
            "expected server message in error: {}",
            message
        );
    }

    // dns_target unwraps GET /v1/ingress/dns straight into IngressTarget —
    // no envelope on this endpoint. Locks in the path, the hostname variant
    // (most common production config), and that an empty `ips` field
    // round-trips to an empty Vec rather than failing to deserialize.
    #[test]
    fn dns_target_returns_ingress_target() {
        let body = serde_json::json!({
            "hostname": "ingress.example.com",
            "source": "hostname"
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let target = client.dns_target().expect("dns_target should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("GET /v1/ingress/dns HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(target.hostname.as_deref(), Some("ingress.example.com"));
        assert_eq!(target.source, "hostname");
        assert!(target.ips.is_empty());
    }

    // The IPs-source variant: server returns ips array, hostname omitted.
    // Confirms `hostname` deserializes to `None` when missing and the ips
    // list round-trips intact.
    #[test]
    fn dns_target_returns_ips_variant() {
        let body = serde_json::json!({
            "ips": ["203.0.113.10", "2001:db8::1"],
            "source": "ips"
        })
        .to_string();
        let (url, _request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let target = client.dns_target().expect("dns_target should succeed");

        assert!(target.hostname.is_none());
        assert_eq!(target.source, "ips");
        assert_eq!(target.ips, vec!["203.0.113.10", "2001:db8::1"]);
    }

    // custom_domain_dns returns the composed records + target. Locks in the
    // path, the records list, the embedded target, and that `notes` is
    // optional (omitted on most rows, present on Cloudflare-style hints).
    #[test]
    fn custom_domain_dns_returns_records_and_target() {
        let body = serde_json::json!({
            "records": [
                {
                    "hostname": "api.acme.com",
                    "type": "CNAME",
                    "name": "api",
                    "value": "ingress.example.com"
                },
                {
                    "hostname": "acme.com",
                    "type": "CNAME",
                    "name": "@",
                    "value": "ingress.example.com",
                    "notes": "Cloudflare: DNS only (gray cloud)"
                }
            ],
            "target": {
                "hostname": "ingress.example.com",
                "source": "hostname"
            }
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let dns = client
            .custom_domain_dns("sb-1")
            .expect("custom_domain_dns should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(
            request.starts_with("GET /v1/sandboxes/sb-1/custom-domains/dns HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(dns.records.len(), 2);
        assert_eq!(dns.records[0].hostname, "api.acme.com");
        assert_eq!(dns.records[0].record_type, "CNAME");
        assert_eq!(dns.records[0].name, "api");
        assert_eq!(dns.records[0].value, "ingress.example.com");
        assert!(dns.records[0].notes.is_none());
        assert_eq!(
            dns.records[1].notes.as_deref(),
            Some("Cloudflare: DNS only (gray cloud)")
        );
        assert_eq!(dns.target.hostname.as_deref(), Some("ingress.example.com"));
        assert_eq!(dns.target.source, "hostname");
    }

    // Firecracker rootfs template lifecycle. We stub the server response
    // shape and assert the SDK maps snake_case wire fields to the Template
    // struct and hits the right method/path. Daemon-side concurrency /
    // state-machine behaviour is covered by the internal/service tests on
    // the server side.
    #[test]
    fn create_template_posts_request_and_maps_response() {
        let body = serde_json::json!({
            "id": "tpl-rust",
            "image": "docker://alpine:3.19",
            "status": "pending",
            "min_size_mib": 256,
            "created_at": "2026-05-27T10:00:00Z",
            "updated_at": "2026-05-27T10:00:00Z",
            "has_snapshot": false,
            "has_overlay": false
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");

        let tpl = client
            .create_template(CreateTemplateOptions {
                id: Some("tpl-rust".to_string()),
                image: "docker://alpine:3.19".to_string(),
                min_size_mib: Some(256),
            })
            .expect("create_template should succeed");
        let request = request_rx.recv().expect("request captured");

        assert!(
            request.starts_with("POST /v1/templates HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert!(
            request.contains("\"image\":\"docker://alpine:3.19\""),
            "request body missing image: {}",
            request
        );
        assert!(
            request.contains("\"min_size_mib\":256"),
            "request body missing min_size_mib: {}",
            request
        );
        assert_eq!(tpl.id, "tpl-rust");
        assert_eq!(tpl.status, TemplateStatus::Pending);
        assert_eq!(tpl.min_size_mib, Some(256));
        assert!(!tpl.has_snapshot);
    }

    #[test]
    fn create_template_rejects_empty_image() {
        let client = Client::new(Some("http://127.0.0.1:1"), Some("pat-token"))
            .expect("client should build");
        let err = client
            .create_template(CreateTemplateOptions::default())
            .expect_err("empty image must be rejected");
        match err {
            Error::Api(msg) => assert!(msg.contains("image is required"), "msg = {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn create_wasm_module_posts_request_and_maps_response() {
        let body = serde_json::json!({
            "id": "mod-rust",
            "module_ref": "file:///agent.wasm",
            "status": "ready",
            "module_size_bytes": 4096,
            "has_warm": true,
            "created_at": "2026-05-27T10:00:00Z",
            "updated_at": "2026-05-27T10:00:00Z",
            "ready_at": "2026-05-27T10:00:00Z"
        })
        .to_string();
        let (url, request_rx) = spawn_json_server(body);
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");

        let module = client
            .create_wasm_module(CreateWasmModuleOptions {
                id: None,
                module_ref: "file:///agent.wasm".to_string(),
                entrypoint: Some("_start".to_string()),
            })
            .expect("create_wasm_module should succeed");
        let request = request_rx.recv().expect("request captured");

        assert!(
            request.starts_with("POST /v1/wasm-modules HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert!(
            request.contains("\"module_ref\":\"file:///agent.wasm\""),
            "request body missing module_ref: {}",
            request
        );
        assert_eq!(module.id, "mod-rust");
        assert_eq!(module.status, WasmModuleStatus::Ready);
        assert_eq!(module.module_ref, "file:///agent.wasm");
        assert!(module.has_warm);
    }

    #[test]
    fn create_wasm_module_rejects_empty_module_ref() {
        let client = Client::new(Some("http://127.0.0.1:1"), Some("pat-token"))
            .expect("client should build");
        let err = client
            .create_wasm_module(CreateWasmModuleOptions {
                id: None,
                module_ref: String::new(),
                entrypoint: None,
            })
            .expect_err("empty module_ref must be rejected");
        match err {
            Error::Api(msg) => assert!(msg.contains("module_ref is required"), "msg = {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn delete_wasm_module_sends_delete() {
        let (url, request_rx) = spawn_response_server("204 No Content", "application/json", Vec::new());
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        client.delete_wasm_module("mod-x").expect("delete ok");
        let request = request_rx.recv().expect("request captured");
        assert!(
            request.starts_with("DELETE /v1/wasm-modules/mod-x HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
    }

    #[test]
    fn rebuild_template_surfaces_412_as_error() {
        let body = serde_json::json!({
            "error": "template not eligible for rebuild: current status=pending"
        })
        .to_string();
        let (url, _rx) = spawn_response_server("412 Precondition Failed", "application/json", body.into_bytes());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let err = client
            .rebuild_template("tpl-pending")
            .expect_err("412 must surface as error");
        match err {
            Error::Api(msg) => assert!(msg.contains("not eligible"), "msg = {}", msg),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn rebuild_template_returns_unhealthy_post_transition_state() {
        let body = serde_json::json!({
            "id": "tpl-rebuild",
            "image": "docker://alpine:3.19",
            "status": "unhealthy",
            "created_at": "2026-05-27T10:00:00Z",
            "updated_at": "2026-05-27T10:10:00Z",
            "has_snapshot": true,
            "has_overlay": false
        })
        .to_string();
        let (url, request_rx) = spawn_response_server("202 Accepted", "application/json", body.into_bytes());
        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");

        let tpl = client.rebuild_template("tpl-rebuild").expect("rebuild ok");
        let request = request_rx.recv().expect("request captured");

        assert!(
            request.starts_with("POST /v1/templates/tpl-rebuild/rebuild HTTP/1.1\r\n"),
            "unexpected request: {}",
            request
        );
        assert_eq!(tpl.status, TemplateStatus::Unhealthy);
    }

    // Empty-records case: server returns `target` populated even when no
    // custom domains are attached, so the UI can show DNS instructions
    // before the first attach.
    #[test]
    fn custom_domain_dns_handles_empty_records() {
        let body = serde_json::json!({
            "records": [],
            "target": {
                "hostname": "ingress.example.com",
                "source": "hostname"
            }
        })
        .to_string();
        let (url, _request_rx) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let dns = client
            .custom_domain_dns("sb-1")
            .expect("custom_domain_dns should succeed");

        assert!(dns.records.is_empty());
        assert_eq!(dns.target.hostname.as_deref(), Some("ingress.example.com"));
    }
}
