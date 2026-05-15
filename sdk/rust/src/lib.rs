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
use types::ExposePortResponseWire;
pub use types::{
    BuildImageOptions, BuildImagePushOptions, BuildImageResult, CreateOptions,
    CreateSessionOptions, ExecExitInfo, ExecRequest, ExecResult, ExposeOptions, ExposeProtocol,
    ExposeResult, ExposedPort, HealthStatus, Lifecycle, MountSpec, MountSpecRedacted, MountType,
    NetworkUsage, RegistryAuth, ResizeOptions, Sandbox as SandboxData, SandboxSnapshot, Session,
    SessionList, SessionStatus, SetNetworkLimitsOptions, UpdateLifecycleOptions,
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
        let token = pat_token
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .or_else(|| {
                std::env::var("SB_PAT_TOKEN")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            });

        let pat_token = token.ok_or(Error::MissingToken)?;
        let api_url = api_url
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
        let raw = self.do_json::<(), Vec<SandboxData>>(
            Method::GET,
            &format!("{}/sandboxes", self.version_prefix()),
            None,
        )?;
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

    pub fn destroy(&self, id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(
            Method::DELETE,
            &format!("{}/sandboxes/{}", self.version_prefix(), id),
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

    fn full_url(&self, path: &str) -> String {
        format!("{}{}", self.api_url, path)
    }

    fn do_json<T: Serialize, U: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        payload: Option<&T>,
    ) -> Result<U, Error> {
        let url = self.full_url(path);
        let builder = self
            .inner
            .request(method, &url)
            .bearer_auth(&self.pat_token);
        let builder = if let Some(body) = payload {
            builder.json(body)
        } else {
            builder
        };

        let response = builder.send()?;
        let response = self.handle_response(response)?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return serde_json::from_str("null").map_err(Error::SerdeJson);
        }
        response.json().map_err(Error::Reqwest)
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
            network_bytes_in_limit: None,
            network_bytes_out_limit: None,
            registry: None,
            container_command: None,
            mounts: None,
            lifecycle: None,
            runtime: None,
            gpus: None,
        }
    }

    fn request_json_body(request: &str) -> serde_json::Value {
        let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).expect("request body should be valid JSON")
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
            }
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
                }
            })
        );
        assert_eq!(
            sandbox.data.lifecycle,
            Lifecycle {
                stop_if_idle_for: 3600000000000,
                destroy_if_idle_for: 0,
                stop_at_age: 0,
                destroy_at_age: 86400000000000,
            }
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
            }
        );
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
}
