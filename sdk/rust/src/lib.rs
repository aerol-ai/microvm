mod types;

use std::fmt;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;

use futures_util::{SinkExt, StreamExt};
use http::Request;
use reqwest::blocking::{multipart::{Form, Part}, Client as HttpClient};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};

pub use types::{CreateOptions, CreateSessionOptions, ExecExitInfo, ExecRequest, ExecResult, ExposedPort, HealthStatus, RegistryAuth, ResizeOptions, Sandbox as SandboxData, Session, SessionList, SessionStatus};
pub use types::CreateSandboxResponse;

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
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
            Error::MissingToken => write!(f, "PAT token is required. Set SB_PAT_TOKEN or pass pat_token."),
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

#[derive(Clone, Debug)]
pub struct Client {
    api_url: String,
    pat_token: String,
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
        self.send_text(serde_json::json!({ "type": "resize", "cols": cols, "rows": rows }).to_string())
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
        self.send_text(serde_json::json!({ "type": "resize", "cols": cols, "rows": rows }).to_string())
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

    fn new_with_ssh_private_key(client: Client, data: SandboxData, ssh_private_key: Option<String>) -> Self {
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
        self.client.signal_session(&self.data.id, session_id, signal)
    }

    pub fn resize_session(&self, session_id: &str, cols: u16, rows: u16) -> Result<(), Error> {
        self.client.resize_session(&self.data.id, session_id, cols, rows)
    }

    pub fn session_log(&self, session_id: &str) -> Result<Vec<u8>, Error> {
        self.client.session_log(&self.data.id, session_id)
    }

    pub fn session_recording(&self, session_id: &str) -> Result<Vec<u8>, Error> {
        self.client.session_recording(&self.data.id, session_id)
    }

    pub fn attach_session(&self, session_id: &str, options: SessionAttachOptions) -> Result<SessionAttachHandle, Error> {
        self.client.attach_session(&self.data.id, session_id, options)
    }

    pub fn upload_file(&self, target_path: &str, data: Vec<u8>) -> Result<(), Error> {
        self.client.upload_file(&self.data.id, target_path, data)
    }

    pub fn download_file(&self, target_path: &str) -> Result<Vec<u8>, Error> {
        self.client.download_file(&self.data.id, target_path)
    }

    pub fn expose_port(&self, port: u16) -> Result<String, Error> {
        self.client.expose_port(&self.data.id, port)
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

    pub fn destroy(self) -> Result<(), Error> {
        self.client.destroy(&self.data.id)
    }

    pub fn resize(&mut self, options: ResizeOptions) -> Result<&Self, Error> {
        let updated = self.client.resize(&self.data.id, options)?;
        self.data = updated.data;
        Ok(self)
    }
}

impl Client {
    pub fn new(api_url: Option<&str>, pat_token: Option<&str>) -> Result<Self, Error> {
        let token = pat_token
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .or_else(|| std::env::var("SB_PAT_TOKEN").ok().filter(|value| !value.trim().is_empty()));

        let pat_token = token.ok_or(Error::MissingToken)?;
        let api_url = api_url
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .or_else(|| std::env::var("SB_API_URL").ok().filter(|value| !value.trim().is_empty()).map(|value| value.trim().trim_end_matches('/').to_string()))
            .unwrap_or_else(|| DEFAULT_API_URL.to_string());

        Ok(Client {
            api_url,
            pat_token,
            inner: HttpClient::new(),
        })
    }

    pub fn create(&self, opts: CreateOptions) -> Result<Sandbox, Error> {
        let raw = self.do_json::<CreateOptions, CreateSandboxResponse>(Method::POST, "/v1/sandboxes", Some(&opts))?;
        Ok(Sandbox::new_with_ssh_private_key(self.clone(), raw.sandbox, raw.ssh_private_key))
    }

    pub fn list(&self) -> Result<Vec<Sandbox>, Error> {
        let raw = self.do_json::<(), Vec<SandboxData>>(Method::GET, "/v1/sandboxes", None)?;
        Ok(raw.into_iter().map(|item| Sandbox::new(self.clone(), item)).collect())
    }

    pub fn get(&self, id: &str) -> Result<Sandbox, Error> {
        let raw = self.do_json::<(), SandboxData>(Method::GET, &format!("/v1/sandboxes/{}", id), None)?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn start(&self, id: &str) -> Result<Sandbox, Error> {
        let raw = self.do_json::<(), SandboxData>(Method::POST, &format!("/v1/sandboxes/{}/start", id), None)?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn stop(&self, id: &str) -> Result<Sandbox, Error> {
        let raw = self.do_json::<(), SandboxData>(Method::POST, &format!("/v1/sandboxes/{}/stop", id), None)?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn destroy(&self, id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(Method::DELETE, &format!("/v1/sandboxes/{}", id), None)
    }

    pub fn resize(&self, id: &str, opts: ResizeOptions) -> Result<Sandbox, Error> {
        let raw = self.do_json::<ResizeOptions, SandboxData>(Method::POST, &format!("/v1/sandboxes/{}/resize", id), Some(&opts))?;
        Ok(Sandbox::new(self.clone(), raw))
    }

    pub fn health(&self) -> Result<HealthStatus, Error> {
        self.do_json::<(), HealthStatus>(Method::GET, "/health", None)
    }

    pub fn exec(&self, id: &str, request: ExecRequest) -> Result<ExecResult, Error> {
        self.do_json::<ExecRequest, ExecResult>(Method::POST, &format!("/v1/sandboxes/{}/toolbox/process/execute", id), Some(&request))
    }

    pub fn create_session(&self, id: &str, opts: CreateSessionOptions) -> Result<Session, Error> {
        self.do_json::<CreateSessionOptions, Session>(Method::POST, &format!("/v1/sandboxes/{}/sessions", id), Some(&opts))
    }

    pub fn list_sessions(&self, id: &str) -> Result<Vec<Session>, Error> {
        let raw = self.do_json::<(), SessionList>(Method::GET, &format!("/v1/sandboxes/{}/sessions", id), None)?;
        Ok(raw.sessions)
    }

    pub fn get_session(&self, id: &str, session_id: &str) -> Result<Session, Error> {
        self.do_json::<(), Session>(Method::GET, &format!("/v1/sandboxes/{}/sessions/{}", id, session_id), None)
    }

    pub fn delete_session(&self, id: &str, session_id: &str) -> Result<(), Error> {
        self.do_json::<(), ()>(Method::DELETE, &format!("/v1/sandboxes/{}/sessions/{}", id, session_id), None)
    }

    pub fn signal_session(&self, id: &str, session_id: &str, signal: &str) -> Result<(), Error> {
        self.do_json::<SessionSignalRequest, ()>(
            Method::POST,
            &format!("/v1/sandboxes/{}/sessions/{}/signal", id, session_id),
            Some(&SessionSignalRequest {
                signal: signal.to_string(),
            }),
        )
    }

    pub fn resize_session(&self, id: &str, session_id: &str, cols: u16, rows: u16) -> Result<(), Error> {
        self.do_json::<SessionResizeRequest, ()>(
            Method::POST,
            &format!("/v1/sandboxes/{}/sessions/{}/resize", id, session_id),
            Some(&SessionResizeRequest { cols, rows }),
        )
    }

    pub fn session_log(&self, id: &str, session_id: &str) -> Result<Vec<u8>, Error> {
        let url = self.full_url(&format!("/v1/sandboxes/{}/sessions/{}/log", id, session_id));
        let response = self
            .inner
            .request(Method::GET, &url)
            .bearer_auth(&self.pat_token)
            .send()?;
        self.handle_response(response)?.bytes().map_err(Error::Reqwest).map(|bytes| bytes.to_vec())
    }

    pub fn session_recording(&self, id: &str, session_id: &str) -> Result<Vec<u8>, Error> {
        let url = self.full_url(&format!("/v1/sandboxes/{}/sessions/{}/recording", id, session_id));
        let response = self
            .inner
            .request(Method::GET, &url)
            .bearer_auth(&self.pat_token)
            .send()?;
        self.handle_response(response)?.bytes().map_err(Error::Reqwest).map(|bytes| bytes.to_vec())
    }

    pub fn attach_session(&self, id: &str, session_id: &str, options: SessionAttachOptions) -> Result<SessionAttachHandle, Error> {
        let (control_tx, control_rx) = unbounded_channel();
        let (done_tx, done_rx) = mpsc::channel();
        let api_url = self.api_url.clone();
        let pat_token = self.pat_token.clone();
        let sandbox_id = id.to_string();
        let session_id = session_id.to_string();

        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build();
            let result = match runtime {
                Ok(runtime) => runtime.block_on(run_session_attach(api_url, pat_token, sandbox_id, session_id, options, control_rx)),
                Err(err) => Err(Error::Runtime(err)),
            };
            let _ = done_tx.send(result);
        });

        Ok(SessionAttachHandle { control_tx, done_rx })
    }

    pub fn exec_stream(&self, id: &str, options: ExecStreamOptions) -> Result<ExecStreamHandle, Error> {
        if options.command.trim().is_empty() {
            return Err(Error::Api("command is required".to_string()));
        }

        let (control_tx, control_rx) = unbounded_channel();
        let (done_tx, done_rx) = mpsc::channel();
        let api_url = self.api_url.clone();
        let pat_token = self.pat_token.clone();
        let sandbox_id = id.to_string();

        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build();
            let result = match runtime {
                Ok(runtime) => runtime.block_on(run_exec_stream(api_url, pat_token, sandbox_id, options, control_rx)),
                Err(err) => Err(Error::Runtime(err)),
            };
            let _ = done_tx.send(result);
        });

        Ok(ExecStreamHandle { control_tx, done_rx })
    }

    pub fn upload_file(&self, id: &str, target_path: &str, data: Vec<u8>) -> Result<(), Error> {
        let file_name = Path::new(target_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file");

        let form = Form::new()
            .text("path", target_path.to_string())
            .part("file", Part::bytes(data).file_name(file_name.to_string()));

        self.do_multipart(&format!("/v1/sandboxes/{}/toolbox/files/upload", id), form)
    }

    pub fn download_file(&self, id: &str, target_path: &str) -> Result<Vec<u8>, Error> {
        let url = self.full_url(&format!("/v1/sandboxes/{}/toolbox/files/download?path={}", id, urlencoding::encode(target_path)));
        let response = self
            .inner
            .request(Method::GET, &url)
            .bearer_auth(&self.pat_token)
            .send()?;
        self.handle_response(response)?.bytes().map_err(Error::Reqwest).map(|bytes| bytes.to_vec())
    }

    pub fn expose_port(&self, id: &str, port: u16) -> Result<String, Error> {
        let response = self.do_json::<(), Value>(Method::POST, &format!("/v1/sandboxes/{}/ports/{}", id, port), None)?;
        response
            .get("public_url")
            .and_then(|value| value.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Api("missing public_url in response".to_string()))
    }

    pub fn unexpose_port(&self, id: &str, port: u16) -> Result<(), Error> {
        self.do_json::<(), ()>(Method::DELETE, &format!("/v1/sandboxes/{}/ports/{}", id, port), None)
    }

    fn full_url(&self, path: &str) -> String {
        format!("{}{}", self.api_url, path)
    }

    fn do_json<T: Serialize, U: DeserializeOwned>(&self, method: Method, path: &str, payload: Option<&T>) -> Result<U, Error> {
        let url = self.full_url(path);
        let builder = self.inner.request(method, &url).bearer_auth(&self.pat_token);
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

    fn handle_response(&self, response: reqwest::blocking::Response) -> Result<reqwest::blocking::Response, Error> {
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
    pat_token: String,
    sandbox_id: String,
    options: ExecStreamOptions,
    mut control_rx: tokio::sync::mpsc::UnboundedReceiver<ControlMessage>,
) -> Result<ExecExitInfo, Error> {
    let ws_url = websocket_url(&api_url, &format!("/v1/sandboxes/{}/toolbox/process/exec/stream", urlencoding::encode(&sandbox_id)))?;
    let request = Request::builder()
        .uri(&ws_url)
        .header("Authorization", format!("Bearer {}", pat_token))
        .body(())?;

    let (stream, _) = connect_async(request).await?;
    let (mut write, mut read) = stream.split();

    let start = ExecStreamStartRequest {
        command: options.command.clone(),
        workdir: options.workdir.clone(),
        env: options.env.clone(),
        tty: options.tty,
        cols: options.cols,
        rows: options.rows,
    };
    write.send(Message::Text(serde_json::to_string(&start)?.into())).await?;

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
    pat_token: String,
    sandbox_id: String,
    session_id: String,
    options: SessionAttachOptions,
    mut control_rx: tokio::sync::mpsc::UnboundedReceiver<ControlMessage>,
) -> Result<ExecExitInfo, Error> {
    let ws_url = websocket_url(
        &api_url,
        &format!(
            "/v1/sandboxes/{}/sessions/{}/attach",
            urlencoding::encode(&sandbox_id),
            urlencoding::encode(&session_id)
        ),
    )?;
    let request = Request::builder()
        .uri(&ws_url)
        .header("Authorization", format!("Bearer {}", pat_token))
        .body(())?;

    let (stream, _) = connect_async(request).await?;
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
            stream.write_all(response.as_bytes()).expect("response should write");
            stream.write_all(&body).expect("response body should write");
        });

        (format!("http://{}", addr), request_rx)
    }

    fn spawn_session_attach_server() -> (String, std::sync::mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener address");
        listener.set_nonblocking(true).expect("listener should be non-blocking");
        let (control_tx, control_rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build().expect("runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener should build");
                let (stream, _) = listener.accept().await.expect("server should accept");
                let ws_stream = accept_async(stream).await.expect("websocket should accept");
                let (mut write, mut read) = ws_stream.split();

                for _ in 0..4 {
                    match read.next().await {
                        Some(Ok(Message::Text(text))) => {
                            control_tx.send(text.to_string()).expect("text control should send");
                        }
                        Some(Ok(Message::Binary(payload))) => {
                            control_tx.send(format!("binary:{}", String::from_utf8_lossy(&payload))).expect("binary control should send");
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => panic!("websocket read failed: {}", err),
                        None => panic!("websocket closed early"),
                    }
                }

                write
                    .send(Message::Binary([vec![STREAM_PREFIX_STDOUT], b"hello".to_vec()].concat().into()))
                    .await
                    .expect("stdout frame should send");
                write
                    .send(Message::Binary([vec![STREAM_PREFIX_STDERR], b"warn".to_vec()].concat().into()))
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
            registry: None,
            container_command: None,
        }
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
        let ws = websocket_url("https://sandbox.example.com", "/v1/sandboxes/sb/toolbox/process/exec/stream").expect("ws url");
        assert_eq!(ws, "wss://sandbox.example.com/v1/sandboxes/sb/toolbox/process/exec/stream");
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
        let sandbox = client.create(minimal_create_options()).expect("create should succeed");
        let request = request_rx.recv().expect("request should be captured");
        let request_lower = request.to_ascii_lowercase();

        assert!(request.starts_with("POST /v1/sandboxes HTTP/1.1\r\n"), "unexpected request: {}", request);
        assert!(request_lower.contains("authorization: bearer pat-token"), "missing bearer auth: {}", request);
        assert_eq!(sandbox.data.ssh_public_key.as_deref(), Some("ssh-ed25519 AAAA sandbox"));
        assert_eq!(sandbox.ssh_private_key.as_deref(), Some("PRIVATE"));
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

        assert!(request.starts_with("POST /v1/sandboxes/sb-1/sessions HTTP/1.1\r\n"), "unexpected request: {}", request);
        assert!(request_lower.contains("authorization: bearer pat-token"), "missing bearer auth: {}", request);
        assert!(request.contains("\"command\":\"bash\""), "missing command: {}", request);
        assert!(request.contains("\"workdir\":\"/workspace\""), "missing workdir: {}", request);
        assert_eq!(session.status, SessionStatus::Running);
        assert_eq!(session.argv, vec!["sh".to_string(), "-c".to_string(), "bash".to_string()]);
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
        let (url, _) = spawn_json_server(body);

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let sessions = client.list_sessions("sb-1").expect("list sessions should succeed");

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].name, "default");
        assert_eq!(sessions[0].status, SessionStatus::Running);
    }

    #[test]
    fn delete_session_accepts_no_content() {
        let (url, request_rx) = spawn_response_server("204 No Content", "application/json", Vec::new());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        client.delete_session("sb-1", "ses-1").expect("delete session should succeed");
        let request = request_rx.recv().expect("request should be captured");

        assert!(request.starts_with("DELETE /v1/sandboxes/sb-1/sessions/ses-1 HTTP/1.1\r\n"), "unexpected request: {}", request);
    }

    #[test]
    fn session_log_returns_bytes() {
        let (url, _) = spawn_response_server("200 OK", "text/plain", b"session log".to_vec());

        let client = Client::new(Some(&url), Some("pat-token")).expect("client should build");
        let body = client.session_log("sb-1", "ses-1").expect("session log should succeed");

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
                    on_stdout: Some(Arc::new(move |chunk| stdout_capture.lock().expect("stdout lock").push(chunk))),
                    on_stderr: Some(Arc::new(move |chunk| stderr_capture.lock().expect("stderr lock").push(chunk))),
                    on_error: Some(Arc::new(move |message| error_capture.lock().expect("error lock").push(message))),
                    on_exit: Some(Arc::new(move |info| exit_capture.lock().expect("exit lock").push(info))),
                },
            )
            .expect("attach session should succeed");

        handle.write_string("pwd\n").expect("stdin write should succeed");
        handle.resize(100, 30).expect("resize should succeed");
        handle.signal("INT").expect("signal should succeed");
        let result = handle.wait().expect("attach should exit cleanly");

        assert_eq!(result, ExecExitInfo { code: 0, signal: Some("TERM".to_string()) });
        assert_eq!(stdout_chunks.lock().expect("stdout lock").clone(), vec![b"hello".to_vec()]);
        assert_eq!(stderr_chunks.lock().expect("stderr lock").clone(), vec![b"warn".to_vec()]);
        assert!(error_messages.lock().expect("error lock").is_empty());
        assert_eq!(exits.lock().expect("exit lock").clone(), vec![ExecExitInfo { code: 0, signal: Some("TERM".to_string()) }]);
        assert_eq!(control_rx.recv().expect("initial resize should be captured"), "{\"type\":\"resize\",\"cols\":120,\"rows\":40}");
        assert_eq!(control_rx.recv().expect("stdin should be captured"), "binary:pwd\n");
        assert_eq!(control_rx.recv().expect("resize should be captured"), "{\"type\":\"resize\",\"cols\":100,\"rows\":30}");
        assert_eq!(control_rx.recv().expect("signal should be captured"), "{\"type\":\"signal\",\"signal\":\"INT\"}");
    }
}
