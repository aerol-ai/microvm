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

pub use types::{CreateOptions, ExecExitInfo, ExecRequest, ExecResult, ExposedPort, HealthStatus, RegistryAuth, ResizeOptions, Sandbox as SandboxData};

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";
const STREAM_PREFIX_STDOUT: u8 = 0x01;
const STREAM_PREFIX_STDERR: u8 = 0x02;

pub type StreamCallback = Arc<dyn Fn(Vec<u8>) + Send + Sync + 'static>;
pub type ErrorCallback = Arc<dyn Fn(String) + Send + Sync + 'static>;

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
}

pub struct ExecStreamHandle {
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

impl Sandbox {
    fn new(client: Client, data: SandboxData) -> Self {
        Sandbox { client, data }
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
        let raw = self.do_json::<CreateOptions, SandboxData>(Method::POST, "/v1/sandboxes", Some(&opts))?;
        Ok(Sandbox::new(self.clone(), raw))
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
        self.handle_response(response)?.json().map_err(Error::Reqwest)
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
}
