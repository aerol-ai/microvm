//! The stateful code interpreter (plans/code-interpreter.md): a Python
//! (or JavaScript, TypeScript, Bash, R, Java) process that stays open in the
//! sandbox, so variables set by one run are there for the next.
//!
//! Contexts are managed over REST and each run is one WebSocket, all through
//! the sandbox's toolbox. Every call first checks that the sandbox's agent
//! lists `code.interpreter` on `/version`; an older agent gives
//! [`Error::UnsupportedFeature`] and nothing else is sent.
//!
//! Retries: listing, reading and deleting contexts retry like any safe call.
//! Creating and restarting a context retry only when the server provably did
//! nothing (a refused connection, 429, 503), and a run is never re-sent,
//! because a second send would run the code twice.

use std::collections::HashMap;
use std::fmt;
use std::sync::{mpsc, Arc};
use std::thread;

use futures_util::{SinkExt, StreamExt};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::runtime::Builder;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

use crate::{decorate_ws_handshake, Client, Error, RetryPolicy, Sandbox, WsDial};

/// The toolboxd feature (on `/version`) behind every interpreter route. An
/// older agent answers the routes with 501 or not at all; checking first
/// gives one clear error instead.
const FEATURE_CODE_INTERPRETER: &str = "code.interpreter";

/// The close code the server ends a run with when its timeout fired.
const CLOSE_TIMEOUT: u16 = 4008;
/// What a close frame with no status reads as (RFC 6455, 7.1.5).
const CLOSE_NO_STATUS: u16 = 1005;
/// What a connection that ended without a close frame reads as.
const CLOSE_ABNORMAL: u16 = 1006;
/// The close code [`CodeRunHandle::close`] sends and reports.
const CLOSE_GOING_AWAY: u16 = 1001;

/// One interpreter context: an interpreter process the sandbox keeps open.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeContext {
    pub id: String,
    /// `python`, `javascript`, `typescript`, `bash`, `r` or `java`.
    #[serde(default)]
    pub language: String,
    /// The folder the context's code starts in.
    #[serde(default)]
    pub cwd: String,
    /// When the context was made, as the server wrote it (RFC 3339).
    #[serde(rename = "createdAt", default)]
    pub created_at: String,
    /// False after the context's process died or was stopped; its next run
    /// starts a new process (variables are gone).
    #[serde(default)]
    pub active: bool,
}

/// Options for [`Client::create_code_context`]. Unset fields take the
/// server's defaults: python, and the sandbox's working folder.
#[derive(Serialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeContextOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

#[derive(Deserialize)]
struct CodeContextList {
    #[serde(default)]
    contexts: Option<Vec<CodeContext>>,
}

/// One rich output of a run, such as the value of the last line, a chart or
/// a table. A field is `None` when the output does not have that format.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CodeResult {
    pub text: Option<String>,
    pub html: Option<String>,
    pub markdown: Option<String>,
    pub svg: Option<String>,
    /// A PNG image, base64 encoded (for example a matplotlib chart).
    pub png: Option<String>,
    /// A JPEG image, base64 encoded.
    pub jpeg: Option<String>,
    pub pdf: Option<String>,
    pub latex: Option<String>,
    pub json: Option<Value>,
    pub javascript: Option<String>,
    /// Table data (for example a pandas DataFrame).
    pub data: Option<Value>,
    /// Formats the fields above do not name, keyed by their name.
    pub extra: Option<Map<String, Value>>,
    /// True for the value of the run's last line, the result
    /// [`Execution::text`] reads.
    pub is_main_result: bool,
}

impl CodeResult {
    fn from_frame(frame: &Value) -> Self {
        let text = |name: &str| {
            frame
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(String::from)
        };
        // Result frames always carry "text", so an empty string means the
        // result has no text, not an empty one.
        let object = |name: &str| frame.get(name).filter(|value| !value.is_null()).cloned();
        CodeResult {
            text: text("text"),
            html: text("html"),
            markdown: text("markdown"),
            svg: text("svg"),
            png: text("png"),
            jpeg: text("jpeg"),
            pdf: text("pdf"),
            latex: text("latex"),
            json: object("json"),
            javascript: text("javascript"),
            data: object("data"),
            extra: frame.get("extra").and_then(Value::as_object).cloned(),
            is_main_result: frame.get("is_main_result").and_then(Value::as_bool).unwrap_or(false),
        }
    }

    /// The formats this result has: `text`, `html`, `markdown`, `svg`,
    /// `png`, `jpeg`, `pdf`, `latex`, `json`, `javascript` and `data` in
    /// that order when present, then the names in `extra`, sorted.
    pub fn formats(&self) -> Vec<String> {
        let named = [
            ("text", self.text.is_some()),
            ("html", self.html.is_some()),
            ("markdown", self.markdown.is_some()),
            ("svg", self.svg.is_some()),
            ("png", self.png.is_some()),
            ("jpeg", self.jpeg.is_some()),
            ("pdf", self.pdf.is_some()),
            ("latex", self.latex.is_some()),
            ("json", self.json.is_some()),
            ("javascript", self.javascript.is_some()),
            ("data", self.data.is_some()),
        ];
        let mut out: Vec<String> = named
            .iter()
            .filter(|(_, present)| *present)
            .map(|(name, _)| name.to_string())
            .collect();
        if let Some(extra) = &self.extra {
            let mut keys: Vec<String> = extra.keys().cloned().collect();
            keys.sort();
            out.extend(keys);
        }
        out
    }
}

/// The exception the run's code raised. The run still ends normally: this
/// is the code's error, not the SDK's.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionError {
    /// The exception's type, such as `NameError`.
    pub name: String,
    /// The exception's message.
    pub value: String,
    pub traceback: String,
}

/// Everything a run printed, chunk by chunk as it arrived.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionLogs {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
}

/// What a run produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Execution {
    pub results: Vec<CodeResult>,
    pub logs: ExecutionLogs,
    /// Set when the code raised an exception.
    pub error: Option<ExecutionError>,
    /// The context's run counter, when the server reported it.
    pub execution_count: Option<i64>,
    /// True when the run was stopped by an interrupt.
    pub interrupted: bool,
}

impl Execution {
    /// The text of the main result (the value of the run's last line), or
    /// `None` when there is none.
    pub fn text(&self) -> Option<&str> {
        self.results
            .iter()
            .find(|result| result.is_main_result)
            .and_then(|result| result.text.as_deref())
    }
}

/// A run that did not end normally, returned as [`Error::CodeRun`]: the
/// server's run timeout fired ([`CodeRunError::is_timeout`]), the server
/// refused or ended the run (`context not found: <id>`, `code is required`,
/// `worker process ended`), or the connection dropped. It carries what the
/// run produced before that.
#[derive(Debug, Clone, PartialEq)]
pub struct CodeRunError {
    close_code: u16,
    reason: String,
    // Boxed so Error, which every call returns, stays as small as it was.
    execution: Box<Execution>,
}

impl CodeRunError {
    /// The WebSocket close code: 4008 for the run timeout, 1006 when the
    /// connection ended without a close frame, 1001 after
    /// [`CodeRunHandle::close`].
    pub fn close_code(&self) -> u16 {
        self.close_code
    }

    /// The close frame's reason, empty when it had none.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// What the run produced before it ended.
    pub fn execution(&self) -> &Execution {
        &self.execution
    }

    /// Takes the partial [`Execution`].
    pub fn into_execution(self) -> Execution {
        *self.execution
    }

    /// The server's run timeout fired (close code 4008).
    pub fn is_timeout(&self) -> bool {
        self.close_code == CLOSE_TIMEOUT
    }
}

impl fmt::Display for CodeRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_timeout() {
            write!(f, "code run timed out")?;
        } else {
            write!(f, "code run failed (close {})", self.close_code)?;
        }
        if !self.reason.is_empty() {
            write!(f, ": {}", self.reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for CodeRunError {}

/// Called with each chunk a run prints.
pub type TextCallback = Arc<dyn Fn(String) + Send + Sync + 'static>;
/// Called with each rich result as it arrives.
pub type CodeResultCallback = Arc<dyn Fn(CodeResult) + Send + Sync + 'static>;
/// Called with the exception the run's code raised.
pub type ExecutionErrorCallback = Arc<dyn Fn(ExecutionError) + Send + Sync + 'static>;

/// Options for [`Client::run_code`]. With neither `context_id` nor
/// `language`, the code runs in the sandbox's default python context.
/// Callbacks run on the run's own thread, in the order the server sent.
#[derive(Default, Clone)]
pub struct RunCodeOptions {
    /// Run in this context (see [`RunCodeOptions::in_context`]).
    pub context_id: Option<String>,
    /// Run in this language's default context. Set `context_id` or
    /// `language`, not both.
    pub language: Option<String>,
    /// Environment variables for this run only.
    pub envs: Option<HashMap<String, String>>,
    /// Stop the run after this many seconds: the server interrupts it and
    /// the call returns an [`Error::CodeRun`] whose `is_timeout()` is true.
    /// `None` takes the server's default (600 s); `Some(0)` means no limit.
    pub timeout_seconds: Option<u64>,
    pub on_stdout: Option<TextCallback>,
    pub on_stderr: Option<TextCallback>,
    pub on_result: Option<CodeResultCallback>,
    pub on_error: Option<ExecutionErrorCallback>,
}

impl RunCodeOptions {
    /// Options that run in `context`; set the other fields with struct
    /// update syntax: `RunCodeOptions { timeout_seconds: Some(5),
    /// ..RunCodeOptions::in_context(&context) }`.
    pub fn in_context(context: &CodeContext) -> Self {
        RunCodeOptions {
            context_id: Some(context.id.clone()),
            ..Default::default()
        }
    }
}

#[derive(Serialize)]
struct RunCodeStart<'a> {
    code: &'a str,
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    context_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    language: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    envs: Option<&'a HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<u64>,
    /// Asks for result and execution_count frames, which a Daytona client
    /// (same route, same protocol otherwise) never gets.
    #[serde(rename = "richOutput")]
    rich_output: bool,
}

/// The value when it is set to something other than blanks.
fn given(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.trim().is_empty())
}

/// The run's start frame, or the reason not to send one.
fn start_frame(code: &str, options: &RunCodeOptions) -> Result<String, Error> {
    let context_id = given(&options.context_id);
    let language = given(&options.language);
    if context_id.is_some() && language.is_some() {
        // The server would run in the context and ignore the language.
        return Err(Error::Client("set context or language, not both".to_string()));
    }
    let start = RunCodeStart {
        code,
        context_id,
        language,
        envs: options.envs.as_ref().filter(|envs| !envs.is_empty()),
        timeout: options.timeout_seconds,
        rich_output: true,
    };
    Ok(serde_json::to_string(&start)?)
}

enum RunControl {
    Interrupt,
    Close,
}

/// A running piece of code, from [`Client::start_code`].
pub struct CodeRunHandle {
    control_tx: UnboundedSender<RunControl>,
    done_rx: mpsc::Receiver<Result<Execution, Error>>,
}

impl CodeRunHandle {
    /// Asks the server to stop the run, as Ctrl-C would. The run then ends
    /// normally and [`wait`](CodeRunHandle::wait) returns an [`Execution`]
    /// whose `interrupted` is true. Code that ignores the interrupt keeps
    /// running until its timeout. [`Error::ChannelClosed`] once the run has
    /// ended.
    pub fn interrupt(&self) -> Result<(), Error> {
        self.control_tx
            .send(RunControl::Interrupt)
            .map_err(|_| Error::ChannelClosed)
    }

    /// Stops listening. This does not stop the run: the sandbox finishes it
    /// and its output is dropped. [`wait`](CodeRunHandle::wait) then returns
    /// [`Error::CodeRun`] with close code 1001. Calling it after the run
    /// ended does nothing.
    pub fn close(&self) {
        // The run is over when the channel is gone; nothing to close.
        let _ = self.control_tx.send(RunControl::Close);
    }

    /// Blocks until the run ends and returns what it produced.
    pub fn wait(self) -> Result<Execution, Error> {
        self.done_rx.recv().map_err(|_| Error::ChannelClosed)?
    }
}

/// How the run's socket ended, turned into the call's result.
fn finish(close_code: u16, reason: String, execution: Execution) -> Result<Execution, Error> {
    if close_code == 1000 || close_code == CLOSE_NO_STATUS {
        return Ok(execution);
    }
    Err(Error::CodeRun(CodeRunError {
        close_code,
        reason,
        execution: Box::new(execution),
    }))
}

/// Applies one server frame to the run. Frames the SDK does not know (a
/// newer server's) and frames that are not JSON are skipped.
fn apply_frame(text: &str, options: &RunCodeOptions, execution: &mut Execution) {
    let Ok(frame) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let field = |name: &str| frame.get(name).and_then(Value::as_str).unwrap_or_default().to_string();
    match frame.get("type").and_then(Value::as_str).unwrap_or_default() {
        "stdout" => {
            let chunk = field("text");
            execution.logs.stdout.push(chunk.clone());
            if let Some(callback) = &options.on_stdout {
                callback(chunk);
            }
        }
        "stderr" => {
            let chunk = field("text");
            execution.logs.stderr.push(chunk.clone());
            if let Some(callback) = &options.on_stderr {
                callback(chunk);
            }
        }
        "result" => {
            let result = CodeResult::from_frame(&frame);
            execution.results.push(result.clone());
            if let Some(callback) = &options.on_result {
                callback(result);
            }
        }
        "execution_count" => {
            if let Some(count) = frame.get("count").and_then(Value::as_i64) {
                execution.execution_count = Some(count);
            }
        }
        "error" => {
            let error = ExecutionError {
                name: field("name"),
                value: field("value"),
                traceback: field("traceback"),
            };
            execution.error = Some(error.clone());
            if let Some(callback) = &options.on_error {
                callback(error);
            }
        }
        // The close frame that follows decides how the run ended; a
        // timeout can still close 4008 after the interrupted control.
        "control" if field("text") == "interrupted" => execution.interrupted = true,
        _ => {}
    }
}

async fn run_code_stream(
    dial: WsDial,
    sandbox_id: String,
    start: String,
    options: RunCodeOptions,
    mut control_rx: UnboundedReceiver<RunControl>,
) -> Result<Execution, Error> {
    let route = format!(
        "{}/sandboxes/{}/toolbox/process/interpreter/execute",
        dial.api_version.path_prefix(),
        urlencoding::encode(&sandbox_id)
    );
    let stream = dial
        .connect(&route, |err| decorate_ws_handshake("code run", err))
        .await?;
    let (mut write, mut read) = stream.split();
    write.send(Message::Text(start.into())).await?;

    let mut execution = Execution::default();
    loop {
        tokio::select! {
            Some(control) = control_rx.recv() => match control {
                RunControl::Interrupt => {
                    // A failed send means the connection is gone; the read
                    // side reports how it ended.
                    let _ = write
                        .send(Message::Text(serde_json::json!({ "type": "interrupt" }).to_string().into()))
                        .await;
                }
                RunControl::Close => {
                    let reason = "closed by the client before the run ended";
                    let _ = write
                        .send(Message::Close(Some(CloseFrame {
                            code: CloseCode::from(CLOSE_GOING_AWAY),
                            reason: reason.into(),
                        })))
                        .await;
                    return finish(CLOSE_GOING_AWAY, reason.to_string(), execution);
                }
            },
            message = read.next() => match message {
                Some(Ok(Message::Text(text))) => apply_frame(text.as_ref(), &options, &mut execution),
                Some(Ok(Message::Close(frame))) => {
                    let (code, reason) = frame
                        .map(|frame| (u16::from(frame.code), frame.reason.to_string()))
                        .unwrap_or((CLOSE_NO_STATUS, String::new()));
                    return finish(code, reason, execution);
                }
                Some(Ok(_)) => {}
                Some(Err(err)) => return finish(CLOSE_ABNORMAL, err.to_string(), execution),
                None => {
                    return finish(CLOSE_ABNORMAL, "connection ended without a close frame".to_string(), execution)
                }
            },
        }
    }
}

impl Client {
    fn interpreter_path(&self, id: &str, route: &str) -> String {
        format!(
            "{}/sandboxes/{}/toolbox/process/interpreter{}",
            self.version_prefix(),
            urlencoding::encode(id),
            route
        )
    }

    fn context_path(&self, id: &str, context_id: &str, route: &str) -> Result<String, Error> {
        let context_id = context_id.trim();
        if context_id.is_empty() {
            return Err(Error::Client("context id is required".to_string()));
        }
        Ok(self.interpreter_path(
            id,
            &format!("/context/{}{}", urlencoding::encode(context_id), route),
        ))
    }

    /// Makes a new interpreter context in sandbox `id`: its own process,
    /// with its own variables. Each call makes another one, so a failure
    /// after the request was sent is returned, not retried. Over the
    /// sandbox's context limit the server answers 429.
    ///
    /// Needs an agent that lists `code.interpreter`; an older one gives
    /// [`Error::UnsupportedFeature`].
    pub fn create_code_context(&self, id: &str, options: CodeContextOptions) -> Result<CodeContext, Error> {
        self.require_toolbox_features(id, &[FEATURE_CODE_INTERPRETER])?;
        let (context, _) = self.send_json::<CodeContextOptions, CodeContext>(
            Method::POST,
            &self.interpreter_path(id, "/context"),
            Some(&options),
            RetryPolicy::UnsentOnly,
        )?;
        Ok(context)
    }

    /// Lists the contexts made with [`Client::create_code_context`]. The
    /// default python context is not listed.
    pub fn list_code_contexts(&self, id: &str) -> Result<Vec<CodeContext>, Error> {
        self.require_toolbox_features(id, &[FEATURE_CODE_INTERPRETER])?;
        let list = self.do_json::<(), Option<CodeContextList>>(
            Method::GET,
            &self.interpreter_path(id, "/context"),
            None,
        )?;
        Ok(list.and_then(|list| list.contexts).unwrap_or_default())
    }

    /// Reads one context. An unknown id gives a 404 [`Error::Api`].
    pub fn get_code_context(&self, id: &str, context_id: &str) -> Result<CodeContext, Error> {
        let path = self.context_path(id, context_id, "")?;
        self.require_toolbox_features(id, &[FEATURE_CODE_INTERPRETER])?;
        self.do_json::<(), CodeContext>(Method::GET, &path, None)
    }

    /// Deletes a context and stops its process. An unknown id gives a 404
    /// [`Error::Api`]; the default context cannot be deleted (400).
    pub fn delete_code_context(&self, id: &str, context_id: &str) -> Result<(), Error> {
        let path = self.context_path(id, context_id, "")?;
        self.require_toolbox_features(id, &[FEATURE_CODE_INTERPRETER])?;
        self.do_json::<(), Value>(Method::DELETE, &path, None)?;
        Ok(())
    }

    /// Restarts a context's process: same id, all variables gone. Like
    /// create, a failure after the request was sent is not retried.
    pub fn restart_code_context(&self, id: &str, context_id: &str) -> Result<CodeContext, Error> {
        let path = self.context_path(id, context_id, "/restart")?;
        self.require_toolbox_features(id, &[FEATURE_CODE_INTERPRETER])?;
        let (context, _) = self.send_json::<(), CodeContext>(Method::POST, &path, None, RetryPolicy::UnsentOnly)?;
        Ok(context)
    }

    /// Runs `code` in sandbox `id` and waits for it to end, calling the
    /// options' callbacks as output arrives. The code's own exception is in
    /// [`Execution::error`], not an `Err`. A run the server ended early is
    /// an [`Error::CodeRun`] (`is_timeout()` for the run timeout) carrying
    /// the partial [`Execution`].
    ///
    /// The run is sent once and never retried. To stop it early, use
    /// [`Client::start_code`] and [`CodeRunHandle::interrupt`]; dropping the
    /// connection does not stop it. Needs an agent that lists
    /// `code.interpreter`; an older one gives [`Error::UnsupportedFeature`].
    pub fn run_code(&self, id: &str, code: &str, options: RunCodeOptions) -> Result<Execution, Error> {
        self.start_code(id, code, options)?.wait()
    }

    /// [`Client::run_code`] without waiting: the returned handle can
    /// interrupt the run and wait for it.
    pub fn start_code(&self, id: &str, code: &str, options: RunCodeOptions) -> Result<CodeRunHandle, Error> {
        let start = start_frame(code, &options)?;
        // Before the socket opens, so an older agent never gets a run.
        self.require_toolbox_features(id, &[FEATURE_CODE_INTERPRETER])?;

        let (control_tx, control_rx) = unbounded_channel();
        let (done_tx, done_rx) = mpsc::channel();
        let dial = self.ws_dial();
        let sandbox_id = id.to_string();
        thread::spawn(move || {
            let result = match Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(run_code_stream(dial, sandbox_id, start, options, control_rx)),
                Err(err) => Err(Error::Runtime(err)),
            };
            let _ = done_tx.send(result);
        });
        Ok(CodeRunHandle { control_tx, done_rx })
    }
}

impl Sandbox {
    /// Makes a new interpreter context in this sandbox. See
    /// [`Client::create_code_context`].
    pub fn create_code_context(&self, options: CodeContextOptions) -> Result<CodeContext, Error> {
        self.client.create_code_context(&self.data.id, options)
    }

    /// Lists this sandbox's interpreter contexts. See
    /// [`Client::list_code_contexts`].
    pub fn list_code_contexts(&self) -> Result<Vec<CodeContext>, Error> {
        self.client.list_code_contexts(&self.data.id)
    }

    /// Reads one interpreter context. See [`Client::get_code_context`].
    pub fn get_code_context(&self, context_id: &str) -> Result<CodeContext, Error> {
        self.client.get_code_context(&self.data.id, context_id)
    }

    /// Deletes an interpreter context. See [`Client::delete_code_context`].
    pub fn delete_code_context(&self, context_id: &str) -> Result<(), Error> {
        self.client.delete_code_context(&self.data.id, context_id)
    }

    /// Restarts an interpreter context. See [`Client::restart_code_context`].
    pub fn restart_code_context(&self, context_id: &str) -> Result<CodeContext, Error> {
        self.client.restart_code_context(&self.data.id, context_id)
    }

    /// Runs code in this sandbox and waits for it. See [`Client::run_code`].
    pub fn run_code(&self, code: &str, options: RunCodeOptions) -> Result<Execution, Error> {
        self.client.run_code(&self.data.id, code, options)
    }

    /// Starts code in this sandbox. See [`Client::start_code`].
    pub fn start_code(&self, code: &str, options: RunCodeOptions) -> Result<CodeRunHandle, Error> {
        self.client.start_code(&self.data.id, code, options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiVersion, ClientConfig, RetryConfig, SandboxData};
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const AGENT: &str = r#"{"version":"0.7.6","features":["code.interpreter"]}"#;
    const OLD_AGENT: &str = r#"{"version":"0.7.5","features":["exec.argv"]}"#;

    /// One thing the fake toolbox does on a run's WebSocket, in order.
    #[derive(Clone)]
    enum Step {
        /// Send a JSON text frame.
        Send(Value),
        /// Send this frame as it is (non-JSON text, binary).
        Raw(Message),
        /// Wait for the client's next text frame and log it as `ws recv`.
        AwaitText,
        /// Send a close frame with this code and reason.
        Close(u16, &'static str),
        /// Send a close frame with no status.
        CloseEmpty,
        /// Drop the connection without a close frame.
        Drop,
        /// Wait until the client closes, then log `client closed <code>`.
        AwaitClientClose,
        /// Refuse the handshake with this HTTP status and JSON body.
        Refuse(u16, &'static str),
    }

    /// Answers an interpreter REST call, given its request line and body.
    type Rest = fn(&str, &str) -> (u16, String);

    struct Fake {
        client: Client,
        /// Every request line, body and frame the fake saw, in order.
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Fake {
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        /// The JSON start frames the client sent, in order.
        fn starts(&self) -> Vec<Value> {
            self.log()
                .iter()
                .filter_map(|line| line.strip_prefix("ws start "))
                .map(|text| serde_json::from_str(text).expect("start frame is JSON"))
                .collect()
        }

        fn sandbox(&self) -> Sandbox {
            let data: SandboxData = serde_json::from_value(serde_json::json!({
                "id": "sb-1", "image": "x", "status": "started", "public_url": "", "cpu": 1, "memory_mb": 1,
                "disk_gb": 1, "os_user": "root", "network_block_all": false, "toolbox_enabled": true,
                "created_at": "", "updated_at": "", "last_active_at": "", "lifecycle": {}
            }))
            .expect("sandbox data");
            Sandbox::new(self.client.clone(), data)
        }
    }

    fn rest_not_found(_: &str, _: &str) -> (u16, String) {
        (404, r#"{"error":"not found","message":"not found"}"#.to_string())
    }

    /// A stand-in for sandboxd's toolbox pass-through. `/version` answers
    /// `version`, other HTTP calls go to `rest`, and every run's WebSocket
    /// plays `steps`.
    fn fake(version: &'static str, rest: Rest, steps: Vec<Step>) -> Fake {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener address");
        listener.set_nonblocking(true).expect("non-blocking");
        let log = Arc::new(Mutex::new(Vec::new()));
        let server_log = log.clone();
        thread::spawn(move || {
            let runtime = Builder::new_current_thread().enable_all().build().expect("runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                loop {
                    let Ok((stream, _)) = listener.accept().await else { return };
                    if is_upgrade(&stream).await {
                        serve_run(stream, &steps, &server_log).await;
                    } else {
                        serve_rest(stream, version, rest, &server_log).await;
                    }
                }
            });
        });
        let client = Client::with_config(
            ClientConfig {
                api_url: Some(format!("http://{}", addr)),
                pat_token: Some("pat".to_string()),
                retry: Some(RetryConfig {
                    max_retries: Some(3),
                    base_delay_ms: Some(1),
                    max_delay_ms: Some(1),
                    max_retry_after_ms: None,
                }),
                ..Default::default()
            },
            ApiVersion::V1,
        )
        .expect("client should build");
        Fake { client, log }
    }

    /// Whether the connection's request asks for a WebSocket, read without
    /// consuming it so the handshake can still read it.
    async fn is_upgrade(stream: &tokio::net::TcpStream) -> bool {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = stream.peek(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return false;
            }
            let head = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            if head.contains("\r\n\r\n") {
                return head.contains("upgrade: websocket");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    async fn read_head(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                break;
            }
            buf.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse().ok())
            .unwrap_or(0usize);
        let mut body = vec![0u8; length];
        let _ = stream.read_exact(&mut body).await;
        (head, body)
    }

    async fn respond(stream: &mut tokio::net::TcpStream, status: u16, body: &str) {
        let head = format!(
            "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status,
            body.len()
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(body.as_bytes()).await;
        let _ = stream.shutdown().await;
    }

    async fn serve_rest(mut stream: tokio::net::TcpStream, version: &str, rest: Rest, log: &Mutex<Vec<String>>) {
        let (head, body) = read_head(&mut stream).await;
        let line = head.lines().next().unwrap_or_default().trim_end_matches(" HTTP/1.1").to_string();
        let body = String::from_utf8_lossy(&body).to_string();
        log.lock().unwrap().push(line.clone());
        if !body.is_empty() {
            log.lock().unwrap().push(format!("body {}", body));
        }
        let (status, reply) = if line.ends_with("/toolbox/version") {
            (200, version.to_string())
        } else {
            rest(&line, &body)
        };
        respond(&mut stream, status, &reply).await;
    }

    // tungstenite fixes the handshake callback's error type (a whole HTTP
    // response), which clippy calls large.
    #[allow(clippy::result_large_err)]
    async fn serve_run(mut stream: tokio::net::TcpStream, steps: &[Step], log: &Mutex<Vec<String>>) {
        if let Some(Step::Refuse(status, body)) = steps.first() {
            let (head, _) = read_head(&mut stream).await;
            log.lock().unwrap().push(format!("ws refused {}", head.lines().next().unwrap_or_default()));
            respond(&mut stream, *status, body).await;
            return;
        }
        let ws = tokio_tungstenite::accept_hdr_async(
            stream,
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                let auth = request
                    .headers()
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                log.lock().unwrap().push(format!("ws {} auth {}", request.uri(), auth));
                Ok(response)
            },
        )
        .await
        .expect("websocket should accept");
        let (mut write, mut read) = ws.split();
        let start = match read.next().await {
            Some(Ok(Message::Text(text))) => text.to_string(),
            other => panic!("want a start frame, got {:?}", other),
        };
        log.lock().unwrap().push(format!("ws start {}", start));
        for step in steps {
            match step {
                Step::Send(frame) => {
                    write.send(Message::Text(frame.to_string().into())).await.expect("frame should send");
                }
                Step::Raw(message) => write.send(message.clone()).await.expect("frame should send"),
                Step::AwaitText => loop {
                    match read.next().await {
                        Some(Ok(Message::Text(text))) => {
                            log.lock().unwrap().push(format!("ws recv {}", text));
                            break;
                        }
                        Some(Ok(_)) => {}
                        other => panic!("want a client text frame, got {:?}", other),
                    }
                },
                Step::Close(code, reason) => {
                    let frame = CloseFrame { code: CloseCode::from(*code), reason: (*reason).into() };
                    let _ = write.send(Message::Close(Some(frame))).await;
                    break;
                }
                Step::CloseEmpty => {
                    let _ = write.send(Message::Close(None)).await;
                    break;
                }
                Step::Drop => return,
                Step::AwaitClientClose => {
                    while let Some(Ok(message)) = read.next().await {
                        if let Message::Close(frame) = message {
                            let code = frame.map(|frame| u16::from(frame.code)).unwrap_or(CLOSE_NO_STATUS);
                            log.lock().unwrap().push(format!("client closed {}", code));
                            break;
                        }
                    }
                    return;
                }
                Step::Refuse(..) => unreachable!("refuse is only a first step"),
            }
        }
        // Read until the client hangs up, so closing never resets the
        // connection under a close frame the client has not read yet.
        let _ = tokio::time::timeout(Duration::from_secs(2), async { while read.next().await.is_some() {} }).await;
    }

    fn frame(kind: &str, fields: Value) -> Value {
        let mut frame = serde_json::json!({ "type": kind, "text": "", "name": "", "value": "", "traceback": "" });
        for (key, value) in fields.as_object().expect("object").clone() {
            frame[key] = value;
        }
        frame
    }

    fn completed() -> Step {
        Step::Send(frame("control", serde_json::json!({ "text": "completed" })))
    }

    type Collector<T> = (Arc<Mutex<Vec<T>>>, Arc<dyn Fn(T) + Send + Sync>);

    fn collector<T: Send + 'static>() -> Collector<T> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        (seen, Arc::new(move |item| sink.lock().unwrap().push(item)))
    }

    /// An on_stdout callback that reports the first chunk on the receiver.
    fn first_stdout() -> (TextCallback, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        (
            Arc::new(move |_| {
                let _ = tx.lock().unwrap().send(());
            }),
            rx,
        )
    }

    #[test]
    fn run_code_streams_output_results_and_the_count() {
        let fake = fake(
            AGENT,
            rest_not_found,
            vec![
                Step::Send(frame("stdout", serde_json::json!({ "text": "hi\n" }))),
                Step::Raw(Message::Text("not json".into())),
                Step::Raw(Message::Binary(vec![1, 2, 3].into())),
                Step::Send(frame("keepalive", serde_json::json!({}))),
                Step::Send(frame("stderr", serde_json::json!({ "text": "careful\n" }))),
                Step::Send(frame("execution_count", serde_json::json!({ "count": 3 }))),
                Step::Send(frame(
                    "result",
                    serde_json::json!({
                        "svg": "<svg/>", "png": "iVBOR", "data": { "a": [1, 2] }, "extra": { "z/x": 1, "a/b": {} },
                        "is_main_result": false
                    }),
                )),
                Step::Send(frame(
                    "result",
                    serde_json::json!({ "text": "42", "html": "", "json": { "n": 42 }, "is_main_result": true }),
                )),
                completed(),
                Step::Close(1000, ""),
            ],
        );
        let (stdout, on_stdout) = collector::<String>();
        let (stderr, on_stderr) = collector::<String>();
        let (results, on_result) = collector::<CodeResult>();
        let execution = fake
            .sandbox()
            .run_code(
                "x = 5\nx",
                RunCodeOptions {
                    on_stdout: Some(on_stdout),
                    on_stderr: Some(on_stderr),
                    on_result: Some(on_result),
                    ..Default::default()
                },
            )
            .expect("run");
        assert_eq!(execution.logs.stdout, ["hi\n"]);
        assert_eq!(execution.logs.stderr, ["careful\n"]);
        assert_eq!(*stdout.lock().unwrap(), ["hi\n"]);
        assert_eq!(*stderr.lock().unwrap(), ["careful\n"]);
        assert_eq!(execution.execution_count, Some(3));
        assert_eq!(execution.text(), Some("42"));
        assert!(execution.error.is_none() && !execution.interrupted);
        assert_eq!(execution.results.len(), 2);
        assert_eq!(*results.lock().unwrap(), execution.results);
        assert_eq!(execution.results[0].formats(), ["svg", "png", "data", "a/b", "z/x"]);
        assert_eq!(execution.results[0].text, None, "an empty text is no text");
        assert_eq!(execution.results[1].formats(), ["text", "json"]);
        assert_eq!(execution.results[1].json, Some(serde_json::json!({ "n": 42 })));

        let log = fake.log();
        assert_eq!(log[0], "GET /v1/sandboxes/sb-1/toolbox/version");
        assert_eq!(log[1], "ws /v1/sandboxes/sb-1/toolbox/process/interpreter/execute auth Bearer pat");
        assert_eq!(fake.starts(), [serde_json::json!({ "code": "x = 5\nx", "richOutput": true })]);
    }

    #[test]
    fn run_code_start_frame_carries_only_what_was_set() {
        let fake = fake(AGENT, rest_not_found, vec![completed(), Step::Close(1000, "")]);
        let context = CodeContext { id: "ctx-1".to_string(), ..Default::default() };
        let envs: HashMap<String, String> = [("A".to_string(), "1".to_string())].into();
        fake.client
            .run_code(
                "sb-1",
                "print(1)",
                RunCodeOptions { timeout_seconds: Some(0), envs: Some(envs), ..RunCodeOptions::in_context(&context) },
            )
            .expect("context run");
        fake.client
            .run_code(
                "sb-1",
                "1",
                RunCodeOptions {
                    language: Some("javascript".to_string()),
                    context_id: Some(" ".to_string()),
                    envs: Some(HashMap::new()),
                    timeout_seconds: Some(30),
                    ..Default::default()
                },
            )
            .expect("language run");
        assert_eq!(
            fake.starts(),
            [
                serde_json::json!({ "code": "print(1)", "contextId": "ctx-1", "envs": { "A": "1" }, "timeout": 0, "richOutput": true }),
                serde_json::json!({ "code": "1", "language": "javascript", "timeout": 30, "richOutput": true }),
            ]
        );
        let versions = fake.log().iter().filter(|line| line.ends_with("/toolbox/version")).count();
        assert_eq!(versions, 1, "the feature check is cached per sandbox");
    }

    #[test]
    fn run_code_reports_the_codes_exception_as_data() {
        let fake = fake(
            AGENT,
            rest_not_found,
            vec![
                Step::Send(frame(
                    "error",
                    serde_json::json!({ "name": "NameError", "value": "name 'y' is not defined", "traceback": "Traceback..." }),
                )),
                completed(),
                Step::Close(1000, ""),
            ],
        );
        let (errors, on_error) = collector::<ExecutionError>();
        let execution = fake
            .client
            .run_code("sb-1", "y", RunCodeOptions { on_error: Some(on_error), ..Default::default() })
            .expect("a raised exception is not an SDK error");
        let want = ExecutionError {
            name: "NameError".to_string(),
            value: "name 'y' is not defined".to_string(),
            traceback: "Traceback...".to_string(),
        };
        assert_eq!(execution.error, Some(want.clone()));
        assert_eq!(*errors.lock().unwrap(), [want]);
        assert_eq!(execution.text(), None);
    }

    #[test]
    fn run_code_ends_by_the_close_frame() {
        // 1000 and a close with no status (1005) both end the run normally.
        for end in [Step::Close(1000, "done"), Step::CloseEmpty] {
            let fake = fake(
                AGENT,
                rest_not_found,
                vec![Step::Send(frame("control", serde_json::json!({ "text": "interrupted" }))), end],
            );
            let execution = fake.client.run_code("sb-1", "while True: pass", RunCodeOptions::default()).expect("run");
            assert!(execution.interrupted);
        }

        for (end, code, reason) in [
            (Step::Close(1008, "context not found: abc"), 1008, "context not found: abc"),
            (Step::Close(1011, "worker process ended"), 1011, "worker process ended"),
            (Step::Close(1001, "context deleted"), 1001, "context deleted"),
            (Step::Close(1002, "bad first frame"), 1002, "bad first frame"),
            (Step::Drop, 1006, ""),
        ] {
            let fake = fake(
                AGENT,
                rest_not_found,
                vec![Step::Send(frame("stdout", serde_json::json!({ "text": "partial" }))), end],
            );
            match fake.client.run_code("sb-1", "x", RunCodeOptions::default()) {
                Err(Error::CodeRun(err)) => {
                    assert_eq!(err.close_code(), code);
                    if !reason.is_empty() {
                        assert_eq!(err.reason(), reason);
                        assert_eq!(err.to_string(), format!("code run failed (close {}): {}", code, reason));
                    }
                    assert!(!err.is_timeout());
                    assert_eq!(err.execution().logs.stdout, ["partial"]);
                }
                other => panic!("want CodeRun {}, got {:?}", code, other),
            }
        }
    }

    #[test]
    fn run_code_timeout_carries_the_partial_execution() {
        let fake = fake(
            AGENT,
            rest_not_found,
            vec![
                Step::Send(frame("stdout", serde_json::json!({ "text": "started\n" }))),
                Step::Send(frame("control", serde_json::json!({ "text": "interrupted" }))),
                Step::Close(4008, "timeout"),
            ],
        );
        let err = fake
            .client
            .run_code("sb-1", "import time; time.sleep(9)", RunCodeOptions { timeout_seconds: Some(1), ..Default::default() })
            .expect_err("the run timed out");
        assert!(err.is_timeout());
        assert_eq!(err.to_string(), "code run timed out: timeout");
        let Error::CodeRun(err) = err else { panic!("want CodeRun") };
        assert!(err.is_timeout());
        assert_eq!(err.close_code(), 4008);
        let execution = err.into_execution();
        assert_eq!(execution.logs.stdout, ["started\n"]);
        assert!(execution.interrupted);
    }

    #[test]
    fn interrupt_sends_the_interrupt_frame() {
        let fake = fake(
            AGENT,
            rest_not_found,
            vec![
                Step::Send(frame("stdout", serde_json::json!({ "text": "running" }))),
                Step::AwaitText,
                Step::Send(frame("control", serde_json::json!({ "text": "interrupted" }))),
                Step::Close(1000, ""),
            ],
        );
        let (on_stdout, started) = first_stdout();
        let handle = fake
            .client
            .start_code("sb-1", "while True: pass", RunCodeOptions { on_stdout: Some(on_stdout), ..Default::default() })
            .expect("start");
        started.recv_timeout(Duration::from_secs(5)).expect("the run started");
        handle.interrupt().expect("interrupt");
        let execution = handle.wait().expect("an interrupted run ends normally");
        assert!(execution.interrupted);
        assert!(fake.log().contains(&r#"ws recv {"type":"interrupt"}"#.to_string()), "{:?}", fake.log());
    }

    #[test]
    fn close_stops_listening_without_stopping_the_run() {
        let fake = fake(
            AGENT,
            rest_not_found,
            vec![Step::Send(frame("stdout", serde_json::json!({ "text": "x" }))), Step::AwaitClientClose],
        );
        let (on_stdout, started) = first_stdout();
        let handle = fake
            .sandbox()
            .start_code("while True: print('x')", RunCodeOptions { on_stdout: Some(on_stdout), ..Default::default() })
            .expect("start");
        started.recv_timeout(Duration::from_secs(5)).expect("the run started");
        handle.close();
        match handle.wait() {
            Err(Error::CodeRun(err)) => {
                assert_eq!(err.close_code(), 1001);
                assert_eq!(err.execution().logs.stdout, ["x"]);
            }
            other => panic!("want CodeRun 1001, got {:?}", other),
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !fake.log().contains(&"client closed 1001".to_string()) {
            assert!(std::time::Instant::now() < deadline, "{:?}", fake.log());
            thread::sleep(Duration::from_millis(5));
        }
        let interrupts = fake.log().iter().filter(|line| line.contains("interrupt")).count();
        assert_eq!(interrupts, 0, "close must not interrupt the run");
    }

    #[test]
    fn interrupt_after_the_run_ended_reports_it() {
        let fake = fake(AGENT, rest_not_found, vec![completed(), Step::Close(1000, "")]);
        let handle = fake.client.start_code("sb-1", "1", RunCodeOptions::default()).expect("start");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while handle.interrupt().is_ok() {
            assert!(std::time::Instant::now() < deadline, "the run never ended");
            thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(handle.interrupt(), Err(Error::ChannelClosed)));
        handle.close();
        handle.wait().expect("run");
    }

    #[test]
    fn bad_arguments_fail_before_any_request() {
        // Port 9 is never contacted: each call fails before a request.
        let client = Client::with_config(
            ClientConfig {
                api_url: Some("http://127.0.0.1:9".to_string()),
                pat_token: Some("pat".to_string()),
                ..Default::default()
            },
            ApiVersion::V1,
        )
        .expect("client");
        let options = RunCodeOptions {
            context_id: Some("ctx-1".to_string()),
            language: Some("python".to_string()),
            ..Default::default()
        };
        match client.start_code("sb-1", "1", options) {
            Err(Error::Client(message)) => assert_eq!(message, "set context or language, not both"),
            Err(other) => panic!("want Client error, got {:?}", other),
            Ok(_) => panic!("want Client error"),
        }
        for result in [
            client.get_code_context("sb-1", " ").map(|_| ()),
            client.delete_code_context("sb-1", ""),
            client.restart_code_context("sb-1", "").map(|_| ()),
        ] {
            match result {
                Err(Error::Client(message)) => assert_eq!(message, "context id is required"),
                other => panic!("want Client error, got {:?}", other),
            }
        }
    }

    #[test]
    fn run_code_handshake_refusal_names_the_status() {
        let fake = fake(AGENT, rest_not_found, vec![Step::Refuse(501, r#"{"error":"not implemented"}"#)]);
        match fake.client.run_code("sb-1", "1", RunCodeOptions::default()) {
            Err(Error::Client(message)) => {
                assert!(message.starts_with("code run websocket handshake failed: status=501"), "{}", message);
                assert!(message.contains("not implemented"), "{}", message);
            }
            other => panic!("want handshake Client error, got {:?}", other),
        }
    }

    fn context_json(id: &str) -> String {
        serde_json::json!({ "id": id, "cwd": "/work", "createdAt": "2026-11-15T10:00:00Z", "active": true, "language": "python" })
            .to_string()
    }

    fn rest_contexts(line: &str, _: &str) -> (u16, String) {
        let base = "/v1/sandboxes/sb-1/toolbox/process/interpreter/context";
        if line == format!("POST {}", base) || line == format!("POST {}/ctx-1/restart", base) {
            (200, context_json("ctx-1"))
        } else if line == format!("GET {}", base) {
            (200, format!(r#"{{"contexts":[{}]}}"#, context_json("ctx-1")))
        } else if line == format!("GET {}/ctx%2F1", base) {
            (200, context_json("ctx/1"))
        } else if line == format!("DELETE {}/ctx-1", base) {
            (200, r#"{"message":"Context deleted successfully"}"#.to_string())
        } else {
            rest_not_found(line, "")
        }
    }

    #[test]
    fn context_calls_use_the_interpreter_routes() {
        let fake = fake(AGENT, rest_contexts, vec![]);
        let sandbox = fake.sandbox();
        let created = sandbox
            .create_code_context(CodeContextOptions { language: Some("python".to_string()), cwd: Some("/work".to_string()) })
            .expect("create");
        assert_eq!(
            created,
            CodeContext {
                id: "ctx-1".to_string(),
                language: "python".to_string(),
                cwd: "/work".to_string(),
                created_at: "2026-11-15T10:00:00Z".to_string(),
                active: true,
            }
        );
        sandbox.create_code_context(CodeContextOptions::default()).expect("create with defaults");
        assert_eq!(sandbox.list_code_contexts().expect("list"), std::slice::from_ref(&created));
        assert_eq!(sandbox.get_code_context("ctx/1").expect("get").id, "ctx/1");
        sandbox.delete_code_context("ctx-1").expect("delete");
        assert_eq!(sandbox.restart_code_context("ctx-1").expect("restart"), created);
        let err = sandbox.get_code_context("nope").expect_err("unknown context");
        assert!(err.is_not_found(), "{:?}", err);

        let base = "/v1/sandboxes/sb-1/toolbox/process/interpreter/context";
        assert_eq!(
            fake.log(),
            [
                "GET /v1/sandboxes/sb-1/toolbox/version".to_string(),
                format!("POST {}", base),
                r#"body {"language":"python","cwd":"/work"}"#.to_string(),
                format!("POST {}", base),
                "body {}".to_string(),
                format!("GET {}", base),
                format!("GET {}/ctx%2F1", base),
                format!("DELETE {}/ctx-1", base),
                format!("POST {}/ctx-1/restart", base),
                format!("GET {}/nope", base),
            ]
        );
    }

    #[test]
    fn list_code_contexts_reads_a_missing_list_as_empty() {
        fn rest(_: &str, _: &str) -> (u16, String) {
            (200, r#"{"contexts":null}"#.to_string())
        }
        let fake = fake(AGENT, rest, vec![]);
        assert!(fake.client.list_code_contexts("sb-1").expect("list").is_empty());
    }

    #[test]
    fn create_and_restart_are_not_resent_after_a_lost_reply() {
        fn rest(_: &str, _: &str) -> (u16, String) {
            (502, r#"{"error":"bad gateway"}"#.to_string())
        }
        let fake = fake(AGENT, rest, vec![]);
        let err = fake.client.create_code_context("sb-1", CodeContextOptions::default()).expect_err("502");
        assert_eq!(err.api_error().map(|err| err.status()), Some(502));
        let err = fake.client.restart_code_context("sb-1", "ctx-1").expect_err("502");
        assert_eq!(err.api_error().map(|err| err.status()), Some(502));
        let posts = fake.log().iter().filter(|line| line.starts_with("POST ")).count();
        assert_eq!(posts, 2, "each POST went out once: {:?}", fake.log());

        // A safe call retries the same 502 (three retries).
        let _ = fake.client.list_code_contexts("sb-1").expect_err("502");
        let gets = fake.log().iter().filter(|line| line.starts_with("GET ") && line.ends_with("/context")).count();
        assert_eq!(gets, 4);
    }

    #[test]
    fn an_older_agent_gets_only_the_version_read() {
        let fake = fake(OLD_AGENT, rest_contexts, vec![completed(), Step::Close(1000, "")]);
        let client = &fake.client;
        let results: Vec<Result<(), Error>> = vec![
            client.create_code_context("sb-1", CodeContextOptions::default()).map(|_| ()),
            client.list_code_contexts("sb-1").map(|_| ()),
            client.get_code_context("sb-1", "ctx-1").map(|_| ()),
            client.delete_code_context("sb-1", "ctx-1"),
            client.restart_code_context("sb-1", "ctx-1").map(|_| ()),
            client.run_code("sb-1", "1", RunCodeOptions::default()).map(|_| ()),
            client.start_code("sb-1", "1", RunCodeOptions::default()).map(|_| ()),
        ];
        for result in results {
            match result {
                Err(Error::UnsupportedFeature(err)) => {
                    assert_eq!(err.features(), ["code.interpreter".to_string()]);
                    assert_eq!(err.agent_version(), "0.7.5");
                }
                other => panic!("want UnsupportedFeature, got {:?}", other.err()),
            }
        }
        assert!(
            fake.log().iter().all(|line| line == "GET /v1/sandboxes/sb-1/toolbox/version"),
            "{:?}",
            fake.log()
        );
    }

    #[test]
    fn code_result_formats_and_execution_text() {
        let result = CodeResult::from_frame(&serde_json::json!({
            "type": "result", "text": "t", "html": "<b/>", "markdown": "*m*", "svg": "<svg/>", "png": "p",
            "jpeg": "j", "pdf": "d", "latex": "$x$", "json": [1], "javascript": "js", "data": {}, "extra": {},
            "is_main_result": true
        }));
        assert_eq!(
            result.formats(),
            ["text", "html", "markdown", "svg", "png", "jpeg", "pdf", "latex", "json", "javascript", "data"]
        );
        let empty = CodeResult::from_frame(&serde_json::json!({ "type": "result", "text": "", "json": null }));
        assert!(empty.formats().is_empty() && !empty.is_main_result);

        let mut execution = Execution {
            results: vec![CodeResult { text: Some("side".to_string()), ..Default::default() }],
            ..Default::default()
        };
        assert_eq!(execution.text(), None, "only the main result counts");
        execution.results.push(CodeResult { is_main_result: true, ..Default::default() });
        assert_eq!(execution.text(), None, "a main result with no text");
        execution.results[1].text = Some("main".to_string());
        assert_eq!(execution.text(), Some("main"));
    }
}
