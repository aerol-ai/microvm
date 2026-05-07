mod types;

use std::fmt;
use std::path::Path;

use reqwest::blocking::{multipart::{Form, Part}, Client as HttpClient};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub use types::{CreateOptions, ExecRequest, ExecResult, ExposedPort, HealthStatus, RegistryAuth, ResizeOptions, Sandbox as SandboxData};

const DEFAULT_API_URL: &str = "http://127.0.0.1:8080";

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    MissingToken,
    Api(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Reqwest(err) => write!(f, "HTTP error: {}", err),
            Error::MissingToken => write!(f, "PAT token is required. Set SB_PAT_TOKEN or pass pat_token."),
            Error::Api(message) => write!(f, "API error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Reqwest(err)
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
            .map(|value| value.trim().trim_end_matches('/').to_string())
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

    fn do_json<T: serde::Serialize, U: DeserializeOwned>(&self, method: Method, path: &str, payload: Option<&T>) -> Result<U, Error> {
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
