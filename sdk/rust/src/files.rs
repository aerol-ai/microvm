//! File verbs beyond upload and download (plans/agent-sandbox-feature-
//! parity.md, F1), through the sandbox's toolbox. A sandbox whose agent
//! predates them fails closed with [`Error::UnsupportedFeature`] instead of
//! ignoring a safety option; WASM and V8 isolate sandboxes answer HTTP 501.
//!
//! Retries: `list_files`, `get_file_info`, `file_exists`, `search_files`,
//! `find_in_files`, `delete_file` and `make_dir` are safe to re-send and
//! retry on 421, 429, 502, 503 and 504 (a retried delete or mkdir whose work
//! is already done counts as success). `move_file` and `copy_file` retry only
//! on 429 and 503, because a lost reply may hide a move that happened.

use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use reqwest::blocking::multipart::{Form, Part};
use reqwest::Method;
use serde::Deserialize;
use serde_json::Value;

use crate::{Authorize, Client, Error, RetryPolicy, Sandbox};

/// The toolboxd feature (on `/version`) behind the file verbs' options: list
/// depth and cap, the move and copy overwrite guard, mkdir without parents
/// and the copy route. An older agent ignores those options (overwrite=false
/// would overwrite), so the calls that send them check first.
const FEATURE_FILE_VERBS: &str = "files.verbs";

/// The toolboxd feature behind upload's write options. An older agent
/// ignores them: create_only would replace an existing file.
const FEATURE_WRITE_OPTIONS: &str = "files.write_options";

/// The toolboxd feature behind upload's extract=true (`upload_dir`). An
/// older agent ignores extract and would store the archive as a file.
const FEATURE_EXTRACT: &str = "files.extract";

/// Error codes toolboxd puts on the file errors a retry acts on.
const CODE_FILE_NOT_FOUND: &str = "file_not_found";
const CODE_FOLDER_EXISTS: &str = "folder_exists";

/// The entry cap [`Client::list_files`] sends when the caller gives none.
pub const DEFAULT_LIST_LIMIT: u32 = 10_000;

/// One file, folder or symlink in a sandbox.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileInfo {
    pub name: String,
    /// The full path in the sandbox.
    pub path: String,
    pub is_dir: bool,
    /// Bytes.
    pub size: u64,
    /// Type and permission string, such as `-rw-r--r--`.
    pub mode: String,
    /// Octal permission bits, such as `0644`.
    pub permissions: String,
    pub owner: String,
    pub group: String,
    /// Last change time, RFC 3339 in UTC.
    pub mod_time: String,
    /// Where a symlink points. Only on `list_files` entries: `get_file_info`
    /// follows a symlink and describes what it names.
    pub symlink_target: Option<String>,
}

/// The result of [`Client::list_files`]. `truncated` means the listing
/// reached its limit and more entries exist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileList {
    pub entries: Vec<FileInfo>,
    pub truncated: bool,
}

/// Options for [`Client::list_files`]. The default lists one level, up to
/// [`DEFAULT_LIST_LIMIT`] entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListFilesOptions {
    /// Levels to go down; 1 (the default) is the folder's own entries.
    /// Symlinked folders are listed but never entered.
    pub depth: Option<u32>,
    /// The most entries to return.
    pub limit: Option<u32>,
}

/// Options for [`Client::delete_file`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeleteFileOptions {
    /// Delete a folder and everything in it. Without it a folder is refused
    /// (HTTP 409).
    pub recursive: bool,
}

/// Options for [`Client::make_dir`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MakeDirOptions {
    /// Also make missing parent folders, and accept an existing folder
    /// (`mkdir -p`).
    pub parents: bool,
    /// Permissions such as `0o750`; 0755 when `None`.
    pub mode: Option<u32>,
}

/// Options for [`Client::move_file`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MoveFileOptions {
    /// Replace an existing destination. Without it an existing destination
    /// is refused (HTTP 409).
    pub overwrite: bool,
}

/// Options for [`Client::copy_file`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CopyFileOptions {
    /// Replace an existing destination.
    pub overwrite: bool,
    /// Copy a folder and everything in it, keeping modes and symlinks.
    /// Without it a folder is refused (HTTP 409).
    pub recursive: bool,
}

/// How [`Client::upload_file_with_options`] writes its file. The default is
/// a plain upload: missing folders are made and an existing file is replaced
/// in place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UploadFileOptions {
    /// Add to the end of the file instead of replacing it.
    pub append: bool,
    /// Write only if the file does not exist yet (HTTP 412 otherwise). Of
    /// two uploads racing for one new path, exactly one wins.
    pub create_only: bool,
    /// Write a temp file and rename it into place, so a reader never sees
    /// half a file. Cannot be combined with `append`.
    pub atomic: bool,
    /// Permissions such as `0o600`. Without it a new file is 0644 and an
    /// existing one keeps its own.
    pub mode: Option<u32>,
}

/// Options for a download.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DownloadFileOptions {
    /// Refuse a file larger than this many bytes: before reading when the
    /// server states the size, otherwise as soon as more arrives. A guard
    /// against a file larger than expected filling memory.
    pub max_bytes: Option<u64>,
}

/// One line [`Client::find_in_files`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct FileMatch {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: u64,
    #[serde(default)]
    pub content: String,
}

/// Wire shape of toolboxd's file info with extended=true. An older agent
/// ignores extended and sends only Daytona's fields (a 32-bit size, no
/// path), so each extended field falls back.
#[derive(Deserialize, Default)]
struct FileInfoWire {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "isDir")]
    is_dir: bool,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    size_bytes: Option<u64>,
    #[serde(default)]
    path: String,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    permissions: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    group: String,
    #[serde(default, rename = "modTime")]
    mod_time: String,
    #[serde(default)]
    symlink_target: Option<String>,
}

impl FileInfoWire {
    fn into_info(self, fallback_path: String) -> FileInfo {
        FileInfo {
            path: if self.path.is_empty() { fallback_path } else { self.path },
            size: self.size_bytes.unwrap_or(self.size),
            name: self.name,
            is_dir: self.is_dir,
            mode: self.mode,
            permissions: self.permissions,
            owner: self.owner,
            group: self.group,
            mod_time: self.mod_time,
            symlink_target: self.symlink_target,
        }
    }
}

/// A missing file, not a missing sandbox (also a 404). Current agents say
/// file_not_found; older ones send no code, but their message is the OS
/// error, which ends "no such file or directory".
fn is_missing_file(err: &Error) -> bool {
    match err {
        Error::Api(api) if api.status() == 404 => match api.code() {
            Some(code) => code == CODE_FILE_NOT_FOUND,
            None => api.message().ends_with("no such file or directory"),
        },
        _ => false,
    }
}

impl Client {
    fn toolbox_path(&self, id: &str, route: &str, query: &[(&str, &str)]) -> String {
        let query: Vec<String> = query
            .iter()
            .map(|(key, value)| format!("{}={}", key, urlencoding::encode(value)))
            .collect();
        format!(
            "{}/sandboxes/{}/toolbox{}?{}",
            self.version_prefix(),
            urlencoding::encode(id),
            route,
            query.join("&")
        )
    }

    /// List a folder in sandbox `id`. Always sends a depth and an entry cap,
    /// so it needs an agent that lists `files.verbs`.
    pub fn list_files(&self, id: &str, path: &str, options: ListFilesOptions) -> Result<FileList, Error> {
        let depth = options.depth.unwrap_or(1);
        let limit = options.limit.unwrap_or(DEFAULT_LIST_LIMIT);
        if depth < 1 || limit < 1 {
            return Err(Error::Client("depth and limit must be at least 1".to_string()));
        }
        self.require_toolbox_features(id, &[FEATURE_FILE_VERBS])?;
        let (depth, limit) = (depth.to_string(), limit.to_string());
        let route = self.toolbox_path(
            id,
            "/files",
            &[("path", path), ("depth", &depth), ("limit", &limit), ("extended", "true")],
        );
        let (items, headers): (Option<Vec<FileInfoWire>>, _) =
            self.send_json::<Value, _>(Method::GET, &route, None, RetryPolicy::Idempotent)?;
        let base = path.trim_end_matches('/');
        let entries = items
            .unwrap_or_default()
            .into_iter()
            .map(|item| {
                let fallback = format!("{}/{}", base, item.name);
                item.into_info(fallback)
            })
            .collect();
        let truncated = headers
            .get("x-toolbox-truncated")
            .and_then(|value| value.to_str().ok())
            == Some("true");
        Ok(FileList { entries, truncated })
    }

    /// Describe one path. A symlink is followed.
    pub fn get_file_info(&self, id: &str, path: &str) -> Result<FileInfo, Error> {
        // extended=true only adds fields; an older agent that ignores it
        // answers fields this still reads, so no /version check.
        let route = self.toolbox_path(id, "/files/info", &[("path", path), ("extended", "true")]);
        let (item, _): (Option<FileInfoWire>, _) =
            self.send_json::<Value, _>(Method::GET, &route, None, RetryPolicy::Idempotent)?;
        Ok(item.unwrap_or_default().into_info(path.to_string()))
    }

    /// Whether `path` exists. A missing sandbox is an error, not `false`.
    pub fn file_exists(&self, id: &str, path: &str) -> Result<bool, Error> {
        match self.get_file_info(id, path) {
            Ok(_) => Ok(true),
            Err(err) if is_missing_file(&err) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Delete a file, or a folder and its contents with `recursive`.
    pub fn delete_file(&self, id: &str, path: &str, options: DeleteFileOptions) -> Result<(), Error> {
        let mut query = vec![("path", path)];
        if options.recursive {
            query.push(("recursive", "true"));
        }
        let route = self.toolbox_path(id, "/files", &query);
        self.file_call(Method::DELETE, &route, RetryPolicy::Idempotent, Some(CODE_FILE_NOT_FOUND))
    }

    /// Make a folder; with `parents`, like `mkdir -p`.
    pub fn make_dir(&self, id: &str, path: &str, options: MakeDirOptions) -> Result<(), Error> {
        if !options.parents {
            // An older agent ignores parents=false and makes them anyway.
            self.require_toolbox_features(id, &[FEATURE_FILE_VERBS])?;
        }
        let mode = options.mode.map(|mode| format!("{:o}", mode));
        let mut query = vec![("path", path), ("parents", if options.parents { "true" } else { "false" })];
        if let Some(mode) = mode.as_deref() {
            query.push(("mode", mode));
        }
        let route = self.toolbox_path(id, "/files/folder", &query);
        self.file_call(Method::POST, &route, RetryPolicy::Idempotent, Some(CODE_FOLDER_EXISTS))
    }

    /// Move or rename a file or folder. Without `overwrite`, an existing
    /// destination is refused (HTTP 409).
    pub fn move_file(&self, id: &str, source: &str, destination: &str, options: MoveFileOptions) -> Result<(), Error> {
        if !options.overwrite {
            // An older agent ignores overwrite=false and replaces the file.
            self.require_toolbox_features(id, &[FEATURE_FILE_VERBS])?;
        }
        let overwrite = if options.overwrite { "true" } else { "false" };
        let route = self.toolbox_path(
            id,
            "/files/move",
            &[("source", source), ("destination", destination), ("overwrite", overwrite)],
        );
        self.file_call(Method::POST, &route, RetryPolicy::UnsentOnly, None)
    }

    /// Copy a file, or a folder with `recursive` (keeping modes and
    /// symlinks).
    pub fn copy_file(&self, id: &str, source: &str, destination: &str, options: CopyFileOptions) -> Result<(), Error> {
        self.require_toolbox_features(id, &[FEATURE_FILE_VERBS])?;
        let route = self.toolbox_path(
            id,
            "/files/copy",
            &[
                ("source", source),
                ("destination", destination),
                ("overwrite", if options.overwrite { "true" } else { "false" }),
                ("recursive", if options.recursive { "true" } else { "false" }),
            ],
        );
        self.file_call(Method::POST, &route, RetryPolicy::UnsentOnly, None)
    }

    /// Paths under `path` whose name matches a glob such as `*.rs`.
    pub fn search_files(&self, id: &str, path: &str, pattern: &str) -> Result<Vec<String>, Error> {
        #[derive(Deserialize, Default)]
        struct Found {
            #[serde(default)]
            files: Option<Vec<String>>,
        }
        let route = self.toolbox_path(id, "/files/search", &[("path", path), ("pattern", pattern)]);
        let (found, _): (Option<Found>, _) = self.send_json::<Value, _>(Method::GET, &route, None, RetryPolicy::Idempotent)?;
        Ok(found.and_then(|found| found.files).unwrap_or_default())
    }

    /// Each line under `path` that contains `text` (plain text).
    pub fn find_in_files(&self, id: &str, path: &str, text: &str) -> Result<Vec<FileMatch>, Error> {
        let route = self.toolbox_path(id, "/files/find", &[("path", path), ("pattern", text)]);
        let (matches, _): (Option<Vec<FileMatch>>, _) =
            self.send_json::<Value, _>(Method::GET, &route, None, RetryPolicy::Idempotent)?;
        Ok(matches.unwrap_or_default())
    }

    /// Upload `data` to `target_path`. Plain and atomic uploads retry on
    /// 421/429/502/503/504; `append` and `create_only` only on 429/503,
    /// because a second send would append twice or find the first one's
    /// file. A sandbox whose agent predates the options fails with
    /// [`Error::UnsupportedFeature`] instead of ignoring them.
    pub fn upload_file_with_options(
        &self,
        id: &str,
        target_path: &str,
        data: Vec<u8>,
        options: UploadFileOptions,
    ) -> Result<(), Error> {
        let (route, policy) = self.upload_route(id, options)?;
        let file_name = Path::new(target_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_string();
        let _: (Value, _) = self.send_with_retry(Method::POST, &route, policy, &[], None, |builder| {
            builder.multipart(
                Form::new()
                    .text("path", target_path.to_string())
                    .part("file", Part::bytes(data.clone()).file_name(file_name.clone())),
            )
        })?;
        Ok(())
    }

    /// Read a whole file, refusing one larger than `options.max_bytes`.
    /// The request retries like any safe call.
    pub fn download_file_with_options(&self, id: &str, target_path: &str, options: DownloadFileOptions) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.download_file_to(id, target_path, &mut out, options)?;
        Ok(out)
    }

    /// Stream a file into `dest` a piece at a time, so a large file never
    /// sits in memory, and return the bytes written. With `max_bytes`, a
    /// larger file is refused before reading when the server states the
    /// size, otherwise as soon as more arrives (what was written stays in
    /// `dest`). The request retries until the file starts to arrive, never
    /// after (plans/agent-sandbox-feature-parity.md, F4).
    pub fn download_file_to(
        &self,
        id: &str,
        target_path: &str,
        dest: &mut impl io::Write,
        options: DownloadFileOptions,
    ) -> Result<u64, Error> {
        let route = self.toolbox_path(id, "/files/download", &[("path", target_path)]);
        let Some(mut response) = self.send_raw_with_retry(Method::GET, &route, RetryPolicy::Idempotent, &[], None, |builder| builder)? else {
            return Ok(0);
        };
        let too_large = |max: u64| Error::Client(format!("{} is larger than max_bytes ({} bytes)", target_path, max));
        if let (Some(max), Some(length)) = (options.max_bytes, response.content_length()) {
            if length > max {
                return Err(too_large(max));
            }
        }
        let mut written = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = io::Read::read(&mut response, &mut buf).map_err(|err| Error::Client(format!("read {}: {}", target_path, err)))?;
            if n == 0 {
                return Ok(written);
            }
            let chunk = &buf[..n];
            if let Some(max) = options.max_bytes {
                if written + n as u64 > max {
                    let keep = (max - written) as usize;
                    dest.write_all(&chunk[..keep]).map_err(|err| Error::Client(err.to_string()))?;
                    return Err(too_large(max));
                }
            }
            dest.write_all(chunk).map_err(|err| Error::Client(err.to_string()))?;
            written += n as u64;
        }
    }

    /// Upload from `reader` a piece at a time, so a large file never sits in
    /// memory. The options are [`Client::upload_file_with_options`]'s. The
    /// data is read as it is sent, so it is sent once and never retried.
    pub fn upload_file_from(
        &self,
        id: &str,
        target_path: &str,
        reader: impl io::Read + Send + 'static,
        options: UploadFileOptions,
    ) -> Result<(), Error> {
        let (route, _) = self.upload_route(id, options)?;
        let file_name = Path::new(target_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .to_string();
        let form = Form::new()
            .text("path", target_path.to_string())
            .part("file", Part::reader(reader).file_name(file_name));
        let response = self.inner.post(self.full_url(&route)).authorize(self).multipart(form).send()?;
        self.handle_response(response).map(|_| ())
    }

    /// The upload route with the write options as query (after the /version
    /// check they need) and the upload's retry tier.
    fn upload_route(&self, id: &str, options: UploadFileOptions) -> Result<(String, RetryPolicy), Error> {
        let mode = options.mode.map(|mode| format!("{:o}", mode));
        let mut query = Vec::new();
        if options.append {
            query.push(("append", "true"));
        }
        if options.create_only {
            query.push(("create_only", "true"));
        }
        if options.atomic {
            query.push(("atomic", "true"));
        }
        if let Some(mode) = mode.as_deref() {
            query.push(("mode", mode));
        }
        let route = if query.is_empty() {
            format!("{}/sandboxes/{}/toolbox/files/upload", self.version_prefix(), urlencoding::encode(id))
        } else {
            self.require_toolbox_features(id, &[FEATURE_WRITE_OPTIONS])?;
            self.toolbox_path(id, "/files/upload", &query)
        };
        let policy = if options.append || options.create_only {
            RetryPolicy::UnsentOnly
        } else {
            RetryPolicy::Idempotent
        };
        Ok((route, policy))
    }

    /// Copy the local folder `local_dir` into `remote_dir` in the sandbox
    /// (made if missing). The folder is packed as a tar and the sandbox
    /// unpacks it safely: no entry can land outside `remote_dir`. Symlinks
    /// are sent as links, hard-linked files as separate files; devices,
    /// pipes and sockets are skipped. The archive is built in memory and
    /// sent once, never retried.
    pub fn upload_dir(&self, id: &str, local_dir: impl AsRef<Path>, remote_dir: &str) -> Result<(), Error> {
        let local_dir = local_dir.as_ref();
        let is_dir = fs::metadata(local_dir).map(|meta| meta.is_dir()).map_err(|err| {
            Error::Client(format!("{}: {}", local_dir.display(), err))
        })?;
        if !is_dir {
            return Err(Error::Client(format!("{} is not a folder", local_dir.display())));
        }
        self.require_toolbox_features(id, &[FEATURE_EXTRACT])?;
        let archive = tar_folder(local_dir).map_err(|err| Error::Client(format!("pack {}: {}", local_dir.display(), err)))?;
        let route = self.toolbox_path(id, "/files/upload", &[("extract", "true")]);
        let form = Form::new()
            .text("path", remote_dir.to_string())
            .part("file", Part::bytes(archive).file_name("upload.tar"));
        let response = self
            .inner
            .post(self.full_url(&route))
            .authorize(self)
            .multipart(form)
            .send()?;
        self.handle_response(response).map(|_| ())
    }

    /// A body-less file call whose success reply is discarded.
    fn file_call(&self, method: Method, route: &str, policy: RetryPolicy, done_code: Option<&str>) -> Result<(), Error> {
        let _: (Value, _) = self.send_json_done::<Value, Value>(method, route, None, policy, &[], done_code)?;
        Ok(())
    }
}

/// The contents of `root` as an uncompressed tar (ustar, with PAX records
/// for names past 100 bytes), names relative to `root`. The SDK takes no tar
/// crate; toolboxd reads plain tar as well as gzip.
fn tar_folder(root: &Path) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    tar_walk(root, "", &mut out)?;
    out.extend_from_slice(&[0u8; 1024]);
    Ok(out)
}

fn tar_walk(root: &Path, prefix: &str, out: &mut Vec<u8>) -> io::Result<()> {
    let dir = if prefix.is_empty() { root.to_path_buf() } else { root.join(prefix) };
    let mut names: Vec<String> = fs::read_dir(&dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        let rel = if prefix.is_empty() { name } else { format!("{}/{}", prefix, name) };
        let full = root.join(&rel);
        let meta = fs::symlink_metadata(&full)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let kind = meta.file_type();
        let mode = file_mode(&meta, kind.is_dir());
        if kind.is_symlink() {
            let target = fs::read_link(&full)?.to_string_lossy().into_owned();
            tar_entry(out, &rel, b'2', mode, mtime, &[], &target);
        } else if kind.is_dir() {
            tar_entry(out, &format!("{}/", rel), b'5', mode, mtime, &[], "");
            tar_walk(root, &rel, out)?;
        } else if kind.is_file() {
            tar_entry(out, &rel, b'0', mode, mtime, &fs::read(&full)?, "");
        }
        // Devices, pipes and sockets are skipped: the sandbox refuses them.
    }
    Ok(())
}

#[cfg(unix)]
fn file_mode(meta: &fs::Metadata, _is_dir: bool) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn file_mode(_meta: &fs::Metadata, is_dir: bool) -> u32 {
    if is_dir { 0o755 } else { 0o644 }
}

fn tar_entry(out: &mut Vec<u8>, name: &str, typeflag: u8, mode: u32, mtime: u64, data: &[u8], link: &str) {
    let mut records = Vec::new();
    if name.len() > 100 {
        records.extend(pax_record("path", name));
    }
    if link.len() > 100 {
        records.extend(pax_record("linkpath", link));
    }
    if !records.is_empty() {
        out.extend_from_slice(&tar_header("PaxHeader", b'x', 0o644, records.len(), mtime, ""));
        tar_padded(out, &records);
    }
    out.extend_from_slice(&tar_header(name, typeflag, mode, data.len(), mtime, link));
    tar_padded(out, data);
}

fn tar_padded(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    let rest = data.len() % 512;
    if rest != 0 {
        out.extend(std::iter::repeat_n(0u8, 512 - rest));
    }
}

fn tar_header(name: &str, typeflag: u8, mode: u32, size: usize, mtime: u64, link: &str) -> [u8; 512] {
    fn put(block: &mut [u8; 512], offset: usize, len: usize, value: &[u8]) {
        let n = value.len().min(len);
        block[offset..offset + n].copy_from_slice(&value[..n]);
    }
    fn octal(block: &mut [u8; 512], offset: usize, len: usize, value: u64) {
        put(block, offset, len - 1, format!("{:0width$o}", value, width = len - 1).as_bytes());
    }
    let mut block = [0u8; 512];
    put(&mut block, 0, 100, name.as_bytes());
    octal(&mut block, 100, 8, u64::from(mode & 0o7777));
    octal(&mut block, 108, 8, 0);
    octal(&mut block, 116, 8, 0);
    octal(&mut block, 124, 12, size as u64);
    octal(&mut block, 136, 12, mtime);
    block[148..156].fill(b' ');
    block[156] = typeflag;
    put(&mut block, 157, 100, link.as_bytes());
    put(&mut block, 257, 6, b"ustar\0");
    put(&mut block, 263, 2, b"00");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    put(&mut block, 148, 8, format!("{:06o}\0 ", sum).as_bytes());
    block
}

/// A PAX record: "<length> <key>=<value>\n", the length counting itself.
fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let body = format!(" {}={}\n", key, value);
    let mut length = body.len() + body.len().to_string().len();
    if length.to_string().len() != body.len().to_string().len() {
        // Adding the digits made the number one digit longer (98 -> 100).
        length = body.len() + length.to_string().len();
    }
    format!("{}{}", length, body).into_bytes()
}

impl Sandbox {
    /// Copy a local folder into the sandbox. See [`Client::upload_dir`].
    pub fn upload_dir(&self, local_dir: impl AsRef<Path>, remote_dir: &str) -> Result<(), Error> {
        self.client.upload_dir(&self.data.id, local_dir, remote_dir)
    }

    /// List a folder. See [`ListFilesOptions`]; `truncated` means more
    /// entries exist.
    pub fn list_files(&self, path: &str, options: ListFilesOptions) -> Result<FileList, Error> {
        self.client.list_files(&self.data.id, path, options)
    }

    /// Describe one path. A symlink is followed.
    pub fn get_file_info(&self, path: &str) -> Result<FileInfo, Error> {
        self.client.get_file_info(&self.data.id, path)
    }

    /// Whether `path` exists.
    pub fn file_exists(&self, path: &str) -> Result<bool, Error> {
        self.client.file_exists(&self.data.id, path)
    }

    /// Delete a file, or a folder with `recursive`.
    pub fn delete_file(&self, path: &str, options: DeleteFileOptions) -> Result<(), Error> {
        self.client.delete_file(&self.data.id, path, options)
    }

    /// Make a folder; with `parents`, like `mkdir -p`.
    pub fn make_dir(&self, path: &str, options: MakeDirOptions) -> Result<(), Error> {
        self.client.make_dir(&self.data.id, path, options)
    }

    /// Move or rename a file or folder.
    pub fn move_file(&self, source: &str, destination: &str, options: MoveFileOptions) -> Result<(), Error> {
        self.client.move_file(&self.data.id, source, destination, options)
    }

    /// Copy a file, or a folder with `recursive`.
    pub fn copy_file(&self, source: &str, destination: &str, options: CopyFileOptions) -> Result<(), Error> {
        self.client.copy_file(&self.data.id, source, destination, options)
    }

    /// Paths under `path` whose name matches a glob.
    pub fn search_files(&self, path: &str, pattern: &str) -> Result<Vec<String>, Error> {
        self.client.search_files(&self.data.id, path, pattern)
    }

    /// Each line under `path` that contains `text`.
    pub fn find_in_files(&self, path: &str, text: &str) -> Result<Vec<FileMatch>, Error> {
        self.client.find_in_files(&self.data.id, path, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiVersion, ClientConfig, RetryConfig, SandboxData};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Clone, Debug)]
    struct Call {
        method: String,
        route: String,
        query: HashMap<String, String>,
        body: Vec<u8>,
    }

    type Reply = fn(&Call, usize) -> (u16, Option<String>, Vec<(&'static str, &'static str)>);

    /// A local stand-in for sandboxd's toolbox pass-through: `/version`
    /// lists `features`, every other call is recorded and answered by
    /// `reply(call, n)`, `n` counting that method and route's calls from 0.
    fn fake_toolbox(features: &'static [&'static str], reply: Reply) -> (Client, Arc<Mutex<Vec<Call>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener address");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let server_calls = calls.clone();
        thread::spawn(move || {
            let mut counts: HashMap<String, usize> = HashMap::new();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    continue;
                }
                let mut length = 0usize;
                let mut chunked = false;
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                        if name.trim().eq_ignore_ascii_case("transfer-encoding") && value.trim().eq_ignore_ascii_case("chunked") {
                            chunked = true;
                        }
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                while chunked {
                    let mut size_line = String::new();
                    if reader.read_line(&mut size_line).is_err() {
                        break;
                    }
                    let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                    let mut chunk = vec![0u8; size + 2];
                    let _ = reader.read_exact(&mut chunk);
                    if size == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..size]);
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();
                let (path, raw_query) = target.split_once('?').unwrap_or((&target, ""));
                let (status, body, headers) = if path.ends_with("/toolbox/version") {
                    let list: Vec<String> = features.iter().map(|f| format!("\"{}\"", f)).collect();
                    (200, Some(format!(r#"{{"version":"test","features":[{}]}}"#, list.join(","))), vec![])
                } else {
                    let query = raw_query
                        .split('&')
                        .filter(|pair| !pair.is_empty())
                        .filter_map(|pair| pair.split_once('='))
                        .map(|(k, v)| (k.to_string(), urlencoding::decode(v).unwrap().into_owned()))
                        .collect();
                    let call = Call {
                        method: method.clone(),
                        route: path.split_once("/toolbox").map(|(_, r)| r.to_string()).unwrap_or_default(),
                        query,
                        body: body.clone(),
                    };
                    let key = format!("{} {}", method, call.route);
                    let n = *counts.get(&key).unwrap_or(&0);
                    counts.insert(key, n + 1);
                    server_calls.lock().unwrap().push(call.clone());
                    reply(&call, n)
                };
                let body = body.unwrap_or_default();
                // X-No-Length: a body whose size shows only as it arrives.
                let mut head = if headers.iter().any(|(name, _)| *name == "X-No-Length") {
                    format!("HTTP/1.1 {} X\r\nConnection: close\r\n", status)
                } else {
                    format!("HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n", status, body.len())
                };
                if !body.is_empty() {
                    head.push_str("Content-Type: application/json\r\n");
                }
                for (name, value) in headers {
                    head.push_str(&format!("{}: {}\r\n", name, value));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            }
        });
        let client = Client::with_config(
            ClientConfig {
                api_url: Some(format!("http://{}", addr)),
                pat_token: Some("pat".to_string()),
                retry: Some(RetryConfig { max_retries: Some(3), base_delay_ms: Some(1), max_delay_ms: Some(1), max_retry_after_ms: None }),
                ..Default::default()
            },
            ApiVersion::V1,
        )
        .expect("client should build");
        (client, calls)
    }

    fn err(message: &str, code: Option<&str>) -> Option<String> {
        Some(match code {
            Some(code) => serde_json::json!({"error": message, "code": code}).to_string(),
            None => serde_json::json!({"error": message}).to_string(),
        })
    }

    fn api_status(result: Result<(), Error>) -> u16 {
        match result {
            Err(Error::Api(api)) => api.status(),
            other => panic!("want an API error, got {:?}", other),
        }
    }

    #[test]
    fn list_files_sends_a_depth_and_cap_and_reads_extended_info() {
        let (client, calls) = fake_toolbox(&["files.verbs"], |_, _| {
            let body = serde_json::json!([
                {"name": "a", "isDir": true, "size": 64, "size_bytes": 64, "path": "/w/a"},
                {"name": "big", "size": 2147483647u64, "size_bytes": 5u64 << 30, "path": "/w/big"},
                {"name": "link", "size": 4, "size_bytes": 4, "path": "/w/link", "symlink_target": "a"},
                {"name": "old", "size": 7}
            ]);
            (200, Some(body.to_string()), vec![("X-Toolbox-Truncated", "true")])
        });
        let list = client.list_files("sb-1", "/w/", ListFilesOptions::default()).expect("list");
        let first = calls.lock().unwrap()[0].clone();
        assert_eq!(first.query.get("depth").map(String::as_str), Some("1"));
        assert_eq!(first.query.get("limit").map(String::as_str), Some("10000"));
        assert_eq!(first.query.get("extended").map(String::as_str), Some("true"));
        assert!(list.truncated);
        let paths: Vec<&str> = list.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["/w/a", "/w/big", "/w/link", "/w/old"]);
        assert_eq!(list.entries[1].size, 5 << 30);
        assert_eq!(list.entries[2].symlink_target.as_deref(), Some("a"));
        assert_eq!(list.entries[3].size, 7);

        client
            .list_files("sb-1", "/w", ListFilesOptions { depth: Some(3), limit: Some(5) })
            .expect("list");
        let second = calls.lock().unwrap()[1].clone();
        assert_eq!(second.query.get("depth").map(String::as_str), Some("3"));
        assert_eq!(second.query.get("limit").map(String::as_str), Some("5"));
        assert!(client.list_files("sb-1", "/w", ListFilesOptions { depth: Some(0), limit: None }).is_err());
    }

    #[test]
    fn an_older_agent_fails_closed_before_any_file_call() {
        let (client, calls) = fake_toolbox(&[], |_, _| (204, None, vec![]));
        let refused = [
            client.list_files("sb-1", "/", ListFilesOptions::default()).map(|_| ()),
            client.move_file("sb-1", "/a", "/b", MoveFileOptions::default()),
            client.copy_file("sb-1", "/a", "/b", CopyFileOptions::default()),
            client.make_dir("sb-1", "/d", MakeDirOptions::default()),
        ];
        for result in refused {
            assert!(matches!(result, Err(Error::UnsupportedFeature(_))), "got {:?}", result);
        }
        assert!(calls.lock().unwrap().is_empty());
        // An older agent does what these ask anyway, so no check is needed.
        client
            .move_file("sb-1", "/a", "/b", MoveFileOptions { overwrite: true })
            .expect("move with overwrite");
        client
            .make_dir("sb-1", "/d", MakeDirOptions { parents: true, mode: None })
            .expect("mkdir -p");
        let calls = calls.lock().unwrap();
        assert_eq!(calls[0].query.get("overwrite").map(String::as_str), Some("true"));
        assert_eq!(calls[1].query.get("parents").map(String::as_str), Some("true"));
    }

    #[test]
    fn get_file_info_falls_back_and_file_exists_tells_a_missing_file_from_a_missing_sandbox() {
        let (client, calls) = fake_toolbox(&[], |call, _| match call.query.get("path").map(String::as_str) {
            Some("/new") => (200, Some(r#"{"name":"new","size":2147483647,"size_bytes":3221225472,"path":"/new"}"#.to_string()), vec![]),
            Some("/old") => (200, Some(r#"{"name":"old","size":12}"#.to_string()), vec![]),
            Some("/gone") => (404, err("stat /gone: no such file or directory", Some("file_not_found")), vec![]),
            Some("/gone-old") => (404, err("stat /gone-old: no such file or directory", None), vec![]),
            Some("/no-sandbox") => (404, err("sandbox not found", None), vec![]),
            _ => (403, err("permission denied", None), vec![]),
        });
        let info = client.get_file_info("sb-1", "/new").expect("info");
        assert_eq!(info.size, 3 << 30);
        assert_eq!(calls.lock().unwrap()[0].query.get("extended").map(String::as_str), Some("true"));
        let old = client.get_file_info("sb-1", "/old").expect("old agent info");
        assert_eq!((old.size, old.path.as_str()), (12, "/old"));
        assert!(client.file_exists("sb-1", "/new").expect("exists"));
        assert!(!client.file_exists("sb-1", "/gone").expect("gone"));
        assert!(!client.file_exists("sb-1", "/gone-old").expect("gone on an old agent"));
        assert!(client.file_exists("sb-1", "/no-sandbox").is_err());
        assert!(client.file_exists("sb-1", "/broken").is_err());
    }

    #[test]
    fn a_retried_delete_or_mkdir_counts_work_already_done() {
        // n counts per route and every delete is one route (the path is in
        // the query), so the cases that fail only their first try count
        // their own tries.
        // Reply is a plain fn, so the count lives in a static.
        static TRIES: Mutex<Option<std::collections::HashMap<String, usize>>> = Mutex::new(None);
        let (client, calls) = fake_toolbox(&["files.verbs"], |call, n| {
            let path = call.query.get("path").cloned().unwrap_or_default();
            let tried = {
                let mut tries = TRIES.lock().unwrap();
                let t = tries.get_or_insert_with(Default::default).entry(path.clone()).or_insert(0);
                *t += 1;
                *t
            };
            if path.starts_with("/lost") {
                if n == 0 {
                    return (502, None, vec![]);
                }
                return if call.method == "DELETE" {
                    (404, err("lstat: no such file or directory", Some("file_not_found")), vec![])
                } else {
                    (409, err("already exists", Some("folder_exists")), vec![])
                };
            }
            match path.as_str() {
                "/route-missing" if tried == 1 => (503, None, vec![("Retry-After", "0")]),
                "/route-missing" => (404, err("not found", None), vec![]),
                // A 429 is answered before any work: the path was never there.
                "/refused" if tried == 1 => (429, None, vec![("Retry-After", "0")]),
                "/refused" => (404, err("lstat: no such file or directory", Some("file_not_found")), vec![]),
                "/missing" => (404, err("lstat /missing: no such file or directory", Some("file_not_found")), vec![]),
                "/a-file" => (409, err("mkdir /a-file: file exists", None), vec![]),
                "/new-dir" => (201, None, vec![]),
                _ => (204, None, vec![]),
            }
        });
        client
            .delete_file("sb-1", "/lost-del", DeleteFileOptions { recursive: true })
            .expect("a retried delete that finds the path gone succeeds");
        client
            .make_dir("sb-1", "/lost-dir", MakeDirOptions { parents: false, mode: Some(0o1750) })
            .expect("a retried mkdir that finds its folder succeeds");
        client
            .make_dir("sb-1", "/new-dir", MakeDirOptions::default())
            .expect("mkdir's bare 201");
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls[0].query.get("recursive").map(String::as_str), Some("true"));
            assert_eq!(calls[2].query.get("mode").map(String::as_str), Some("1750"));
            assert_eq!(calls[2].query.get("parents").map(String::as_str), Some("false"));
        }
        match client.delete_file("sb-1", "/missing", DeleteFileOptions::default()) {
            Err(Error::Api(api)) => assert_eq!((api.status(), api.code()), (404, Some("file_not_found"))),
            other => panic!("first-attempt 404 = {:?}", other),
        }
        assert_eq!(api_status(client.make_dir("sb-1", "/a-file", MakeDirOptions::default())), 409);
        // An uncoded 404 on a retry may be an agent without the route.
        assert_eq!(api_status(client.delete_file("sb-1", "/route-missing", DeleteFileOptions::default())), 404);
        // After a 429 the server did nothing, so a coded 404 on the retry
        // means the path never existed, not that this call deleted it.
        match client.delete_file("sb-1", "/refused", DeleteFileOptions::default()) {
            Err(Error::Api(api)) => assert_eq!((api.status(), api.code()), (404, Some("file_not_found"))),
            other => panic!("delete of a missing path after a 429 = {:?}", other),
        }
    }

    #[test]
    fn move_and_copy_retry_only_a_429_or_503() {
        let (client, calls) = fake_toolbox(&["files.verbs"], |call, n| match call.query.get("source").map(String::as_str) {
            Some("/refused-once") if n == 0 => (503, None, vec![]),
            Some("/bad-gateway") => (502, None, vec![]),
            Some("/taken") => (409, err("rename /taken /b: file exists", None), vec![]),
            _ => (204, None, vec![]),
        });
        client
            .move_file("sb-1", "/refused-once", "/b", MoveFileOptions::default())
            .expect("move after a 503");
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(api_status(client.move_file("sb-1", "/bad-gateway", "/b", MoveFileOptions::default())), 502);
        assert_eq!(calls.lock().unwrap().len(), 3, "a 502 on a move was re-sent");
        assert_eq!(api_status(client.move_file("sb-1", "/taken", "/b", MoveFileOptions::default())), 409);
        assert_eq!(
            api_status(client.copy_file("sb-1", "/bad-gateway", "/c", CopyFileOptions { overwrite: false, recursive: true })),
            502
        );
        let last = calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last.route, "/files/copy");
        assert_eq!(last.query.get("recursive").map(String::as_str), Some("true"));
        assert_eq!(last.query.get("overwrite").map(String::as_str), Some("false"));
    }

    #[test]
    fn search_and_find() {
        let (client, _) = fake_toolbox(&[], |call, _| {
            let none = call.query.get("pattern").map(String::as_str) == Some("none");
            let search = call.route.ends_with("/search");
            let body = match (none, search) {
                (true, true) => r#"{"files":null}"#,
                (true, false) => "null",
                (false, true) => r#"{"files":["/w/a.rs"]}"#,
                (false, false) => r#"[{"file":"/w/a.rs","line":2,"content":"fn main()"}]"#,
            };
            (200, Some(body.to_string()), vec![])
        });
        assert_eq!(client.search_files("sb-1", "/w", "*.rs").expect("search"), vec!["/w/a.rs".to_string()]);
        let matches = client.find_in_files("sb-1", "/w", "main").expect("find");
        assert_eq!(matches, vec![FileMatch { file: "/w/a.rs".into(), line: 2, content: "fn main()".into() }]);
        assert!(client.search_files("sb-1", "/w", "none").expect("empty search").is_empty());
        assert!(client.find_in_files("sb-1", "/w", "none").expect("empty find").is_empty());
    }

    #[test]
    fn sandbox_file_methods_delegate() {
        let (client, calls) = fake_toolbox(&["files.verbs"], |call, _| {
            if call.route == "/files/info" {
                return (200, Some(r#"{"name":"x"}"#.to_string()), vec![]);
            }
            if call.method == "GET" {
                let body = if call.route == "/files/search" { r#"{"files":[]}"# } else { "[]" };
                return (200, Some(body.to_string()), vec![]);
            }
            (204, None, vec![])
        });
        let data: SandboxData = serde_json::from_value(serde_json::json!({
            "id": "sb-1", "image": "x", "status": "started", "public_url": "", "cpu": 1, "memory_mb": 1, "disk_gb": 1,
            "os_user": "root", "network_block_all": false, "toolbox_enabled": true, "created_at": "", "updated_at": "",
            "last_active_at": "", "lifecycle": {}
        }))
        .expect("sandbox data");
        let sandbox = Sandbox::new(client, data);
        sandbox.list_files("/", ListFilesOptions::default()).expect("list");
        sandbox.get_file_info("/x").expect("info");
        assert!(sandbox.file_exists("/x").expect("exists"));
        sandbox.delete_file("/x", DeleteFileOptions::default()).expect("delete");
        sandbox.make_dir("/d", MakeDirOptions { parents: true, mode: None }).expect("mkdir");
        sandbox.move_file("/a", "/b", MoveFileOptions { overwrite: true }).expect("move");
        sandbox.copy_file("/a", "/b", CopyFileOptions::default()).expect("copy");
        sandbox.search_files("/", "*").expect("search");
        sandbox.find_in_files("/", "x").expect("find");
        let routes: Vec<String> = calls.lock().unwrap().iter().map(|c| c.route.clone()).collect();
        assert_eq!(
            routes,
            [
                "/files", "/files/info", "/files/info", "/files", "/files/folder", "/files/move", "/files/copy",
                "/files/search", "/files/find"
            ]
        );
    }

    #[test]
    fn upload_options_are_sent_after_the_version_check_on_the_right_retry_tier() {
        let (client, calls) = fake_toolbox(&["files.write_options"], |call, n| {
            if call.method == "POST" && n == 0 {
                return (502, None, vec![]);
            }
            (201, Some("{}".to_string()), vec![])
        });
        // A plain upload is re-sent after a 502.
        client.upload_file("sb-1", "/a", b"x".to_vec()).expect("plain upload");
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(calls.lock().unwrap()[0].query.is_empty());

        let (client, calls) = fake_toolbox(&["files.write_options"], |_, n| {
            if n == 0 {
                return (502, None, vec![]);
            }
            (201, Some("{}".to_string()), vec![])
        });
        let options = UploadFileOptions { create_only: true, atomic: true, mode: Some(0o600), append: false };
        // create_only is not re-sent after a 502: the first send may have made the file.
        match client.upload_file_with_options("sb-1", "/a", b"x".to_vec(), options) {
            Err(Error::Api(api)) => assert_eq!(api.status(), 502),
            other => panic!("create_only through a 502 = {:?}", other),
        }
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].query.get("create_only").map(String::as_str), Some("true"));
        assert_eq!(calls[0].query.get("atomic").map(String::as_str), Some("true"));
        assert_eq!(calls[0].query.get("mode").map(String::as_str), Some("600"));
    }

    #[test]
    fn upload_options_fail_closed_on_an_older_agent() {
        let (client, calls) = fake_toolbox(&[], |_, _| (201, Some("{}".to_string()), vec![]));
        for options in [
            UploadFileOptions { append: true, ..Default::default() },
            UploadFileOptions { create_only: true, ..Default::default() },
            UploadFileOptions { atomic: true, ..Default::default() },
            UploadFileOptions { mode: Some(0o644), ..Default::default() },
        ] {
            let result = client.upload_file_with_options("sb-1", "/a", b"x".to_vec(), options);
            assert!(matches!(result, Err(Error::UnsupportedFeature(_))), "got {:?}", result);
        }
        assert!(calls.lock().unwrap().is_empty());
        let data: SandboxData = serde_json::from_value(serde_json::json!({
            "id": "sb-1", "image": "x", "status": "started", "public_url": "", "cpu": 1, "memory_mb": 1, "disk_gb": 1,
            "os_user": "root", "network_block_all": false, "toolbox_enabled": true, "created_at": "", "updated_at": "",
            "last_active_at": "", "lifecycle": {}
        }))
        .expect("sandbox data");
        let sandbox = Sandbox::new(client, data);
        sandbox.upload_file("/a", b"x".to_vec()).expect("a plain upload needs no check");
        assert!(sandbox
            .upload_file_with_options("/a", b"x".to_vec(), UploadFileOptions { append: true, ..Default::default() })
            .is_err());
    }

    /// Reads a tar back the way a tar reader does, checking each checksum:
    /// (name, typeflag, mode, data, link) per entry, PAX names applied.
    fn parse_tar(archive: &[u8]) -> Vec<(String, u8, u32, Vec<u8>, String)> {
        let field = |block: &[u8], offset: usize, len: usize| -> String {
            let raw = &block[offset..offset + len];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(len);
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        let mut out = Vec::new();
        let mut pax: HashMap<String, String> = HashMap::new();
        let mut offset = 0;
        while offset + 512 <= archive.len() {
            let block = &archive[offset..offset + 512];
            if block.iter().all(|&b| b == 0) {
                break;
            }
            let sum: u32 = block.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u32::from(b) }).sum();
            assert_eq!(u32::from_str_radix(field(block, 148, 7).trim(), 8).unwrap(), sum, "checksum");
            assert_eq!(field(block, 257, 6), "ustar");
            let size = usize::from_str_radix(&field(block, 124, 12), 8).unwrap();
            let data = archive[offset + 512..offset + 512 + size].to_vec();
            let typeflag = block[156];
            offset += 512 + size.div_ceil(512) * 512;
            if typeflag == b'x' {
                let mut rest = String::from_utf8(data).unwrap();
                while !rest.is_empty() {
                    let length: usize = rest.split(' ').next().unwrap().parse().unwrap();
                    let record: String = rest.drain(..length).collect();
                    assert!(record.ends_with('\n'), "a PAX record's length must count the whole record");
                    let (key, value) = record[record.find(' ').unwrap() + 1..record.len() - 1].split_once('=').unwrap();
                    pax.insert(key.to_string(), value.to_string());
                }
                continue;
            }
            let name = pax.remove("path").unwrap_or_else(|| field(block, 0, 100));
            let link = pax.remove("linkpath").unwrap_or_else(|| field(block, 157, 100));
            let mode = u32::from_str_radix(&field(block, 100, 8), 8).unwrap();
            out.push((name, typeflag, mode, data, link));
        }
        out
    }

    fn temp_folder() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aerolvm-upload-dir-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(dir.join("pkg")).unwrap();
        std::fs::write(dir.join("a.txt"), "alpha").unwrap();
        std::fs::write(dir.join("pkg").join("b.rs"), "beta").unwrap();
        let long = "x".repeat(120);
        std::fs::write(dir.join("pkg").join(&long), "long").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.join("pkg").join("b.rs"), std::fs::Permissions::from_mode(0o750)).unwrap();
            std::os::unix::fs::symlink("a.txt", dir.join("link")).unwrap();
            std::fs::hard_link(dir.join("a.txt"), dir.join("hard.txt")).unwrap();
        }
        dir
    }

    #[cfg(unix)]
    #[test]
    fn tar_folder_writes_files_folders_symlinks_and_long_names() {
        let dir = temp_folder();
        let archive = tar_folder(&dir).expect("tar");
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(archive.len() % 512, 0);
        let entries = parse_tar(&archive);
        let long = format!("pkg/{}", "x".repeat(120));
        let names: Vec<(String, u8)> = entries.iter().map(|e| (e.0.clone(), e.1)).collect();
        assert_eq!(
            names,
            vec![
                ("a.txt".to_string(), b'0'),
                ("hard.txt".to_string(), b'0'),
                ("link".to_string(), b'2'),
                ("pkg/".to_string(), b'5'),
                ("pkg/b.rs".to_string(), b'0'),
                (long, b'0'),
            ]
        );
        assert_eq!(entries[1].3, b"alpha".to_vec(), "a hard-linked file is sent as its own file");
        assert_eq!(entries[2].4, "a.txt");
        assert_eq!(entries[4].2, 0o750);
        assert_eq!(entries[5].3, b"long".to_vec());
    }

    #[test]
    fn a_pax_record_length_counts_its_own_digits() {
        for n in 80..1010 {
            let record = pax_record("path", &"v".repeat(n));
            let length: usize = String::from_utf8_lossy(&record).split(' ').next().unwrap().parse().unwrap();
            assert_eq!(length, record.len(), "value length {}", n);
        }
    }

    #[cfg(unix)]
    #[test]
    fn upload_dir_sends_the_folder_once_with_extract() {
        let dir = temp_folder();
        let (client, calls) = fake_toolbox(&["files.extract"], |_, _| (503, None, vec![]));
        match client.upload_dir("sb-1", &dir, "/work/app") {
            Err(Error::Api(api)) => assert_eq!(api.status(), 503),
            other => panic!("upload_dir = {:?}", other),
        }
        let calls = calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "a folder upload was re-sent");
        assert_eq!(calls[0].route, "/files/upload");
        assert_eq!(calls[0].query.get("extract").map(String::as_str), Some("true"));
        let body = String::from_utf8_lossy(&calls[0].body);
        assert!(body.contains("/work/app") && body.contains("pkg/b.rs") && body.contains("alpha"));

        let (old, old_calls) = fake_toolbox(&[], |_, _| (201, Some("{}".to_string()), vec![]));
        assert!(matches!(old.upload_dir("sb-1", &dir, "/w"), Err(Error::UnsupportedFeature(_))));
        assert!(matches!(old.upload_dir("sb-1", dir.join("a.txt"), "/w"), Err(Error::Client(_))));
        assert!(matches!(old.upload_dir("sb-1", dir.join("missing"), "/w"), Err(Error::Client(_))));
        assert!(old_calls.lock().unwrap().is_empty());

        let (ok, ok_calls) = fake_toolbox(&["files.extract"], |_, _| (201, Some("{}".to_string()), vec![]));
        let data: SandboxData = serde_json::from_value(serde_json::json!({
            "id": "sb-1", "image": "x", "status": "started", "public_url": "", "cpu": 1, "memory_mb": 1, "disk_gb": 1,
            "os_user": "root", "network_block_all": false, "toolbox_enabled": true, "created_at": "", "updated_at": "",
            "last_active_at": "", "lifecycle": {}
        }))
        .expect("sandbox data");
        Sandbox::new(ok, data).upload_dir(&dir, "/w").expect("upload_dir");
        assert_eq!(ok_calls.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn downloads_honour_max_bytes_and_retry_until_the_file_starts() {
        let (client, calls) = fake_toolbox(&[], |call, n| match call.query.get("path").map(String::as_str) {
            Some("/flaky") if n == 0 => (503, None, vec![]),
            Some("/streamed") => (200, Some("x".repeat(10)), vec![("X-No-Length", "1")]),
            _ => (200, Some("0123456789".to_string()), vec![]),
        });
        assert_eq!(client.download_file("sb-1", "/flaky").expect("download after a 503"), b"0123456789".to_vec());
        assert_eq!(calls.lock().unwrap().len(), 2);
        let capped = |max| DownloadFileOptions { max_bytes: Some(max) };
        assert!(matches!(client.download_file_with_options("sb-1", "/sized", capped(5)), Err(Error::Client(msg)) if msg.contains("max_bytes")));
        assert_eq!(client.download_file_with_options("sb-1", "/sized", capped(10)).expect("at the cap").len(), 10);
        let mut dest = Vec::new();
        assert!(matches!(client.download_file_to("sb-1", "/streamed", &mut dest, capped(4)), Err(Error::Client(_))));
        assert_eq!(dest, b"xxxx".to_vec(), "what arrived up to the cap is kept");
        let mut dest = Vec::new();
        assert_eq!(client.download_file_to("sb-1", "/streamed", &mut dest, DownloadFileOptions::default()).expect("streamed"), 10);
        assert_eq!(dest.len(), 10);
    }

    #[test]
    fn upload_file_from_streams_the_body_once() {
        let (client, calls) = fake_toolbox(&["files.write_options"], |_, n| if n == 0 { (503, None, vec![]) } else { (201, Some("{}".to_string()), vec![]) });
        let data = std::io::Cursor::new(vec![b'a'; 5000]);
        match client.upload_file_from("sb-1", "/w/big.bin", data, UploadFileOptions::default()) {
            Err(Error::Api(api)) => assert_eq!(api.status(), 503),
            other => panic!("streamed upload = {:?}", other),
        }
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1, "a streamed upload was re-sent");
            let body = String::from_utf8_lossy(&calls[0].body);
            assert!(body.contains("/w/big.bin") && body.contains(&"a".repeat(5000)));
        }
        let data: SandboxData = serde_json::from_value(serde_json::json!({
            "id": "sb-1", "image": "x", "status": "started", "public_url": "", "cpu": 1, "memory_mb": 1, "disk_gb": 1,
            "os_user": "root", "network_block_all": false, "toolbox_enabled": true, "created_at": "", "updated_at": "",
            "last_active_at": "", "lifecycle": {}
        }))
        .expect("sandbox data");
        let sandbox = Sandbox::new(client, data);
        sandbox
            .upload_file_from("/w/x", std::io::Cursor::new(b"x".to_vec()), UploadFileOptions { create_only: true, ..Default::default() })
            .expect("upload with create_only");
        assert_eq!(calls.lock().unwrap()[1].query.get("create_only").map(String::as_str), Some("true"));
        assert_eq!(sandbox.download_file_with_options("/w/x", DownloadFileOptions::default()).expect("read").len(), 2);
        let mut dest = Vec::new();
        assert_eq!(sandbox.download_file_to("/w/x", &mut dest, DownloadFileOptions::default()).expect("read to"), 2);
    }
}
