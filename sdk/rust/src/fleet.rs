//! Calls that act on sandboxes by name or by tag rather than by ID (plan
//! section 5.3, S4 and S5).

use crate::{Client, CreateOptions, Error, Sandbox};

impl Client {
    /// Returns the caller's sandbox called `name`, creating it from `opts`
    /// when there is none. The `bool` is true only when this call made the
    /// sandbox.
    ///
    /// Safe to retry and to run at the same time from many processes. Names
    /// are unique per owner, so when two callers race to create the same
    /// name, one gets a 409 and reads the winner's sandbox instead; a 409
    /// whose name still cannot be found is a conflict on something else and
    /// is returned as is. An existing sandbox is returned as it is: its image
    /// and settings are not compared with `opts`. `opts.name` may be `None`
    /// or repeat `name`.
    pub fn get_or_create(&self, name: &str, mut opts: CreateOptions) -> Result<(Sandbox, bool), Error> {
        let wanted = name.trim();
        if wanted.is_empty() {
            return Err(Error::Client("sandbox name is required".into()));
        }
        if let Some(given) = opts.name.as_deref().map(str::trim).filter(|given| !given.is_empty()) {
            if given != wanted {
                return Err(Error::Client(format!("options name {given:?} differs from {wanted:?}")));
            }
        }
        if let Some(existing) = self.get_by_name(wanted)? {
            return Ok((existing, false));
        }
        opts.name = Some(wanted.to_string());
        match self.create(opts) {
            Ok(created) => Ok((created, true)),
            Err(err) if err.is_conflict() => match self.get_by_name(wanted) {
                Ok(Some(winner)) => Ok((winner, false)),
                _ => Err(err),
            },
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{ApiVersion, ClientConfig, RetryConfig};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    /// A fake sandboxd keeping sandboxes by name the way the real server
    /// does (names unique per owner, a second create of a name is a 409).
    /// `lookup_barrier` holds the first N name lookups until all N arrive,
    /// so N concurrent callers all miss before any of them creates.
    #[derive(Default)]
    pub(crate) struct FakeState {
        pub sandboxes: BTreeMap<String, Value>,
        pub requests: Vec<String>,
        pub next_id: u32,
        pub conflict_without_name: bool,
        pub delete_status: BTreeMap<String, u16>,
        barrier_left: usize,
    }

    impl FakeState {
        pub fn add(&mut self, name: &str, tags: Value, image: &str) -> String {
            self.next_id += 1;
            let id = format!("sb-{:03}", self.next_id);
            self.sandboxes.insert(id.clone(), sandbox_json(&id, name, tags, image));
            id
        }

        pub fn count(&self, method: &str) -> usize {
            self.requests.iter().filter(|r| r.starts_with(&format!("{method} "))).count()
        }
    }

    fn sandbox_json(id: &str, name: &str, tags: Value, image: &str) -> Value {
        json!({"id": id, "name": name, "image": image, "status": "started", "tags": tags,
               "cpu": 1, "memory_mb": 512, "disk_gb": 1, "os_user": "root", "public_url": "",
               "network_block_all": false, "toolbox_enabled": true,
               "created_at": "2026-11-06T00:00:00Z", "updated_at": "2026-11-06T00:00:00Z",
               "last_active_at": "2026-11-06T00:00:00Z", "lifecycle": {}})
    }

    pub(crate) fn spawn_fake(lookup_barrier: usize) -> (String, Arc<Mutex<FakeState>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let state = Arc::new(Mutex::new(FakeState { barrier_left: lookup_barrier, ..Default::default() }));
        let barrier = Arc::new(Barrier::new(lookup_barrier.max(1)));
        let shared = state.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let state = shared.clone();
                let barrier = barrier.clone();
                thread::spawn(move || serve(stream, state, barrier));
            }
        });
        (url, state)
    }

    fn serve(mut stream: std::net::TcpStream, state: Arc<Mutex<FakeState>>, barrier: Arc<Barrier>) {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).expect("header");
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            if let Some((key, value)) = header.split_once(':') {
                if key.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).expect("body");
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
        let params: Vec<(String, String)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (urlencoding::decode(k).unwrap().into_owned(), urlencoding::decode(v).unwrap().into_owned())
            })
            .collect();
        let param = |key: &str| params.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        state.lock().unwrap().requests.push(format!("{method} {target}"));

        let (status, extra, payload): (u16, String, Option<Value>) = match (method.as_str(), path) {
            ("GET", "/v1/sandboxes") if param("name").is_some() => {
                let wait = {
                    let mut st = state.lock().unwrap();
                    if st.barrier_left > 0 {
                        st.barrier_left -= 1;
                        true
                    } else {
                        false
                    }
                };
                if wait {
                    barrier.wait();
                }
                let name = param("name").unwrap();
                let st = state.lock().unwrap();
                let hits: Vec<Value> = st.sandboxes.values().filter(|s| s["name"] == name.as_str()).cloned().collect();
                (200, String::new(), Some(Value::Array(hits)))
            }
            ("GET", "/v1/sandboxes") => {
                let st = state.lock().unwrap();
                let matched: Vec<Value> = st
                    .sandboxes
                    .values()
                    .filter(|s| {
                        params.iter().all(|(k, v)| match k.strip_prefix("tag.") {
                            Some(tag) => s["tags"][tag] == v.as_str(),
                            None => true,
                        })
                    })
                    .cloned()
                    .collect();
                let start: usize = param("page_token").and_then(|t| t.parse().ok()).unwrap_or(0);
                let end = (start + 2).min(matched.len());
                let next = if end < matched.len() {
                    format!("X-Cluster-List-Next-Page-Token: {end}\r\n")
                } else {
                    String::new()
                };
                (200, next, Some(Value::Array(matched[start.min(end)..end].to_vec())))
            }
            ("POST", "/v1/sandboxes") => {
                let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let mut st = state.lock().unwrap();
                let name = req["name"].as_str().unwrap_or_default().to_string();
                if st.conflict_without_name {
                    (409, String::new(), Some(json!({"error": "sandbox id already reserved"})))
                } else if !name.is_empty() && st.sandboxes.values().any(|s| s["name"] == name.as_str()) {
                    (409, String::new(), Some(json!({"error": "sandbox name already in use"})))
                } else {
                    let tags = req.get("tags").cloned().unwrap_or(json!({}));
                    let image = req["image"].as_str().unwrap_or_default().to_string();
                    let id = st.add(&name, tags, &image);
                    (201, String::new(), Some(st.sandboxes[&id].clone()))
                }
            }
            ("DELETE", p) if p.starts_with("/v1/sandboxes/") => {
                let id = p.trim_start_matches("/v1/sandboxes/").to_string();
                let mut st = state.lock().unwrap();
                let forced = st.delete_status.get(&id).copied();
                let status = match forced {
                    Some(status) => status,
                    None if st.sandboxes.remove(&id).is_some() => 204,
                    None => 404,
                };
                let payload = (status != 204).then(|| json!({"error": format!("delete failed with {status}")}));
                (status, String::new(), payload)
            }
            _ => (404, String::new(), Some(json!({"error": "not found"}))),
        };
        let body = payload.map(|p| p.to_string()).unwrap_or_default();
        let response = if status == 204 {
            "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_string()
        } else {
            format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
        };
        let _ = stream.write_all(response.as_bytes());
    }

    pub(crate) fn fake_client(url: &str) -> Client {
        Client::with_config(
            ClientConfig {
                api_url: Some(url.to_string()),
                pat_token: Some("pat".to_string()),
                retry: Some(RetryConfig { max_retries: Some(0), ..Default::default() }),
                ..Default::default()
            },
            ApiVersion::V1,
        )
        .expect("client")
    }

    fn opts(image: &str) -> CreateOptions {
        CreateOptions { image: image.to_string(), ..Default::default() }
    }

    #[test]
    fn get_or_create_creates_when_the_name_is_free() {
        let (url, state) = spawn_fake(0);
        let mut options = opts("alpine");
        options.tags = Some([("team".to_string(), "x".to_string())].into_iter().collect());
        let (sandbox, created) = fake_client(&url).get_or_create(" agent-1 ", options).expect("get_or_create");
        assert!(created);
        assert_eq!(sandbox.data.name.as_deref(), Some("agent-1"));
        let st = state.lock().unwrap();
        assert_eq!((st.count("GET"), st.count("POST")), (1, 1));
    }

    #[test]
    fn get_or_create_returns_the_existing_sandbox() {
        let (url, state) = spawn_fake(0);
        let id = state.lock().unwrap().add("agent-1", json!({}), "ubuntu");
        let mut options = opts("alpine");
        options.name = Some("agent-1".to_string());
        let (sandbox, created) = fake_client(&url).get_or_create("agent-1", options).expect("get_or_create");
        assert!(!created);
        assert_eq!(sandbox.data.id, id);
        assert_eq!(sandbox.data.image, "ubuntu");
        assert_eq!(state.lock().unwrap().count("POST"), 0);
    }

    #[test]
    fn get_or_create_gives_concurrent_callers_one_sandbox() {
        const CALLERS: usize = 8;
        let (url, state) = spawn_fake(CALLERS);
        let handles: Vec<_> = (0..CALLERS)
            .map(|_| {
                let client = fake_client(&url);
                thread::spawn(move || client.get_or_create("shared", opts("alpine")).expect("get_or_create"))
            })
            .collect();
        let results: Vec<(Sandbox, bool)> = handles.into_iter().map(|h| h.join().expect("join")).collect();
        let ids: std::collections::HashSet<_> = results.iter().map(|(s, _)| s.data.id.clone()).collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(results.iter().filter(|(_, created)| *created).count(), 1);
        let st = state.lock().unwrap();
        assert_eq!(st.sandboxes.len(), 1);
        assert_eq!(st.count("POST"), CALLERS);
    }

    #[test]
    fn get_or_create_returns_a_conflict_on_something_else() {
        let (url, state) = spawn_fake(0);
        state.lock().unwrap().conflict_without_name = true;
        let err = fake_client(&url).get_or_create("agent-1", opts("alpine")).expect_err("conflict");
        assert!(err.is_conflict(), "{err}");
        assert_eq!(err.api_error().map(|e| e.message().to_string()).as_deref(), Some("sandbox id already reserved"));
    }

    #[test]
    fn get_or_create_refuses_bad_names_before_sending() {
        let (url, state) = spawn_fake(0);
        let client = fake_client(&url);
        for (name, given) in [("", None), ("  ", None), ("a", Some("b"))] {
            let mut options = opts("alpine");
            options.name = given.map(String::from);
            let err = client.get_or_create(name, options).expect_err(name);
            assert!(matches!(err, Error::Client(_)), "{err}");
        }
        assert!(state.lock().unwrap().requests.is_empty());
    }
}
