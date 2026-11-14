//! Calls that act on sandboxes by name or by tag rather than by ID, and the
//! guard that deletes a sandbox when it goes out of scope (plan section 5.3,
//! S2, S4 and S5).

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use crate::{Client, CreateOptions, Error, Sandbox};

impl Sandbox {
    /// Wraps the sandbox in a [`SandboxGuard`] that deletes it when the
    /// guard is dropped, at the end of its scope or while unwinding from a
    /// panic. Calling this is the opt-in: a plain [`Sandbox`] is never
    /// deleted on drop. The guard derefs to the sandbox, so every method
    /// still works through it.
    pub fn destroy_on_drop(self) -> SandboxGuard {
        SandboxGuard { sandbox: Some(self) }
    }
}

/// A [`Sandbox`] that is deleted when this guard is dropped. Made by
/// [`Sandbox::destroy_on_drop`].
///
/// `Drop` cannot return an error, so a failed delete on drop is ignored (a
/// sandbox already gone counts as deleted). Call [`SandboxGuard::destroy`] to
/// delete it and see the error, or [`SandboxGuard::keep`] to keep the sandbox.
/// The guard is not `Clone`: one guard owns one delete, so a copy can never
/// delete the sandbox while another handle still uses it.
pub struct SandboxGuard {
    sandbox: Option<Sandbox>,
}

impl SandboxGuard {
    /// Deletes the sandbox now and returns the error, if any. A sandbox that
    /// is already gone (404) counts as deleted.
    pub fn destroy(mut self) -> Result<(), Error> {
        match self.sandbox.take() {
            Some(sandbox) => match sandbox.destroy() {
                Err(err) if err.is_not_found() => Ok(()),
                other => other,
            },
            None => Ok(()),
        }
    }

    /// Keeps the sandbox: returns it and deletes nothing.
    pub fn keep(mut self) -> Sandbox {
        self.sandbox.take().expect("a live guard always holds its sandbox")
    }
}

impl Deref for SandboxGuard {
    type Target = Sandbox;

    fn deref(&self) -> &Sandbox {
        self.sandbox.as_ref().expect("a live guard always holds its sandbox")
    }
}

impl DerefMut for SandboxGuard {
    fn deref_mut(&mut self) -> &mut Sandbox {
        self.sandbox.as_mut().expect("a live guard always holds its sandbox")
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        if let Some(sandbox) = self.sandbox.take() {
            let _ = sandbox.destroy();
        }
    }
}

impl Client {
    /// Deletes every sandbox of yours that carries all of `tags` and returns
    /// the IDs of the ones now gone.
    ///
    /// It lists every page first, then deletes them one at a time. A sandbox
    /// that is already gone (404) counts as deleted, so a second call, or two
    /// calls at once, is safe. Any other failed delete stops the call and is
    /// returned; the sandboxes already deleted stay deleted, and calling it
    /// again finishes the job. `tags` must not be empty: with no filter it
    /// would delete every sandbox you own.
    pub fn destroy_all(&self, tags: &HashMap<String, String>) -> Result<Vec<String>, Error> {
        if tags.is_empty() {
            return Err(Error::Client(
                "destroy_all needs at least one tag; with none it would delete every sandbox you own".into(),
            ));
        }
        let ids: Vec<String> = self.list_with_tags(tags)?.into_iter().map(|sandbox| sandbox.data.id).collect();
        let mut gone = Vec::with_capacity(ids.len());
        for id in ids {
            match self.destroy(&id) {
                Ok(()) => {}
                Err(err) if err.is_not_found() => {}
                Err(err) => return Err(err),
            }
            gone.push(id);
        }
        Ok(gone)
    }

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
                // Read the answer on arrival, before the barrier: no caller
                // can create until every gated lookup has arrived, so all of
                // them miss. Reading after the wait could see a sandbox
                // another caller had made since.
                let name = param("name").unwrap();
                let hits: Vec<Value> = {
                    let st = state.lock().unwrap();
                    st.sandboxes.values().filter(|s| s["name"] == name.as_str()).cloned().collect()
                };
                if wait {
                    barrier.wait();
                }
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

    fn tagged(pairs: &[(&str, &str)]) -> Value {
        Value::Object(pairs.iter().map(|(k, v)| (k.to_string(), json!(v))).collect())
    }

    fn tag_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn destroy_all_deletes_every_match_across_pages() {
        let (url, state) = spawn_fake(0);
        let pairs = [("run", "42"), ("team", "x")];
        let doomed: Vec<String> = (0..5).map(|i| state.lock().unwrap().add(&format!("a-{i}"), tagged(&pairs), "alpine")).collect();
        state.lock().unwrap().add("other", tagged(&[("run", "41"), ("team", "x")]), "alpine");
        state.lock().unwrap().add("untagged", json!({}), "alpine");
        let client = fake_client(&url);
        assert_eq!(client.destroy_all(&tag_map(&pairs)).expect("destroy_all"), doomed);
        {
            let st = state.lock().unwrap();
            assert_eq!(st.sandboxes.len(), 2);
            assert_eq!((st.count("GET"), st.count("DELETE")), (3, 5));
        }
        assert!(client.destroy_all(&tag_map(&pairs)).expect("second destroy_all").is_empty());
    }

    #[test]
    fn destroy_all_counts_an_already_gone_sandbox_as_deleted() {
        let (url, state) = spawn_fake(0);
        let first = state.lock().unwrap().add("a", tagged(&[("run", "42")]), "alpine");
        let second = state.lock().unwrap().add("b", tagged(&[("run", "42")]), "alpine");
        state.lock().unwrap().delete_status.insert(first.clone(), 404);
        let gone = fake_client(&url).destroy_all(&tag_map(&[("run", "42")])).expect("destroy_all");
        assert_eq!(gone, vec![first, second]);
    }

    #[test]
    fn destroy_all_stops_at_a_failed_delete() {
        let (url, state) = spawn_fake(0);
        let first = state.lock().unwrap().add("a", tagged(&[("run", "42")]), "alpine");
        let second = state.lock().unwrap().add("b", tagged(&[("run", "42")]), "alpine");
        let third = state.lock().unwrap().add("c", tagged(&[("run", "42")]), "alpine");
        state.lock().unwrap().delete_status.insert(second, 500);
        let err = fake_client(&url).destroy_all(&tag_map(&[("run", "42")])).expect_err("500");
        assert_eq!(err.api_error().map(|e| e.status()), Some(500));
        let st = state.lock().unwrap();
        assert!(!st.sandboxes.contains_key(&first));
        assert!(st.sandboxes.contains_key(&third));
        assert_eq!(st.count("DELETE"), 2);
    }

    #[test]
    fn destroy_all_needs_a_tag() {
        let (url, state) = spawn_fake(0);
        let err = fake_client(&url).destroy_all(&HashMap::new()).expect_err("no tags");
        assert!(matches!(err, Error::Client(_)), "{err}");
        assert!(state.lock().unwrap().requests.is_empty());
    }

    fn new_sandbox() -> (Arc<Mutex<FakeState>>, Sandbox) {
        let (url, state) = spawn_fake(0);
        let (sandbox, _) = fake_client(&url).get_or_create("box", opts("alpine")).expect("get_or_create");
        (state, sandbox)
    }

    #[test]
    fn a_plain_sandbox_is_not_deleted_on_drop() {
        let (state, sandbox) = new_sandbox();
        drop(sandbox);
        assert_eq!(state.lock().unwrap().count("DELETE"), 0);
    }

    #[test]
    fn the_guard_deletes_on_drop_and_derefs_to_the_sandbox() {
        let (state, sandbox) = new_sandbox();
        {
            let guard = sandbox.destroy_on_drop();
            assert_eq!(guard.data.name.as_deref(), Some("box"));
        }
        let st = state.lock().unwrap();
        assert_eq!(st.count("DELETE"), 1);
        assert!(st.sandboxes.is_empty());
    }

    #[test]
    fn the_guard_deletes_while_unwinding_from_a_panic() {
        let (state, sandbox) = new_sandbox();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = sandbox.destroy_on_drop();
            panic!("work failed");
        }));
        assert!(result.is_err());
        assert!(state.lock().unwrap().sandboxes.is_empty());
    }

    #[test]
    fn keep_disarms_the_guard() {
        let (state, sandbox) = new_sandbox();
        let kept = sandbox.destroy_on_drop().keep();
        drop(kept);
        assert_eq!(state.lock().unwrap().count("DELETE"), 0);
    }

    #[test]
    fn destroy_reports_a_failure_and_counts_a_404_as_deleted() {
        let (state, sandbox) = new_sandbox();
        let id = sandbox.data.id.clone();
        state.lock().unwrap().delete_status.insert(id.clone(), 500);
        let err = sandbox.clone().destroy_on_drop().destroy().expect_err("500");
        assert_eq!(err.api_error().map(|e| e.status()), Some(500));
        state.lock().unwrap().delete_status.insert(id, 404);
        sandbox.destroy_on_drop().destroy().expect("404 counts as deleted");
    }
}
