//! Cell routing (C16). A federation is several AerolVM installs ("cells"),
//! each with its own API address, that accept the same token. A cell asked
//! about a sandbox that another cell holds answers 421 and names the right
//! cell in [`crate::CELL_ENDPOINT_HEADER`]. The client sends the request
//! there once and remembers the cell, so the sandbox's later calls skip the
//! wrong cell.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::CELL_ENDPOINT_HEADER;

/// How many sandboxes' cells one client keeps. Past it the oldest is
/// dropped; a dropped sandbox costs one extra 421 round trip, never a wrong
/// answer.
const MAX_CELL_ROUTES: usize = 10_000;

/// What a response's [`CELL_ENDPOINT_HEADER`] asks the client to do.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CellHint {
    /// Not a 421, or no usable header: the in-cluster 421 a node gives for a
    /// sandbox it does not hold, which the retry loop handles as before.
    None,
    /// Send the request to this cell base URL (no trailing slash).
    Follow(String),
    /// An `http` cell for an `https` client. Following it would send the
    /// token in clear text, so the 421 goes to the caller.
    Downgrade,
}

/// Reads a response for a cell redirect. `configured` is the client's own
/// base URL, which decides whether an `http` cell is a downgrade.
pub(crate) fn cell_hint(status: http::StatusCode, headers: &http::HeaderMap, configured: &str) -> CellHint {
    if status != http::StatusCode::MISDIRECTED_REQUEST {
        return CellHint::None;
    }
    let Some(value) = headers
        .get(CELL_ENDPOINT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return CellHint::None;
    };
    let Ok(url) = reqwest::Url::parse(value) else {
        return CellHint::None;
    };
    // The client appends `/v1/...` to the base, so a query or fragment
    // would land in the middle of the request URL.
    if !matches!(url.scheme(), "http" | "https") || !url.has_host() || url.query().is_some() || url.fragment().is_some()
    {
        return CellHint::None;
    }
    let configured_https = reqwest::Url::parse(configured).is_ok_and(|base| base.scheme() == "https");
    if configured_https && url.scheme() == "http" {
        return CellHint::Downgrade;
    }
    // Trimmed like the configured base, so a cell's path prefix joins the
    // request path the same way.
    CellHint::Follow(url.as_str().trim_end_matches('/').to_string())
}

/// The sandbox a request path is for: the segment after
/// `{prefix}/sandboxes/`. `None` for a route that is not per-sandbox, such
/// as the list and create routes.
pub(crate) fn sandbox_of(path: &str, prefix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?.strip_prefix("/sandboxes/")?;
    let raw = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    if raw.is_empty() {
        return None;
    }
    // Some routes percent-encode the id and some do not; decoding gives
    // both spellings one entry.
    Some(urlencoding::decode(raw).map_or_else(|_| raw.to_string(), |id| id.into_owned()))
}

/// Each sandbox's cell base URL. A client's clones share one, so a
/// [`crate::Sandbox`] uses what its client learned. Entries never expire
/// on a timer: a sandbox does not move between cells, and a 404 from its
/// cell is what drops one.
#[derive(Debug, Default)]
pub(crate) struct CellRoutes {
    routes: Mutex<Routes>,
}

#[derive(Debug, Default)]
struct Routes {
    by_id: HashMap<String, String>,
    /// `by_id`'s keys, oldest first, for dropping the oldest.
    order: VecDeque<String>,
}

impl CellRoutes {
    fn lock(&self) -> std::sync::MutexGuard<'_, Routes> {
        // A panic while the lock was held cannot leave the map half
        // written: every change is one insert or remove.
        self.routes.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn get(&self, sandbox_id: &str) -> Option<String> {
        self.lock().by_id.get(sandbox_id).cloned()
    }

    pub(crate) fn remember(&self, sandbox_id: &str, base: &str) {
        let mut routes = self.lock();
        if let Some(known) = routes.by_id.get_mut(sandbox_id) {
            *known = base.to_string();
            return;
        }
        routes.by_id.insert(sandbox_id.to_string(), base.to_string());
        routes.order.push_back(sandbox_id.to_string());
        while routes.by_id.len() > MAX_CELL_ROUTES {
            let Some(oldest) = routes.order.pop_front() else { break };
            routes.by_id.remove(&oldest);
        }
    }

    /// Drops the sandbox's cell, but only while it is still `base`: another
    /// thread may have learned a newer cell since this request was sent.
    pub(crate) fn forget(&self, sandbox_id: &str, base: &str) {
        let mut routes = self.lock();
        if routes.by_id.get(sandbox_id).map(String::as_str) != Some(base) {
            return;
        }
        routes.by_id.remove(sandbox_id);
        // O(n), but only on a 404 from a cell, which is rare.
        routes.order.retain(|id| id != sandbox_id);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().by_id.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: Option<&str>) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        if let Some(value) = value {
            headers.insert(CELL_ENDPOINT_HEADER, http::HeaderValue::from_str(value).expect("header value"));
        }
        headers
    }

    #[test]
    fn cell_hint_follows_only_a_421_naming_an_absolute_http_url() {
        let misdirected = http::StatusCode::MISDIRECTED_REQUEST;
        let follow = |url: &str| CellHint::Follow(url.to_string());
        for (status, value, configured, want) in [
            (misdirected, Some("https://cell2.example.com"), "https://cell1.example.com", follow("https://cell2.example.com")),
            (misdirected, Some(" https://cell2.example.com:8443/api/ "), "https://cell1.example.com", follow("https://cell2.example.com:8443/api")),
            (misdirected, Some("http://cell2.example.com"), "http://cell1.example.com", follow("http://cell2.example.com")),
            // An upgrade is fine; only https -> http sends the token in clear.
            (misdirected, Some("https://cell2.example.com"), "http://cell1.example.com", follow("https://cell2.example.com")),
            (misdirected, Some("http://cell2.example.com"), "https://cell1.example.com", CellHint::Downgrade),
            (misdirected, Some("http://cell2.example.com"), "HTTPS://cell1.example.com/prefix", CellHint::Downgrade),
            (misdirected, None, "https://cell1.example.com", CellHint::None),
            (misdirected, Some("   "), "https://cell1.example.com", CellHint::None),
            (misdirected, Some("cell2.example.com"), "https://cell1.example.com", CellHint::None),
            (misdirected, Some("/v1/elsewhere"), "https://cell1.example.com", CellHint::None),
            (misdirected, Some("ftp://cell2.example.com"), "https://cell1.example.com", CellHint::None),
            (misdirected, Some("https://cell2.example.com/?x=1"), "https://cell1.example.com", CellHint::None),
            (misdirected, Some("https://cell2.example.com/#x"), "https://cell1.example.com", CellHint::None),
            (http::StatusCode::NOT_FOUND, Some("https://cell2.example.com"), "https://cell1.example.com", CellHint::None),
            (http::StatusCode::OK, Some("https://cell2.example.com"), "https://cell1.example.com", CellHint::None),
        ] {
            assert_eq!(cell_hint(status, &headers(value), configured), want, "{} {:?} from {}", status, value, configured);
        }
    }

    #[test]
    fn sandbox_of_reads_the_segment_after_sandboxes() {
        for (path, want) in [
            ("/v1/sandboxes/sb-1", Some("sb-1")),
            ("/v1/sandboxes/sb-1/stop", Some("sb-1")),
            ("/v1/sandboxes/sb-1?include_env=true", Some("sb-1")),
            ("/v1/sandboxes/sb-1/toolbox/files/download?path=%2Fw", Some("sb-1")),
            ("/v1/sandboxes/sb%2D1/toolbox/version", Some("sb-1")),
            ("/v1/sandboxes", None),
            ("/v1/sandboxes/", None),
            ("/v1/sandboxes?tag.team=a", None),
            ("/v1/sandboxesX/sb-1", None),
            ("/v1/tokens/tok_1", None),
            ("/v2/sandboxes/sb-1", None),
        ] {
            assert_eq!(sandbox_of(path, "/v1").as_deref(), want, "{}", path);
        }
    }

    #[test]
    fn routes_remember_update_and_forget() {
        let routes = CellRoutes::default();
        assert_eq!(routes.get("sb-1"), None);
        routes.remember("sb-1", "https://cell2.example.com");
        assert_eq!(routes.get("sb-1").as_deref(), Some("https://cell2.example.com"));
        routes.remember("sb-1", "https://cell3.example.com");
        assert_eq!(routes.get("sb-1").as_deref(), Some("https://cell3.example.com"));
        assert_eq!(routes.len(), 1);
        // A 404 from a cell the entry no longer names leaves it alone.
        routes.forget("sb-1", "https://cell2.example.com");
        assert_eq!(routes.get("sb-1").as_deref(), Some("https://cell3.example.com"));
        routes.forget("sb-1", "https://cell3.example.com");
        assert_eq!(routes.get("sb-1"), None);
        assert!(routes.lock().order.is_empty());
    }

    #[test]
    fn routes_drop_the_oldest_past_the_cap() {
        let routes = CellRoutes::default();
        for i in 0..MAX_CELL_ROUTES + 2 {
            routes.remember(&format!("sb-{}", i), "https://cell2.example.com");
        }
        assert_eq!(routes.len(), MAX_CELL_ROUTES);
        assert_eq!(routes.lock().order.len(), MAX_CELL_ROUTES);
        assert_eq!(routes.get("sb-0"), None);
        assert_eq!(routes.get("sb-1"), None);
        assert!(routes.get("sb-2").is_some());
        assert!(routes.get(&format!("sb-{}", MAX_CELL_ROUTES + 1)).is_some());
    }

    #[test]
    fn routes_are_shared_safely_across_threads() {
        let routes = std::sync::Arc::new(CellRoutes::default());
        let workers: Vec<_> = (0..8)
            .map(|t| {
                let routes = routes.clone();
                std::thread::spawn(move || {
                    for i in 0..500 {
                        let id = format!("sb-{}-{}", t, i);
                        routes.remember(&id, "https://cell2.example.com");
                        if i % 2 == 0 {
                            routes.forget(&id, "https://cell2.example.com");
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(routes.len(), 8 * 250);
        assert_eq!(routes.lock().order.len(), 8 * 250);
    }
}
