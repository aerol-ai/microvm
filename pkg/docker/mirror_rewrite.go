package docker

import (
	"strings"
)

// MirrorUpstream maps an upstream registry host to the short prefix the
// AOCR mirror uses to disambiguate it in its URL path.
//
// Example: `{Host: "ghcr.io", Shortname: "ghcr"}` causes
// `ghcr.io/aerol-ai/sandbox:v1` to be rewritten to
// `mirror.aocr.aerol.ai/_/ghcr/aerol-ai/sandbox:v1`. The `_/` prefix is the
// Distribution-v2 reserved-namespace convention; AOCR's auth route helper
// (`auth/src/upstreamAuth/route.ts`) strips `_/<short>/` back off when
// routing scope strings to the upstream probe.
//
// Docker Hub is intentionally absent from this list: it's handled by the
// Docker daemon's `registry-mirrors` daemon.json setting (which only
// supports DockerHub), not by client-side rewriting. Refs that resolve to
// `docker.io` pass through unchanged here.
type MirrorUpstream struct {
	Host      string
	Shortname string
}

// MirrorConfig is the per-node mirror policy. A zero value disables all
// rewriting — pullImage behaves exactly as it did before. This is the
// safety hatch for any node that isn't running with AOCR mirror enabled.
//
// `Host` is the mirror vhost (e.g. `mirror.aocr.aerol.ai`). `PushHost`
// is the AOCR push vhost (e.g. `aocr.aerol.ai`); we recognize both so
// already-rewritten refs and cluster-snapshot refs pass through
// unchanged — important on the failover path where a sandbox's stored
// `RegistryRef` may already point at the AOCR side.
type MirrorConfig struct {
	Host      string
	PushHost  string
	Upstreams []MirrorUpstream
}

// Enabled reports whether mirror rewriting is active. Returns false for
// any zero/empty config so callers can short-circuit without parsing.
func (c MirrorConfig) Enabled() bool {
	return strings.TrimSpace(c.Host) != "" && len(c.Upstreams) > 0
}

// MirrorRewrite is the structured result of `RewriteImageRefForMirror`.
// All fields are populated even when no rewrite happened so the caller
// has a single value to plumb through (no nil checks).
type MirrorRewrite struct {
	// RewrittenRef is what should actually be pulled. When Rewritten=false
	// this equals the original input.
	RewrittenRef string
	// OriginalRef is the user-visible ref (what to store on the sandbox
	// row for trace/display). Always equals the input.
	OriginalRef string
	// Rewritten=true means the ref was redirected to the mirror.
	Rewritten bool
	// UpstreamHost / UpstreamRepo / UpstreamTag are the components AOCR's
	// auth service needs to validate a wrapped credential and probe the
	// upstream. They are populated only when Rewritten=true.
	UpstreamHost string
	// UpstreamRepo is the *mirror-side* repo path, e.g.
	// `_/ghcr/aerol-ai/sandbox` — this matches the Distribution scope
	// string AOCR's `route.ts` parses. For Docker Hub passthrough or
	// non-rewritten refs this is empty.
	UpstreamRepo string
	UpstreamTag  string
}

// RewriteImageRefForMirror is a pure function: no I/O, no globals. It
// inspects an image reference and decides whether to redirect it through
// the AOCR mirror vhost.
//
// Rules (in order):
//  1. Empty / unparseable refs are passed through.
//  2. Refs that already point at the mirror or push vhost are passed
//     through (idempotency — re-running a rewrite is a no-op).
//  3. Refs whose host matches a configured `MirrorUpstream.Host` are
//     rewritten to `<mirrorHost>/_/<short>/<repo>:<tag>`.
//  4. Docker Hub refs (host=docker.io, or no host prefix at all) pass
//     through — the Docker daemon handles them via `registry-mirrors`.
//  5. Refs with an unknown host pass through, so private registries the
//     operator didn't configure as mirror upstreams keep working.
func RewriteImageRefForMirror(ref string, cfg MirrorConfig) MirrorRewrite {
	original := strings.TrimSpace(ref)
	pass := MirrorRewrite{RewrittenRef: original, OriginalRef: original}

	if original == "" || !cfg.Enabled() {
		return pass
	}

	host, rest := splitHostRepo(original)

	// Already pointing at our own mirror or push vhost — leave it alone.
	mirrorHost := strings.ToLower(strings.TrimSpace(cfg.Host))
	pushHost := strings.ToLower(strings.TrimSpace(cfg.PushHost))
	if host != "" {
		hostLower := strings.ToLower(host)
		if hostLower == mirrorHost || (pushHost != "" && hostLower == pushHost) {
			return pass
		}
	}

	// Find an upstream match. Comparison is host-only, lowercase; AOCR's
	// route table is likewise case-insensitive.
	short := ""
	upstreamHost := ""
	if host != "" {
		for _, u := range cfg.Upstreams {
			if strings.EqualFold(strings.TrimSpace(u.Host), host) {
				short = strings.TrimSpace(u.Shortname)
				upstreamHost = strings.ToLower(strings.TrimSpace(u.Host))
				break
			}
		}
	}
	if short == "" {
		// Unknown / not-configured host (includes docker.io which intentionally
		// isn't in the upstreams list — handled by daemon.json registry-mirrors).
		return pass
	}

	repoOnly, tag, digest := splitRepoRefTag(rest)
	if repoOnly == "" {
		return pass
	}

	mirrorRepo := "_/" + short + "/" + repoOnly
	rewrittenRef := mirrorHost + "/" + mirrorRepo
	if tag != "" {
		rewrittenRef += ":" + tag
	} else if digest != "" {
		rewrittenRef += "@" + digest
	}

	return MirrorRewrite{
		RewrittenRef: rewrittenRef,
		OriginalRef:  original,
		Rewritten:    true,
		UpstreamHost: upstreamHost,
		UpstreamRepo: mirrorRepo,
		UpstreamTag:  tag,
	}
}

// splitHostRepo splits `host/repo...` from a Docker image reference.
// Returns `("", ref)` when there is no host prefix (Docker Hub
// shortcut form like `library/redis` or `redis:tag`).
//
// The host-detection heuristic matches what Docker itself uses: the
// first slash-delimited segment is a host if it contains `:` (port) or
// `.` (FQDN), or is literally `localhost`. Anything else is treated as
// a Docker Hub namespace, not a host.
func splitHostRepo(ref string) (host, repo string) {
	first, rest, ok := strings.Cut(ref, "/")
	if !ok {
		// No slash → bare image name → no host.
		return "", ref
	}
	if first == "localhost" || strings.Contains(first, ".") || strings.Contains(first, ":") {
		return first, rest
	}
	return "", ref
}

// splitRepoRefTag splits a `repo[:tag][@digest]` string. The digest takes
// precedence over the tag per OCI conventions (`repo:tag@digest` keeps the
// digest authoritative). Tag colons inside a host:port were already
// peeled off by splitHostRepo.
func splitRepoRefTag(s string) (repo, tag, digest string) {
	// Digest first — `@sha256:...` is unambiguous.
	if at := strings.IndexByte(s, '@'); at >= 0 {
		digest = s[at+1:]
		s = s[:at]
	}
	// Tag is the last `:` IF it appears after the last `/` (otherwise it
	// could be a port we somehow didn't strip — defense in depth).
	if colon := strings.LastIndexByte(s, ':'); colon >= 0 {
		if slash := strings.LastIndexByte(s, '/'); colon > slash {
			tag = s[colon+1:]
			s = s[:colon]
		}
	}
	return s, tag, digest
}
