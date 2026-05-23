package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// captureClient builds a Client that records the X-Registry-Auth header and
// the fromImage query value of the last /images/create call, plus the path
// and query of any follow-up /tag call (the mirror-alias retag).
type captureClient struct {
	client       *Client
	calls        atomic.Int64
	lastFrom     atomic.Value // string
	lastAuthB64  atomic.Value // string
	lastTagPath  atomic.Value // string
	lastTagQuery atomic.Value // string
}

func newCaptureClient(cfg MirrorConfig, ring *secrets.UpstreamWrapKeyRing) *captureClient {
	cap := &captureClient{}
	cap.lastFrom.Store("")
	cap.lastAuthB64.Store("")
	cap.lastTagPath.Store("")
	cap.lastTagQuery.Store("")
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/tag") {
			cap.lastTagPath.Store(r.URL.Path)
			cap.lastTagQuery.Store(r.URL.RawQuery)
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}
		cap.calls.Add(1)
		q, _ := url.ParseQuery(r.URL.RawQuery)
		cap.lastFrom.Store(q.Get("fromImage"))
		cap.lastAuthB64.Store(r.Header.Get("X-Registry-Auth"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status":"done"}`)),
			Header:     make(http.Header),
		}, nil
	})
	cap.client = &Client{
		logger:       slog.Default(),
		streamClient: &http.Client{Transport: transport},
		httpClient:   &http.Client{Transport: transport},
	}
	cap.client.ConfigureMirror(cfg, ring)
	return cap
}

func (c *captureClient) tagPath() string  { return c.lastTagPath.Load().(string) }
func (c *captureClient) tagQuery() string { return c.lastTagQuery.Load().(string) }

func (c *captureClient) from() string { return c.lastFrom.Load().(string) }
func (c *captureClient) auth() map[string]string {
	raw := c.lastAuthB64.Load().(string)
	if raw == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(decoded, &m); err != nil {
		return nil
	}
	return m
}

func TestPullImage_NoMirrorConfig_PassesThrough(t *testing.T) {
	cap := newCaptureClient(MirrorConfig{}, nil)
	auth := &models.RegistryAuth{Server: "ghcr.io", Username: "u", Password: "p"}
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", auth); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if cap.from() != "ghcr.io/aerol-ai/sandbox:v1" {
		t.Fatalf("fromImage rewritten despite disabled mirror: %q", cap.from())
	}
	a := cap.auth()
	if a["username"] != "u" || a["password"] != "p" {
		t.Fatalf("auth dropped raw creds: %+v", a)
	}
	if _, hasToken := a["identitytoken"]; hasToken {
		t.Fatalf("unexpected identitytoken without mirror config: %+v", a)
	}
}

func TestPullImage_MirrorEnabled_RewritesURL(t *testing.T) {
	ring := secrets.ParseUpstreamWrapKeyRing(b64DockerTest(key32DockerTest(0xa7)))
	cap := newCaptureClient(defaultMirrorCfg(), ring)
	auth := &models.RegistryAuth{Server: "ghcr.io", Username: "octocat", Password: "ghp_xxx"}
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", auth); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if want := "mirror.aocr.aerol.ai/aocr/ghcr/aerol-ai/sandbox:v1"; cap.from() != want {
		t.Fatalf("fromImage: got %q want %q", cap.from(), want)
	}
	a := cap.auth()
	tok := a["identitytoken"]
	if !strings.HasPrefix(tok, secrets.IdentityTokenPrefix) {
		t.Fatalf("identitytoken missing or wrong prefix: %q", tok)
	}
	if a["username"] != "" || a["password"] != "" {
		t.Fatalf("identitytoken path must blank username/password (leaks otherwise): %+v", a)
	}
	if a["serveraddress"] != "mirror.aocr.aerol.ai" {
		t.Fatalf("serveraddress: %q", a["serveraddress"])
	}
}

func TestPullImage_MirrorEnabled_NoWrapKeyRing_FallsBackToRawAuth(t *testing.T) {
	// Rewriting still happens (so the daemon hits the mirror vhost), but
	// without a key ring we can't wrap creds — Docker sends raw u/p. This
	// is the documented degraded mode; the mirror will then 401 on private
	// upstreams, but public pulls (no auth) still work.
	cap := newCaptureClient(defaultMirrorCfg(), nil)
	auth := &models.RegistryAuth{Server: "ghcr.io", Username: "octocat", Password: "ghp_xxx"}
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", auth); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if cap.from() != "mirror.aocr.aerol.ai/aocr/ghcr/aerol-ai/sandbox:v1" {
		t.Fatalf("fromImage: %q", cap.from())
	}
	a := cap.auth()
	if _, hasToken := a["identitytoken"]; hasToken {
		t.Fatalf("identitytoken set despite nil key ring: %+v", a)
	}
	if a["username"] != "octocat" {
		t.Fatalf("raw username dropped: %+v", a)
	}
}

func TestPullImage_MirrorEnabled_NoAuth_NoIdentityToken(t *testing.T) {
	// Anonymous pulls of public images: still rewritten, but no auth
	// header at all (preserves existing behaviour for unauth pulls).
	ring := secrets.ParseUpstreamWrapKeyRing(b64DockerTest(key32DockerTest(0xa8)))
	cap := newCaptureClient(defaultMirrorCfg(), ring)
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if cap.from() != "mirror.aocr.aerol.ai/aocr/ghcr/aerol-ai/sandbox:v1" {
		t.Fatalf("fromImage: %q", cap.from())
	}
	if cap.lastAuthB64.Load().(string) != "" {
		t.Fatalf("expected no X-Registry-Auth for anonymous pull, got %q", cap.lastAuthB64.Load())
	}
}

func TestPullImage_DockerHub_PassesThrough_EvenWithMirror(t *testing.T) {
	// Docker Hub is handled by the daemon's registry-mirrors setting, not
	// by us. We must not rewrite docker.io refs even when mirror is on.
	ring := secrets.ParseUpstreamWrapKeyRing(b64DockerTest(key32DockerTest(0xa9)))
	cap := newCaptureClient(defaultMirrorCfg(), ring)
	auth := &models.RegistryAuth{Server: "docker.io", Username: "u", Password: "p"}
	if err := cap.client.pullImage(context.Background(), "redis:7.2", auth); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if cap.from() != "redis:7.2" {
		t.Fatalf("docker hub ref rewritten: %q", cap.from())
	}
	a := cap.auth()
	if _, hasToken := a["identitytoken"]; hasToken {
		t.Fatalf("identitytoken set for docker.io passthrough: %+v", a)
	}
	if a["username"] != "u" {
		t.Fatalf("raw username dropped on passthrough: %+v", a)
	}
}

// Docker stores pulled images keyed by `fromImage`, so a mirror-rewritten
// pull lands ONLY under the rewritten ref. CreateSandbox then inspects /
// runs by the user's original ref and 404s. aliasMirrorPull adds the
// original ref as a tag on the same image ID after a successful pull so
// the rest of the pipeline keeps working unchanged.
func TestPullImage_MirrorEnabled_AddsAliasTagForOriginalRef(t *testing.T) {
	ring := secrets.ParseUpstreamWrapKeyRing(b64DockerTest(key32DockerTest(0xb0)))
	cap := newCaptureClient(defaultMirrorCfg(), ring)
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	// URL parsing normalizes the percent-escaped slashes back to "/" by the
	// time the round-tripper sees the request, so assert on the substring
	// (the source ref) rather than the exact pre-escape encoding.
	if got := cap.tagPath(); !strings.Contains(got, "mirror.aocr.aerol.ai") ||
		!strings.HasSuffix(got, "sandbox:v1/tag") {
		t.Fatalf("tag path: got %q want it to target the rewritten ref", got)
	}
	q, err := url.ParseQuery(cap.tagQuery())
	if err != nil {
		t.Fatalf("parse tag query: %v", err)
	}
	if got := q.Get("repo"); got != "ghcr.io/aerol-ai/sandbox" {
		t.Fatalf("tag repo: got %q want ghcr.io/aerol-ai/sandbox", got)
	}
	if got := q.Get("tag"); got != "v1" {
		t.Fatalf("tag tag: got %q want v1", got)
	}
}

func TestPullImage_MirrorEnabled_UntaggedRef_AliasesAsLatest(t *testing.T) {
	cap := newCaptureClient(defaultMirrorCfg(), nil)
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox", nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	q, _ := url.ParseQuery(cap.tagQuery())
	if got := q.Get("repo"); got != "ghcr.io/aerol-ai/sandbox" {
		t.Fatalf("tag repo: got %q", got)
	}
	if got := q.Get("tag"); got != "latest" {
		t.Fatalf("tag defaults to latest, got %q", got)
	}
}

func TestPullImage_MirrorEnabled_DigestPull_SkipsAlias(t *testing.T) {
	// Digest refs are content-addressable: inspect by `repo@sha256:...`
	// resolves to the same image ID regardless of which name we pulled
	// under. No alias needed; we must not POST /tag with a malformed
	// (digest-as-tag) request.
	cap := newCaptureClient(defaultMirrorCfg(), nil)
	digestRef := "ghcr.io/aerol-ai/sandbox@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := cap.client.pullImage(context.Background(), digestRef, nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if got := cap.tagPath(); got != "" {
		t.Fatalf("digest pull should skip retag, got tag path %q", got)
	}
}

func TestPullImage_NoMirrorConfig_SkipsAlias(t *testing.T) {
	cap := newCaptureClient(MirrorConfig{}, nil)
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox:v1", nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if got := cap.tagPath(); got != "" {
		t.Fatalf("passthrough pull should skip retag, got tag path %q", got)
	}
}

func TestPullImage_DockerHub_PassesThrough_SkipsAlias(t *testing.T) {
	cap := newCaptureClient(defaultMirrorCfg(), nil)
	if err := cap.client.pullImage(context.Background(), "redis:7.2", nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if got := cap.tagPath(); got != "" {
		t.Fatalf("docker.io pull should skip retag (no rewrite), got tag path %q", got)
	}
}

// observerFires tests the PullObserver firing predicate. Hand-rolled against
// the actual pullImage path (no daemon, just our roundtrip stub) so the
// truth table is observable: only (mirror-rewrite AND non-anonymous auth AND
// sandbox ID on ctx AND observer set) fires the callback.
func TestPullObserver_FirePredicate(t *testing.T) {
	ring := secrets.ParseUpstreamWrapKeyRing(b64DockerTest(key32DockerTest(0x42)))
	cases := []struct {
		name      string
		image     string
		auth      *models.RegistryAuth
		ctxSbxID  string
		setObs    bool
		wantFires bool
	}{
		{"private mirror pull + sandbox id fires once", "ghcr.io/aerol-ai/sandbox:v1", &models.RegistryAuth{Username: "u", Password: "p", Server: "ghcr.io"}, "sb-1", true, true},
		{"anonymous mirror pull does not fire", "ghcr.io/aerol-ai/sandbox:v1", nil, "sb-1", true, false},
		{"empty username treated as anonymous", "ghcr.io/aerol-ai/sandbox:v1", &models.RegistryAuth{Username: "", Password: ""}, "sb-1", true, false},
		{"docker.io passthrough does not fire", "redis:7", &models.RegistryAuth{Username: "u", Password: "p", Server: "https://index.docker.io/v1/"}, "sb-1", true, false},
		{"missing sandbox id does not fire", "ghcr.io/aerol-ai/sandbox:v1", &models.RegistryAuth{Username: "u", Password: "p", Server: "ghcr.io"}, "", true, false},
		{"no observer installed is a no-op", "ghcr.io/aerol-ai/sandbox:v1", &models.RegistryAuth{Username: "u", Password: "p", Server: "ghcr.io"}, "sb-1", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cap := newCaptureClient(defaultMirrorCfg(), ring)
			var fired atomic.Int64
			var gotID atomic.Value
			gotID.Store("")
			if c.setObs {
				cap.client.SetPullObserver(func(_ context.Context, id string) {
					fired.Add(1)
					gotID.Store(id)
				})
			}
			ctx := context.Background()
			if c.ctxSbxID != "" {
				ctx = WithSandboxID(ctx, c.ctxSbxID)
			}
			if err := cap.client.pullImage(ctx, c.image, c.auth); err != nil {
				t.Fatalf("pullImage: %v", err)
			}
			got := fired.Load()
			if c.wantFires {
				if got != 1 {
					t.Fatalf("observer fired %d times, want 1", got)
				}
				if id := gotID.Load().(string); id != c.ctxSbxID {
					t.Fatalf("observer got sandbox id %q, want %q", id, c.ctxSbxID)
				}
			} else if got != 0 {
				t.Fatalf("observer fired %d times, want 0", got)
			}
		})
	}
}

// TestWithSandboxID_RoundTripAndEmptyHandling asserts the ctx helper drops
// empty IDs (a guardrail so a missing sandboxID doesn't accidentally overwrite
// a real one set further up the stack).
func TestWithSandboxID_RoundTripAndEmptyHandling(t *testing.T) {
	base := context.Background()
	if got := sandboxIDFromContext(base); got != "" {
		t.Fatalf("empty base ctx returned %q, want empty", got)
	}
	ctx := WithSandboxID(base, "sb-42")
	if got := sandboxIDFromContext(ctx); got != "sb-42" {
		t.Fatalf("round-trip returned %q, want sb-42", got)
	}
	// Whitespace-only IDs are treated as empty so they don't shadow the
	// parent's real value.
	ctx2 := WithSandboxID(ctx, "   ")
	if got := sandboxIDFromContext(ctx2); got != "sb-42" {
		t.Fatalf("whitespace ID shadowed parent: got %q", got)
	}
}

// Local helpers (duplicated rather than imported across packages — these
// mirror the secrets/test helpers so we don't widen the secrets package's
// export surface just for tests).
func key32DockerTest(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
func b64DockerTest(k []byte) string { return base64.StdEncoding.EncodeToString(k) }
