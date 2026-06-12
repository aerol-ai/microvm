package wasmmod

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
)

// testOCIRegistry is a minimal in-memory OCI distribution v2 server for unit
// tests. Enough for oras.Copy push/pull/delete round-trips on loopback refs.
type testOCIRegistry struct {
	t       *testing.T
	server  *httptest.Server
	baseRef string // host:port/repo/name (no tag)

	mu        sync.Mutex
	blobs     map[string][]byte
	manifests map[string][]byte // keyed by "repo/tag-or-digest"
}

func startTestOCIRegistry(t *testing.T, repo string) *testOCIRegistry {
	t.Helper()
	reg := &testOCIRegistry{
		t:         t,
		blobs:     map[string][]byte{},
		manifests: map[string][]byte{},
	}
	reg.server = httptest.NewServer(http.HandlerFunc(reg.serve))
	u, err := url.Parse(reg.server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	reg.baseRef = u.Host + "/" + strings.Trim(repo, "/")
	return reg
}

func (r *testOCIRegistry) ref(tag string) string {
	if tag == "" {
		tag = "latest"
	}
	return r.baseRef + ":" + tag
}

func (r *testOCIRegistry) close() { r.server.Close() }

func (r *testOCIRegistry) setManifest(tag string, body []byte) {
	_, rest, _ := strings.Cut(r.baseRef, "/")
	key := rest + "/" + tag
	r.mu.Lock()
	r.manifests[key] = body
	if len(body) > 0 {
		dgst := digest.FromBytes(body).String()
		r.manifests[rest+"/"+dgst] = body
	}
	r.mu.Unlock()
}

func (r *testOCIRegistry) serve(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimSuffix(req.URL.Path, "/")
	if req.Method == http.MethodGet && path == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(path, "/v2/") {
		http.NotFound(w, req)
		return
	}
	rest := strings.TrimPrefix(path, "/v2/")

	switch {
	case strings.HasSuffix(rest, "/blobs/uploads"):
		if req.Method == http.MethodPost {
			r.serveBlobUploadStart(w, rest)
			return
		}
	case strings.Contains(rest, "/blobs/uploads/"):
		if req.Method == http.MethodPut {
			r.serveBlobUploadComplete(w, req)
			return
		}
	case strings.Contains(rest, "/blobs/"):
		r.serveBlob(w, req, rest)
		return
	case strings.Contains(rest, "/manifests/"):
		r.serveManifest(w, req, rest)
		return
	}
	http.NotFound(w, req)
}

func (r *testOCIRegistry) serveBlobUploadStart(w http.ResponseWriter, repoPath string) {
	loc := "/v2/" + repoPath + "/blobs/uploads/test-upload-id"
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusAccepted)
}

func (r *testOCIRegistry) serveBlobUploadComplete(w http.ResponseWriter, req *http.Request) {
	dgst := req.URL.Query().Get("digest")
	if dgst == "" {
		http.Error(w, "digest required", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if d := digest.FromBytes(body); d.String() != dgst {
		http.Error(w, "digest mismatch", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.blobs[dgst] = body
	r.mu.Unlock()
	w.Header().Set("Docker-Content-Digest", dgst)
	w.WriteHeader(http.StatusCreated)
}

func (r *testOCIRegistry) serveBlob(w http.ResponseWriter, req *http.Request, rest string) {
	i := strings.LastIndex(rest, "/blobs/")
	if i < 0 {
		http.NotFound(w, req)
		return
	}
	dgst := rest[i+len("/blobs/"):]

	r.mu.Lock()
	data, ok := r.blobs[dgst]
	r.mu.Unlock()

	switch req.Method {
	case http.MethodHead:
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Docker-Content-Digest", dgst)
		if _, err := w.Write(data); err != nil {
			r.t.Errorf("write blob: %v", err)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *testOCIRegistry) serveManifest(w http.ResponseWriter, req *http.Request, rest string) {
	i := strings.LastIndex(rest, "/manifests/")
	if i < 0 {
		http.NotFound(w, req)
		return
	}
	key := rest[:i] + "/" + rest[i+len("/manifests/"):]

	switch req.Method {
	case http.MethodHead, http.MethodGet:
		r.mu.Lock()
		data, ok := r.manifests[key]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		ct := "application/vnd.oci.image.manifest.v1+json"
		var probe struct {
			MediaType string `json:"mediaType"`
		}
		_ = json.Unmarshal(data, &probe)
		if probe.MediaType != "" {
			ct = probe.MediaType
		}
		w.Header().Set("Content-Type", ct)
		dgst := digest.FromBytes(data).String()
		w.Header().Set("Docker-Content-Digest", dgst)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		if req.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if _, err := w.Write(data); err != nil {
			r.t.Errorf("write manifest: %v", err)
		}
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		dgst := digest.FromBytes(body).String()
		r.mu.Lock()
		r.manifests[key] = body
		// ORAS resolves by tag then fetches by content digest.
		if i := strings.LastIndex(key, "/"); i >= 0 {
			r.manifests[key[:i]+"/"+dgst] = body
		}
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		r.mu.Lock()
		delete(r.manifests, key)
		r.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
