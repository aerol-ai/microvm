package clustercreate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type cov96ErrCapture struct {
	status  int
	message string
}

func (c *cov96ErrCapture) write(_ http.ResponseWriter, status int, message string) {
	c.status = status
	c.message = message
}

func cov96LocalOnlyReq() models.CreateSandboxRequest {
	return models.CreateSandboxRequest{
		Image:                 "e2b/sb-local:default",
		ImageDistributionMode: models.ImageDistributionLocalOnly,
	}
}

func TestCov96PrepareWrongTargetFiresOnForwardStale(t *testing.T) {
	svc := testServiceWithCluster(&clusterStub{Noop: cluster.NewNoop("node-a", "", "")})
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	r.Header.Set(HeaderTarget, "node-b")
	var stale int
	var capture cov96ErrCapture
	_, ok := Prepare(httptest.NewRecorder(), r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, capture.write,
		PrepareOptions{OnForwardStale: func() { stale++ }})
	if ok || capture.status != http.StatusMisdirectedRequest {
		t.Fatalf("ok=%v status=%d, want 421", ok, capture.status)
	}
	if stale != 1 {
		t.Fatalf("OnForwardStale calls = %d, want 1", stale)
	}
}

func TestCov96PrepareNormalizeHook(t *testing.T) {
	t.Run("error rejects create", func(t *testing.T) {
		stub := &clusterStub{Noop: cluster.NewNoop("node-a", "", "")}
		svc := testServiceWithCluster(stub)
		var capture cov96ErrCapture
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
			models.CreateSandboxRequest{Image: "alpine:3.20"}, capture.write,
			PrepareOptions{Normalize: func(*models.CreateSandboxRequest) error { return errors.New("bad runtime") }})
		if ok || capture.status != http.StatusBadRequest || capture.message != "bad runtime" {
			t.Fatalf("ok=%v status=%d msg=%q, want 400 bad runtime", ok, capture.status, capture.message)
		}
		if len(stub.selectReqs) != 0 {
			t.Fatal("placement ran after the normalize hook rejected the create")
		}
	})

	t.Run("sync body carries normalized spec", func(t *testing.T) {
		svc := testServiceWithCluster(&clusterStub{Noop: cluster.NewNoop("node-a", "", "")})
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"stale"}`))
		_, ok := Prepare(httptest.NewRecorder(), r, svc, cov96LocalOnlyReq(), nil, PrepareOptions{
			SyncBody:  true,
			Normalize: func(req *models.CreateSandboxRequest) error { req.Runtime = models.RuntimeDocker; return nil },
		})
		if !ok {
			t.Fatal("Prepare ok=false, want local-only create to stay local")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var got models.CreateSandboxRequest
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("synced body %q: %v", body, err)
		}
		if got.Image != "e2b/sb-local:default" || got.Runtime != models.RuntimeDocker {
			t.Fatalf("synced body = %+v, want normalized image/runtime", got)
		}
		if r.ContentLength != int64(len(body)) {
			t.Fatalf("ContentLength = %d, want %d", r.ContentLength, len(body))
		}
	})

	t.Run("sync body marshal failure", func(t *testing.T) {
		svc := testServiceWithCluster(&clusterStub{Noop: cluster.NewNoop("node-a", "", "")})
		var capture cov96ErrCapture
		_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
			cov96LocalOnlyReq(), capture.write, PrepareOptions{
				SyncBody:  true,
				Normalize: func(req *models.CreateSandboxRequest) error { req.CPU = math.NaN(); return nil },
			})
		if ok || capture.status != http.StatusInternalServerError || !strings.Contains(capture.message, "normalize create body") {
			t.Fatalf("ok=%v status=%d msg=%q, want 500 normalize create body", ok, capture.status, capture.message)
		}
	})
}

func cov96ServerOnlyStub() *clusterStub {
	return &clusterStub{
		Noop: cluster.NewNoop("server-a", "http://server-a", ""),
		members: []cluster.Member{
			{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
			{NodeID: "worker-b", APIURL: "http://worker-b", Alive: true, Role: config.NodeRoleWorker},
		},
	}
}

// A built image whose worker is gone must be re-created, so the router
// answers with the machine-readable code and no Retry-After.
func TestCov96PrepareBuiltImageArtifactNodeUnavailable(t *testing.T) {
	stub := cov96ServerOnlyStub()
	stub.selectErr = cluster.ErrArtifactNodeUnavailable
	svc := testServiceWithCluster(stub)
	w := httptest.NewRecorder()
	var capture cov96ErrCapture
	_, ok := Prepare(w, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
		models.CreateSandboxRequest{Image: docker.BuiltImageNamespace + "/abc:latest"}, capture.write, PrepareOptions{})
	if ok {
		t.Fatal("Prepare ok=true, want artifact-node-unavailable rejection")
	}
	var body models.ErrorResponse
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusServiceUnavailable || body.Code != models.ErrorCodeArtifactNodeUnavailable {
		t.Fatalf("response = %d %+v, want 503 %s", w.Code, body, models.ErrorCodeArtifactNodeUnavailable)
	}
	if capture.status != 0 || w.Header().Get("Retry-After") != "" {
		t.Fatalf("writeError status=%d Retry-After=%q, want direct write without retry hint", capture.status, w.Header().Get("Retry-After"))
	}
}

func TestCov96PrepareBuiltImageForwardIsLogged(t *testing.T) {
	stub := cov96ServerOnlyStub()
	stub.selectTarget = cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b"}
	svc := testServiceWithCluster(stub)
	var logs bytes.Buffer
	image := docker.BuiltImageNamespace + "/abc:latest"
	_, ok := Prepare(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil), svc,
		models.CreateSandboxRequest{Image: image}, nil,
		PrepareOptions{Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if ok || stub.forwards != 1 {
		t.Fatalf("ok=%v forwards=%d, want one forward", ok, stub.forwards)
	}
	if out := logs.String(); !strings.Contains(out, "forwarding built local image") || !strings.Contains(out, "worker-b") {
		t.Fatalf("log = %q, want forward trace naming the target", out)
	}
}
