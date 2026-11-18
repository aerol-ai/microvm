package daytona

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
)

// workerCluster is a worker's cluster: the servers' feed says whether they
// sign, and calls sent on to a server are recorded.
type workerCluster struct {
	*cluster.Noop
	since int64
	sent  []string
}

func (c *workerCluster) FetchSigningKeys(context.Context) (cluster.SigningKeys, error) {
	return cluster.SigningKeys{SinceUnixNano: c.since}, nil
}
func (c *workerCluster) SignSandboxToken(context.Context, cluster.SandboxTokenSignRequest) (cluster.SandboxTokenSignResponse, error) {
	return cluster.SandboxTokenSignResponse{}, nil
}
func (c *workerCluster) SignIdentityToken(context.Context, cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error) {
	return cluster.IdentityTokenSignResponse{}, nil
}
func (c *workerCluster) ForwardToServer(w http.ResponseWriter, r *http.Request) {
	c.sent = append(c.sent, r.Method+" "+r.URL.Path)
	w.WriteHeader(http.StatusTeapot)
}

// Once servers sign, a worker sends a volume's create and delete on to a
// server with the caller's credential; before, and on a server, it serves
// them itself.
func TestVolumeWritesGoToServers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	served := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	call := func(role string, since int64, bearer string) (int, []string) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: role}, logger, nil, nil, nil, nil, nil, nil, nil)
		c := &workerCluster{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""), since: since}
		svc.AttachCluster(c)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		r := httptest.NewRequest(http.MethodPost, PathPrefix+"/volumes", nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		rr := httptest.NewRecorder()
		h.volumeWritesViaServers(served).ServeHTTP(rr, r)
		return rr.Code, c.sent
	}
	if code, sent := call(config.NodeRoleWorker, 5, "pat"); code != http.StatusTeapot || len(sent) != 1 {
		t.Fatalf("worker once servers sign = %d %v", code, sent)
	}
	if code, sent := call(config.NodeRoleWorker, 0, "pat"); code != http.StatusNoContent || len(sent) != 0 {
		t.Fatalf("worker before = %d %v", code, sent)
	}
	if code, sent := call(config.NodeRoleServer, 5, "pat"); code != http.StatusNoContent || len(sent) != 0 {
		t.Fatalf("server = %d %v", code, sent)
	}
	if code, _ := call(config.NodeRoleWorker, 5, ""); code != http.StatusBadRequest {
		t.Fatalf("no credential = %d", code)
	}
}

// feedOnly is a worker whose servers sign but that has no way to a server.
type feedOnly struct{ *cluster.Noop }

func (c *feedOnly) FetchSigningKeys(context.Context) (cluster.SigningKeys, error) {
	return cluster.SigningKeys{SinceUnixNano: 1}, nil
}
func (c *feedOnly) SignSandboxToken(context.Context, cluster.SandboxTokenSignRequest) (cluster.SandboxTokenSignResponse, error) {
	return cluster.SandboxTokenSignResponse{}, nil
}
func (c *feedOnly) SignIdentityToken(context.Context, cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error) {
	return cluster.IdentityTokenSignResponse{}, nil
}

// With no way to a server, a volume write is 503, never written here.
func TestVolumeWritesWithNoServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleWorker}, logger, nil, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(&feedOnly{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", "")})
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}
	r := httptest.NewRequest(http.MethodPost, PathPrefix+"/volumes", nil)
	r.Header.Set("Authorization", "Bearer pat")
	rr := httptest.NewRecorder()
	h.volumeWritesViaServers(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rr, r)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("no server = %d", rr.Code)
	}
}
