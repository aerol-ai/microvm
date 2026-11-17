package clustercreate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// signingServerStub is a server whose servers sign, placing creates on
// another node; its forward answers forwardCode.
type signingServerStub struct {
	*clusterStub
	forwardCode int
	forwarded   []*http.Request
}

func (s *signingServerStub) ServerSigningRecord() (cluster.ServerSigning, bool) {
	return cluster.ServerSigning{Sealed: []byte("x"), SinceUnixNano: 1}, true
}
func (s *signingServerStub) ServerSigningAllowed() bool { return true }
func (s *signingServerStub) IsLeader() bool             { return true }
func (s *signingServerStub) WriteServerSigning(context.Context, cluster.ServerSigningWrite) (cluster.ServerSigning, error) {
	return cluster.ServerSigning{}, errors.New("not here")
}

func (s *signingServerStub) ForwardHTTP(target cluster.Endpoint, w http.ResponseWriter, r *http.Request) {
	s.forwards++
	s.lastTarget = target
	s.forwarded = append(s.forwarded, r)
	w.WriteHeader(s.forwardCode)
}

// signingWorkerStub is a worker or gateway whose servers sign, and its way
// to a server.
type signingWorkerStub struct {
	*clusterStub
	sent []string
}

func (s *signingWorkerStub) FetchSigningKeys(context.Context) (cluster.SigningKeys, error) {
	return cluster.SigningKeys{SinceUnixNano: 1}, nil
}
func (s *signingWorkerStub) SignSandboxToken(context.Context, cluster.SandboxTokenSignRequest) (cluster.SandboxTokenSignResponse, error) {
	return cluster.SandboxTokenSignResponse{}, errors.New("not here")
}
func (s *signingWorkerStub) SignIdentityToken(context.Context, cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error) {
	return cluster.IdentityTokenSignResponse{}, errors.New("not here")
}
func (s *signingWorkerStub) ForwardToServer(w http.ResponseWriter, r *http.Request) {
	s.sent = append(s.sent, "retry")
	w.WriteHeader(http.StatusTeapot)
}
func (s *signingWorkerStub) ForwardToServerOnce(w http.ResponseWriter, r *http.Request) {
	s.sent = append(s.sent, "once")
	w.WriteHeader(http.StatusTeapot)
}

var volumeCreate = models.CreateSandboxRequest{Image: "alpine:3.20", PlatformVolumes: []models.PlatformVolumeMount{{Name: "data", Path: "/data"}}}

func teamRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
	return r.WithContext(controlplane.ContextWithAccess(r.Context(),
		controlplane.TokenAccess("tok_x", "x", controlplane.RoleRunner, "payments", time.Time{})))
}

// Once servers sign, a worker or gateway sends a create that names a
// platform volume to a server with the caller's credential, once unless
// the create is keyed; one with no credential is refused.
func TestPrepareSendsVolumeCreatesToServers(t *testing.T) {
	stub := &signingWorkerStub{clusterStub: &clusterStub{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", ""),
		selectTarget: cluster.PlacementTarget{NodeID: "wkr-2", APIURL: "http://wkr-2"}}}
	svc, _ := newCreateServiceWithConfig(t, stub, newFakeRuntime(), false, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleWorker })
	run := func(r *http.Request, req models.CreateSandboxRequest) (int, bool) {
		w := httptest.NewRecorder()
		_, ok := Prepare(w, r, svc, req, nil, PrepareOptions{})
		return w.Code, ok
	}
	r := teamRequest(`{}`)
	r.Header.Set("Authorization", "Bearer avm_x")
	if code, ok := run(r, volumeCreate); ok || code != http.StatusTeapot || strings.Join(stub.sent, ",") != "once" {
		t.Fatalf("sent %v code %d", stub.sent, code)
	}
	r = teamRequest(`{}`)
	r.Header.Set("X-API-KEY", "e2b_x")
	r.Header.Set(HeaderIdempotencyKey, "k-1")
	if _, ok := run(r, volumeCreate); ok || strings.Join(stub.sent, ",") != "once,retry" {
		t.Fatalf("a keyed create with an API key: %v", stub.sent)
	}
	if code, ok := run(teamRequest(`{}`), volumeCreate); ok || code != http.StatusBadRequest || len(stub.sent) != 2 {
		t.Fatalf("no credential: %d %v", code, stub.sent)
	}
	// A create with no volume, and the owner's half, stay here.
	r = teamRequest(`{}`)
	r.Header.Set("Authorization", "Bearer avm_x")
	run(r, models.CreateSandboxRequest{Image: "alpine:3.20"})
	r = teamRequest(`{}`)
	r.Header.Set(HeaderTarget, "wkr-1")
	r.Header.Set(HeaderID, "sb-1")
	run(r, volumeCreate)
	if len(stub.sent) != 2 {
		t.Fatalf("sent %v", stub.sent)
	}
	// No way to a server: 503, never served as this node.
	plain := &clusterStub{Noop: cluster.NewNoop("wkr-1", "http://wkr-1", "")}
	w := httptest.NewRecorder()
	sendCreateToServer(w, func() *http.Request { r := teamRequest(`{}`); r.Header.Set("Authorization", "Bearer x"); return r }(), plain,
		func(w http.ResponseWriter, code int, msg string) { http.Error(w, msg, code) })
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no forwarder = %d", w.Code)
	}
}

// A server makes the rows before the create goes to another node, and
// removes those it made when that node refuses the create; an unknown
// outcome keeps them. A row it cannot make is the caller's answer, and the
// reservation goes.
func TestPrepareMakesVolumeRowsBeforeTheForward(t *testing.T) {
	tenant := volumes.TenantForOwnerRef("team:payments")
	for _, tc := range []struct {
		name     string
		code     int
		req      models.CreateSandboxRequest
		wantRow  bool
		wantCode int
		cancels  int
	}{
		{"the node takes it", http.StatusCreated, volumeCreate, true, http.StatusCreated, 0},
		{"the node refuses it", http.StatusConflict, volumeCreate, false, http.StatusConflict, 0},
		{"the node fails it", http.StatusInternalServerError, volumeCreate, false, http.StatusInternalServerError, 0},
		{"no answer", http.StatusBadGateway, volumeCreate, true, http.StatusBadGateway, 0},
		{"a row it cannot make", http.StatusCreated, models.CreateSandboxRequest{Image: "alpine:3.20", PlatformVolumes: []models.PlatformVolumeMount{{Name: "../x", Path: "/x"}}}, false, http.StatusBadRequest, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &signingServerStub{clusterStub: &clusterStub{Noop: cluster.NewNoop("srv-1", "http://srv-1", ""),
				selectTarget: cluster.PlacementTarget{NodeID: "wkr-2", APIURL: "http://wkr-2", InternalURL: "https://wkr-2:7002"}}, forwardCode: tc.code}
			svc, _ := newCreateServiceWithConfig(t, stub, newFakeRuntime(), false, func(cfg *config.Config) {
				cfg.NodeRole = config.NodeRoleServer
				cfg.PlatformVolumes = config.PlatformVolumesConfig{Enabled: true, Backend: config.PlatformVolumesBackendS3, S3Bucket: "vols", S3Prefix: "pfx"}
			})
			w := httptest.NewRecorder()
			if _, ok := Prepare(w, teamRequest(`{}`), svc, tc.req, nil, PrepareOptions{PreferredSandboxID: "sb-v"}); ok {
				t.Fatal("the create stayed here")
			}
			_, err := stub.VolumeByName(context.Background(), tenant, "data")
			if (err == nil) != tc.wantRow || w.Code != tc.wantCode || stub.cancels != tc.cancels {
				t.Fatalf("row %v (%v), code %d, cancels %d", err == nil, err, w.Code, stub.cancels)
			}
		})
	}
	// An image only another node holds: no reservation, the rows still
	// made first.
	stub := &signingServerStub{clusterStub: &clusterStub{Noop: cluster.NewNoop("srv-1", "http://srv-1", ""),
		selectTarget: cluster.PlacementTarget{NodeID: "wkr-2", APIURL: "http://wkr-2"},
		members:      []cluster.Member{{NodeID: "srv-1", Role: config.NodeRoleServer}, {NodeID: "wkr-2", Role: config.NodeRoleWorker}}}, forwardCode: http.StatusCreated}
	svc, _ := newCreateServiceWithConfig(t, stub, newFakeRuntime(), false, func(cfg *config.Config) {
		cfg.NodeRole = config.NodeRoleServer
		cfg.PlatformVolumes = config.PlatformVolumesConfig{Enabled: true, Backend: config.PlatformVolumesBackendS3, S3Bucket: "vols", S3Prefix: "pfx"}
	})
	local := volumeCreate
	local.ImageDistributionMode = models.ImageDistributionLocalOnly
	lw := httptest.NewRecorder()
	if _, ok := Prepare(lw, teamRequest(`{}`), svc, local, nil, PrepareOptions{}); ok || stub.forwards != 1 {
		t.Fatalf("forwards %d: %d %s", stub.forwards, lw.Code, lw.Body.String())
	}
	if _, err := stub.VolumeByName(context.Background(), tenant, "data"); err != nil {
		t.Fatalf("no row before a node-local forward: %v", err)
	}
}

// A create a gateway sent on to a server: the server is its edge, and the
// forward marker goes, so it can send the create on.
func TestPrepareTakesACreateSentOn(t *testing.T) {
	stub := &signingServerStub{clusterStub: &clusterStub{Noop: cluster.NewNoop("srv-1", "http://srv-1", ""),
		selectTarget: cluster.PlacementTarget{NodeID: "wkr-2", APIURL: "http://wkr-2", InternalURL: "https://wkr-2:7002"}}, forwardCode: http.StatusCreated}
	svc, _ := newCreateServiceWithConfig(t, stub, newFakeRuntime(), false, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleServer })
	sentBy := func(role string) *http.Request {
		r := teamRequest(`{}`)
		r.Header.Set(cluster.HeaderForwarded, "1")
		cert := &x509.Certificate{DNSNames: []string{"node:p1", "role:" + role}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		return r
	}
	r := sentBy(controlplane.NodeRoleIngress)
	Prepare(httptest.NewRecorder(), r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{PreferredSandboxID: "sb-e"})
	if r.Header.Get(cluster.HeaderForwarded) != "" {
		t.Fatal("a create a gateway sent on kept the forward marker")
	}
	r = sentBy(controlplane.NodeRoleServer)
	Prepare(httptest.NewRecorder(), r, svc, models.CreateSandboxRequest{Image: "alpine:3.20"}, nil, PrepareOptions{PreferredSandboxID: "sb-s"})
	if r.Header.Get(cluster.HeaderForwarded) != "1" {
		t.Fatal("a server's forward lost its marker")
	}
}

// answerStatus sees the status a forward answered with, keeps the rows for
// a body with no header (the implicit 200), and passes a flush on.
func TestAnswerStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	a := &answerStatus{ResponseWriter: rec}
	_, _ = a.Write([]byte("ok"))
	a.Flush()
	if a.status != 0 || a.refused() || !rec.Flushed || rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("status %d refused %v flushed %v answered %d %q", a.status, a.refused(), rec.Flushed, rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	a = &answerStatus{ResponseWriter: rec}
	a.WriteHeader(http.StatusConflict)
	a.WriteHeader(http.StatusOK)
	if a.status != http.StatusConflict || !a.refused() {
		t.Fatalf("status %d refused %v; the first status set is the answer", a.status, a.refused())
	}
	for code, want := range map[int]bool{400: true, 409: true, 500: true, 501: true, 505: true, 502: false, 503: false, 504: false, 201: false, 0: false} {
		if got := (&answerStatus{status: code}).refused(); got != want {
			t.Errorf("refused(%d) = %v", code, got)
		}
	}
	(&answerStatus{ResponseWriter: struct{ http.ResponseWriter }{rec}}).Flush()
}
