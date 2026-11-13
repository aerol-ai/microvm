package nodejoin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

func init() { pollEvery = 5 * time.Millisecond }

// fakeHost is a machine for the tests: root, a fixed clock and address,
// and listeners on loopback ports the kernel picks, so no test ever binds
// the real 7000-7003.
type fakeHost struct {
	mu         sync.Mutex
	notRoot    bool
	reloadErr  error
	restartErr error
	stopErr    error
	held       map[int]bool // ports Listen answers EADDRINUSE for
	listenErr  error
	free       uint64
	freeErr    error
	ip         string
	ipErr      error
	hostname   string
	now        time.Time
	listened   []string
	restarts   int
	reloads    int
	stops      int
	onRestart  func()
}

func newFakeHost() *fakeHost {
	return &fakeHost{free: 100 << 30, ip: "10.0.0.9", hostname: "node-a", now: time.Now(), held: map[int]bool{}}
}

func (h *fakeHost) IsRoot() bool { return !h.notRoot }
func (h *fakeHost) DaemonReload(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reloads++
	return h.reloadErr
}
func (h *fakeHost) RestartSandboxd(context.Context) error {
	h.mu.Lock()
	h.restarts++
	fn := h.onRestart
	h.mu.Unlock()
	if h.restartErr == nil && fn != nil {
		fn()
	}
	return h.restartErr
}
func (h *fakeHost) StopSandboxd(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stops++
	return h.stopErr
}
func (h *fakeHost) Listen(addr string) (net.Listener, error) {
	h.mu.Lock()
	h.listened = append(h.listened, addr)
	h.mu.Unlock()
	_, port, _ := net.SplitHostPort(addr)
	if p, _ := strconv.Atoi(port); h.held[p] {
		return nil, &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", syscall.EADDRINUSE)}
	}
	if h.listenErr != nil {
		return nil, h.listenErr
	}
	return net.Listen("tcp", "127.0.0.1:0")
}
func (h *fakeHost) FreeBytes(string) (uint64, error) { return h.free, h.freeErr }
func (h *fakeHost) PrimaryIP() (string, error)       { return h.ip, h.ipErr }
func (h *fakeHost) Hostname() (string, error) {
	if h.hostname == "" {
		return "", errors.New("no host name")
	}
	return h.hostname, nil
}
func (h *fakeHost) Now() time.Time { return h.now }

// testPaths puts every node path under one temp dir, with install.sh's
// sandboxd.env and a cgroup v2 root in place.
func testPaths(t *testing.T) Paths {
	t.Helper()
	dir := t.TempDir()
	p := Paths{
		EnvFile:      filepath.Join(dir, "etc", "sandboxd.env"),
		ClusterEnv:   filepath.Join(dir, "etc", "cluster.env"),
		DropIn:       filepath.Join(dir, "systemd", "sandboxd.service.d", "cluster.conf"),
		Unit:         filepath.Join(dir, "systemd", "sandboxd.service"),
		TLSDir:       filepath.Join(dir, "etc", "tls"),
		CADir:        filepath.Join(dir, "etc", "cluster-ca"),
		RaftDir:      filepath.Join(dir, "var", "raft"),
		StateDir:     filepath.Join(dir, "var"),
		AdminContext: filepath.Join(dir, "etc", "admin-context.json"),
		CgroupRoot:   filepath.Join(dir, "cgroup"),
		KVMDevice:    filepath.Join(dir, "dev-kvm"),
	}
	mustWrite(t, filepath.Join(p.CgroupRoot, "cgroup.controllers"), "cpu memory\n")
	keyPath := filepath.Join(dir, "var", "credential_encryption.key")
	mustWrite(t, p.EnvFile, "SB_PAT_TOKEN=node-pat\nSB_API_PORT=21212\nSB_DOMAIN=\nSB_PUBLIC_HOST=203.0.113.9\n"+
		"SB_CREDENTIAL_ENCRYPTION_KEY_PATH="+keyPath+"\nSB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH="+keyPath+".wrapped\n")
	return p
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fakeJoinServer is a join port: a TLS server with a node cert signed by a
// test CA, serving the three join paths the way internal/cluster does.
type fakeJoinServer struct {
	t      *testing.T
	ca     *cluster.ClusterCA
	srv    *httptest.Server
	url    string
	mu     sync.Mutex
	tokens map[string]string // token -> role
	used   map[string]string // token -> key hash of a single-use token
	keys   map[string]string // node id -> key hash it was admitted with
	// refuse answers every call to path with this status and reason.
	refuse   map[string]joinRefuseSpec
	dialFail bool
	inUse    map[string]bool
	version  string
	pat      string
	custody  cluster.JoinCredentials
	badMAC   bool
	skew     time.Duration
	joins    int
	// patFree answers a worker or ingress join without the PAT, the way a
	// server answers once every member takes cert-only calls.
	patFree bool
}

type joinRefuseSpec struct {
	status int
	reason string
}

func newFakeJoinServer(t *testing.T) *fakeJoinServer {
	t.Helper()
	certPEM, keyPEM, err := cluster.GenerateClusterCA("test CA", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := cluster.ParseClusterCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeJoinServer{
		t: t, ca: ca, tokens: map[string]string{}, used: map[string]string{}, keys: map[string]string{},
		refuse: map[string]joinRefuseSpec{}, inUse: map[string]bool{}, version: "v9.9.9", pat: "cluster-pat",
		custody: cluster.JoinCredentials{Custody: "file", Key: base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"))},
	}
	srvKey, srvKeyPEM, err := cluster.NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	srvCert, _, err := ca.SignNodeCert(cluster.NodeCertRequest{PublicKey: srvKey.Public(), NodeID: "srv-1", Role: cluster.JoinRoleServer})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(srvCert, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+cluster.JoinClusterInfoPath, f.clusterInfo)
	mux.HandleFunc("POST "+cluster.JoinPreflightPath, f.preflight)
	mux.HandleFunc("POST "+cluster.JoinPath, f.join)
	mux.HandleFunc("POST "+cluster.JoinByCertPath, f.joinByCert)
	f.srv = httptest.NewUnstartedServer(mux)
	// As the join port in external-CA mode: a client certificate, when
	// given, must chain to the CA (token clients send none).
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca.Certificate())
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCAs}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.url = f.srv.URL
	return f
}

// token makes a token for role.
func (f *fakeJoinServer) token(role string) string {
	tok, err := cluster.GenerateJoinToken()
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.tokens[tok] = role
	f.mu.Unlock()
	return tok
}

func (f *fakeJoinServer) refused(w http.ResponseWriter, path string) bool {
	f.mu.Lock()
	spec, ok := f.refuse[path]
	f.mu.Unlock()
	if !ok {
		return false
	}
	w.WriteHeader(spec.status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "refused: " + spec.reason, "reason": spec.reason})
	return true
}

func (f *fakeJoinServer) clusterInfo(w http.ResponseWriter, r *http.Request) {
	if f.refused(w, cluster.JoinClusterInfoPath) {
		return
	}
	id := r.URL.Query().Get("token_id")
	var tok string
	f.mu.Lock()
	for t := range f.tokens {
		if strings.HasPrefix(t, id+".") {
			tok = t
		}
	}
	f.mu.Unlock()
	if tok == "" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "cluster: join token is not valid", "reason": "token_invalid"})
		return
	}
	key, _ := cluster.JoinDiscoveryKey(tok)
	if f.badMAC {
		key = []byte("not-the-discovery-key-not-the-key")
	}
	info := cluster.ClusterInfo{CACert: string(f.ca.CertPEM()), ClusterID: cluster.CACertHash(f.ca.Certificate()), Version: f.version, JoinURLs: []string{f.url}}
	info.MAC = base64.StdEncoding.EncodeToString(cluster.JoinDiscoveryMAC(key, f.ca.CertPEM()))
	info.InfoMAC = base64.StdEncoding.EncodeToString(cluster.JoinDiscoveryMAC(key, cluster.ClusterInfoSigningBytes(info)))
	w.Header().Set("Date", time.Now().Add(f.skew).UTC().Format(http.TimeFormat))
	_ = json.NewEncoder(w).Encode(info)
}

func (f *fakeJoinServer) results() []cluster.DialBackResult {
	return []cluster.DialBackResult{
		{Name: "gossip", Port: 7001, OK: !f.dialFail, Error: map[bool]string{true: "connection refused"}[f.dialFail]},
		{Name: "internal", Port: 7002, OK: true},
	}
}

func (f *fakeJoinServer) preflight(w http.ResponseWriter, r *http.Request) {
	if f.refused(w, cluster.JoinPreflightPath) {
		return
	}
	var req cluster.PreflightRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	role, ok := f.tokens[req.Token]
	inUse := f.inUse[req.NodeID]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad token", "reason": "token_invalid"})
		return
	}
	_ = json.NewEncoder(w).Encode(cluster.PreflightResponse{
		OK: !f.dialFail && !inUse, Role: role, DialBack: f.results(), ServerTime: time.Now().Add(f.skew), Version: f.version, NodeIDInUse: inUse,
	})
}

func (f *fakeJoinServer) join(w http.ResponseWriter, r *http.Request) {
	if f.refused(w, cluster.JoinPath) {
		return
	}
	var req cluster.JoinRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.joins++
	role, ok := f.tokens[req.Token]
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "bad token", "reason": "token_invalid"})
		return
	}
	if f.dialFail {
		w.WriteHeader(http.StatusPreconditionFailed)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "dial back", "reason": "dial_back", "dial_back": f.results()})
		return
	}
	csr, err := cluster.ParseCertificateRequestPEM([]byte(req.CSR))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	kh, _ := cluster.PublicKeyHash(csr.PublicKey)
	replay := f.keys[req.NodeID] == kh
	if prev, ok := f.keys[req.NodeID]; ok && prev != kh {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "node ID in use", "reason": "node_id_in_use"})
		return
	}
	f.keys[req.NodeID] = kh
	certPEM, leaf, err := f.ca.SignNodeCert(cluster.NodeCertRequest{PublicKey: csr.PublicKey, NodeID: req.NodeID, Role: role})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := cluster.JoinResponse{
		NodeID: req.NodeID, Role: role, ClusterID: cluster.CACertHash(f.ca.Certificate()), NodeCert: string(certPEM),
		CACert: string(f.ca.CertPEM()), GossipKey: "Z29zc2lwLWtleS0xNi1ieXRlcw==", BootstrapPeers: []string{"10.0.0.5:7001"},
		JoinURLs: []string{f.url}, Credentials: f.custody, NotAfter: leaf.NotAfter, Version: f.version, Replay: replay,
		DialBack: f.results(), PATToken: f.pat,
	}
	if role == cluster.JoinRoleServer {
		resp.CAKey = string(f.ca.KeyPEM())
	} else if f.patFree {
		resp.PATToken, resp.PATSHA256, resp.OperatorVolumeScope = "", []string{config.PATSHA256(f.pat)}, "op-cluster"
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// fakeLocalAPI is the node's own sandboxd API.
type fakeLocalAPI struct {
	mu        sync.Mutex
	srv       *httptest.Server
	leader    string
	members   []localMember
	tokens    []cluster.JoinTokenCreateRequest
	tokenErr  int
	adoptErr  string
	adopts    []cluster.AdoptRequest
	deleted   []string
	deleteErr int
	auth      []string
	// joinURLs and caHash go in each made token's answer (join-command
	// prints the line from them); tokenAuth records the token calls' header.
	joinURLs  []string
	caHash    string
	tokenAuth []string
}

func newFakeLocalAPI(t *testing.T) *fakeLocalAPI {
	t.Helper()
	l := &fakeLocalAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/cluster/leader", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.auth = append(l.auth, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]string{"leader": l.leader})
	})
	mux.HandleFunc("GET /v1/cluster/members", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.auth = append(l.auth, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"members": l.members})
	})
	mux.HandleFunc("POST "+cluster.PublicJoinTokensPath, func(w http.ResponseWriter, r *http.Request) {
		var req cluster.JoinTokenCreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.tokenErr != 0 {
			w.WriteHeader(l.tokenErr)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "no tokens today"})
			return
		}
		l.tokens = append(l.tokens, req)
		l.tokenAuth = append(l.tokenAuth, r.Header.Get("Authorization"))
		tok := req.Token
		if tok == "" {
			tok, _ = cluster.GenerateJoinToken()
		}
		id, _, _ := cluster.ParseJoinToken(tok)
		out := cluster.JoinTokenCreated{Token: tok, ID: id, Role: req.Role, Reusable: req.Reusable, JoinURLs: l.joinURLs, CACertHash: l.caHash}
		if req.TTL != "0" {
			exp := time.Now().Add(2 * time.Hour)
			out.ExpiresAt = &exp
		} else {
			out.Warning = "this token never expires"
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST "+cluster.PublicAdoptPath, func(w http.ResponseWriter, r *http.Request) {
		var req cluster.AdoptRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.adoptErr != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": l.adoptErr})
			return
		}
		l.adopts = append(l.adopts, req)
		_ = json.NewEncoder(w).Encode(cluster.AdoptResponse{ClusterID: "sha256:abc", CASource: "ca_store", Admitted: []string{"node-a"},
			Already: []string{}, Skipped: map[string]string{"wrk-9": "unreachable: timeout"}})
	})
	mux.HandleFunc("DELETE "+cluster.PublicNodesPath+"{id}", func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.deleteErr != 0 {
			w.WriteHeader(l.deleteErr)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "cluster: unknown node"})
			return
		}
		l.deleted = append(l.deleted, r.PathValue("id")+"?"+r.URL.RawQuery)
		_ = json.NewEncoder(w).Encode(cluster.NodeDeleteResult{NodeID: r.PathValue("id"), Denied: true})
	})
	l.srv = httptest.NewServer(mux)
	t.Cleanup(l.srv.Close)
	return l
}

func (l *fakeLocalAPI) setMembers(m ...localMember) {
	l.mu.Lock()
	l.members = m
	l.mu.Unlock()
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// joinByCert answers a join by certificate the way the join port does in
// external-CA mode: the verified client certificate names the node and its
// role; the answer carries no certificate and no CA key.
func (f *fakeJoinServer) joinByCert(w http.ResponseWriter, r *http.Request) {
	if f.refused(w, cluster.JoinByCertPath) {
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "no client certificate", "reason": "no_client_cert"})
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	roles := cluster.ExtractCertRoles(leaf)
	f.mu.Lock()
	f.joins++
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(cluster.JoinResponse{
		NodeID: cluster.ExtractPeerNodeID(leaf), Role: roles[0], ClusterID: cluster.CACertHash(f.ca.Certificate()),
		GossipKey: "Z29zc2lwLWtleS0xNi1ieXRlcw==", BootstrapPeers: []string{"10.0.0.5:7001"}, JoinURLs: []string{f.url},
		Credentials: f.custody, NotAfter: leaf.NotAfter, Version: f.version, PATToken: f.pat,
	})
}
