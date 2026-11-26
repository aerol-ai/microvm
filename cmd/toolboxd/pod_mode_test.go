package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/podtrust"
	"github.com/aerol-ai/microvm/internal/testport"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestLoadPodMode(t *testing.T) {
	caPEM, _ := testCell(t)
	files := map[string][]byte{"/ca.crt": caPEM, "/empty.crt": []byte("not pem")}
	read := func(p string) ([]byte, error) {
		if b, ok := files[p]; ok {
			return b, nil
		}
		return nil, os.ErrNotExist
	}
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	if cfg, err := loadPodMode(env(), read); cfg != nil || err != nil {
		t.Fatalf("pod mode off = %+v, %v; want nil, nil", cfg, err)
	}
	cfg, err := loadPodMode(env("SB_POD_MODE", "1", "SB_POD_WORKER", " worker-0 ", "SB_POD_WORKER_CA", "/ca.crt", "SB_SANDBOX_ID", "sb-1"), read)
	if err != nil || cfg.worker != "worker-0" || cfg.port != podtrust.DefaultAdoptPort || cfg.sandboxID != "sb-1" || cfg.cas == nil {
		t.Fatalf("loadPodMode = %+v, %v", cfg, err)
	}
	cfg, err = loadPodMode(env("SB_POD_MODE", "1", "SB_POD_WORKER", "w", "SB_POD_WORKER_CA", "/ca.crt", "SB_POD_ADOPT_PORT", "3001"), read)
	if err != nil || cfg.port != 3001 {
		t.Fatalf("port = %+v, %v", cfg, err)
	}
	bad := []struct {
		name string
		env  func(string) string
		want string
	}{
		{"no worker", env("SB_POD_MODE", "1", "SB_POD_WORKER_CA", "/ca.crt"), "SB_POD_WORKER"},
		{"no CA file (default path)", env("SB_POD_MODE", "1", "SB_POD_WORKER", "w"), defaultWorkerCAPath},
		{"CA file with no certificate", env("SB_POD_MODE", "1", "SB_POD_WORKER", "w", "SB_POD_WORKER_CA", "/empty.crt"), "no certificate"},
		{"bad port", env("SB_POD_MODE", "1", "SB_POD_WORKER", "w", "SB_POD_WORKER_CA", "/ca.crt", "SB_POD_ADOPT_PORT", "70000"), "not a port"},
	}
	for _, tc := range bad {
		if _, err := loadPodMode(tc.env, read); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: loadPodMode = %v, want an error with %q", tc.name, err, tc.want)
		}
	}
}

func TestScrubPodEnv(t *testing.T) {
	for _, k := range podEnvKeys {
		t.Setenv(k, "x")
	}
	scrubPodEnv()
	for _, k := range podEnvKeys {
		if _, ok := os.LookupEnv(k); ok {
			t.Errorf("%s still set", k)
		}
	}
}

func newAdopter(t *testing.T, sandboxID string) (*podAdopter, *server, *atomic.Int32) {
	t.Helper()
	withSandboxEnv(t, nil)
	srv := &server{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), parkedMode: true, sandboxID: sandboxID}
	var starts atomic.Int32
	return &podAdopter{srv: srv, logger: srv.logger, sandboxID: sandboxID, startCommand: func() { starts.Add(1) }}, srv, &starts
}

func postAdopt(t *testing.T, h http.Handler, frame any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(frame)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, podtrust.AdoptPath, bytes.NewReader(body)))
	return rec
}

func TestPodAdopt(t *testing.T) {
	a, srv, starts := newAdopter(t, "sb-pod")
	if srv.servingRequests() {
		t.Fatal("a pod-mode agent serves before it is adopted")
	}
	frame := readyproto.AdoptFrame{Event: readyproto.EventAdopt, SandboxID: "sb-pod", Token: "tok-1", Nonce: "n1", Env: map[string]string{"BANK_SECRET": envCanary}}

	rec := postAdopt(t, a, frame)
	if rec.Code != http.StatusOK {
		t.Fatalf("first adopt = %d %s", rec.Code, rec.Body)
	}
	var ack readyproto.ReadySignal
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || !readyproto.EnvDigestMatches("n1", frame.Env, ack.EnvDigest) || ack.Token != "tok-1" {
		t.Fatalf("ack = %+v, %v", ack, err)
	}
	if !srv.servingRequests() || starts.Load() != 1 {
		t.Fatalf("after adopt: serving=%v, command starts=%d", srv.servingRequests(), starts.Load())
	}
	if got := sandboxEnv.Environ(nil); !slices.Equal(got, []string{"BANK_SECRET=" + envCanary}) {
		t.Fatalf("env = %v", got)
	}

	// The same token again (a retry, or a start sending the env again):
	// applied again, the command not started twice.
	frame.Env = map[string]string{"REGION": "eu"}
	frame.Nonce = "n2"
	if rec := postAdopt(t, a, frame); rec.Code != http.StatusOK || starts.Load() != 1 {
		t.Fatalf("repeat adopt = %d, starts=%d", rec.Code, starts.Load())
	}
	if got := sandboxEnv.Environ(nil); !slices.Equal(got, []string{"REGION=eu"}) {
		t.Fatalf("env after the repeat = %v (it replaces, not merges)", got)
	}

	// Another token never replaces the first.
	other := frame
	other.Token = "tok-2"
	if rec := postAdopt(t, a, other); rec.Code != http.StatusConflict {
		t.Fatalf("adopt with another token = %d", rec.Code)
	}
	if _, tok := srv.identity(); tok != "tok-1" {
		t.Fatalf("token = %q after another adopt", tok)
	}
}

func TestPodAdoptRefusals(t *testing.T) {
	a, srv, starts := newAdopter(t, "sb-pod")
	good := readyproto.AdoptFrame{SandboxID: "sb-pod", Token: "tok", Nonce: "n"}
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		code   int
	}{
		{"another path", http.MethodPost, "/v1/other", "{}", http.StatusNotFound},
		{"not POST", http.MethodGet, podtrust.AdoptPath, "", http.StatusMethodNotAllowed},
		{"not JSON", http.MethodPost, podtrust.AdoptPath, "{", http.StatusBadRequest},
		{"no token", http.MethodPost, podtrust.AdoptPath, `{"sandbox_id":"sb-pod","token":" "}`, http.StatusBadRequest},
		{"another sandbox", http.MethodPost, podtrust.AdoptPath, `{"sandbox_id":"sb-other","token":"tok"}`, http.StatusConflict},
		{"env the store refuses", http.MethodPost, podtrust.AdoptPath, `{"sandbox_id":"sb-pod","token":"tok","env":{"BAD=KEY":"v"}}`, http.StatusBadRequest},
		{"too big", http.MethodPost, podtrust.AdoptPath, `{"token":"` + strings.Repeat("x", maxAdoptBytes) + `"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code != tc.code {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body, tc.code)
		}
		if strings.Contains(rec.Body.String(), "BAD=KEY") {
			t.Errorf("%s: the answer repeats the env", tc.name)
		}
	}
	if srv.servingRequests() || starts.Load() != 0 {
		t.Fatal("a refused adopt changed the agent")
	}
	// A pod parked with no sandbox yet takes any sandbox ID.
	b, _, _ := newAdopter(t, "")
	if rec := postAdopt(t, b, good); rec.Code != http.StatusOK {
		t.Fatalf("adopt of a parked pod = %d", rec.Code)
	}
}

// testCell is a cluster CA made the cluster's own way, and a client
// certificate for node id signed by it.
func testCell(t *testing.T) (caPEM []byte, sign func(id string) tls.Certificate) {
	t.Helper()
	caPEM, keyPEM, err := cluster.GenerateClusterCA("test-cell", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := cluster.ParseClusterCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return caPEM, func(id string) tls.Certificate {
		key, _, err := cluster.NewNodeKey()
		if err != nil {
			t.Fatal(err)
		}
		_, leaf, err := ca.SignNodeCert(cluster.NodeCertRequest{PublicKey: key.Public(), NodeID: id, Role: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	}
}

// The whole adopt path over a real mTLS listener: only the named worker's
// certificate gets an answer.
func TestPodAdoptOverMTLS(t *testing.T) {
	caPEM, sign := testCell(t)
	cas, err := podtrust.LoadCAs(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	withSandboxEnv(t, nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &server{logger: logger, parkedMode: true, sandboxID: "sb-pod", deferredCmd: []string{"sleep", "1"}}
	var started atomic.Int32
	old := startUserCommandFn
	startUserCommandFn = func(_ *slog.Logger, args []string) {
		if slices.Equal(args, []string{"sleep", "1"}) {
			started.Add(1)
		}
	}
	t.Cleanup(func() { startUserCommandFn = old })

	addr, err := startPodAdopt(logger, srv, &podModeConfig{worker: "worker-0", cas: cas, port: 0, sandboxID: "sb-pod"})
	if err != nil {
		t.Fatal(err)
	}
	url := "https://127.0.0.1:" + portOf(t, addr) + podtrust.AdoptPath
	post := func(cert *tls.Certificate) (*http.Response, error) {
		cfg := &tls.Config{InsecureSkipVerify: true} // the server's own identity is M4 PR 4's
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
		body, _ := json.Marshal(readyproto.AdoptFrame{SandboxID: "sb-pod", Token: "tok", Nonce: "n", Env: map[string]string{"A": "b"}})
		return client.Post(url, "application/json", bytes.NewReader(body))
	}

	for name, cert := range map[string]*tls.Certificate{"no certificate": nil, "another worker": ptrTo(sign("worker-7"))} {
		if resp, err := post(cert); err == nil {
			resp.Body.Close()
			t.Errorf("%s: got %d, want the handshake refused", name, resp.StatusCode)
		}
	}
	if srv.servingRequests() {
		t.Fatal("adopted by a caller that is not its worker")
	}
	resp, err := post(ptrTo(sign("worker-0")))
	if err != nil {
		t.Fatalf("its own worker: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !srv.servingRequests() {
		t.Fatalf("its own worker's adopt = %d, serving=%v", resp.StatusCode, srv.servingRequests())
	}
	deadline := time.Now().Add(5 * time.Second)
	for started.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if started.Load() != 1 {
		t.Fatal("the held-back command did not start after the adopt")
	}
}

func ptrTo[T any](v T) *T { return &v }

func portOf(t *testing.T, addr net.Addr) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestStartPodAdoptErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := startPodAdopt(logger, &server{}, &podModeConfig{worker: ""}); err == nil {
		t.Error("no worker: want an error")
	}
	caPEM, _ := testCell(t)
	cas, _ := podtrust.LoadCAs(caPEM)
	old := netListenFn
	t.Cleanup(func() { netListenFn = old })
	netListenFn = func(string, string) (net.Listener, error) { return nil, errors.New("port taken") }
	if _, err := startPodAdopt(logger, &server{}, &podModeConfig{worker: "w", cas: cas}); err == nil || !strings.Contains(err.Error(), "port taken") {
		t.Errorf("listen failure = %v", err)
	}
}

// main in pod mode holds the image's command back until its worker adopts
// it: run toolboxd's main with a command that leaves a marker file. Before
// the adopt, no marker (the command would run without its env); after it,
// the marker. (Review of #1489: removing the line that parks pod mode in
// main broke nothing before this test.)
func TestMainPodModeHoldsTheCommandUntilAdopted(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	caPEM, sign := testCell(t)
	dir := t.TempDir()
	caPath := dir + "/ca.crt"
	marker := dir + "/command-ran"
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	toolboxPort := testport.Reserve(t, false)
	adoptPort := testport.Reserve(t, false)
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainPodModeHolds")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS_POD_HOLD=1",
		"POD_HOLD_MARKER="+marker,
		"SB_POD_MODE=1",
		"SB_POD_WORKER=worker-0",
		"SB_POD_WORKER_CA="+caPath,
		"SB_POD_ADOPT_PORT="+strconv.Itoa(adoptPort),
		"SB_TOOLBOX_PORT="+strconv.Itoa(toolboxPort),
		"SB_SANDBOX_ID=sb-pod",
		"SB_RECORDING_DIR="+dir+"/recordings",
		"SB_CLONE_GEN_PATH="+dir+"/clonegen",
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	// A child toolboxd started could still hold the output pipe after the
	// kill; do not wait on it.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	cert := sign("worker-0")
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // the server's own identity is M4 PR 4's
		Certificates:       []tls.Certificate{cert},
	}}}
	adoptURL := "https://127.0.0.1:" + strconv.Itoa(adoptPort) + podtrust.AdoptPath
	healthURL := "http://127.0.0.1:" + strconv.Itoa(toolboxPort) + "/health"
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("toolboxd never came up: %v\n%s", err, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Up and serving /health, adopt listener open: give a command that was
	// not held back ample time to run.
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("the image's command ran before the worker adopted the pod\n%s", out.String())
	}

	body, _ := json.Marshal(readyproto.AdoptFrame{SandboxID: "sb-pod", Token: "tok", Nonce: "n"})
	resp, err := client.Post(adoptURL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("adopt: %v\n%s", err, out.String())
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("adopt = %d", resp.StatusCode)
	}
	for {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the image's command did not run after the adopt\n%s", out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHelperProcessMainPodModeHolds(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_POD_HOLD") != "1" {
		return
	}
	os.Args = []string{"toolboxd", "sh", "-c", "touch " + os.Getenv("POD_HOLD_MARKER")}
	main()
	os.Exit(0)
}

// A pod-mode toolboxd whose settings are missing exits at once instead of
// serving with no way to be adopted.
func TestMainPodModeExitsWithoutSettings(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessMainPodMode")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_POD_MODE=1", "SB_POD_MODE=1", "SB_POD_WORKER=")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), "SB_POD_WORKER") {
		t.Fatalf("pod mode with no worker: %v: %s; want exit 1 naming SB_POD_WORKER", err, out)
	}
}

func TestHelperProcessMainPodMode(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_POD_MODE") != "1" {
		return
	}
	os.Args = []string{"toolboxd"}
	main()
	os.Exit(0)
}
