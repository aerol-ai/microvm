package nodejoin

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clusterNode(t *testing.T, p Paths, role string) {
	t.Helper()
	body := "SB_ENABLE_CLUSTER=true\nSB_NODE_ID=node-a\n"
	if role != "" {
		body += "SB_NODE_ROLE=" + role + "\n"
	}
	mustWrite(t, p.ClusterEnv, body)
}

func TestAdopt(t *testing.T) {
	ctx := context.Background()
	p := testPaths(t)
	api := newFakeLocalAPI(t)
	var out bytes.Buffer
	a := &Adopter{Paths: p, Host: newFakeHost(), Printer: Printer{Out: &out}, LocalAPI: api.srv.URL}

	if _, err := a.Run(ctx, AdoptOptions{}); err == nil || !strings.Contains(err.Error(), "not in a cluster") {
		t.Fatalf("adopt off-cluster = %v", err)
	}
	clusterNode(t, p, "worker")
	if _, err := a.Run(ctx, AdoptOptions{}); !errors.Is(err, ErrNotAServer) {
		t.Fatalf("adopt on a worker = %v", err)
	}
	clusterNode(t, p, "bogus")
	if _, err := a.Run(ctx, AdoptOptions{}); err == nil {
		t.Fatal("a bogus role adopted")
	}

	// On the seed: cluster-init.sh's ca.key is handed over explicitly.
	clusterNode(t, p, "server")
	mustWrite(t, filepath.Join(p.CADir, "ca.key"), "SEED-KEY")
	res, err := a.Run(ctx, AdoptOptions{})
	if err != nil || res.CASource != "ca_store" || len(api.adopts) != 1 || api.adopts[0].CAKey != "SEED-KEY" {
		t.Fatalf("adopt = %+v %v (adopts %+v)", res, err, api.adopts)
	}
	for _, want := range []string{"admitted now: node-a", "admitted before: none", "skipped wrk-9: unreachable", "on every other server"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	// --ca-key wins over the store; a missing file is an error.
	keyFile := filepath.Join(t.TempDir(), "saved.key")
	mustWrite(t, keyFile, "SAVED-KEY")
	if _, err := a.Run(ctx, AdoptOptions{CAKeyFile: keyFile}); err != nil || api.adopts[1].CAKey != "SAVED-KEY" {
		t.Fatalf("adopt --ca-key = %v %+v", err, api.adopts)
	}
	if _, err := a.Run(ctx, AdoptOptions{CAKeyFile: keyFile + ".missing"}); err == nil {
		t.Fatal("a missing --ca-key file adopted")
	}
	// Another server with no key anywhere gets a fix that names the seed.
	_ = os.Remove(filepath.Join(p.CADir, "ca.key"))
	api.adoptErr = "cluster: no CA key here and none from another server (keep ca.key from the seed, or run adopt on the seed first): no other live server"
	if _, err := a.Run(ctx, AdoptOptions{}); err == nil || !strings.Contains(err.Error(), "fix: run `sudo sandboxd adopt` on the seed") {
		t.Fatalf("adopt without a CA key = %v", err)
	}
	api.adoptErr = "something else"
	if _, err := a.Run(ctx, AdoptOptions{}); err == nil || strings.Contains(err.Error(), "fix:") {
		t.Fatalf("other adopt error = %v", err)
	}
	a.Host.(*fakeHost).notRoot = true
	if _, err := a.Run(ctx, AdoptOptions{}); err == nil {
		t.Fatal("adopt ran without root")
	}
	if listOrNone(nil) != "none" || listOrNone([]string{"a", "b"}) != "a, b" {
		t.Fatal("listOrNone")
	}
}

func TestReset(t *testing.T) {
	ctx := context.Background()
	p := testPaths(t)
	api := newFakeLocalAPI(t)
	h := newFakeHost()
	var out bytes.Buffer
	r := &Resetter{Paths: p, Host: h, Printer: Printer{Out: &out}, LocalAPI: api.srv.URL}

	if err := r.Run(ctx, ResetOptions{}); !errors.Is(err, ErrResetNeedsYes) {
		t.Fatalf("reset without --yes = %v", err)
	}
	h.notRoot = true
	if err := r.Run(ctx, ResetOptions{Yes: true}); err == nil {
		t.Fatal("reset ran without root")
	}
	h.notRoot = false

	// A joined node: everything cluster goes, the rest stays.
	clusterNode(t, p, "worker")
	mustWrite(t, p.DropIn, dropInBody)
	for _, f := range []string{"ca.crt", "node.crt", "node.key"} {
		mustWrite(t, filepath.Join(p.TLSDir, f), "x")
	}
	mustWrite(t, filepath.Join(p.CADir, "ca.key"), "x")
	mustWrite(t, filepath.Join(p.RaftDir, "raft.db"), "x")
	if err := r.Run(ctx, ResetOptions{Yes: true}); err != nil {
		t.Fatal(err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "node-a?force=true" {
		t.Fatalf("deletes = %v", api.deleted)
	}
	for _, f := range []string{p.ClusterEnv, p.DropIn, filepath.Join(p.TLSDir, "node.key"), filepath.Join(p.CADir, "ca.key"), p.RaftDir} {
		if exists(f) {
			t.Fatalf("%s survived reset", f)
		}
	}
	if !exists(p.EnvFile) || h.stops != 1 || !strings.Contains(out.String(), "removed node-a from the cluster") {
		t.Fatalf("stops %d, output:\n%s", h.stops, out.String())
	}

	// Again: nothing left, and nothing to ask the cluster.
	out.Reset()
	if err := r.Run(ctx, ResetOptions{Yes: true}); err != nil || !strings.Contains(out.String(), "nothing to reset") || len(api.deleted) != 1 {
		t.Fatalf("second reset = %v\n%s", err, out.String())
	}

	// The cluster can't be reached, or sandboxd won't stop: reset still
	// cleans up and says what to do.
	clusterNode(t, p, "worker")
	api.deleteErr = http.StatusServiceUnavailable
	h.stopErr = errors.New("unit not loaded")
	h.reloadErr = errors.New("no systemd")
	out.Reset()
	if err := r.Run(ctx, ResetOptions{Yes: true}); err != nil || exists(p.ClusterEnv) {
		t.Fatalf("reset with the cluster away = %v", err)
	}
	if !strings.Contains(out.String(), "aerolvm delete node node-a") || !strings.Contains(out.String(), "unit not loaded") {
		t.Fatalf("output:\n%s", out.String())
	}

	// A Raft dir path too short to be one is refused.
	if err := removeTree("/var"); err == nil {
		t.Fatal("removeTree(/var) allowed")
	}
	if err := removeTree("relative/a/b/c"); err == nil {
		t.Fatal("a relative path allowed")
	}
}

func TestLocalAPIEdges(t *testing.T) {
	ctx := context.Background()
	api := newFakeLocalAPI(t)
	l := &localAPI{base: api.srv.URL, pat: "p"}
	if err := l.do(ctx, http.MethodGet, "/nowhere", nil, nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("a 404 = %v", err)
	}
	if err := l.do(ctx, http.MethodPost, "/x", make(chan int), nil); err == nil {
		t.Fatal("an unencodable body was sent")
	}
	if err := l.do(ctx, "BAD METHOD", "/x", nil, nil); err == nil {
		t.Fatal("a bad method was sent")
	}
	var out struct{}
	if err := (&localAPI{base: "http://127.0.0.1:1"}).do(ctx, http.MethodGet, "/", nil, &out); err == nil {
		t.Fatal("an unreachable API answered")
	}
	// A 200 that is not JSON.
	plain := newFakeLocalAPI(t)
	plain.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) })
	if err := (&localAPI{base: plain.srv.URL}).do(ctx, http.MethodGet, "/", nil, &out); err == nil {
		t.Fatal("non-JSON decoded")
	}
	if errorMessage([]byte(`{"error":"boom"}`)) != "boom" || errorMessage([]byte(" text ")) != "text" {
		t.Fatal("errorMessage")
	}
	// The leader wait names who leads while it waits.
	api.leader = "other"
	if err := l.waitForLeader(ctx, "me", 30*time.Millisecond); err == nil || !strings.Contains(err.Error(), `"other"`) {
		t.Fatalf("leader wait = %v", err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := waitFor(cctx, time.Second, func(context.Context) (bool, error) { return false, nil }); err == nil || !strings.Contains(err.Error(), "still not ready") {
		t.Fatalf("waitFor = %v", err)
	}
	if err := (&localAPI{base: "http://127.0.0.1:1"}).waitForLeader(ctx, "me", 20*time.Millisecond); err == nil {
		t.Fatal("leader wait against nothing passed")
	}
	if _, err := (&localAPI{base: "http://127.0.0.1:1"}).waitForMember(ctx, "me", 20*time.Millisecond); err == nil {
		t.Fatal("member wait against nothing passed")
	}
}

func TestNodeEnvHelpers(t *testing.T) {
	e := nodeEnv{merged: map[string]string{"SB_PUBLIC_HOST": "1.2.3.4"}}
	if e.publicAPIURL("10.0.0.1") != "http://1.2.3.4:21212" || (nodeEnv{merged: map[string]string{}}).publicAPIURL("10.0.0.1") != "http://10.0.0.1:21212" {
		t.Fatal("publicAPIURL")
	}
	cases := map[string]string{"": "server", "mixed": "server", "worker,ingress": "worker", "ingress": "ingress", "server,worker": "server"}
	for in, want := range cases {
		if got, err := joinRoleOf(in); err != nil || got != want {
			t.Fatalf("joinRoleOf(%q) = %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"mixed,worker", "boss", "worker,"} {
		if _, err := joinRoleOf(bad); err == nil {
			t.Fatalf("joinRoleOf(%q) passed", bad)
		}
	}
	p := testPaths(t)
	mustWrite(t, p.ClusterEnv, "SB_ENABLE_CLUSTER=true\n")
	if err := os.Chmod(p.EnvFile, 0); err == nil && os.Geteuid() != 0 {
		if _, err := loadNodeEnv(p); err == nil {
			t.Fatal("an unreadable sandboxd.env loaded")
		}
	}
}

func TestSystemHost(t *testing.T) {
	h := SystemHost{}
	_ = h.IsRoot()
	if h.Now().IsZero() {
		t.Fatal("no clock")
	}
	if name, err := h.Hostname(); err != nil || name == "" || strings.Contains(name, ".") {
		t.Fatalf("hostname = %q %v", name, err)
	}
	if free, err := h.FreeBytes(filepath.Join(t.TempDir(), "not", "made", "yet")); err != nil || free == 0 {
		t.Fatalf("free = %d %v", free, err)
	}
	ln, err := h.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	if ip, err := h.PrimaryIP(); err != nil || ip == "" {
		t.Logf("no primary IP here (%v); fine offline", err)
	}
	if nearestExisting("/") != "/" {
		t.Fatal("nearestExisting(/)")
	}
}
