package nodejoin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// One table-driven test per §4.3 check, each over a fake file system or
// network (plans/kubectl-style-cluster-ops.md §10, "Preflight").

func TestCheckCgroup(t *testing.T) {
	cases := []struct {
		name        string
		v2, fc      bool
		want        CheckStatus
		detailHas   string
		fixRequired bool
	}{
		{"v2 mounted", true, false, StatusOK, "unified hierarchy", false},
		{"v1 only warns", false, false, StatusWarn, "not mounted", true},
		{"v1 on a Firecracker node says what it costs", false, true, StatusWarn, "won't survive a sandboxd restart", true},
	}
	for _, tc := range cases {
		p := Paths{CgroupRoot: t.TempDir()}
		if tc.v2 {
			mustWrite(t, filepath.Join(p.CgroupRoot, "cgroup.controllers"), "cpu\n")
		}
		c := checkCgroup(p, tc.fc)
		if c.Status != tc.want || !strings.Contains(c.Detail, tc.detailHas) || (c.Fix != "") != tc.fixRequired {
			t.Fatalf("%s: %+v", tc.name, c)
		}
	}
}

func TestCheckKVM(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "kvm")
	mustWrite(t, present, "")
	cases := []struct {
		name   string
		device string
		fc     bool
		want   CheckStatus
	}{
		{"Firecracker off", filepath.Join(dir, "none"), false, StatusOK},
		{"Firecracker on, device there", present, true, StatusOK},
		{"Firecracker on, no device", filepath.Join(dir, "none"), true, StatusFail},
	}
	for _, tc := range cases {
		c := checkKVM(Paths{KVMDevice: tc.device}, tc.fc)
		if c.Status != tc.want || (tc.want == StatusFail && !strings.Contains(c.Fix, "metal")) {
			t.Fatalf("%s: %+v", tc.name, c)
		}
	}
}

func TestCheckDisk(t *testing.T) {
	cases := []struct {
		name string
		free uint64
		err  error
		want CheckStatus
	}{
		{"plenty", 50 << 30, nil, StatusOK},
		{"too little", 100 << 20, nil, StatusFail},
		{"unreadable", 0, errors.New("statfs: no such device"), StatusWarn},
	}
	for _, tc := range cases {
		h := newFakeHost()
		h.free, h.freeErr = tc.free, tc.err
		c := checkDisk(h, Paths{StateDir: "/var/lib/sandboxd"}, DefaultMinFreeBytes)
		if c.Status != tc.want || (tc.want == StatusFail && !strings.Contains(c.Fix, "free space")) {
			t.Fatalf("%s: %+v", tc.name, c)
		}
	}
	if humanBytes(3<<30) != "3.0 GiB" || humanBytes(5<<20) != "5 MiB" {
		t.Fatal("humanBytes")
	}
}

func TestCheckLocalPorts(t *testing.T) {
	cases := []struct {
		name      string
		held      []int
		clustered bool
		want      CheckStatus
	}{
		{"all free", nil, false, StatusOK},
		{"one held by another program", []int{7002}, false, StatusFail},
		{"held by this node's own sandboxd", []int{7000, 7001}, true, StatusOK},
	}
	for _, tc := range cases {
		h := newFakeHost()
		for _, p := range tc.held {
			h.held[p] = true
		}
		c := checkLocalPorts(h, rolePorts(cluster.JoinRoleServer, true), tc.clustered)
		if c.Status != tc.want {
			t.Fatalf("%s: %+v", tc.name, c)
		}
		if len(h.listened) != 4 {
			t.Fatalf("%s: listened on %v, want the four server ports", tc.name, h.listened)
		}
	}
}

func TestRolePorts(t *testing.T) {
	names := func(ps []portSpec) string {
		var out []string
		for _, p := range ps {
			out = append(out, p.name)
		}
		return strings.Join(out, ",")
	}
	cases := map[string]string{
		cluster.JoinRoleServer + "/join":  "raft,gossip,internal,join",
		cluster.JoinRoleServer:            "raft,gossip,internal",
		cluster.JoinRoleWorker + "/join":  "gossip,internal",
		cluster.JoinRoleIngress + "/join": "gossip,internal",
	}
	for in, want := range cases {
		role, join := strings.CutSuffix(in, "/join")
		if got := names(rolePorts(role, join)); got != want {
			t.Fatalf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestDialBackCheck(t *testing.T) {
	ok := dialBackCheck([]cluster.DialBackResult{{Name: "gossip", Port: 7001, OK: true}, {Name: "internal", Port: 7002, OK: true}})
	if ok.Status != StatusOK || !strings.Contains(ok.Detail, "7001, 7002") {
		t.Fatalf("all reached: %+v", ok)
	}
	bad := dialBackCheck([]cluster.DialBackResult{{Name: "raft", Port: 7000, OK: false}, {Name: "gossip", Port: 7001, OK: true}})
	if bad.Status != StatusFail || !strings.Contains(bad.Detail, "7000 (raft)") || bad.Fix != portFix {
		t.Fatalf("one blocked: %+v", bad)
	}
}

func TestClockCheck(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		server time.Time
		want   CheckStatus
	}{
		{"no server time", time.Time{}, StatusWarn},
		{"close", now.Add(-3 * time.Second), StatusOK},
		{"server ahead", now.Add(2 * time.Minute), StatusFail},
		{"server behind", now.Add(-31 * time.Second), StatusFail},
	}
	for _, tc := range cases {
		c := clockCheck(tc.server, now)
		if c.Status != tc.want || (tc.want == StatusFail && !strings.Contains(c.Fix, "chrony")) {
			t.Fatalf("%s: %+v", tc.name, c)
		}
	}
}

func TestNodeRoleCheck(t *testing.T) {
	cases := []struct {
		nodeRole, token string
		want            CheckStatus
	}{
		{"", cluster.JoinRoleWorker, StatusOK},
		{"worker,ingress", cluster.JoinRoleWorker, StatusOK},
		{"mixed", cluster.JoinRoleServer, StatusOK},
		{"server", cluster.JoinRoleWorker, StatusFail},
		{"bogus", cluster.JoinRoleWorker, StatusFail},
	}
	for _, tc := range cases {
		if c := nodeRoleCheck(tc.nodeRole, tc.token); c.Status != tc.want {
			t.Fatalf("%q with a %s token: %+v", tc.nodeRole, tc.token, c)
		}
	}
}

func TestCustodyCheck(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want CheckStatus
	}{
		{map[string]string{}, StatusOK},
		{map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "wrapped", "SB_SECRET_PROVIDER": "awskms"}, StatusOK},
		{map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "wrapped"}, StatusFail},
	}
	for _, tc := range cases {
		if c := custodyCheck(nodeEnv{merged: tc.env}); c.Status != tc.want {
			t.Fatalf("%v: %+v", tc.env, c)
		}
	}
}

func TestNormalizeJoinURL(t *testing.T) {
	cases := map[string]string{
		"https://10.0.0.5:7003": "https://10.0.0.5:7003",
		"10.0.0.5:7003":         "https://10.0.0.5:7003",
		"10.0.0.5":              "https://10.0.0.5:7003",
		"https://srv.example/":  "https://srv.example:7003",
		"":                      "",
		"http://10.0.0.5:7003":  "",
		"https://":              "",
	}
	for in, want := range cases {
		got, err := normalizeJoinURL(in)
		if (want == "") != (err != nil) || got != want {
			t.Fatalf("%q = %q %v, want %q", in, got, err, want)
		}
	}
}

func TestJoinRefusalFix(t *testing.T) {
	for _, reason := range []string{"token_invalid", "token_expired", "token_used", "role_mismatch", "node_id_in_use",
		"key_revoked", "key_in_use", "version", "dial_back", "rate_limited", "no_ca_signer", "not_leader", "cluster_version"} {
		r := &JoinRefusal{Status: 403, Reason: reason, Message: "x"}
		if r.Fix() == "" || !strings.Contains(r.Error(), reason) {
			t.Fatalf("%s: no fix", reason)
		}
	}
	if (&JoinRefusal{Reason: "error"}).Fix() != "" {
		t.Fatal("an unknown reason got a fix")
	}
	if r := joinRefusal(500, []byte("plain text")); r.Message != "plain text" || r.Reason != "" {
		t.Fatalf("plain refusal = %+v", r)
	}
}

func TestReportPrint(t *testing.T) {
	r := Report{Checks: []Check{
		{Name: "disk", Status: StatusOK, Detail: "fine"},
		{Name: "clock", Status: StatusFail, Detail: "off", Fix: "sync it"},
		{Name: "gossip udp", Status: StatusWarn, Detail: "untested", Fix: "open it"},
	}}
	var b bytes.Buffer
	r.Print(&b)
	out := b.String()
	if !strings.Contains(out, "CHECK") || !strings.Contains(out, "fix clock: sync it") || !strings.Contains(out, "note gossip udp: open it") {
		t.Fatalf("printed:\n%s", out)
	}
	b.Reset()
	r.PrintJSON(&b)
	var got struct {
		OK     bool    `json:"ok"`
		Checks []Check `json:"checks"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil || got.OK || len(got.Checks) != 3 {
		t.Fatalf("json = %s %v", b.String(), err)
	}
}

func TestDialBackListeners(t *testing.T) {
	h := newFakeHost()
	h.held[7000] = true
	closeAll, err := dialBackListeners(h, rolePorts(cluster.JoinRoleServer, false))
	if err != nil {
		t.Fatal(err)
	}
	closeAll()
	h = newFakeHost()
	h.listenErr = errors.New("permission denied")
	if _, err := dialBackListeners(h, rolePorts(cluster.JoinRoleWorker, false)); err == nil {
		t.Fatal("a listen error passed")
	}
}

// The join-server checks against a fake join port: each way it can fail,
// with the fix it prints.
func TestRemoteChecks(t *testing.T) {
	ctx := context.Background()
	type setup func(*fakeJoinServer, *remoteInput)
	cases := []struct {
		name     string
		setup    setup
		failName string
		fixHas   string
		ok       bool
	}{
		{name: "all good", setup: func(*fakeJoinServer, *remoteInput) {}, ok: true},
		{name: "unreachable", setup: func(_ *fakeJoinServer, in *remoteInput) { in.joinURL = "https://127.0.0.1:1" }, failName: "join server", fixHas: "TCP 7003"},
		{name: "unknown token", setup: func(f *fakeJoinServer, in *remoteInput) { in.token, _ = cluster.GenerateJoinToken() }, failName: "join server", fixHas: "aerolvm join-command"},
		{name: "malformed token", setup: func(_ *fakeJoinServer, in *remoteInput) { in.token = "nope" }, failName: "join server", fixHas: "copy the whole token"},
		{name: "a server that can't prove the token", setup: func(f *fakeJoinServer, _ *remoteInput) { f.badMAC = true }, failName: "join server", fixHas: "--ca-cert-hash"},
		{name: "a wrong CA pin", setup: func(_ *fakeJoinServer, in *remoteInput) { in.pin = "sha256:00" }, failName: "join server", fixHas: "--ca-cert-hash"},
		{name: "the right CA pin", setup: func(f *fakeJoinServer, in *remoteInput) { in.pin = cluster.CACertHash(f.ca.Certificate()) }, ok: true},
		{name: "a blocked port", setup: func(f *fakeJoinServer, _ *remoteInput) { f.dialFail = true }, failName: "dial-back", fixHas: "TCP 7003 to servers"},
		{name: "preflight refused", setup: func(f *fakeJoinServer, _ *remoteInput) {
			f.refuse[cluster.JoinPreflightPath] = joinRefuseSpec{429, "rate_limited"}
		}, failName: "dial-back", fixHas: "wait a minute"},
		{name: "a taken node ID", setup: func(f *fakeJoinServer, in *remoteInput) { f.inUse["node-a"] = true }, failName: "node id", fixHas: "--node-id"},
		{name: "a skewed clock", setup: func(f *fakeJoinServer, _ *remoteInput) { f.skew = 5 * time.Minute }, failName: "clock", fixHas: "chrony"},
		{name: "a listener that can't open", setup: nil, failName: "dial-back", fixHas: "stop the program"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeJoinServer(t)
			h := newFakeHost()
			in := remoteInput{joinURL: f.url, token: f.token(cluster.JoinRoleWorker), nodeID: "node-a", version: "v9.9.9"}
			if tc.setup != nil {
				tc.setup(f, &in)
			} else {
				h.listenErr = errors.New("permission denied")
			}
			res := remoteChecks(ctx, h, in)
			report := Report{Checks: res.checks}
			if report.OK() != tc.ok {
				t.Fatalf("ok = %t, checks %+v", report.OK(), res.checks)
			}
			if tc.ok {
				if res.disc == nil || res.role != cluster.JoinRoleWorker {
					t.Fatalf("result = %+v", res)
				}
				return
			}
			for _, c := range res.checks {
				if c.Name == tc.failName && c.Status == StatusFail {
					if !strings.Contains(c.Fix, tc.fixHas) {
						t.Fatalf("fix %q, want %q", c.Fix, tc.fixHas)
					}
					return
				}
			}
			t.Fatalf("no failed %q check in %+v", tc.failName, res.checks)
		})
	}
	// Another build than the cluster's is a warning, not a failure.
	f := newFakeJoinServer(t)
	res := remoteChecks(ctx, newFakeHost(), remoteInput{joinURL: f.url, token: f.token(cluster.JoinRoleWorker), version: "v1.0.0"})
	if !(Report{Checks: res.checks}).OK() || res.checks[1].Name != "version" || res.checks[1].Status != StatusWarn {
		t.Fatalf("version mismatch: %+v", res.checks)
	}
}

func TestPreflighterRun(t *testing.T) {
	ctx := context.Background()
	p := testPaths(t)
	f := newFakeJoinServer(t)
	pf := &Preflighter{Paths: p, Host: newFakeHost(), Version: "v9.9.9"}

	// Alone: the local checks, with a server's four ports.
	r, err := pf.Run(ctx, PreflightOptions{})
	if err != nil || !r.OK() || len(r.Checks) != 4 {
		t.Fatalf("local preflight = %+v %v", r, err)
	}
	// With --join: the local checks for the token's role, then the remote ones.
	r, err = pf.Run(ctx, PreflightOptions{JoinURL: f.url, Token: f.token(cluster.JoinRoleWorker), NodeID: "node-a"})
	if err != nil || !r.OK() {
		t.Fatalf("join preflight = %+v %v", r, err)
	}
	if !strings.Contains(r.Checks[3].Detail, "7001") || strings.Contains(r.Checks[3].Detail, "7000") {
		t.Fatalf("a worker's local ports: %+v", r.Checks[3])
	}
	// A node key on disk is sent, so the server can call a re-run a re-run.
	mustWrite(t, filepath.Join(p.TLSDir, "node.key"), string(mustKeyPEM(t)))
	if r, err := pf.Run(ctx, PreflightOptions{JoinURL: f.url, Token: f.token(cluster.JoinRoleServer), Role: "server"}); err != nil || !r.OK() {
		t.Fatalf("server preflight = %+v %v", r, err)
	}
	for _, bad := range []PreflightOptions{{Role: "boss"}, {JoinURL: "http://x", Token: "t"}} {
		if _, err := pf.Run(ctx, bad); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	mustWrite(t, p.ClusterEnv, "")
	if err := os.Chmod(p.ClusterEnv, 0); err == nil && os.Geteuid() != 0 {
		if _, err := pf.Run(ctx, PreflightOptions{}); err == nil {
			t.Fatal("an unreadable cluster.env passed")
		}
	}
}

func mustKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, pem, err := cluster.NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// discover and postJoin decode errors.
func TestDiscoverAndPostJoinEdges(t *testing.T) {
	ctx := context.Background()
	f := newFakeJoinServer(t)
	tok := f.token(cluster.JoinRoleWorker)
	// Unreadable JSON from cluster-info and from a join.
	garbage := newFakeJoinServer(t)
	garbage.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{not json")) })
	if _, err := discover(ctx, insecureClient(), garbage.url, tok, ""); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("garbage cluster-info = %v", err)
	}
	var out cluster.JoinResponse
	if err := postJoin(ctx, insecureClient(), garbage.url, cluster.JoinPath, struct{}{}, &out); err == nil {
		t.Fatal("garbage join answer decoded")
	}
	if err := postJoin(ctx, insecureClient(), f.url, cluster.JoinPath, make(chan int), &out); err == nil {
		t.Fatal("an unencodable body was sent")
	}
	if err := postJoin(ctx, insecureClient(), "https://127.0.0.1:1", cluster.JoinPath, struct{}{}, &out); err == nil {
		t.Fatal("an unreachable join port answered")
	}
	// A cluster-info whose CA is not a cert fails its own check.
	broken := newFakeJoinServer(t)
	broken.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		key, _ := cluster.JoinDiscoveryKey(tok)
		info := cluster.ClusterInfo{CACert: "not a cert", Version: "v1"}
		info.MAC = b64(cluster.JoinDiscoveryMAC(key, []byte(info.CACert)))
		info.InfoMAC = b64(cluster.JoinDiscoveryMAC(key, cluster.ClusterInfoSigningBytes(info)))
		_ = json.NewEncoder(w).Encode(info)
	})
	if _, err := discover(ctx, insecureClient(), broken.url, tok, ""); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("a non-cert CA = %v", err)
	}
	if shortHash("sha256:0123456789abcdef0123") == "sha256:0123456789abcdef0123" || shortHash("short") != "short" {
		t.Fatal("shortHash")
	}
}
