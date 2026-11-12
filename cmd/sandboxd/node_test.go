package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/nodejoin"
)

// nodeCLIHost is a machine for the node command tests: never root unless
// asked, listeners on loopback only.
type nodeCLIHost struct{ root bool }

func (h nodeCLIHost) IsRoot() bool                        { return h.root }
func (nodeCLIHost) DaemonReload(context.Context) error    { return nil }
func (nodeCLIHost) RestartSandboxd(context.Context) error { return nil }
func (nodeCLIHost) StopSandboxd(context.Context) error    { return nil }
func (nodeCLIHost) Listen(string) (net.Listener, error)   { return net.Listen("tcp", "127.0.0.1:0") }
func (nodeCLIHost) FreeBytes(string) (uint64, error)      { return 100 << 30, nil }
func (nodeCLIHost) PrimaryIP() (string, error)            { return "10.0.0.9", nil }
func (nodeCLIHost) Hostname() (string, error)             { return "node-a", nil }
func (nodeCLIHost) Now() time.Time                        { return time.Now() }

// withNodeSeams points the node commands at a temp machine.
func withNodeSeams(t *testing.T, root bool) nodejoin.Paths {
	t.Helper()
	dir := t.TempDir()
	p := nodejoin.Paths{
		EnvFile: filepath.Join(dir, "sandboxd.env"), ClusterEnv: filepath.Join(dir, "cluster.env"),
		DropIn: filepath.Join(dir, "cluster.conf"), TLSDir: filepath.Join(dir, "tls"), CADir: filepath.Join(dir, "ca"),
		RaftDir: filepath.Join(dir, "raft"), StateDir: dir, AdminContext: filepath.Join(dir, "admin-context.json"),
		CgroupRoot: dir, KVMDevice: filepath.Join(dir, "kvm"),
		OSRelease: filepath.Join(dir, "osrelease"), BridgeNF: filepath.Join(dir, "bridge-nf-call-iptables"),
	}
	if err := os.WriteFile(p.EnvFile, []byte("SB_PAT_TOKEN=p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origPaths, origHost, origAPI, origKey := nodePaths, newNodeHost, nodeLocalAPI, nodeKeyTool
	t.Cleanup(func() { nodePaths, newNodeHost, nodeLocalAPI, nodeKeyTool = origPaths, origHost, origAPI, origKey })
	nodePaths = func() nodejoin.Paths { return p }
	newNodeHost = func() nodejoin.Host { return nodeCLIHost{root: root} }
	nodeLocalAPI = "http://127.0.0.1:1"
	return p
}

func runNode(cmd string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := runNodeCLI(cmd, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestNodeCommandsUsage(t *testing.T) {
	withNodeSeams(t, true)
	for _, cmd := range []string{"init", "join", "preflight", "adopt", "reset", "join-command"} {
		if !isNodeCommand(cmd) {
			t.Fatalf("%s is not a node command", cmd)
		}
		if code, out, _ := runNode(cmd, "--help"); code != 0 || !strings.Contains(out, "usage: ") {
			t.Fatalf("%s --help = %d %q", cmd, code, out)
		}
		if code, _, errOut := runNode(cmd, "--no-such-flag"); code != 2 || !strings.Contains(errOut, "usage: ") {
			t.Fatalf("%s with a bad flag = %d %q", cmd, code, errOut)
		}
	}
	if isNodeCommand("upgrade") || isNodeCommand("") {
		t.Fatal("isNodeCommand too wide")
	}
	cases := []struct {
		cmd  string
		args []string
		has  string
	}{
		{"join", nil, "missing the join URL"},
		{"join", []string{"https://10.0.0.5:7003"}, "--token is required"},
		{"join", []string{"a", "b", "--token", "x"}, "unexpected argument"},
		{"init", []string{"extra"}, "unexpected argument"},
		{"init", []string{"--token", "boss=abc"}, "role must be server, worker or ingress"},
		{"preflight", []string{"-o", "yaml"}, "-o must be text or json"},
		{"preflight", []string{"--join", "https://x"}, "--join and --token go together"},
		{"preflight", []string{"--role", "boss"}, "--role must be server, worker or ingress"},
		{"preflight", []string{"--kvm"}, "--kvm goes with --pod"},
		{"preflight", []string{"--pod", "--join", "https://x", "--token", "t"}, "leave out --join"},
		{"reset", nil, "run it again with --yes"},
		{"join-command", []string{"extra"}, "unexpected argument"},
	}
	for _, tc := range cases {
		if code, _, errOut := runNode(tc.cmd, tc.args...); code != 2 || !strings.Contains(errOut, tc.has) {
			t.Fatalf("%s %v = %d %q, want %q", tc.cmd, tc.args, code, errOut, tc.has)
		}
	}
}

func TestNodeCommandsRun(t *testing.T) {
	p := withNodeSeams(t, true)
	// preflight alone: local checks pass on this temp machine.
	if err := os.WriteFile(filepath.Join(p.CgroupRoot, "cgroup.controllers"), []byte("cpu\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runNode("preflight")
	if code != 0 || !strings.Contains(out, "CHECK") {
		t.Fatalf("preflight = %d\n%s%s", code, out, errOut)
	}
	code, out, _ = runNode("preflight", "-o", "json")
	var report struct {
		OK bool `json:"ok"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &report) != nil || !report.OK {
		t.Fatalf("preflight -o json = %d %s", code, out)
	}
	// --pod: the worker pod's checks. This machine has cgroup v2 but no
	// kernel version file and no br_netfilter: exit 1, one summary line last.
	code, out, _ = runNode("preflight", "--pod")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if last := lines[len(lines)-1]; code != 1 || !strings.HasPrefix(last, "preflight failed: kernel: ") || !strings.Contains(last, "br_netfilter: ") {
		t.Fatalf("preflight --pod = %d\n%s", code, out)
	}
	if err := os.WriteFile(p.OSRelease, []byte("6.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.BridgeNF, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ = runNode("preflight", "--pod"); code != 0 || strings.Contains(out, "preflight failed") {
		t.Fatalf("preflight --pod on a good machine = %d\n%s", code, out)
	}
	if code, out, _ = runNode("preflight", "--pod", "--kvm", "-o", "json"); code != 1 || !strings.Contains(out, `"ok": false`) {
		t.Fatalf("preflight --pod --kvm with no /dev/kvm = %d\n%s", code, out)
	}
	// A join server that isn't there fails the check: exit 1.
	tok, _ := cluster.GenerateJoinToken()
	if code, out, _ := runNode("preflight", "--join", "https://127.0.0.1:1", "--token", tok); code != 1 || !strings.Contains(out, "fix join server") {
		t.Fatalf("preflight against nothing = %d\n%s", code, out)
	}
	if code, _, errOut := runNode("join", "https://127.0.0.1:1", "--token", tok); code != 1 || !strings.Contains(errOut, "preflight failed") {
		t.Fatalf("join against nothing = %d %s", code, errOut)
	}
	// reset with nothing to reset, adopt off-cluster.
	if code, out, _ := runNode("reset", "--yes"); code != 0 || !strings.Contains(out, "nothing to reset") {
		t.Fatalf("reset = %d %s", code, out)
	}
	if code, _, errOut := runNode("adopt"); code != 1 || !strings.Contains(errOut, "not in a cluster") {
		t.Fatalf("adopt = %d %s", code, errOut)
	}
	// init: a key tool call reaches sandboxd key.
	keyCalls := 0
	nodeKeyTool = func(context.Context, []string, io.Writer) error { keyCalls++; return nil }
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) }))
	defer api.Close()
	nodeLocalAPI = api.URL
	if err := os.WriteFile(p.EnvFile, []byte("SB_PAT_TOKEN=p\nSB_SECRET_PROVIDER=awskms\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runNode("init", "--key-custody", "wrapped", "--wait-timeout", "50ms")
	if code != 1 || keyCalls != 1 || !strings.Contains(errOut, "did not take the lead") {
		t.Fatalf("init = %d keyCalls %d %s", code, keyCalls, errOut)
	}
}

func TestNodeCommandsNeedRoot(t *testing.T) {
	withNodeSeams(t, false)
	tok, _ := cluster.GenerateJoinToken()
	for _, c := range [][]string{{"init"}, {"join", "https://x", "--token", tok}, {"adopt"}, {"reset", "--yes"}, {"join-command"}} {
		if code, _, errOut := runNode(c[0], c[1:]...); code != 1 || !strings.Contains(errOut, "as root") {
			t.Fatalf("%v = %d %s", c, code, errOut)
		}
	}
}

func TestMainDispatchesNodeCommands(t *testing.T) {
	withNodeSeams(t, true)
	origArgs, origExit := os.Args, osExit
	t.Cleanup(func() { os.Args, osExit = origArgs, origExit })
	got := -1
	osExit = func(code int) { got = code }
	os.Args = []string{"sandboxd", "reset"}
	main()
	if got != 2 {
		t.Fatalf("sandboxd reset exit = %d, want 2", got)
	}
}

// TestNodeJoinCommand: sandboxd join-command on a server prints only the
// join line (or, with --json, the token and the line) on stdout, and the
// note about the token on stderr; off a cluster it fails.
func TestNodeJoinCommand(t *testing.T) {
	p := withNodeSeams(t, true)
	if code, _, errOut := runNode("join-command"); code != 1 || !strings.Contains(errOut, "not in a cluster") {
		t.Fatalf("join-command off-cluster = %d %s", code, errOut)
	}
	if err := os.WriteFile(p.ClusterEnv, []byte("SB_ENABLE_CLUSTER=true\nSB_NODE_ID=srv-1\nSB_NODE_ROLE=server\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var asked []cluster.JoinTokenCreateRequest
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req cluster.JoinTokenCreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		asked = append(asked, req)
		if r.Header.Get("Authorization") != "Bearer p" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(cluster.JoinTokenCreated{Token: "abcdef.0123456789abcdefghijklmnopqrstuv", ID: "abcdef", Role: req.Role,
			CACertHash: "sha256:ff", JoinURLs: []string{"https://10.0.0.5:7003"}})
	}))
	defer api.Close()
	nodeLocalAPI = api.URL

	code, out, errOut := runNode("join-command", "--role", "server", "--ttl", "2h")
	want := "curl -fsSL https://aerolvm.aerol.ai | sudo bash -s -- join https://10.0.0.5:7003 --token abcdef.0123456789abcdefghijklmnopqrstuv --ca-cert-hash sha256:ff\n"
	if code != 0 || out != want {
		t.Fatalf("join-command = %d %q (stderr %q)", code, out, errOut)
	}
	if !strings.Contains(errOut, "server token abcdef never expires") || len(asked) != 1 || asked[0].Role != "server" || asked[0].TTL != "2h" {
		t.Fatalf("stderr %q, asked %+v", errOut, asked)
	}
	code, out, _ = runNode("join-command", "--role", "server", "--json")
	var res struct {
		Token   string `json:"token"`
		Role    string `json:"role"`
		Command string `json:"command"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.Token != "abcdef.0123456789abcdefghijklmnopqrstuv" || res.Role != "server" || !strings.HasPrefix(res.Command, "curl -fsSL ") {
		t.Fatalf("join-command --json = %d %s", code, out)
	}
}

// F14: --files-only reaches init and join, and lets a user that is not root
// write a node's files (a Kubernetes init container).
func TestNodeCommandsFilesOnly(t *testing.T) {
	p := withNodeSeams(t, false)
	if err := os.WriteFile(filepath.Join(p.CgroupRoot, "cgroup.controllers"), []byte("cpu\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The server key goes where sandboxd.env says, as in a pod's volume.
	env := "SB_PAT_TOKEN=p\nSB_CREDENTIAL_ENCRYPTION_KEY_PATH=" + filepath.Join(p.StateDir, "credential_encryption.key") + "\n"
	if err := os.WriteFile(p.EnvFile, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runNode("init", "--files-only")
	if code != 0 || !strings.Contains(out, "files written (--files-only)") {
		t.Fatalf("init --files-only = %d\nout: %q\nerr: %q", code, out, errOut)
	}
	if _, err := os.Stat(p.DropIn); err == nil {
		t.Fatal("init --files-only wrote the systemd drop-in")
	}
	// join reads the flag too; with no join server it stops at preflight,
	// past the root check.
	tok, _ := cluster.GenerateJoinToken()
	if code, _, errOut := runNode("join", "https://127.0.0.1:1", "--token", tok, "--files-only"); code != 1 || !strings.Contains(errOut, "preflight failed") {
		t.Fatalf("join --files-only against nothing = %d %s", code, errOut)
	}
}
