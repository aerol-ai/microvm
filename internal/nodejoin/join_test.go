package nodejoin

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// joinRig is one machine joining a fake cluster.
type joinRig struct {
	paths Paths
	host  *fakeHost
	srv   *fakeJoinServer
	api   *fakeLocalAPI
	out   bytes.Buffer
}

func newJoinRig(t *testing.T) *joinRig {
	t.Helper()
	r := &joinRig{paths: testPaths(t), host: newFakeHost(), srv: newFakeJoinServer(t), api: newFakeLocalAPI(t)}
	// sandboxd shows up as a member once it restarts.
	r.host.onRestart = func() { r.api.setMembers(localMember{NodeID: "node-a", Alive: true, Voter: true}) }
	return r
}

func (r *joinRig) joiner() *Joiner {
	return &Joiner{Paths: r.paths, Host: r.host, Version: "v9.9.9", Printer: Printer{Out: &r.out}, LocalAPI: r.api.srv.URL}
}

func (r *joinRig) run(t *testing.T, o JoinOptions) (JoinResult, error) {
	t.Helper()
	if o.URL == "" {
		o.URL = r.srv.url
	}
	if o.WaitTimeout == 0 {
		o.WaitTimeout = 2 * time.Second
	}
	return r.joiner().Run(context.Background(), o)
}

// clusterFiles are the files a join writes besides node.key.
func (r *joinRig) clusterFiles() []string {
	return []string{
		filepath.Join(r.paths.TLSDir, "ca.crt"), filepath.Join(r.paths.TLSDir, "node.crt"),
		r.paths.ClusterEnv, r.paths.DropIn, filepath.Join(r.paths.CADir, "ca.key"),
	}
}

func TestJoinWorker(t *testing.T) {
	r := newJoinRig(t)
	tok := r.srv.token(cluster.JoinRoleWorker)
	res, err := r.run(t, JoinOptions{Token: tok, CACertHash: cluster.CACertHash(r.srv.ca.Certificate())})
	if err != nil {
		t.Fatalf("join: %v\n%s", err, r.out.String())
	}
	if res.NodeID != "node-a" || res.Role != cluster.JoinRoleWorker || res.Replay {
		t.Fatalf("result = %+v", res)
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	for k, want := range map[string]string{
		"SB_ENABLE_CLUSTER": "true", "SB_CLUSTER_BOOTSTRAP": "false", "SB_NODE_ID": "node-a", "SB_NODE_ROLE": "worker",
		"SB_GOSSIP_SECRET_KEY": "Z29zc2lwLWtleS0xNi1ieXRlcw==", "SB_BOOTSTRAP_PEERS": "10.0.0.5:7001",
		"SB_API_ADVERTISE_URL": "http://10.0.0.9:21212", "SB_GOSSIP_ADVERTISE_ADDR": "10.0.0.9:7001",
		"SB_CLUSTER_INTERNAL_ADVERTISE": "https://10.0.0.9:7002", "SB_CLUSTER_TLS_DIR": r.paths.TLSDir,
		"SB_RAFT_DATA_DIR": r.paths.RaftDir, "SB_DATA_PLANE_ADVERTISE_HOST": "10.0.0.9",
	} {
		if env[k] != want {
			t.Fatalf("cluster.env %s = %q, want %q", k, env[k], want)
		}
	}
	if !strings.HasPrefix(readFile(t, r.paths.ClusterEnv), "# Managed by sandboxd init / sandboxd join") {
		t.Fatal("cluster.env has no header")
	}
	if readFile(t, r.paths.DropIn) != dropInBody {
		t.Fatal("drop-in differs from cluster-init.sh's")
	}
	// The cluster's PAT replaces install.sh's random one.
	if base, _ := readEnvFile(r.paths.EnvFile); base["SB_PAT_TOKEN"] != "cluster-pat" || base["SB_API_PORT"] != "21212" {
		t.Fatalf("sandboxd.env = %v", base)
	}
	// The server key, as cluster-join.sh installs it from the bundle.
	keyPath := env["SB_CREDENTIAL_ENCRYPTION_KEY_PATH"]
	if keyPath == "" || !exists(keyPath) || env["SB_CREDENTIAL_ENCRYPTION_KEY"] == "" {
		t.Fatalf("server key not installed: %v", env)
	}
	// A worker never holds the CA key.
	if exists(filepath.Join(r.paths.CADir, "ca.key")) {
		t.Fatal("a worker got the CA key")
	}
	if st, _ := os.Stat(nodeKeyFile(r.paths.TLSDir)); st.Mode().Perm() != 0o600 {
		t.Fatalf("node.key mode %v", st.Mode().Perm())
	}
	if r.host.restarts != 1 || r.host.reloads != 1 {
		t.Fatalf("restarts %d reloads %d", r.host.restarts, r.host.reloads)
	}
	// The member wait used the cluster's PAT.
	if r.api.auth[len(r.api.auth)-1] != "Bearer cluster-pat" {
		t.Fatalf("auth = %v", r.api.auth)
	}

	// A re-run: same key, so the server answers replay; every file is the
	// same, so sandboxd is not restarted.
	before := readFile(t, r.paths.ClusterEnv)
	res, err = r.run(t, JoinOptions{Token: tok})
	if err != nil || !res.Replay {
		t.Fatalf("re-run = %+v %v\n%s", res, err, r.out.String())
	}
	if readFile(t, r.paths.ClusterEnv) != before || r.host.restarts != 1 {
		t.Fatalf("re-run changed files or restarted (restarts %d)", r.host.restarts)
	}
	if !strings.Contains(r.out.String(), "already joined; nothing changed") {
		t.Fatalf("output:\n%s", r.out.String())
	}
}

func TestJoinServerGetsTheCAKeyAndKeepsAppendedSettings(t *testing.T) {
	r := newJoinRig(t)
	// Terraform appends its ops block to cluster.env after a join; a later
	// re-run must keep it. Simulate one already there.
	r.host.onRestart = func() { r.api.setMembers(localMember{NodeID: "srv-2", Alive: true, Voter: false}) }
	res, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleServer), NodeID: "srv-2", Advertise: "10.1.1.1",
		Address: AddressOptions{NodeRole: "mixed", IngressAdvertiseHost: "api.example.com"}})
	if err != nil {
		t.Fatalf("join: %v\n%s", err, r.out.String())
	}
	if res.Role != cluster.JoinRoleServer || res.Voter {
		t.Fatalf("result = %+v", res)
	}
	ca, err := cluster.LoadClusterCA(r.paths.CADir)
	if err != nil || ca == nil {
		t.Fatalf("CA store = %v %v", ca, err)
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	if env["SB_NODE_ROLE"] != "mixed" || env["SB_INGRESS_ADVERTISE_HOST"] != "api.example.com" || env["SB_RAFT_ADVERTISE_ADDR"] != "10.1.1.1:7000" {
		t.Fatalf("cluster.env = %v", env)
	}
	if !strings.Contains(r.out.String(), "not a Raft voter yet") {
		t.Fatalf("output:\n%s", r.out.String())
	}
}

func TestJoinStopsBeforeWritingWhenACheckFails(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*joinRig)
		opts  JoinOptions
	}{
		{"a blocked port", func(r *joinRig) { r.srv.dialFail = true }, JoinOptions{}},
		{"a taken node ID", func(r *joinRig) { r.srv.inUse["node-a"] = true }, JoinOptions{}},
		{"the wrong CA", func(*joinRig) {}, JoinOptions{CACertHash: "sha256:00"}},
		{"too little disk", func(r *joinRig) { r.host.free = 1 << 20 }, JoinOptions{}},
		{"a role the token can't give", func(*joinRig) {}, JoinOptions{Address: AddressOptions{NodeRole: "server"}}},
		{"another cluster's Raft data", func(r *joinRig) { mustWrite(t, filepath.Join(r.paths.RaftDir, "raft.db"), "x") }, JoinOptions{}},
		{"wrapped custody without a key store", func(r *joinRig) {
			mustWrite(t, r.paths.EnvFile, readFile(t, r.paths.EnvFile)+"SB_CREDENTIAL_KEY_CUSTODY=wrapped\n")
		}, JoinOptions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newJoinRig(t)
			tc.setup(r)
			o := tc.opts
			o.Token = r.srv.token(cluster.JoinRoleWorker)
			if _, err := r.run(t, o); !errors.Is(err, ErrPreflight) {
				t.Fatalf("join = %v, want ErrPreflight\n%s", err, r.out.String())
			}
			for _, f := range append(r.clusterFiles(), nodeKeyFile(r.paths.TLSDir)) {
				if exists(f) {
					t.Fatalf("%s was written", f)
				}
			}
			if r.srv.joins != 0 || r.host.restarts != 0 {
				t.Fatalf("joins %d restarts %d", r.srv.joins, r.host.restarts)
			}
			if !strings.Contains(r.out.String(), "fix ") {
				t.Fatalf("no fix printed:\n%s", r.out.String())
			}
		})
	}
}

func TestJoinRefusedKeepsOnlyTheKey(t *testing.T) {
	cases := []struct {
		reason string
		status int
		fixHas string
	}{
		{"key_revoked", 403, "sandboxd reset --yes"},
		{"token_used", 403, "aerolvm join-command"},
		{"version", 412, "install the version"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			r := newJoinRig(t)
			r.srv.refuse[cluster.JoinPath] = joinRefuseSpec{tc.status, tc.reason}
			_, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleWorker)})
			var refusal *JoinRefusal
			if !errors.As(err, &refusal) || refusal.Reason != tc.reason {
				t.Fatalf("join = %v", err)
			}
			if !strings.Contains(r.out.String(), tc.fixHas) {
				t.Fatalf("output:\n%s", r.out.String())
			}
			if !exists(nodeKeyFile(r.paths.TLSDir)) {
				t.Fatal("the node key is gone; a re-run could not replay")
			}
			for _, f := range r.clusterFiles() {
				if exists(f) {
					t.Fatalf("%s was written", f)
				}
			}
		})
	}
	// A dial-back refusal at join time names the port.
	r := newJoinRig(t)
	tok := r.srv.token(cluster.JoinRoleWorker)
	r.srv.refuse[cluster.JoinPath] = joinRefuseSpec{412, "dial_back"}
	if _, err := r.run(t, JoinOptions{Token: tok}); err == nil || !strings.Contains(r.out.String(), portFix) {
		t.Fatalf("dial-back refusal = %v\n%s", err, r.out.String())
	}
}

func TestJoinRestartFailureRollsBack(t *testing.T) {
	for _, which := range []string{"reload", "restart"} {
		t.Run(which, func(t *testing.T) {
			r := newJoinRig(t)
			if which == "reload" {
				r.host.reloadErr = errors.New("reload failed")
			} else {
				r.host.restartErr = errors.New("job failed")
			}
			before := readFile(t, r.paths.EnvFile)
			if _, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleServer)}); err == nil {
				t.Fatal("join passed a failed restart")
			}
			for _, f := range r.clusterFiles() {
				if exists(f) {
					t.Fatalf("%s survived the rollback", f)
				}
			}
			if readFile(t, r.paths.EnvFile) != before {
				t.Fatal("sandboxd.env (the PAT) was not put back")
			}
			if !exists(nodeKeyFile(r.paths.TLSDir)) || !strings.Contains(r.out.String(), "put every file back") {
				t.Fatalf("output:\n%s", r.out.String())
			}
		})
	}
}

func TestJoinWrappedCustody(t *testing.T) {
	r := newJoinRig(t)
	mustWrite(t, r.paths.EnvFile, readFile(t, r.paths.EnvFile)+"SB_CREDENTIAL_KEY_CUSTODY=wrapped\nSB_SECRET_PROVIDER=awskms\n")
	base, _ := readEnvFile(r.paths.EnvFile)
	plain := base["SB_CREDENTIAL_ENCRYPTION_KEY_PATH"]
	mustWrite(t, plain, "this node's own key\n")
	r.srv.custody = cluster.JoinCredentials{Custody: "wrapped", Wrapped: base64.StdEncoding.EncodeToString([]byte("ciphertext"))}
	if _, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleWorker)}); err != nil {
		t.Fatalf("join: %v\n%s", err, r.out.String())
	}
	if exists(plain) {
		t.Fatal("the plaintext key is still there; the daemon would refuse wrapped custody")
	}
	if readFile(t, base["SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH"]) != "ciphertext" {
		t.Fatal("the wrapped key was not written")
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	if env["SB_CREDENTIAL_KEY_CUSTODY"] != "wrapped" || env["SB_CREDENTIAL_ENCRYPTION_KEY"] != "" {
		t.Fatalf("cluster.env = %v", env)
	}
}

func TestJoinCredentialEdges(t *testing.T) {
	cases := []struct {
		name  string
		creds cluster.JoinCredentials
		ok    bool
	}{
		{"no key sent (warned, joined)", cluster.JoinCredentials{Custody: "file"}, true},
		{"a key ring too", cluster.JoinCredentials{Custody: "file", Key: b64([]byte(b64(make([]byte, 32)))), KeyRing: b64([]byte("ring"))}, true},
		{"a key that is not base64", cluster.JoinCredentials{Custody: "file", Key: "%%%"}, false},
		{"a key of the wrong size", cluster.JoinCredentials{Custody: "file", Key: b64([]byte(b64(make([]byte, 8))))}, false},
		{"a ring that is not base64", cluster.JoinCredentials{Custody: "file", Key: b64([]byte(b64(make([]byte, 32)))), KeyRing: "%%%"}, false},
		{"wrapped with no blob", cluster.JoinCredentials{Custody: "wrapped"}, false},
		{"wrapped with no key store here", cluster.JoinCredentials{Custody: "wrapped", Wrapped: b64([]byte("c"))}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newJoinRig(t)
			r.srv.custody = tc.creds
			_, err := r.run(t, JoinOptions{Token: r.srv.token(cluster.JoinRoleWorker)})
			if (err == nil) != tc.ok {
				t.Fatalf("join = %v\n%s", err, r.out.String())
			}
			if !tc.ok && exists(r.paths.ClusterEnv) {
				t.Fatal("a refused answer left cluster.env behind")
			}
		})
	}
}

func TestJoinArgumentsAndMachine(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*joinRig, *JoinOptions)
		has   string
	}{
		{"not root", func(r *joinRig, _ *JoinOptions) { r.host.notRoot = true }, "as root"},
		{"not installed", func(r *joinRig, _ *JoinOptions) { _ = os.Remove(r.paths.EnvFile) }, "install AerolVM first"},
		{"a bad URL", func(_ *joinRig, o *JoinOptions) { o.URL = "http://x" }, "must be https"},
		{"a bad token", func(_ *joinRig, o *JoinOptions) { o.Token = "nope" }, "join token must look like"},
		{"a bad node ID", func(_ *joinRig, o *JoinOptions) { o.NodeID = "-bad" }, "node ID"},
		{"no host name", func(r *joinRig, _ *JoinOptions) { r.host.hostname = "" }, "--node-id"},
		{"a bad advertise", func(_ *joinRig, o *JoinOptions) { o.Advertise = "nope" }, "not an IP"},
		{"no address", func(r *joinRig, _ *JoinOptions) { r.host.ip = "" }, "--advertise"},
		{"address lookup fails", func(r *joinRig, _ *JoinOptions) { r.host.ipErr = errors.New("no route") }, "no route"},
		{"an unreadable node key", func(r *joinRig, _ *JoinOptions) { mustWrite(t, nodeKeyFile(r.paths.TLSDir), "garbage") }, "no PEM private key"},
		{"never a member", func(r *joinRig, _ *JoinOptions) { r.host.onRestart = nil }, "did not show up as a member"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newJoinRig(t)
			o := JoinOptions{Token: r.srv.token(cluster.JoinRoleWorker), WaitTimeout: 50 * time.Millisecond}
			tc.setup(r, &o)
			if _, err := r.run(t, o); err == nil || !strings.Contains(err.Error(), tc.has) {
				t.Fatalf("join = %v, want %q", err, tc.has)
			}
		})
	}
}
