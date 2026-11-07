package nodejoin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

type initRig struct {
	paths    Paths
	host     *fakeHost
	api      *fakeLocalAPI
	out      bytes.Buffer
	keyCalls [][]string
	keyErr   error
}

func newInitRig(t *testing.T) *initRig {
	t.Helper()
	r := &initRig{paths: testPaths(t), host: newFakeHost(), api: newFakeLocalAPI(t)}
	r.host.onRestart = func() {
		r.api.mu.Lock()
		r.api.leader = "node-a"
		r.api.mu.Unlock()
	}
	return r
}

func (r *initRig) run(t *testing.T, o InitOptions) (InitResult, error) {
	t.Helper()
	if o.WaitTimeout == 0 {
		o.WaitTimeout = 2 * time.Second
	}
	in := &Initer{Paths: r.paths, Host: r.host, Version: "v9.9.9", Printer: Printer{Out: &r.out}, LocalAPI: r.api.srv.URL,
		KeyTool: func(_ context.Context, args []string) error {
			r.keyCalls = append(r.keyCalls, args)
			if r.keyErr == nil && len(args) > 0 && args[0] == "wrap" {
				base, _ := readEnvFile(r.paths.EnvFile)
				mustWrite(t, base["SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH"], "wrapped")
			}
			return r.keyErr
		}}
	return in.Run(context.Background(), o)
}

func TestInitStartsACluster(t *testing.T) {
	r := newInitRig(t)
	worker, _ := cluster.GenerateJoinToken()
	server, _ := cluster.GenerateJoinToken()
	res, err := r.run(t, InitOptions{Tokens: []TokenSpec{{Role: "worker", Token: worker, TTL: "0"}, {Role: "server", Token: server, TTL: "24h"}}})
	if err != nil {
		t.Fatalf("init: %v\n%s", err, r.out.String())
	}
	ca, err := cluster.LoadClusterCA(r.paths.CADir)
	if err != nil || ca == nil || res.ClusterID != cluster.CACertHash(ca.Certificate()) {
		t.Fatalf("CA store = %v %v, result %+v", ca, err, res)
	}
	// The seed's cert: signed by that CA, for this node, as a server.
	key, _, err := loadNodeKey(r.paths.TLSDir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := checkNodeCert([]byte(readFile(t, filepath.Join(r.paths.TLSDir, "node.crt"))), ca.Certificate(), "node-a", key)
	if err != nil || cluster.ExtractPeerRole(leaf) != cluster.JoinRoleServer || leaf.NotAfter.Sub(leaf.NotBefore) < 89*24*time.Hour {
		t.Fatalf("seed cert = %v, %v", leaf, err)
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	for k, want := range map[string]string{
		"SB_ENABLE_CLUSTER": "true", "SB_CLUSTER_BOOTSTRAP": "true", "SB_NODE_ID": "node-a",
		"SB_RAFT_ADVERTISE_ADDR": "10.0.0.9:7000", "SB_CLUSTER_MAX_AUTO_VOTERS": "5",
	} {
		if env[k] != want {
			t.Fatalf("cluster.env %s = %q, want %q", k, env[k], want)
		}
	}
	if checkGossipKey(env["SB_GOSSIP_SECRET_KEY"]) != nil || env["SB_CREDENTIAL_ENCRYPTION_KEY"] == "" || env["SB_NODE_ROLE"] != "" {
		t.Fatalf("cluster.env = %v", env)
	}
	// Adopt admitted the seed; the tokens were registered as given, reusable.
	if len(r.api.adopts) != 1 || len(r.api.tokens) != 2 || r.api.tokens[0].Token != worker || !r.api.tokens[0].Reusable || r.api.tokens[1].TTL != "24h" {
		t.Fatalf("adopts %v tokens %+v", r.api.adopts, r.api.tokens)
	}
	// admin-context.json: 0600, the shape aerolvm config import reads.
	st, err := os.Stat(r.paths.AdminContext)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("admin context = %v %v", st, err)
	}
	var adm adminContext
	if err := json.Unmarshal([]byte(readFile(t, r.paths.AdminContext)), &adm); err != nil || adm.Token != "node-pat" || adm.APIURL != "http://203.0.113.9:21212" {
		t.Fatalf("admin context = %+v %v", adm, err)
	}
	out := r.out.String()
	for _, want := range []string{
		"join https://10.0.0.9:7003 --token " + worker + " --ca-cert-hash " + res.ClusterID,
		"never expires", "aerolvm config import admin-context.json", "aerolvm login http://203.0.113.9:21212",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "node-pat") {
		t.Fatal("init printed the PAT")
	}

	// A re-run changes no file and no key, and registers the same tokens.
	certBefore := readFile(t, filepath.Join(r.paths.TLSDir, "node.crt"))
	res2, err := r.run(t, InitOptions{Tokens: []TokenSpec{{Role: "worker", Token: worker, TTL: "0"}}})
	if err != nil || !res2.Again || res2.ClusterID != res.ClusterID {
		t.Fatalf("re-run = %+v %v\n%s", res2, err, r.out.String())
	}
	if readFile(t, filepath.Join(r.paths.TLSDir, "node.crt")) != certBefore || r.host.restarts != 1 {
		t.Fatalf("re-run rewrote the cert or restarted (restarts %d)", r.host.restarts)
	}
}

func TestInitDefaultsAndDomain(t *testing.T) {
	r := newInitRig(t)
	mustWrite(t, r.paths.EnvFile, readFile(t, r.paths.EnvFile)+"SB_DOMAIN=api.example.com\nSB_CLUSTER_NODE_CERT_TTL=10m\n")
	res, err := r.run(t, InitOptions{Address: AddressOptions{NodeRole: "server"}, InstallerURL: "https://mirror.example/install.sh",
		GossipKey: b64(make([]byte, 16))})
	if err != nil {
		t.Fatalf("init: %v\n%s", err, r.out.String())
	}
	// With no --token, init makes one reusable worker token with the default TTL.
	if len(r.api.tokens) != 1 || r.api.tokens[0].Role != "worker" || r.api.tokens[0].Token != "" || !r.api.tokens[0].Reusable {
		t.Fatalf("tokens = %+v", r.api.tokens)
	}
	if res.APIURL != "https://api.example.com" || !strings.Contains(r.out.String(), "curl -fsSL https://mirror.example/install.sh | sudo bash -s -- join") {
		t.Fatalf("result %+v\n%s", res, r.out.String())
	}
	env, _ := readEnvFile(r.paths.ClusterEnv)
	if env["SB_NODE_ROLE"] != "server" || env["SB_GOSSIP_SECRET_KEY"] != b64(make([]byte, 16)) {
		t.Fatalf("cluster.env = %v", env)
	}
	// SB_CLUSTER_NODE_CERT_TTL sets the seed's cert life too.
	leaf, _ := firstCert([]byte(readFile(t, filepath.Join(r.paths.TLSDir, "node.crt"))))
	if life := leaf.NotAfter.Sub(leaf.NotBefore); life > 20*time.Minute {
		t.Fatalf("seed cert life %s, want about 10m", life)
	}
}

func TestInitWrappedCustody(t *testing.T) {
	cases := []struct {
		name     string
		wrapped  bool
		plain    bool
		wantCall string
		keyErr   error
	}{
		{"generate a new wrapped key", false, false, "wrap --generate --seed", nil},
		{"wrap install.sh's plaintext key", false, true, "wrap", nil},
		{"verify an existing wrapped key", true, false, "verify", nil},
		{"the key store fails", false, false, "wrap --generate --seed", errors.New("kms: access denied")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newInitRig(t)
			r.keyErr = tc.keyErr
			mustWrite(t, r.paths.EnvFile, readFile(t, r.paths.EnvFile)+"SB_SECRET_PROVIDER=awskms\n")
			base, _ := readEnvFile(r.paths.EnvFile)
			if tc.wrapped {
				mustWrite(t, base["SB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH"], "wrapped")
			}
			if tc.plain {
				mustWrite(t, base["SB_CREDENTIAL_ENCRYPTION_KEY_PATH"], b64(make([]byte, 32))+"\n")
			}
			_, err := r.run(t, InitOptions{KeyCustody: "wrapped"})
			if (err != nil) != (tc.keyErr != nil) {
				t.Fatalf("init = %v\n%s", err, r.out.String())
			}
			if len(r.keyCalls) != 1 || strings.Join(r.keyCalls[0], " ") != tc.wantCall {
				t.Fatalf("key tool calls = %v", r.keyCalls)
			}
			if tc.keyErr != nil {
				if exists(r.paths.ClusterEnv) || exists(filepath.Join(r.paths.CADir, "ca.key")) {
					t.Fatal("a failed init left files behind")
				}
				return
			}
			if tc.plain && exists(base["SB_CREDENTIAL_ENCRYPTION_KEY_PATH"]) {
				t.Fatal("the plaintext key is still there after wrapping")
			}
			env, _ := readEnvFile(r.paths.ClusterEnv)
			if env["SB_CREDENTIAL_KEY_CUSTODY"] != "wrapped" || env["SB_CREDENTIAL_ENCRYPTION_KEY"] != "" {
				t.Fatalf("cluster.env = %v", env)
			}
		})
	}
	// Wrapped custody with no key store is refused before any file.
	r := newInitRig(t)
	if _, err := r.run(t, InitOptions{KeyCustody: "wrapped"}); err == nil || exists(r.paths.ClusterEnv) {
		t.Fatalf("wrapped without a key store = %v", err)
	}
}

func TestInitRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*initRig, *InitOptions)
		has   string
	}{
		{"not root", func(r *initRig, _ *InitOptions) { r.host.notRoot = true }, "as root"},
		{"not installed", func(r *initRig, _ *InitOptions) { _ = os.Remove(r.paths.EnvFile) }, "install AerolVM first"},
		{"a worker role", func(_ *initRig, o *InitOptions) { o.Address.NodeRole = "worker" }, "must include server"},
		{"a bogus role", func(_ *initRig, o *InitOptions) { o.Address.NodeRole = "boss" }, "server, worker or ingress"},
		{"a bogus custody", func(_ *initRig, o *InitOptions) { o.KeyCustody = "hsm" }, "file or wrapped"},
		{"a bad gossip key", func(_ *initRig, o *InitOptions) { o.GossipKey = "short" }, "--gossip-key"},
		{"a bad node ID", func(_ *initRig, o *InitOptions) { o.NodeID = "a b" }, "node ID"},
		{"a bad advertise", func(_ *initRig, o *InitOptions) { o.Advertise = "x" }, "not an IP"},
		{"another cluster's Raft data", func(r *initRig, _ *InitOptions) {
			mustWrite(t, filepath.Join(r.paths.RaftDir, "raft.db"), "x")
		}, ErrPreflight.Error()},
		{"a held port", func(r *initRig, _ *InitOptions) { r.host.held[7003] = true }, ErrPreflight.Error()},
		{"never leads", func(r *initRig, o *InitOptions) { r.host.onRestart = nil; o.WaitTimeout = 50 * time.Millisecond }, "did not take the lead"},
		{"adopt fails", func(r *initRig, _ *InitOptions) { r.api.adoptErr = "cluster: no raft" }, "record this node as admitted"},
		{"token refused", func(r *initRig, _ *InitOptions) { r.api.tokenErr = 409 }, "register the worker join token"},
		{"a bad server-key file", func(r *initRig, _ *InitOptions) {
			base, _ := readEnvFile(r.paths.EnvFile)
			mustWrite(t, base["SB_CREDENTIAL_ENCRYPTION_KEY_PATH"], "short\n")
		}, "not base64 of 32 bytes"},
		{"restart fails", func(r *initRig, _ *InitOptions) { r.host.restartErr = errors.New("job failed") }, "job failed"},
		{"reload fails", func(r *initRig, _ *InitOptions) { r.host.reloadErr = errors.New("reload failed") }, "reload failed"},
		{"no PAT for the admin login", func(r *initRig, _ *InitOptions) {
			mustWrite(t, r.paths.EnvFile, strings.Replace(readFile(t, r.paths.EnvFile), "SB_PAT_TOKEN=node-pat\n", "", 1))
		}, "no SB_PAT_TOKEN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newInitRig(t)
			var o InitOptions
			tc.setup(r, &o)
			if _, err := r.run(t, o); err == nil || !strings.Contains(err.Error(), tc.has) {
				t.Fatalf("init = %v, want %q\n%s", err, tc.has, r.out.String())
			}
		})
	}
	// A failed restart puts every file back.
	r := newInitRig(t)
	r.host.restartErr = errors.New("job failed")
	_, _ = r.run(t, InitOptions{})
	for _, f := range []string{r.paths.ClusterEnv, r.paths.DropIn, filepath.Join(r.paths.CADir, "ca.key"), filepath.Join(r.paths.TLSDir, "node.crt")} {
		if exists(f) {
			t.Fatalf("%s survived the rollback", f)
		}
	}
}

func TestParseTokenSpec(t *testing.T) {
	tok, _ := cluster.GenerateJoinToken()
	cases := []struct {
		in   string
		want TokenSpec
		ok   bool
	}{
		{"worker=" + tok + ":0", TokenSpec{Role: "worker", Token: tok, TTL: "0"}, true},
		{"Ingress=" + tok, TokenSpec{Role: "ingress", Token: tok}, true},
		{"server=" + tok + ":24h", TokenSpec{Role: "server", Token: tok, TTL: "24h"}, true},
		{"server=" + tok + ":0", TokenSpec{}, false},
		{"server=" + tok + ":48h", TokenSpec{}, false},
		{"worker=" + tok + ":soon", TokenSpec{}, false},
		{"worker=" + tok + ":-1h", TokenSpec{}, false},
		{"boss=" + tok, TokenSpec{}, false},
		{"worker=abc", TokenSpec{}, false},
		{tok, TokenSpec{}, false},
	}
	for _, tc := range cases {
		got, err := ParseTokenSpec(tc.in)
		if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
			t.Fatalf("%q = %+v %v", tc.in, got, err)
		}
	}
	if got := JoinCommand("", "https://10.0.0.5:7003", tok, ""); got != "curl -fsSL "+DefaultInstallerURL+" | sudo bash -s -- join https://10.0.0.5:7003 --token "+tok {
		t.Fatalf("JoinCommand = %q", got)
	}
}
