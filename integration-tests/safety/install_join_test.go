package safety

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// install.sh's `init` and `join` words (plans/kubectl-style-cluster-ops.md
// §3.1, §6.5, §7). A join asks the cluster which build to install, and
// trusts the answer only when its MACs check out under the token, exactly
// as sandboxd join does (cluster.VerifyClusterInfo): a second
// implementation in the installer's Python, checked here against the Go one.

func installScript(t *testing.T) string {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	return script
}

// fakeClusterInfo serves cluster-info signed for token, the way
// internal/cluster does; tamper changes the version after signing.
func fakeClusterInfo(t *testing.T, token, version string, tamper bool) *httptest.Server {
	t.Helper()
	certPEM, _, err := cluster.GenerateClusterCA("test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _, _ := cluster.ParseJoinToken(token)
		if r.URL.Path != cluster.JoinClusterInfoPath || r.URL.Query().Get("token_id") != id {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "cluster: join token is not valid", "reason": "token_invalid"})
			return
		}
		key, _ := cluster.JoinDiscoveryKey(token)
		info := cluster.ClusterInfo{CACert: string(certPEM), ClusterID: "sha256:abc", Version: version, JoinURLs: []string{"https://10.0.0.5:7003"}}
		info.MAC = base64.StdEncoding.EncodeToString(cluster.JoinDiscoveryMAC(key, certPEM))
		info.InfoMAC = base64.StdEncoding.EncodeToString(cluster.JoinDiscoveryMAC(key, cluster.ClusterInfoSigningBytes(info)))
		if !cluster.VerifyClusterInfo(token, info) {
			t.Error("the test's own answer fails the Go check")
		}
		if tamper {
			info.Version = "v0.0.1"
		}
		_ = json.NewEncoder(w).Encode(info)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestInstallJoinAsksTheClusterForItsVersion(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	token, _ := cluster.GenerateJoinToken()
	other, _ := cluster.GenerateJoinToken()
	good := fakeClusterInfo(t, token, "v0.6.12", false)
	tampered := fakeClusterInfo(t, token, "v0.6.12", true)
	hostPort := strings.TrimPrefix(good.URL, "https://")
	cases := []struct {
		name string
		args []string
		ok   bool
		want string
	}{
		{"the cluster's version", []string{"join", good.URL, "--token", token}, true, "v0.6.12"},
		{"a bare host:port and --token=", []string{"join", hostPort, "--node-id", "w-1", "--token=" + token}, true, "v0.6.12"},
		{"a man in the middle swapped the version", []string{"join", tampered.URL, "--token", token}, false, "could not prove it knows the token"},
		{"a token the cluster does not know", []string{"join", good.URL, "--token", other}, false, "refused the token (403)"},
		{"a malformed token", []string{"join", good.URL, "--token", "abc.def"}, false, "must look like"},
		{"nobody listening", []string{"join", "https://127.0.0.1:1", "--token", token}, false, "can't reach the join server"},
		{"no token", []string{"join", good.URL}, false, "join needs the join URL and a token"},
		{"no URL", []string{"join", "--token", token}, false, "join needs the join URL and a token"},
		{"not with join", []string{"init"}, false, "--print-join-version goes with join"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", append([]string{installScript(t), "--print-join-version"}, tc.args...)...)
			cmd.Dir = t.TempDir()
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.ok || !strings.Contains(string(out), tc.want) {
				t.Fatalf("install.sh %v = %v:\n%s", tc.args, err, out)
			}
		})
	}
}

func TestInstallRefusesInitAndJoinWhereTheyCantWork(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	token, _ := cluster.GenerateJoinToken()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--local", "init"}, "does not work with --cli-only, --local or --config-only"},
		{[]string{"--cli-only", "join", "https://x", "--token", token}, "does not work with --cli-only, --local or --config-only"},
		{[]string{"--config-only", "init"}, "does not work with --cli-only, --local or --config-only"},
	} {
		cmd := exec.Command("bash", append([]string{installScript(t)}, tc.args...)...)
		cmd.Dir = t.TempDir()
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), tc.want) {
			t.Fatalf("install.sh %v = %v:\n%s", tc.args, err, out)
		}
	}
}

// Everything after the word belongs to sandboxd: flags the installer
// doesn't know are never "Unknown argument" there, and an installer flag
// after the word is not taken by the installer.
func TestInstallPassesArgumentsAfterTheWordToSandboxd(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command("bash", installScript(t), "--local", "join", "https://x:7003", "--token", "t", "--advertise", "10.0.0.1", "--cli-only")
	cmd.Dir = t.TempDir()
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "Unknown argument") || strings.Contains(string(out), "aerolvm installed") {
		t.Fatalf("arguments after join were parsed by the installer:\n%s", out)
	}
}
