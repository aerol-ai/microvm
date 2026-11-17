package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cluster-init.sh and cluster-join.sh are thin wrappers over sandboxd init
// and join for one release (plans/kubectl-style-cluster-ops.md D2). These
// run them against a stub sandboxd that records its arguments.

func clusterScript(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "scripts", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// stubSandboxd writes a sandboxd that records its arguments in args.txt.
func stubSandboxd(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "sandboxd")
	script := "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > " + filepath.Join(dir, "args.txt") + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestClusterInitWrapsSandboxdInit(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, custody := range []string{"file", "wrapped"} {
		t.Run(custody, func(t *testing.T) {
			dir := t.TempDir()
			bin := stubSandboxd(t, dir)
			tlsDir := filepath.Join(dir, "tls")
			if err := os.MkdirAll(tlsDir, 0o700); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(tlsDir, "ca.crt"), "CA")
			keyPath := filepath.Join(dir, "credential_encryption.key")
			mustWrite(t, keyPath, "KEY")
			mustWrite(t, keyPath+".wrapped", "WRAPPED")
			env := filepath.Join(dir, "sandboxd.env")
			mustWrite(t, env, "SB_CREDENTIAL_ENCRYPTION_KEY_PATH="+keyPath+"\n")
			clusterEnv := filepath.Join(dir, "cluster.env")
			body := "SB_CLUSTER_TLS_DIR=" + tlsDir + "\n"
			if custody == "wrapped" {
				body += "SB_CREDENTIAL_KEY_CUSTODY=wrapped\nSB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH=" + keyPath + ".wrapped\n"
			}
			mustWrite(t, clusterEnv, body)
			tlsOut, credOut := filepath.Join(dir, "tls.tgz"), filepath.Join(dir, "cred.tgz")
			cmd := exec.Command("bash", clusterScript(t, "cluster-init.sh"),
				"--role", "server", "--node-id", "server-1", "--ingress-advertise-host", "api.example.com",
				"--gossip-key", "Z2s=", "--key-custody", custody, "--tls-bundle-out", tlsOut, "--cred-bundle-out", credOut)
			cmd.Env = append(os.Environ(), "SANDBOXD_BIN="+bin, "SB_ENV_FILE="+env, "SB_CLUSTER_ENV_FILE="+clusterEnv, "CLUSTER_INIT_ALLOW_NONROOT=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("cluster-init.sh: %v\n%s", err, out)
			}
			args, _ := os.ReadFile(filepath.Join(dir, "args.txt"))
			want := "init\n--role\nserver\n--node-id\nserver-1\n--ingress-advertise-host\napi.example.com\n--gossip-key\nZ2s=\n--key-custody\n" + custody + "\n"
			if string(args) != want {
				t.Fatalf("sandboxd got:\n%s\nwant:\n%s", args, want)
			}
			if !strings.Contains(string(out), "now runs: sandboxd init") {
				t.Fatalf("no note naming the new command:\n%s", out)
			}
			list := func(tgz string) string {
				o, err := exec.Command("tar", "-tzf", tgz).Output()
				if err != nil {
					t.Fatalf("tar -tzf %s: %v", tgz, err)
				}
				return strings.TrimSpace(string(o))
			}
			if got := list(tlsOut); got != "ca.crt" {
				t.Fatalf("TLS bundle holds %q, want only ca.crt", got)
			}
			wantCred := "credential_encryption.key"
			if custody == "wrapped" {
				wantCred = "credential_encryption.key.wrapped"
			}
			if got := list(credOut); got != wantCred {
				t.Fatalf("cred bundle holds %q, want %q", got, wantCred)
			}
		})
	}
}

func TestClusterInitNamesTheNewCommandForOldFlags(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for flag, want := range map[string]string{
		"--raft-bind":       "sandboxd init --advertise",
		"--tls-dir":         "SB_CLUSTER_TLS_DIR",
		"--node-cert-days":  "SB_CLUSTER_NODE_CERT_TTL",
		"--max-auto-voters": "SB_CLUSTER_MAX_AUTO_VOTERS",
		"--force":           "sandboxd reset --yes",
	} {
		args := []string{clusterScript(t, "cluster-init.sh"), flag}
		if flag != "--force" {
			args = append(args, "x")
		}
		out, err := exec.Command("bash", args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), want) {
			t.Fatalf("cluster-init.sh %s = %v:\n%s", flag, err, out)
		}
	}
}

func TestClusterJoinNewFormIsSandboxdJoin(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	bin := stubSandboxd(t, dir)
	for _, args := range [][]string{
		{"https://10.0.0.5:7003", "--token", "abc123.x"},
		{"10.0.0.5:7003", "--token=abc123.x", "--node-id", "w-1"},
	} {
		cmd := exec.Command("bash", append([]string{clusterScript(t, "cluster-join.sh")}, args...)...)
		cmd.Env = append(os.Environ(), "SANDBOXD_BIN="+bin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("cluster-join.sh %v: %v\n%s", args, err, out)
		}
		got, _ := os.ReadFile(filepath.Join(dir, "args.txt"))
		if string(got) != "join\n"+strings.Join(args, "\n")+"\n" {
			t.Fatalf("sandboxd got %q for %v", got, args)
		}
	}
	// The old form still parses (Terraform's default mode), with a notice.
	out, _ := exec.Command("bash", clusterScript(t, "cluster-join.sh"), "--gossip-key", "x").CombinedOutput()
	if !strings.Contains(string(out), "deprecated") {
		t.Fatalf("old form gave no notice:\n%s", out)
	}
}

// sandboxd-node-lifecycle.sh sends the admin token to this node: to the
// admin token's own listener when the node has one (SB_PAT_LOCAL_LISTEN
// under SB_PAT_SCOPE=host; its API port then refuses the admin token), else
// the API port, as sandboxd's LocalAdminURL does (round-2 review, item 1).
func TestNodeLifecycleUsesTheAdminListener(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, tc := range []struct{ env, want string }{
		{"", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_API_PORT=9000\n", "http://127.0.0.1:9000/v1/cluster/nodes/n1/uncordon"},
		{"SB_PAT_SCOPE=host\nSB_PAT_LOCAL_LISTEN=127.0.0.1:21219\n", "http://127.0.0.1:21219/v1/cluster/nodes/n1/uncordon"},
		{"SB_PAT_SCOPE=any\nSB_PAT_LOCAL_LISTEN=127.0.0.1:21219\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_PAT_SCOPE=host\nSB_PAT_LOCAL_LISTEN=[::1]:21219\n", "http://[::1]:21219/v1/cluster/nodes/n1/uncordon"},
		// Only a loopback literal (round 3): anything else would send the
		// admin token off the machine; the API port on loopback instead.
		{"SB_PAT_SCOPE=host\nSB_PAT_LOCAL_LISTEN=collector.example:80\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_PAT_SCOPE=host\nSB_PAT_LOCAL_LISTEN=10.0.0.5:21219\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_PAT_SCOPE=host\nSB_PAT_LOCAL_LISTEN=127.0.0.1:0\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_PAT_SCOPE=host\nSB_PAT_LOCAL_LISTEN=127.0.0.1:99999\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		// The API port as sandboxd reads it, 1-65535, else 21212 (round 4).
		{"SB_API_PORT=21212@collector.example\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_API_PORT=0\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
		{"SB_API_PORT=65536\n", "http://127.0.0.1:21212/v1/cluster/nodes/n1/uncordon"},
	} {
		dir := t.TempDir()
		envFile := filepath.Join(dir, "sandboxd.env")
		if err := os.WriteFile(envFile, []byte("SB_PAT_TOKEN=pat\nSB_NODE_ID=n1\n"+tc.env), 0o600); err != nil {
			t.Fatal(err)
		}
		curl := "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > " + filepath.Join(dir, "curl.txt") + "\n"
		if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(curl), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("bash", clusterScript(t, "sandboxd-node-lifecycle.sh"), "uncordon", "--env-file", envFile)
		cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%q: %v\n%s", tc.env, err, out)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "curl.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if args := string(raw); !strings.Contains(args, tc.want+"\n") || !strings.Contains(args, "Authorization: Bearer pat") {
			t.Errorf("%q: curl %q, want %s", tc.env, args, tc.want)
		}
	}
}

// cluster-join.sh's diagnostics take the admin listener by the same
// loopback rule as sandboxd-node-lifecycle.sh (and sandboxd's
// LocalAdminURL): the same pattern, in both.
func TestNodeScriptsShareTheAdminListenerRule(t *testing.T) {
	const rule = `[[ "$listen" =~ ^(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$ ]] && (( BASH_REMATCH[2] <= 65535 ))`
	// And the API port to sandboxd's reading of it (round 4).
	ports := map[string]string{
		"sandboxd-node-lifecycle.sh": `[[ "$api_port" =~ ^[1-9][0-9]{0,4}$ ]] && (( api_port <= 65535 )) || api_port=21212`,
		"cluster-join.sh":            `[[ "$SB_API_PORT_DEFAULT" =~ ^[1-9][0-9]{0,4}$ ]] && (( SB_API_PORT_DEFAULT <= 65535 )) || SB_API_PORT_DEFAULT=21212`,
	}
	for _, s := range []string{"sandboxd-node-lifecycle.sh", "cluster-join.sh"} {
		raw, err := os.ReadFile(clusterScript(t, s))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), rule) {
			t.Errorf("%s does not hold the admin listener to %s", s, rule)
		}
		if !strings.Contains(string(raw), ports[s]) {
			t.Errorf("%s does not hold the API port to %s", s, ports[s])
		}
	}
}
