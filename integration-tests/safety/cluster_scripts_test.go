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
