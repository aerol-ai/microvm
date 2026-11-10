package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/release"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// The generator against the real tree: what release.yml publishes.
func TestRunOnThisTree(t *testing.T) {
	root := filepath.Join("..", "..")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-install-script", filepath.Join(root, "scripts", "install.sh"),
		"-cluster-dir", filepath.Join(root, "internal", "cluster"),
	}, envOf(map[string]string{"VERSION": "v9.9.9"}), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	got, err := release.Parse(stdout.Bytes())
	if err != nil {
		t.Fatalf("Parse output: %v\n%s", err, stdout.String())
	}
	script, err := os.ReadFile(filepath.Join(root, "scripts", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(script)
	if got.Version != "v9.9.9" || got.UpgradeFromMin != upgradeFromMin || got.HostSetupNeedsNetwork != hostSetupNeedsNetwork {
		t.Fatalf("version fields = %+v", got)
	}
	if got.HostSetupSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("host_setup_sha256 = %s, want the install.sh hash", got.HostSetupSHA256)
	}
	if !reflect.DeepEqual(got.OneWayMigrations, store.OneWayMigrations()) {
		t.Fatalf("one_way_migrations = %v, want %v", got.OneWayMigrations, store.OneWayMigrations())
	}
	if got.EgressGatewayProtocol[len(got.EgressGatewayProtocol)-1] != egress.ProtocolVersion {
		t.Fatalf("egress_gateway_protocol = %v, want it to end at %d", got.EgressGatewayProtocol, egress.ProtocolVersion)
	}
	if got.FSMOpsVersion <= 0 {
		t.Fatalf("fsm_ops_version = %d", got.FSMOpsVersion)
	}
}

func TestRunWritesFileAndHonoursFlags(t *testing.T) {
	dir := t.TempDir()
	script := writeFile(t, dir, "install.sh", "#!/bin/sh\necho hi\n")
	cluster := filepath.Join(dir, "cluster")
	if err := os.Mkdir(cluster, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cluster, "fsm.go", "package cluster\n\nconst fsmOpsVersion = 7\n")
	out := filepath.Join(dir, "release.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-version", "v1.2.3", "-upgrade-from-min", "v1.0.0", "-host-setup-needs-network",
		"-install-script", script, "-cluster-dir", cluster, "-o", out,
	}, envOf(map[string]string{"VERSION": "v0.0.1"}), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want nothing with -o", stdout.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got, err := release.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Version != "v1.2.3" || got.UpgradeFromMin != "v1.0.0" || !got.HostSetupNeedsNetwork || got.FSMOpsVersion != 7 {
		t.Fatalf("got %+v", got)
	}
}

func TestRunFailures(t *testing.T) {
	dir := t.TempDir()
	script := writeFile(t, dir, "install.sh", "x")
	cluster := filepath.Join(dir, "cluster")
	if err := os.Mkdir(cluster, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cluster, "fsm.go", "package cluster\n\nconst fsmOpsVersion = 3\n")
	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		wantCode int
		wantErr  string
	}{
		{"no version", []string{"-install-script", script, "-cluster-dir", cluster}, nil, 1, "version"},
		{"bad version", []string{"-version", "dev", "-install-script", script, "-cluster-dir", cluster}, nil, 1, "version"},
		{"missing install script", []string{"-install-script", filepath.Join(dir, "nope"), "-cluster-dir", cluster}, map[string]string{"VERSION": "v1.0.0"}, 1, "read install script"},
		{"missing cluster dir", []string{"-install-script", script, "-cluster-dir", filepath.Join(dir, "nope")}, map[string]string{"VERSION": "v1.0.0"}, 1, "read"},
		{"floor above version", []string{"-version", "v0.1.0", "-install-script", script, "-cluster-dir", cluster}, nil, 1, "newer than version"},
		{"unwritable output", []string{"-version", "v1.0.0", "-install-script", script, "-cluster-dir", cluster, "-o", filepath.Join(dir, "no", "such", "dir", "release.json")}, nil, 1, "no such file"},
		{"unknown flag", []string{"-nope"}, nil, 2, "flag provided but not defined"},
		{"stray argument", []string{"extra"}, nil, 2, "unexpected arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, envOf(tt.env), &stdout, &stderr); code != tt.wantCode {
				t.Fatalf("run = %d, want %d (stderr %s)", code, tt.wantCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantErr) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), tt.wantErr)
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestRunStdoutFailure(t *testing.T) {
	dir := t.TempDir()
	script := writeFile(t, dir, "install.sh", "x")
	writeFile(t, dir, "fsm.go", "package cluster\n\nconst fsmOpsVersion = 3\n")
	var stderr bytes.Buffer
	if code := run([]string{"-version", "v1.0.0", "-install-script", script, "-cluster-dir", dir}, envOf(nil), failingWriter{}, &stderr); code != 1 {
		t.Fatalf("run = %d, want 1", code)
	}
}

func TestGatewayProtocols(t *testing.T) {
	for current, want := range map[int][]int{1: {1}, 2: {1, 2}, 5: {4, 5}} {
		if got := gatewayProtocols(current); !reflect.DeepEqual(got, want) {
			t.Errorf("gatewayProtocols(%d) = %v, want %v", current, got, want)
		}
	}
}

func TestReadIntConst(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		want    int
		wantErr string
	}{
		{name: "literal", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = 10\n"}, want: 10},
		{name: "grouped with comments", files: map[string]string{"a.go": "package p\nconst (\n\t// x\n\tfsmOpsVersion, other = 4, 5\n)\n"}, want: 4},
		{name: "chain across files", files: map[string]string{
			"a.go": "package p\nconst fsmOpsVersion = latest\n",
			"b.go": "package p\nconst latest = (base + 3) - 1\nconst base = 0x8\n",
		}, want: 10},
		{name: "tests ignored", files: map[string]string{
			"a.go":      "package p\nconst fsmOpsVersion = 2\n",
			"a_test.go": "package p\nconst fsmOpsVersion = 99\n",
		}, want: 2},
		{name: "missing", files: map[string]string{"a.go": "package p\nconst x = 1\n"}, wantErr: "not found"},
		{name: "unknown ident", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = y\n"}, wantErr: "constant y not found"},
		{name: "duplicate", files: map[string]string{
			"a.go": "package p\nconst fsmOpsVersion = 1\n",
			"b.go": "package p\nconst fsmOpsVersion = 2\n",
		}, wantErr: "declared in both"},
		{name: "cycle", files: map[string]string{"a.go": "package p\nconst (\n\tfsmOpsVersion = a\n\ta = fsmOpsVersion\n)\n"}, wantErr: "refers to itself"},
		{name: "string literal", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = \"10\"\n"}, wantErr: "not an integer literal"},
		{name: "multiplication", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = 2 * 5\n"}, wantErr: "unsupported operator"},
		{name: "typed conversion", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = int(10)\n"}, wantErr: "unsupported constant expression"},
		{name: "bad left operand", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = \"a\" + 1\n"}, wantErr: "not an integer literal"},
		{name: "bad right operand", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = 1 + nope\n"}, wantErr: "not found"},
		{name: "huge literal", files: map[string]string{"a.go": "package p\nconst fsmOpsVersion = 99999999999999999999\n"}, wantErr: "integer literal"},
		{name: "iota repeat skipped", files: map[string]string{"a.go": "package p\nconst (\n\ta = iota\n\tb\n)\nconst fsmOpsVersion = 1\n"}, want: 1},
		{name: "syntax error", files: map[string]string{"a.go": "package p\nconst = \n"}, wantErr: "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.files {
				writeFile(t, dir, name, body)
			}
			if err := os.Mkdir(filepath.Join(dir, "sub.go"), 0o755); err != nil { // a directory named like a file is skipped
				t.Fatal(err)
			}
			got, err := readIntConst(dir, "fsmOpsVersion")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readIntConst = %d, %v; want an error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("readIntConst = %d, %v; want %d", got, err, tt.want)
			}
		})
	}
}
