package containerd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateResolvConf(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		missing     bool
		wantContain []string
		wantAbsent  []string
	}{
		{
			name:        "strips systemd-resolved loopback stub",
			body:        "nameserver 127.0.0.53\nnameserver 8.8.4.4\n",
			wantContain: []string{"nameserver 8.8.4.4"},
			wantAbsent:  []string{"127.0.0.53"},
		},
		{
			name:        "all-loopback falls back to public resolver",
			body:        "nameserver 127.0.0.1\nnameserver 127.0.0.53\n",
			wantContain: []string{"nameserver 8.8.8.8"},
			wantAbsent:  []string{"127.0.0.1", "127.0.0.53"},
		},
		{
			name:        "missing file falls back to public resolver",
			missing:     true,
			wantContain: []string{"nameserver 8.8.8.8"},
		},
		{
			name:        "preserves search and options, skips comments",
			body:        "# comment\nsearch corp.local example.com\noptions ndots:2\nnameserver 10.0.0.1\n",
			wantContain: []string{"search corp.local example.com", "options ndots:2", "nameserver 10.0.0.1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolv.conf")
			if !tc.missing {
				if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := generateResolvConf(path)
			if err != nil {
				t.Fatalf("generateResolvConf() error = %v", err)
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Fatalf("resolv.conf missing %q:\n%s", want, got)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Fatalf("resolv.conf leaked %q:\n%s", absent, got)
				}
			}
		})
	}
}

func TestPrepareSandboxHostFilesRunDirIsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSandboxHostFiles(path, "sb-1"); err == nil {
		t.Fatal("want error when run dir is a file")
	}
}

func TestPrepareSandboxHostFiles(t *testing.T) {
	dir := t.TempDir()
	hf, err := prepareSandboxHostFiles(dir, "sb-abc")
	if err != nil {
		t.Fatalf("prepareSandboxHostFiles() error = %v", err)
	}
	for _, p := range []string{hf.ResolvConf, hf.Hosts, hf.Hostname} {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Fatalf("expected host file %q: %v", p, statErr)
		}
	}
	name, err := os.ReadFile(hf.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(name)) != "sb-abc" {
		t.Fatalf("hostname = %q, want sb-abc", strings.TrimSpace(string(name)))
	}
}
