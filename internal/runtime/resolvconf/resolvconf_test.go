package resolvconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
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
			got, err := Generate(path)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
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

func TestGenerateSkipsShortLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver\nnameserver 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := Generate(path)
	if err != nil || body != "nameserver 1.1.1.1\n" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestGenerateUnreadableSource(t *testing.T) {
	if _, err := Generate(t.TempDir()); err == nil {
		t.Fatal("want a read error for a directory path")
	}
}

func TestIsLoopback(t *testing.T) {
	for ip, want := range map[string]bool{"127.0.0.1": true, "127.0.0.53": true, "::1": true, "8.8.8.8": false, "not-an-ip": false} {
		if got := isLoopback(ip); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", ip, got, want)
		}
	}
}
