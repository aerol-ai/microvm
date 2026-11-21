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

func TestNameservers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	body := "# c\nnameserver 127.0.0.53\nnameserver 10.0.1.5\nnameserver ::ffff:10.0.0.2\nnameserver bogus\nnameserver\nsearch x\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := Nameservers(path)
	if len(got) != 2 || got[0].String() != "10.0.1.5" || got[1].String() != "10.0.0.2" {
		t.Fatalf("Nameservers = %v", got)
	}
	if Nameservers(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Fatal("a missing file lists none")
	}
}

// TestParseRender: Generate is Parse then Render, so a caller that hands
// Parse's values to another process (the root helper renders the file
// itself) gets the same bytes Generate writes.
func TestParseRender(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	body := "search a.example b.example\noptions ndots:2 edns0\nnameserver 127.0.0.53\nnameserver 10.0.0.1\nnameserver ::1\nnameserver fd00::2\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Nameservers: []string{"10.0.0.1", "fd00::2"}, Search: []string{"a.example", "b.example"}, Options: []string{"ndots:2", "edns0"}}
	if strings.Join(c.Nameservers, ",") != strings.Join(want.Nameservers, ",") ||
		strings.Join(c.Search, ",") != strings.Join(want.Search, ",") ||
		strings.Join(c.Options, ",") != strings.Join(want.Options, ",") {
		t.Fatalf("Parse = %+v, want %+v", c, want)
	}
	gen, err := Generate(path)
	if err != nil || c.Render() != gen {
		t.Fatalf("Render %q, Generate %q (%v)", c.Render(), gen, err)
	}
	if gen != "search a.example b.example\noptions ndots:2 edns0\nnameserver 10.0.0.1\nnameserver fd00::2\n" {
		t.Fatalf("Generate = %q", gen)
	}
	if (Config{}).Render() != "" {
		t.Fatal("an empty config renders as nothing")
	}
	missing, err := Parse(filepath.Join(t.TempDir(), "missing"))
	if err != nil || missing.Render() != Fallback {
		t.Fatalf("missing file: %+v %v", missing, err)
	}
	if _, err := Parse(t.TempDir()); err == nil {
		t.Fatal("want a read error for a directory path")
	}
}
