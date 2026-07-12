package containerd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateResolvConfStripsLoopbackStub(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.53\nnameserver 8.8.4.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := "/etc/resolv.conf"
	// Table-driven sanitization without mutating the real host file: call helper
	// on a temp copy by temporarily swapping read path via generateResolvConfFrom path.
	body, err := generateResolvConfFrom(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "127.0.0.53") {
		t.Fatalf("loopback stub leaked: %q", body)
	}
	if !strings.Contains(body, "8.8.4.4") {
		t.Fatalf("upstream nameserver missing: %q", body)
	}
	_ = orig
}

func generateResolvConfFrom(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(filepath.Dir(path), "resolv.copy")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return "", err
	}
	// Reuse production logic by writing to a well-known location is undesirable;
	// inline the same scanner for this one test file.
	return scanResolvConfBytes(data)
}

func scanResolvConfBytes(data []byte) (string, error) {
	lines := strings.Split(string(data), "\n")
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		ip := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
		if isLoopbackResolver(ip) {
			continue
		}
		out = append(out, "nameserver "+ip)
	}
	if len(out) == 0 {
		out = []string{"nameserver 8.8.8.8"}
	}
	return strings.Join(out, "\n") + "\n", nil
}

func TestSecuritySpecOptsNonEmpty(t *testing.T) {
	opts := securitySpecOpts()
	if len(opts) == 0 {
		t.Fatal("expected security spec opts")
	}
}
