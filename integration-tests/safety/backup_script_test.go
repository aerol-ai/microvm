package safety

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sandboxd-backup.sh decides from the key custody setting whether the
// archive must carry the wrapped server key, and it must read that setting
// as sandboxd does: systemd strips the quotes and whitespace around a value,
// and the cluster drop-in's cluster.env overrides sandboxd.env. Misread, a
// wrapped node's backup leaves out its only copy of the server key.
func TestBackupReadsKeyCustodyAsSandboxdDoes(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "sandboxd-backup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const wrappedPath = "var/lib/sandboxd/credential_encryption.key.wrapped"
	for name, tc := range map[string]struct {
		env         map[string]string // config-dir file -> content
		wantWrapped bool
	}{
		"quoted, spaced, CRLF": {
			env:         map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY = \"wrapped\"\r\n  SB_CREDENTIAL_ENCRYPTION_KEY=plain\n"},
			wantWrapped: true,
		},
		"single quotes": {
			env:         map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY='wrapped'\n"},
			wantWrapped: true,
		},
		// The old glob read sandboxd.env last, after cluster.env.
		"cluster.env wins": {
			env:         map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY=file\n", "cluster.env": "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n"},
			wantWrapped: true,
		},
		"cluster.env wins, the other way": {
			env: map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n", "cluster.env": "SB_CREDENTIAL_KEY_CUSTODY=file\n"},
		},
		"a commented-out line": {
			env: map[string]string{"sandboxd.env": "# SB_CREDENTIAL_KEY_CUSTODY=wrapped\n"},
		},
		"no env files": {},
	} {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			etc := filepath.Join(src, "etc")
			if err := os.MkdirAll(etc, 0o755); err != nil {
				t.Fatal(err)
			}
			for f, body := range tc.env {
				if err := os.WriteFile(filepath.Join(etc, f), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			wrapped := filepath.Join(src, "wrapped")
			if err := os.WriteFile(wrapped, []byte(`{"format":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "backup.tgz")
			out, err := exec.Command("bash", script, "--state-db", filepath.Join(src, "none"), "--raft-dir", filepath.Join(src, "none"),
				"--config-dir", etc, "--wrapped-key", wrapped, "--key-ring", filepath.Join(src, "none"), "--output", archive).CombinedOutput()
			if err != nil {
				t.Fatalf("backup: %v\n%s", err, out)
			}
			files := readArchive(t, archive)
			if _, got := files[wrappedPath]; got != tc.wantWrapped {
				t.Fatalf("wrapped key in the archive = %v, want %v (manifest:\n%s)", got, tc.wantWrapped, files["MANIFEST.txt"])
			}
			for f, body := range files {
				if tc.wantWrapped && strings.HasPrefix(f, "etc/sandboxd/") && strings.Contains(body, "SB_CREDENTIAL_ENCRYPTION_KEY") {
					t.Fatalf("%s carries a plaintext key line beside the wrapped key:\n%s", f, body)
				}
			}
		})
	}
}

func readArchive(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			files[strings.TrimPrefix(h.Name, "./")] = string(b)
		}
	}
}
