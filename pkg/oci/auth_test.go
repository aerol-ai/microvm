package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A private image's credential reaches skopeo in an auth file (mode 0600,
// removed after the copy), never as an argument: any local user can read a
// process's command line.

// recordingSkopeo replaces happyConfig's skopeo with one that also logs its
// argv and copies the --src-authfile (and its mode) into dir.
func recordingSkopeo(t *testing.T, cfg *Config, dir string) {
	t.Helper()
	cfg.SkopeoBin = writeFake(t, dir, "skopeo-recording", `
printf '%s\n' "$@" > "`+dir+`/argv"
prev=""
for a in "$@"; do
  if [ "$prev" = "--src-authfile" ]; then cp "$a" "`+dir+`/auth.json"; ls -l "$a" | cut -c1-10 > "`+dir+`/mode"; echo "$a" > "`+dir+`/authpath"; fi
  prev="$a"
done
last="$1"
while [ $# -gt 1 ]; do shift; last="$1"; done
case "$last" in
  oci:*) path="${last#oci:}"; path="${path%:*}"; mkdir -p "$path/blobs"; echo '{}' > "$path/index.json" ;;
esac
`)
}

func TestBuild_PassesTheCredentialInAnAuthFile(t *testing.T) {
	cfg, _ := happyConfig(t)
	rec := t.TempDir()
	recordingSkopeo(t, &cfg, rec)
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.Build(context.Background(), BuildRequest{
		ImageRef: "docker://aocr.example.com/cluster/c1/snapshots/app:latest",
		Auth:     &models.RegistryAuth{Username: "c1", Password: "pat-secret"},
		OutPath:  filepath.Join(t.TempDir(), "rootfs.ext4"),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer res.CleanupDir()

	argv, _ := os.ReadFile(filepath.Join(rec, "argv"))
	if strings.Contains(string(argv), "pat-secret") {
		t.Fatalf("the password is on skopeo's command line:\n%s", argv)
	}
	if !strings.Contains(string(argv), "--src-authfile\n") {
		t.Fatalf("skopeo got no --src-authfile:\n%s", argv)
	}
	if mode, _ := os.ReadFile(filepath.Join(rec, "mode")); strings.TrimSpace(string(mode)) != "-rw-------" {
		t.Fatalf("auth file mode = %q, want -rw-------", strings.TrimSpace(string(mode)))
	}
	raw, err := os.ReadFile(filepath.Join(rec, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("c1:pat-secret"))
	if got := file.Auths["aocr.example.com"].Auth; got != want {
		t.Fatalf("auths[aocr.example.com].auth = %q, want %q (file %s)", got, want, raw)
	}
	authPath, _ := os.ReadFile(filepath.Join(rec, "authpath"))
	if _, err := os.Stat(strings.TrimSpace(string(authPath))); !os.IsNotExist(err) {
		t.Fatalf("auth file still there after the copy: %v", err)
	}
}

func TestBuild_PullsAnonymouslyWithoutACredential(t *testing.T) {
	for _, auth := range []*models.RegistryAuth{nil, {Server: "ghcr.io"}} {
		cfg, _ := happyConfig(t)
		rec := t.TempDir()
		recordingSkopeo(t, &cfg, rec)
		b, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := b.Build(context.Background(), BuildRequest{
			ImageRef: "docker://alpine:3.20", Auth: auth,
			OutPath: filepath.Join(t.TempDir(), "rootfs.ext4"),
		})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		res.CleanupDir()
		if argv, _ := os.ReadFile(filepath.Join(rec, "argv")); strings.Contains(string(argv), "--src-authfile") {
			t.Fatalf("auth %+v: skopeo got an auth file:\n%s", auth, argv)
		}
	}
}

func TestWriteSkopeoAuthFileRegistryKey(t *testing.T) {
	cases := []struct{ ref, server, want string }{
		{"docker://python:3.11", "", "docker.io"},
		{"docker://library/alpine:3.20", "", "docker.io"},
		{"docker://ghcr.io/org/app:1", "", "ghcr.io"},
		{"docker://localhost:5000/app", "", "localhost:5000"},
		{"docker://localhost/app", "", "localhost"},
		{"docker://ghcr.io/org/app:1", "registry.internal:443", "registry.internal:443"},
	}
	for _, tc := range cases {
		path, err := writeSkopeoAuthFile(t.TempDir(), tc.ref, &models.RegistryAuth{Server: tc.server, Username: "u", Password: "p"})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(path)
		var file struct {
			Auths map[string]any `json:"auths"`
		}
		_ = json.Unmarshal(raw, &file)
		if _, ok := file.Auths[tc.want]; !ok || len(file.Auths) != 1 {
			t.Errorf("ref %q server %q: auths = %v, want key %q", tc.ref, tc.server, file.Auths, tc.want)
		}
	}
	if _, err := writeSkopeoAuthFile(filepath.Join(t.TempDir(), "missing"), "docker://x", &models.RegistryAuth{Username: "u"}); err == nil {
		t.Error("writing into a missing dir succeeded")
	}
}

// The credential file cannot be written: skopeo is never run with a
// half-made one, and the build fails.
func TestRunSkopeoFailsWhenTheAuthFileCannotBeWritten(t *testing.T) {
	cfg, _ := happyConfig(t)
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = b.runSkopeo(context.Background(), "docker://ghcr.io/x:1", &models.RegistryAuth{Username: "u", Password: "p"},
		filepath.Join(t.TempDir(), "missing-staging"), t.TempDir(), "latest")
	if err == nil || !strings.Contains(err.Error(), "registry credential") {
		t.Fatalf("err = %v", err)
	}
}
