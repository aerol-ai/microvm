package safety

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// sandboxd refuses some secret files by their mode (pkg/secrets): the
// upstream wrap key may have no write bit and nothing for group or other
// (0400), and the wrapped server key and its ring nothing for group or other.
// A deploy tool that writes one of them with another mode leaves a node whose
// feature silently stays off: Ansible wrote the wrap key 0600, so private
// pulls through the mirror got 401. These tests read the mode each writer
// uses from its own file and run sandboxd's loader on a file with that mode,
// so a writer and the loader's rule cannot drift apart again.

// secretLoader is one loader and a body it can read.
type secretLoader struct {
	name string
	body string
	load func(path string) error
}

var (
	wrapKeyLoader = secretLoader{name: "upstream wrap key",
		body: base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n",
		load: func(p string) error { _, err := secrets.LoadUpstreamWrapKeyRing(p); return err }}
	wrappedKeyLoader = secretLoader{name: "wrapped server key", body: "{}",
		load: func(p string) error { _, err := secrets.ReadWrappedKeyFile(p); return err }}
	keyRingLoader = secretLoader{name: "server-key ring", body: "{}",
		load: func(p string) error { _, err := secrets.ReadKeyRingFile(p); return err }}
)

// loadWithMode writes body with mode and loads it; the error names no path,
// so two files' errors compare.
func loadWithMode(t *testing.T, l secretLoader, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	if err := os.WriteFile(p, []byte(l.body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	if err := l.load(p); err != nil {
		return strings.ReplaceAll(err.Error(), p, "<file>")
	}
	return ""
}

// checkWriterMode fails unless the loader treats a file with the writer's
// mode as it treats an owner-only, read-only one (0400), which every loader
// here takes: the mode then decides nothing.
func checkWriterMode(t *testing.T, l secretLoader, writer, mode string) {
	t.Helper()
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		t.Fatalf("%s: mode %q is not octal", writer, mode)
	}
	want := loadWithMode(t, l, 0o400)
	if got := loadWithMode(t, l, os.FileMode(m)); got != want {
		t.Errorf("%s writes the %s with mode %s, which sandboxd's loader refuses: %s", writer, l.name, mode, got)
	}
}

func TestSecretFileWritersUseModesTheLoadersTake(t *testing.T) {
	// The reference is sound: an owner-only read-only wrap key loads, and
	// the loader does refuse the mode Ansible used to write.
	if got := loadWithMode(t, wrapKeyLoader, 0o400); got != "" {
		t.Fatalf("the wrap key loader refuses a 0400 file: %s", got)
	}
	if loadWithMode(t, wrapKeyLoader, 0o600) == "" {
		t.Fatal("the wrap key loader takes a 0600 file; this test's reference needs updating")
	}

	// Ansible: every copy to the wrap key's path.
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "Ansible", "playbooks", "configure-ops.yml")), &plays); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, play := range plays {
		tasks, _ := play["tasks"].([]any)
		for _, it := range tasks {
			task, _ := it.(map[string]any)
			args, _ := task["ansible.builtin.copy"].(map[string]any)
			if args == nil || args["dest"] != "{{ sandboxd_upstream_wrap_key_path }}" {
				continue
			}
			found++
			mode, _ := args["mode"].(string)
			checkWriterMode(t, wrapKeyLoader, "Ansible task "+strconvQuote(task["name"]), mode)
		}
	}
	if found != 2 {
		t.Errorf("found %d Ansible tasks that write the wrap key, want 2 (config/secrets.yml and a control-node file)", found)
	}

	// The Terraform bootstrap: its chmod of the wrap key.
	tpl := readRepoFile(t, "Terraform", "templates", "bootstrap.sh.tftpl")
	modes := regexp.MustCompile(`chmod (0[0-7]{3}) /etc/sandboxd/secrets/upstream-wrap\.key`).FindAllStringSubmatch(tpl, -1)
	if len(modes) == 0 {
		t.Error("the Terraform bootstrap no longer sets the wrap key's mode")
	}
	for _, m := range modes {
		checkWriterMode(t, wrapKeyLoader, "the Terraform bootstrap", m[1])
	}

	// cluster-join.sh (the old join path): the wrapped server key and the ring.
	join := readRepoFile(t, "scripts", "cluster-join.sh")
	for _, c := range []struct {
		file string
		l    secretLoader
	}{{"credential_encryption.key.wrapped", wrappedKeyLoader}, {"credential_encryption.key.ring", keyRingLoader}} {
		m := regexp.MustCompile(`install -m (0[0-7]{3}) "\$CRED_STAGE_DIR/` + regexp.QuoteMeta(c.file) + `"`).FindStringSubmatch(join)
		if m == nil {
			t.Errorf("cluster-join.sh no longer installs %s with a mode", c.file)
			continue
		}
		checkWriterMode(t, c.l, "cluster-join.sh", m[1])
	}
}

func strconvQuote(v any) string {
	s, _ := v.(string)
	return strconv.Quote(s)
}
