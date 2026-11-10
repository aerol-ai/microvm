package nodejoin

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Env files are what systemd hands sandboxd: KEY=VALUE lines, # comments.
// sandboxd.env is install.sh's, cluster.env is ours (and cluster-init.sh's
// before us); the unit loads cluster.env last, so its values win.

// readEnvFile parses one env file. A missing file is an empty map.
func readEnvFile(path string) (map[string]string, error) {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		key, value, ok := envLine(sc.Text())
		if ok {
			out[key] = value
		}
	}
	return out, sc.Err()
}

// envLine splits one line, dropping matching outer quotes the way systemd
// does.
func envLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	key, value, ok := strings.Cut(line, "=")
	key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
	if !ok || key == "" {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// envSet is an ordered set of KEY=VALUE writes; an empty value removes the
// key.
type envSet struct {
	keys   []string
	values map[string]string
}

func (s *envSet) set(key, value string) {
	if s.values == nil {
		s.values = map[string]string{}
	}
	if _, seen := s.values[key]; !seen {
		s.keys = append(s.keys, key)
	}
	s.values[key] = value
}

// mergeEnvFile writes set into path and keeps every other line as it was,
// so settings someone else appended (Terraform's ops block, an operator's
// edit) survive a re-run. A key already in the file is rewritten where it
// stands; a new one is appended; an empty value drops the key. header
// starts a file that did not exist. Written atomically with mode 0600: it
// holds secrets.
func mergeEnvFile(path, header string, set envSet) error {
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var b strings.Builder
	if len(old) == 0 && header != "" {
		b.WriteString(header)
	}
	written := map[string]bool{}
	for line := range strings.Lines(string(old)) {
		key, _, ok := envLine(line)
		value, mine := set.values[key]
		switch {
		case !ok || !mine:
			b.WriteString(line)
			if !strings.HasSuffix(line, "\n") {
				b.WriteByte('\n')
			}
		case written[key] || value == "":
			// A duplicate of a key we own, or one we drop.
		default:
			b.WriteString(key + "=" + value + "\n")
		}
		if ok && mine {
			written[key] = true
		}
	}
	for _, key := range set.keys {
		if value := set.values[key]; !written[key] && value != "" {
			b.WriteString(key + "=" + value + "\n")
		}
	}
	return cluster.WriteFileAtomic(path, []byte(b.String()), 0o600)
}
