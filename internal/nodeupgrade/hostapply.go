package nodeupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// HostApplyOptions are the inputs of HostApply.
type HostApplyOptions struct {
	// Script is the install.sh to run: the copy built into sandboxd
	// (scripts.InstallSh).
	Script []byte
	// NodeJSON is the saved settings file install.sh wrote.
	NodeJSON string
	// StateDir is where the script is written to run and where the applied
	// hash is recorded.
	StateDir string
	Host     Host
	// Bash runs the script; empty is "bash".
	Bash string
	Out  io.Writer
}

var nodeKeyRe = regexp.MustCompile(`^[a-z0-9_]+$`)

// HostApply re-renders this node's configuration (§6.3 step 7, §7): it
// runs Script with --config-only, which never downloads or replaces a
// binary, never installs a package and never starts or restarts a service.
// node.json's settings are passed as separate arguments, never inside a
// shell string (§8). On success it records the script's hash as the
// node's host setup.
func HostApply(ctx context.Context, o HostApplyOptions) error {
	if len(o.Script) == 0 {
		return fmt.Errorf("no install.sh is built into this sandboxd")
	}
	args, err := nodeSettingsArgs(o.NodeJSON, o.Script)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(o.StateDir, "install-*.sh")
	if err != nil {
		return err
	}
	script := f.Name()
	defer os.Remove(script)
	if _, err := f.Write(o.Script); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	bash := o.Bash
	if bash == "" {
		bash = "bash"
	}
	out, err := o.Host.Run(ctx, bash, append([]string{script, "--config-only"}, args...)...)
	if o.Out != nil {
		_, _ = o.Out.Write(out)
	}
	if err != nil {
		return fmt.Errorf("install.sh --config-only: %w: %s", err, tail(out))
	}
	sum := sha256.Sum256(o.Script)
	return RecordHostSetup(o.StateDir, hex.EncodeToString(sum[:]))
}

// nodeSettingsArgs turns node.json into install.sh flags: each key is its
// flag without the dashes and with "_" for "-" (install.sh's NODE_SETTINGS).
// A key the script has no flag for is left out, so a node.json written by a
// newer install.sh does not fail an older one; install.sh still reads the
// file itself and refuses a format it does not know. No node.json means no
// flags: install.sh then reads the settings back from sandboxd.env.
func nodeSettingsArgs(path string, script []byte) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var settings map[string]any
	if err := dec.Decode(&settings); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var args []string
	for _, k := range keys {
		if k == "format" {
			continue
		}
		if !nodeKeyRe.MatchString(k) {
			return nil, fmt.Errorf("%s: key %q is not a setting name", path, k)
		}
		flag := "--" + strings.ReplaceAll(k, "_", "-")
		if !bytes.Contains(script, []byte("\n\t\t"+flag+")\n")) {
			continue
		}
		switch v := settings[k].(type) {
		case bool:
			// A false switch is the default; install.sh has no --no-*
			// flags, and reads the false from node.json itself.
			if v {
				args = append(args, flag)
			}
		case string:
			if strings.ContainsAny(v, "\x00\n\r") {
				return nil, fmt.Errorf("%s: %s holds a control character", path, k)
			}
			if v != "" {
				args = append(args, flag, v)
			}
		case json.Number:
			if _, err := strconv.ParseInt(v.String(), 10, 64); err != nil {
				return nil, fmt.Errorf("%s: %s is not a whole number", path, k)
			}
			args = append(args, flag, v.String())
		case nil:
		default:
			return nil, fmt.Errorf("%s: %s is not a string, number or true/false", path, k)
		}
	}
	return args, nil
}
