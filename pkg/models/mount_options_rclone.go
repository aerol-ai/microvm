package models

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// rclone runs on the host as root and reads two caller inputs: the source
// (remote:path, which may name a backend on the fly, :local:/etc, and set
// its options, remote,key_file=/x:path) and credentials.rclone_conf (a
// whole config file, one [section] per remote). Either one can point
// rclone at a host directory or make it run a command, so both are held to
// the same rules: every backend must be on rcloneStorageBackends (or be a
// wrapper of one), and no backend option may be one rcloneOptionRefusal
// names.

// rcloneStorageBackends are the backends a mount may use: each reaches
// storage over the network with what the source and rclone_conf give it.
// rclone takes a backend's name or its prefix, so both are listed where
// they differ. Left out on purpose: local (a host directory); union,
// combine and cache (they join several remotes, or keep data in host
// paths); hdfs (the host's Kerberos setup); memory; and any backend rclone
// adds later, until someone has read its options.
var rcloneStorageBackends = []string{
	"s3", "b2", "gcs", "google cloud storage", "drive", "dropbox", "onedrive", "box",
	"azureblob", "azurefiles", "swift", "sftp", "ftp", "http", "webdav", "smb",
	"pcloud", "mega", "jottacloud", "koofr", "yandex", "mailru", "opendrive", "pikpak",
	"putio", "qingstor", "seafile", "sharefile", "storj", "sugarsync", "zoho", "hidrive",
	"internetarchive", "netstorage", "oracleobjectstorage", "protondrive", "quatrix",
	"filefabric", "fichier", "premiumizeme", "linkbox", "pixeldrain", "gphotos", "google photos",
}

// rcloneWrappers wrap one other remote, named by their remote option. One
// is allowed when that remote is: a section of the same rclone_conf (each
// section is checked on its own) or a storage backend on the fly.
var rcloneWrappers = []string{"alias", "crypt", "chunker", "compress", "hasher"}

// rcloneOptionRefusal says why a backend option may not be set, or "" when
// it may. Names are compared as rclone writes them: lower case, '_' for
// '-'. Inline key material (key_pem, a token, an obscured password) is
// allowed; it is sealed with the rest of credentials.
func rcloneOptionRefusal(name string) string {
	n := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
	switch {
	case strings.Contains(n, "."):
		return "sets one of rclone's global options" // override.x, global.x
	case n == "ssh", strings.HasSuffix(n, "_command"):
		return "runs a command" // sftp ssh, password_command, bearer_token_command
	case strings.HasSuffix(n, "_file"), strings.HasSuffix(n, "_path"), strings.HasSuffix(n, "_dir"):
		return "names a file or folder on the server" // key_file, known_hosts_file, service_account_file
	case n == "key_use_agent":
		return "uses the server's ssh agent"
	case n == "profile":
		return "reads the server's own credential files"
	}
	return ""
}

// rcloneNodeCredential reports whether an option makes rclone take the
// node's own cloud identity: from the environment rclone runs in or from
// the instance metadata service (the node's IAM role, managed identity or
// instance principal), or the node's own Azure CLI login. With such an
// option a tenant's mount acts as the node. A false value of a switch
// (env_auth = false, which rclone config writes by default) takes nothing.
// Allowed only by the operator (MountToolPolicy.NodeCredentials).
func rcloneNodeCredential(name, value string, hasValue bool) bool {
	n := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(name)), "-", "_")
	v := strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
	switch n {
	case "env_auth", "use_msi", "use_az":
		return !hasValue || !slices.Contains([]string{"false", "f", "0", "no", "off", ""}, v)
	case "msi_object_id", "msi_client_id", "msi_mi_res_id", "msi_endpoint":
		// Which managed identity of the node's to take.
		return hasValue && v != ""
	case "provider":
		// oracleobjectstorage's identity sources; every other backend's
		// provider is a vendor name.
		return slices.Contains([]string{"env_auth", "instance_principal_auth", "workload_identity_auth", "resource_principal_auth"}, v)
	}
	return false
}

// rcloneNodeCredentialError refuses one, naming where and the setting.
func rcloneNodeCredentialError(where, name string) error {
	return fmt.Errorf("%s %q makes rclone use this node's own cloud credentials (its environment, instance metadata or managed identity); "+
		"give the mount its own credentials, or have the operator allow node credentials (SB_MOUNTS_ALLOW_NODE_CREDENTIALS)", where, name)
}

// rcloneRemote is the remote part of rclone's remote:path as rclone reads
// it: a configured remote's name, or a backend made on the fly
// (":backend"), then ",name=value" overrides of its options.
type rcloneRemote struct {
	name     string
	onTheFly bool
	params   []rcloneParam
}

// rcloneParam is one ",name=value" override.
type rcloneParam struct {
	name, value string
	hasValue    bool
}

// parseRcloneRemote reads the remote part of s. ok is false when s has
// none, which rclone takes as a local path (data, ../x, /x), or when the
// name is not one rclone reads as a remote name: this accepts a subset of
// rclone's names (ASCII letters, digits and _ . + @ -, not starting with
// -), so whatever it accepts rclone reads as a remote too. A value quoted
// with ' or " may hold ':' and ',' (doubled quotes stay inside).
func parseRcloneRemote(s string) (rcloneRemote, bool) {
	var out rcloneRemote
	s = strings.TrimSpace(s)
	if rest, found := strings.CutPrefix(s, ":"); found {
		out.onTheFly, s = true, rest
	}
	var parts []string
	var quote rune
	start := 0
	end := -1
scan:
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ',':
			parts = append(parts, s[start:i])
			start = i + 1
		case r == ':':
			end = i
			break scan
		}
	}
	if end < 0 {
		return out, false
	}
	parts = append(parts, s[start:end])
	out.name = parts[0]
	if !isRcloneName(out.name) {
		return out, false
	}
	for _, p := range parts[1:] {
		name, value, hasValue := strings.Cut(p, "=")
		if strings.TrimSpace(name) == "" {
			return out, false
		}
		out.params = append(out.params, rcloneParam{name: name, value: value, hasValue: hasValue})
	}
	return out, true
}

func isRcloneName(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '.', r == '+', r == '@', r == '-':
		default:
			return false
		}
	}
	return true
}

// rcloneSection is one [name] of rclone_conf.
type rcloneSection struct {
	name    string
	options map[string]string
	keys    []string // in file order, for a stable error
}

// parseRcloneConf reads rclone_conf the way rclone's config file reader
// does: [name] headers, then key = value (or key: value) lines, with # and
// ; comments. Anything it cannot read for certain is refused: a line
// before the first section, a repeated section or key, a multi-line value,
// an encrypted config (its options cannot be checked). Errors name a line
// number, never its text, since the file holds credentials.
func parseRcloneConf(conf string) ([]rcloneSection, error) {
	var sections []rcloneSection
	seen := map[string]bool{}
	for i, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		lineNo := i + 1
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "["):
			name, ok := strings.CutSuffix(line[1:], "]")
			name = strings.TrimSpace(name)
			if !ok || !isRcloneName(name) {
				return nil, fmt.Errorf("credentials.rclone_conf line %d is not a valid [remote] header", lineNo)
			}
			if seen[name] {
				return nil, fmt.Errorf("credentials.rclone_conf section %q appears twice", name)
			}
			seen[name] = true
			sections = append(sections, rcloneSection{name: name, options: map[string]string{}})
			continue
		}
		if len(sections) == 0 {
			return nil, fmt.Errorf("credentials.rclone_conf line %d is outside any [remote] section (an encrypted rclone.conf cannot be checked; give it decrypted)", lineNo)
		}
		sep := strings.IndexAny(line, "=:")
		if sep <= 0 {
			return nil, fmt.Errorf("credentials.rclone_conf line %d is not key = value", lineNo)
		}
		key, value := strings.TrimSpace(line[:sep]), strings.TrimSpace(line[sep+1:])
		if !isRcloneName(key) {
			return nil, fmt.Errorf("credentials.rclone_conf line %d has a key rclone would not read as an option name", lineNo)
		}
		if strings.HasPrefix(value, `"""`) || strings.HasPrefix(value, "`") {
			return nil, fmt.Errorf("credentials.rclone_conf line %d starts a multi-line value, which cannot be checked", lineNo)
		}
		sec := &sections[len(sections)-1]
		if _, dup := sec.options[key]; dup {
			return nil, fmt.Errorf("credentials.rclone_conf section %q sets %q twice", sec.name, key)
		}
		sec.options[key] = value
		sec.keys = append(sec.keys, key)
	}
	return sections, nil
}

// rcloneDocs points a refusal at the page that lists what is allowed.
const rcloneDocs = `see "Which flags are accepted" in the external storage docs`

func rcloneBackendError(where, backend string) error {
	return fmt.Errorf("%s uses rclone backend %q, which is not allowed: rclone runs on the server, so only backends that reach remote storage are accepted (%s)", where, backend, rcloneDocs)
}

// validateRclone holds an rclone mount's source and every section of its
// rclone_conf to the rules above.
func validateRclone(source, conf string, p MountToolPolicy) error {
	remote, ok := parseRcloneRemote(source)
	if !ok {
		return errors.New("rclone source must look like remote:path, with remote a section of credentials.rclone_conf, or :backend:path")
	}
	sections, err := parseRcloneConf(conf)
	if err != nil {
		return err
	}
	if remote.onTheFly {
		if !slices.Contains(rcloneStorageBackends, remote.name) {
			return rcloneBackendError("rclone source", remote.name)
		}
	} else if !slices.ContainsFunc(sections, func(s rcloneSection) bool { return s.name == remote.name }) {
		return fmt.Errorf("rclone source remote %q is not a section of credentials.rclone_conf", remote.name)
	}
	if err := checkRcloneParams("rclone source", remote.params, p); err != nil {
		return err
	}
	for _, sec := range sections {
		if err := checkRcloneSection(sec, sections, p); err != nil {
			return err
		}
	}
	return nil
}

// checkRcloneParams refuses connection-string overrides. type, remote and
// upstreams are refused outright there: they would swap the backend, or
// the remote a wrapper wraps, for one this check never saw.
func checkRcloneParams(where string, params []rcloneParam, policy MountToolPolicy) error {
	for _, p := range params {
		n := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(p.name)), "-", "_")
		if n == "type" || n == "remote" || n == "upstreams" {
			return fmt.Errorf("%s parameter %q is not allowed: set it in credentials.rclone_conf instead", where, p.name)
		}
		if reason := rcloneOptionRefusal(p.name); reason != "" {
			return fmt.Errorf("%s parameter %q is not allowed: it %s", where, p.name, reason)
		}
		if !policy.NodeCredentials && rcloneNodeCredential(p.name, p.value, p.hasValue) {
			return rcloneNodeCredentialError(where+" parameter", p.name)
		}
	}
	return nil
}

func checkRcloneSection(sec rcloneSection, all []rcloneSection, p MountToolPolicy) error {
	where := fmt.Sprintf("credentials.rclone_conf section %q", sec.name)
	backend := strings.ToLower(strings.TrimSpace(sec.options["type"]))
	switch {
	case backend == "":
		return fmt.Errorf("%s has no type", where)
	case slices.Contains(rcloneStorageBackends, backend):
	case slices.Contains(rcloneWrappers, backend):
		wrapped, ok := parseRcloneRemote(sec.options["remote"])
		if !ok {
			return fmt.Errorf("%s (%s) must wrap a remote:path, not a path on the server", where, backend)
		}
		if wrapped.onTheFly {
			if !slices.Contains(rcloneStorageBackends, wrapped.name) {
				return rcloneBackendError(where+" remote", wrapped.name)
			}
		} else if !slices.ContainsFunc(all, func(s rcloneSection) bool { return s.name == wrapped.name }) {
			return fmt.Errorf("%s wraps remote %q, which is not a section of credentials.rclone_conf", where, wrapped.name)
		}
		if err := checkRcloneParams(where+" remote", wrapped.params, p); err != nil {
			return err
		}
	default:
		return rcloneBackendError(where, backend)
	}
	for _, key := range sec.keys {
		if reason := rcloneOptionRefusal(key); reason != "" {
			return fmt.Errorf("%s option %q is not allowed: it %s", where, key, reason)
		}
		if !p.NodeCredentials && rcloneNodeCredential(key, sec.options[key], true) {
			return rcloneNodeCredentialError(where+" option", key)
		}
	}
	return nil
}
