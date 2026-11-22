package rootpolicy

import (
	"path"
	"strings"
)

// The rule for the root helper's platform volume reclaim on NFS (M1 PR 8):
// root mounts the folder a source names and deletes everything in it, so
// the source must be one volume's folder of the export the helper's own
// settings name, never another folder of that export, the export itself,
// or another server's. A volume's folder is two plain names below the
// export, <scope>/<name> (pkg/volumes MountSource): the tenant's or the
// operator's scope, and the volume's sanitized name.

// RuleReclaim is a refused reclaim.
const RuleReclaim Rule = "reclaim"

// NFSExport is the helper's own NFS platform volume backend.
type NFSExport struct {
	Server string
	// Export is the export's path, with or without its slashes, as the
	// operator wrote SB_PLATFORM_VOLUMES_NFS_EXPORT.
	Export string
}

// CheckReclaimSource checks source against the export: exactly
// <server>:/<export>/<scope>/<name>, with scope and name each a plain name
// (a-z 0-9 . _ -, not . or ..).
func CheckReclaimSource(e NFSExport, source string) error {
	server, dir, ok := strings.Cut(source, ":")
	if !ok || server == "" || server != e.Server {
		return violate(RuleReclaim, "reclaim source is not on this node's platform volume server")
	}
	export := "/" + strings.Trim(e.Export, "/")
	rest, ok := strings.CutPrefix(dir, export+"/")
	if export == "/" || !ok || path.Clean(dir) != dir {
		return violate(RuleReclaim, "reclaim source %q is not a clean path in this node's platform volume export %s", dir, export)
	}
	scope, name, ok := strings.Cut(rest, "/")
	if !ok || !plainVolumeName(scope) || !plainVolumeName(name) {
		return violate(RuleReclaim, "reclaim source %q is not one volume's folder (<export>/<scope>/<name>)", dir)
	}
	return nil
}

// plainVolumeName is one sanitized volume path segment.
func plainVolumeName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
