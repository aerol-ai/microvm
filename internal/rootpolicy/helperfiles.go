package rootpolicy

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// The names the root helper gives the files it makes for a container in its
// own folders (internal/rootd): <root>/<container id>/<name>. A spec binds
// nothing else from a helper file root (Policy.HelperFileRoots), so the two
// sides share these names.
const (
	HostnameFile   = "hostname"
	HostsFile      = "hosts"
	ResolvConfFile = "resolv.conf"
	EgressCAFile   = "egress-ca.pem"
	// ParkSocketFile names a warm-pool slot's park socket. A create's ready
	// socket is <nonce>.sock (ReadySocketFile).
	ParkSocketFile = "ready.sock"
	// MaxReadyNonceLen bounds a ready socket's nonce, which names its file.
	MaxReadyNonceLen = 64
)

// helperFileNames are the fixed names; <nonce>.sock is the one other shape.
var helperFileNames = []string{HostnameFile, HostsFile, ResolvConfFile, EgressCAFile, ParkSocketFile}

// CheckReadyNonce allows a ready socket's nonce: lower-case hex, at most
// MaxReadyNonceLen. It becomes a file name, so nothing else may reach one.
func CheckReadyNonce(n string) error {
	if n == "" || len(n) > MaxReadyNonceLen {
		return violate(RuleMount, "ready nonce %q: want 1 to %d characters", n, MaxReadyNonceLen)
	}
	if _, err := hex.DecodeString(n); err != nil || strings.ToLower(n) != n {
		return violate(RuleMount, "ready nonce %q is not lower-case hex", n)
	}
	return nil
}

// ReadySocketFile is the file name of a container's ready socket in the
// helper's folder: <nonce>.sock for a create, ParkSocketFile for a park
// socket (no nonce). The nonce must pass CheckReadyNonce.
func ReadySocketFile(nonce string) string {
	if nonce == "" {
		return ParkSocketFile
	}
	return nonce + ".sock"
}

// checkHelperFile checks a bind source under the helper file root root.
// Only root can write the helper's folders, and that alone keeps a name
// there from being swapped for a link before runc's mount. A bind of one
// of those folders would give a sandbox, which runs as uid 0, a way to
// write it. So a source names exactly one file the helper makes, at
// <root>/<container id>/<name>: never a folder, never deeper, never a
// temporary name. checkSpecMount also requires the bind to be read-only.
func checkHelperFile(root, src string) error {
	id, name, ok := strings.Cut(strings.TrimPrefix(src, root+"/"), "/")
	if !ok || strings.Contains(name, "/") {
		return violate(RuleMount, "bind source %q: under the helper's %s a bind names one file, <id>/<name>", src, root)
	}
	if err := ValidateID(id); err != nil {
		return violate(RuleMount, "bind source %q: %v", src, err)
	}
	if slices.Contains(helperFileNames, name) {
		return nil
	}
	if nonce, ok := strings.CutSuffix(name, ".sock"); ok && CheckReadyNonce(nonce) == nil {
		return nil
	}
	return violate(RuleMount, "bind source %q: %q is not a file the helper makes", src, name)
}

// helperFileRootFor returns the helper file root src is inside.
func (p Policy) helperFileRootFor(src string) (string, bool) {
	for _, r := range p.HelperFileRoots {
		if within(src, r) {
			return r, true
		}
	}
	return "", false
}

// validateOverlaps keeps what a sandbox may bind apart from what root reads
// on the agent's word. A bind root or helper file root that held the moves
// folder, the FIFO folder or a runsc config would let a spec bind one of
// them, read-write where the rules allow: a runsc config a sandbox can
// rewrite names the binary the next gVisor shim runs as root. And a bind
// root must not hold or sit in a helper file root, where only a read-only
// file may be bound: the looser rule would cover the stricter one's files.
func (p Policy) validateOverlaps() error {
	type area struct{ what, path string }
	rootReads := []area{{"moves dir", p.MovesDir}, {"FIFO dir", p.FIFODir}}
	for _, c := range p.RunscConfigPaths {
		rootReads = append(rootReads, area{"runsc config", c})
	}
	var bindable []area
	for _, r := range p.BindRoots {
		bindable = append(bindable, area{"bind root", r})
	}
	for _, f := range p.BindFiles {
		bindable = append(bindable, area{"bind file", f})
	}
	for _, r := range p.HelperFileRoots {
		bindable = append(bindable, area{"helper file root", r})
	}
	for _, b := range bindable {
		for _, r := range rootReads {
			if overlap(b.path, r.path) {
				return fmt.Errorf("policy %s %q overlaps the %s %q, which root reads", b.what, b.path, r.what, r.path)
			}
		}
	}
	for i, h := range p.HelperFileRoots {
		for _, b := range append(slices.Clone(p.BindRoots), p.BindFiles...) {
			if overlap(b, h) {
				return fmt.Errorf("policy bind source %q overlaps the helper file root %q", b, h)
			}
		}
		for _, h2 := range p.HelperFileRoots[i+1:] {
			if overlap(h, h2) {
				return fmt.Errorf("policy helper file roots %q and %q overlap", h, h2)
			}
		}
	}
	return nil
}

// overlap reports whether a and b are the same path or one holds the other.
func overlap(a, b string) bool { return equalOrWithin(a, b) || equalOrWithin(b, a) }
