package toolhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var errPathEscape = errors.New("path escapes sandbox workdir")

// resolveHostPath maps a toolbox path (guest-absolute or relative) into workDir.
func resolveHostPath(workDir, userPath string) (string, error) {
	workDir = filepath.Clean(workDir)
	userPath = strings.TrimSpace(userPath)
	if userPath == "" {
		return workDir, nil
	}
	if strings.Contains(userPath, "..") {
		return "", fmt.Errorf("%w", errPathEscape)
	}
	clean := filepath.Clean(filepath.FromSlash(userPath))
	if filepath.IsAbs(clean) {
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	abs := filepath.Join(workDir, clean)
	rel, err := filepath.Rel(workDir, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%w", errPathEscape)
	}
	return abs, nil
}

// openInWorkDir resolves userPath like resolveHostPath and opens workDir as
// an os.Root, returning the path relative to it. Every file operation the
// host serves goes through that root: the textual check above cannot see
// symlinks, and the guest can make them in its own directory, so a link to
// ../../etc would otherwise carry a read or write out to the daemon's host.
// os.Root refuses any path — symlinks included — that resolves outside
// workDir. The caller closes the root.
func openInWorkDir(workDir, userPath string) (root *os.Root, rel, hostPath string, err error) {
	hostPath, err = resolveHostPath(workDir, userPath)
	if err != nil {
		return nil, "", "", err
	}
	// resolveHostPath built hostPath as filepath.Join(clean(workDir), <rel>)
	// and refused a rel that escapes, so the cleaned work dir is always a
	// prefix: trimming it is exact, with no fallible second Rel. "" (the work
	// dir itself) becomes "." so os.Root operations address its root.
	rel = strings.TrimPrefix(hostPath, filepath.Clean(workDir))
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" {
		rel = "."
	}
	root, err = os.OpenRoot(workDir)
	if err != nil {
		return nil, "", "", err
	}
	return root, rel, hostPath, nil
}
