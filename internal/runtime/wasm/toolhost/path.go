package toolhost

import (
	"errors"
	"fmt"
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
