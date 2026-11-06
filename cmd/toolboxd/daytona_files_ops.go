package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// The Daytona toolbox file routes below were forwarded by the Daytona facade
// (pkg/api/daytona/toolbox.go) long before toolboxd answered them, so every
// fs.deleteFile, fs.createFolder, fs.replaceInFiles and fs.setFilePermissions
// call from the Daytona SDK fell through to the default 404 (plans/
// agent-sandbox-feature-parity.md, B1). Wire shapes follow the Daytona toolbox
// client pinned in go.mod (toolbox-api-client-go, api_file_system.go).

// daytonaReplaceRequest is POST /files/replace.
type daytonaReplaceRequest struct {
	Files    []string `json:"files"`
	Pattern  string   `json:"pattern"`
	NewValue string   `json:"newValue"`
}

// daytonaReplaceResult is one element of the POST /files/replace response.
// One file failing never fails the whole request: the SDK reports per file.
type daytonaReplaceResult struct {
	File    string `json:"file"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// handleDaytonaReplaceInFiles is POST /files/replace. The pattern is a plain
// string, as in Daytona's daemon, not a regular expression. Each file is
// rewritten through a temp file and a rename so a failure mid-write cannot
// leave it half replaced, and its mode is kept.
func (s *server) handleDaytonaReplaceInFiles(w http.ResponseWriter, r *http.Request) {
	var req daytonaReplaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}
	results := make([]daytonaReplaceResult, 0, len(req.Files))
	for _, raw := range req.Files {
		result := daytonaReplaceResult{File: raw}
		if err := replaceInFile(raw, req.Pattern, req.NewValue); err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
		}
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, results)
}

func replaceInFile(raw, pattern, newValue string) error {
	target, err := resolveDaytonaPath(raw, false)
	if err != nil {
		return err
	}
	// Edit the file a link points to, not the link: the rename below would
	// otherwise turn a symlink into a plain file. Daytona's own toolbox
	// writes in place, which keeps the link.
	if real, err := filepath.EvalSymlinks(target); err == nil {
		target = real
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a folder", target)
	}
	content, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	replaced := strings.ReplaceAll(string(content), pattern, newValue)
	if replaced == string(content) {
		return nil
	}
	return writeFileAtomic(target, []byte(replaced), info)
}

// writeFileAtomic writes data to a temp file beside target and renames it
// over target, so readers see the old or the new content, never a mix. The
// new file keeps the old one's mode (setuid, setgid and sticky included) and,
// as far as toolboxd may, its owner and group, as the atomic upload does
// (writeUploadAtomic): a rename otherwise leaves the file owned by toolboxd's
// user. A chown that is refused (toolboxd not root) leaves that owner.
func writeFileAtomic(target string, data []byte, previous os.FileInfo) error {
	perm := previous.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".replace-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if stat, ok := previous.Sys().(*syscall.Stat_t); ok {
		_ = tmp.Chown(int(stat.Uid), int(stat.Gid))
	}
	// After the chown: changing the owner clears setuid and setgid.
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		cleanup()
		return err
	}
	return nil
}

// handleDaytonaSetPermissions is POST /files/permissions?path=&owner=&group=&mode=.
// owner and group take a name or a numeric id; an unset field is left alone.
func (s *server) handleDaytonaSetPermissions(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	target, err := resolveDaytonaPath(query.Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := os.Lstat(target); err != nil {
		writeFilesystemError(w, err)
		return
	}
	uid, err := lookupOwnerID(query.Get("owner"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	gid, err := lookupGroupID(query.Get("group"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if rawMode := strings.TrimSpace(query.Get("mode")); rawMode != "" {
		mode, err := parseFileMode(rawMode, 0)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := os.Chmod(target, mode); err != nil {
			writeFilesystemError(w, err)
			return
		}
	}
	if uid != -1 || gid != -1 {
		if err := os.Lchown(target, uid, gid); err != nil {
			writeFilesystemError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// parseFileMode reads an octal mode such as "755" or "0644". Only permission
// and the setuid/setgid/sticky bits are accepted.
func parseFileMode(raw string, fallback os.FileMode) (os.FileMode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(raw, 8, 32)
	if err != nil || value > 0o7777 {
		return 0, fmt.Errorf("mode %q must be an octal permission such as 755", raw)
	}
	mode := os.FileMode(value & 0o777)
	if value&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if value&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if value&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode, nil
}

func parseOptionalBool(raw string) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false, nil
	}
	return strconv.ParseBool(raw)
}

// lookupOwnerID returns -1 for an empty owner, which Lchown leaves unchanged.
func lookupOwnerID(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return -1, nil
	}
	if id, err := strconv.Atoi(raw); err == nil && id >= 0 {
		return id, nil
	}
	found, err := user.Lookup(raw)
	if err != nil {
		return 0, fmt.Errorf("unknown owner %q", raw)
	}
	return strconv.Atoi(found.Uid)
}

func lookupGroupID(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return -1, nil
	}
	if id, err := strconv.Atoi(raw); err == nil && id >= 0 {
		return id, nil
	}
	found, err := user.LookupGroup(raw)
	if err != nil {
		return 0, fmt.Errorf("unknown group %q", raw)
	}
	return strconv.Atoi(found.Gid)
}

// Language servers answer 501 with a reason instead of the default 404,
// which reads as a toolboxd bug. They are not planned. (Daytona terminals
// are served by daytona_pty.go.)
const errDaytonaLSPUnsupported = "language servers are not supported on AerolVM"

func isDaytonaLSPPath(path string) bool {
	return path == "/lsp" || strings.HasPrefix(path, "/lsp/")
}
