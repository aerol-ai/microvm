package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The file operations every toolbox API shares (plans/agent-sandbox-feature-
// parity.md, F1 and eng review ER1). The REST handlers the AerolVM SDKs and
// the Daytona facade call, and E2B's envd filesystem RPCs, all do their work
// here; each keeps its own wire format and error shape. Before this core the
// two copies had already drifted (E2B's move made the destination folder,
// Daytona's did not), and the overwrite guard, the move across filesystems
// and the "disk is full" answer would otherwise have reached only one of them.

// fileOptions tunes one shared file operation. The zero value is the most
// careful choice for every field, so a caller states what it allows.
type fileOptions struct {
	// CreateParents makes missing parent folders: mkdir's parents=true, and
	// E2B's Move, which has always created the destination's folder.
	CreateParents bool
	// Overwrite lets move and copy replace an existing destination. Daytona's
	// move always replaced it; the AerolVM SDKs send overwrite=false.
	Overwrite bool
	// Recursive lets delete remove a folder with everything in it, and copy
	// copy one. Without it a folder is a 409, so a caller that passed a folder
	// where it meant a file loses nothing.
	Recursive bool
	// Depth is how many levels a listing goes down: 1 is the folder's own
	// entries. Below 1 counts as 1.
	Depth int
	// EntryCap ends a listing after this many entries; 0 is no cap, which is
	// what Daytona's listFiles has always had.
	EntryCap int
	// Mode is a new folder's permission bits. 0 means 0755 for a folder this
	// call creates and no change to one that was already there.
	Mode os.FileMode
}

// fileRequestError is a request the caller has to change, such as deleting
// "/" or copying a folder into itself. Handlers answer 400.
type fileRequestError struct{ msg string }

func (e *fileRequestError) Error() string { return e.msg }

// fileKindError is a path that exists but is the wrong kind for the call: a
// folder passed to a non-recursive delete, a file where a folder is needed,
// a device file in a tree being copied. Handlers answer 409.
type fileKindError struct{ msg string }

func (e *fileKindError) Error() string { return e.msg }

// Seams for the tests: a real move across filesystems (EXDEV) and a
// filesystem without RENAME_NOREPLACE cannot be set up in a unit test.
var (
	renameFn          = os.Rename
	renameNoReplaceFn = renameNoReplace
)

// statPath reads one path's metadata. follow says whether a symlink is
// resolved: Daytona's getFileDetails reports the file a link points to,
// E2B's Stat reports the link itself.
func statPath(path string, follow bool) (os.FileInfo, error) {
	if follow {
		return os.Stat(path)
	}
	return os.Lstat(path)
}

// listedEntry is one entry of a listing.
type listedEntry struct {
	path string      // where it is on disk, under the folder as it was named
	rel  string      // relative to the listed folder
	info os.FileInfo // the entry itself: a symlink is never followed
}

// listFolder lists root down to opts.Depth levels, in walk order (each
// folder's entries sorted by name, a folder's contents right after it). The
// folder named by root may itself be a symlink, as with ls; nothing under it
// is followed, so a link to "/" cannot turn a listing into a walk of the
// whole disk. truncated says opts.EntryCap cut the listing short.
func listFolder(root string, opts fileOptions) (entries []listedEntry, truncated bool, err error) {
	depth := max(opts.Depth, 1)
	walkRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = resolved
	}
	info, err := os.Stat(walkRoot)
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, &fileKindError{msg: root + " is not a folder"}
	}
	errFull := errors.New("listing reached its entry cap")
	entries = []listedEntry{}
	err = filepath.WalkDir(walkRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if path == walkRoot {
			return walkErr
		}
		if walkErr != nil {
			// A folder that vanished or cannot be read part way down (a
			// process leaving /proc, a permission wall) loses only its own
			// contents; it is still listed itself.
			return nil
		}
		rel, err := filepath.Rel(walkRoot, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			// Gone between reading the folder and reading the entry.
			return nil
		}
		if opts.EntryCap > 0 && len(entries) == opts.EntryCap {
			truncated = true
			return errFull
		}
		entries = append(entries, listedEntry{path: filepath.Join(root, rel), rel: rel, info: info})
		if entry.IsDir() && strings.Count(rel, string(filepath.Separator))+1 >= depth {
			// Its entries are past the depth; skip reading the folder at all.
			return fs.SkipDir
		}
		return nil
	})
	if err != nil && !errors.Is(err, errFull) {
		return nil, false, err
	}
	return entries, truncated, nil
}

// makeDir makes the folder target. With CreateParents it also makes missing
// parents and succeeds when the folder is already there; without it, an
// existing path is an error (fs.ErrExist) and so is a missing parent. A
// folder this call creates gets exactly opts.Mode (default 0755), not the
// umask's version of it; an existing one is changed only when opts.Mode is
// set, so making sure "/tmp" exists never resets its sticky 1777.
func makeDir(target string, opts fileOptions) error {
	perm := opts.Mode
	if perm == 0 {
		perm = defaultFolderMode
	}
	if opts.CreateParents {
		existed := false
		if info, err := os.Stat(target); err == nil {
			if !info.IsDir() {
				return &fileKindError{msg: target + " exists and is not a folder"}
			}
			existed = true
		}
		if err := os.MkdirAll(target, perm); err != nil {
			return err
		}
		if existed && opts.Mode == 0 {
			return nil
		}
	} else if err := os.Mkdir(target, perm); err != nil {
		return err
	}
	return os.Chmod(target, perm)
}

// removePath deletes target. A folder needs opts.Recursive; a symlink is
// removed itself, never what it points to.
func removePath(target string, opts fileOptions) error {
	if filepath.Clean(target) == string(filepath.Separator) {
		return &fileRequestError{msg: "refusing to delete /"}
	}
	info, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if info.IsDir() && !opts.Recursive {
		return &fileKindError{msg: target + " is a folder; pass recursive=true to delete it"}
	}
	if opts.Recursive {
		return os.RemoveAll(target)
	}
	return os.Remove(target)
}

// movePath moves src to dst. Without opts.Overwrite an existing dst is
// fs.ErrExist, decided by the kernel (RENAME_NOREPLACE), so two movers racing
// for one name cannot both win. Across filesystems (a mount, a tmpfs /tmp)
// rename fails with EXDEV; the move then copies src to a temporary name
// beside dst, puts it in place with the same rename rule, and only then
// removes src, so a failure part way leaves src whole and no half-copied dst.
func movePath(src, dst string, opts fileOptions) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if err := refuseNesting(src, dst, "move"); err != nil {
			return err
		}
	}
	if opts.CreateParents {
		if err := os.MkdirAll(filepath.Dir(dst), defaultFolderMode); err != nil {
			return err
		}
	}
	err = placePath(src, dst, opts.Overwrite)
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyIntoPlace(src, dst, info, opts.Overwrite); err != nil {
		return err
	}
	if err := os.RemoveAll(src); err != nil {
		return fmt.Errorf("moved %s to %s, but could not remove the original: %w", src, dst, err)
	}
	return nil
}

// copyPath copies src to dst. A folder needs opts.Recursive and is copied
// with its modes, symlinks (as links, never followed) and, where toolboxd may
// set them, owners. Hard links inside it become separate files. dst appears
// whole or not at all: the copy is built under a temporary name beside dst
// and renamed into place, which is also where the overwrite rule applies.
func copyPath(src, dst string, opts fileOptions) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !opts.Recursive {
			return &fileKindError{msg: src + " is a folder; pass recursive=true to copy it"}
		}
		if err := refuseNesting(src, dst, "copy"); err != nil {
			return err
		}
	}
	return copyIntoPlace(src, dst, info, opts.Overwrite)
}

// placePath renames src to dst, replacing dst only when overwrite is set.
func placePath(src, dst string, overwrite bool) error {
	if overwrite {
		return renameFn(src, dst)
	}
	return renameNoReplaceFn(src, dst)
}

// copyIntoPlace copies src (described by info) to a temporary name in dst's
// folder, then renames it to dst. The temporary copy is removed on any
// failure.
func copyIntoPlace(src, dst string, info os.FileInfo, overwrite bool) error {
	parent := filepath.Dir(dst)
	if _, err := os.Stat(parent); err != nil {
		return err
	}
	if !overwrite {
		// Fail before a long copy; placePath still decides a race.
		if _, err := os.Lstat(dst); err == nil {
			return &os.PathError{Op: "copy", Path: dst, Err: fs.ErrExist}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	tmp := filepath.Join(parent, "."+filepath.Base(dst)+".aerolvm-"+randomSuffix())
	if err := copyTree(src, tmp, info); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	if err := placePath(tmp, dst, overwrite); err != nil {
		_ = os.RemoveAll(tmp)
		return err
	}
	return nil
}

// copyTree copies one entry, and a folder's contents under it. Owners and
// modification times are copied on a best-effort basis: a non-root toolboxd
// cannot give a file away, and that is not worth failing a copy for.
func copyTree(src, dst string, info os.FileInfo) error {
	mode := info.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(target, dst); err != nil {
			return err
		}
	case mode.IsDir():
		// 0700 while the copy is built, so nobody else works inside a half
		// copied folder; the real mode goes on at the end.
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
		children, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, child := range children {
			childInfo, err := child.Info()
			if err != nil {
				return err
			}
			if err := copyTree(filepath.Join(src, child.Name()), filepath.Join(dst, child.Name()), childInfo); err != nil {
				return err
			}
		}
		if err := os.Chmod(dst, mode&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)); err != nil {
			return err
		}
	case mode.IsRegular():
		if err := copyFileContents(src, dst, mode); err != nil {
			return err
		}
	default:
		return &fileKindError{msg: "cannot copy " + src + ": it is a device, pipe or socket, not a file or folder"}
	}
	keepOwnerAndTime(dst, info)
	return nil
}

// copyFileContents copies a regular file's bytes into a new file at dst
// (O_EXCL: dst is always a fresh temporary name) and gives it src's mode.
func copyFileContents(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// After the close: the umask filtered the open, and setuid bits are only
	// kept by an explicit chmod.
	return os.Chmod(dst, mode&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))
}

func keepOwnerAndTime(dst string, info os.FileInfo) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// On Linux a chown clears setuid and setgid on a file, even as
		// root and even to the same owner, so the bits copyTree set are put
		// back. Only when the owner was kept, like cp -p: a setuid file
		// given to whoever ran the copy is not the file that was copied.
		m := info.Mode()
		if os.Lchown(dst, int(stat.Uid), int(stat.Gid)) == nil && m&fs.ModeSymlink == 0 && m&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
			_ = os.Chmod(dst, m&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky))
		}
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		_ = os.Chtimes(dst, info.ModTime(), info.ModTime())
	}
}

// refuseNesting refuses to move or copy a folder into itself, which a copy
// would follow forever. Symlinks in either path are resolved first, so a
// link cannot hide the nesting.
func refuseNesting(src, dst, verb string) error {
	srcReal, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	parentReal, err := filepath.EvalSymlinks(filepath.Dir(dst))
	if err != nil {
		// A missing destination folder is reported by the move or copy itself.
		return nil
	}
	rel, err := filepath.Rel(srcReal, filepath.Join(parentReal, filepath.Base(dst)))
	if err != nil {
		return nil
	}
	// "." is the folder onto itself, which rename treats as a no-op and the
	// overwrite rule settles for a copy; only a destination strictly inside
	// src is refused.
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	return &fileRequestError{msg: "cannot " + verb + " " + src + " into itself (" + dst + ")"}
}

func randomSuffix() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// renameNoReplaceFallback is the overwrite guard where the kernel offers no
// atomic form: check, then rename. Two racing movers can both pass the check
// on such a filesystem; everywhere toolboxd normally runs, renameNoReplace
// does not get here.
func renameNoReplaceFallback(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return &os.LinkError{Op: "rename", Old: src, New: dst, Err: fs.ErrExist}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return renameFn(src, dst)
}

// defaultFolderMode is a new folder's mode when the caller names none, as in
// Daytona's createFolder.
const defaultFolderMode os.FileMode = 0o755

// listTruncatedHeader is set on a listing its entry cap (limit) cut short.
// The body stays a JSON array, the shape Daytona's listFiles expects.
const listTruncatedHeader = "X-Toolbox-Truncated"

// Error codes the SDKs act on. On a retried delete, file_not_found means the
// first attempt already deleted the path; on a retried mkdir without
// parents, folder_exists means it already made the folder (plan section 10,
// "Retries"). A bare 404 is not enough: an agent too old to have the route
// answers 404 too.
const (
	errCodeFileNotFound = "file_not_found"
	errCodeFolderExists = "folder_exists"
)

// daytonaFileInfoResponse is Daytona's FileInfo. Daytona's Go toolbox client
// decodes it with DisallowUnknownFields, so it must keep exactly these
// fields: a new one would fail every Daytona Go SDK call that reads a file's
// details. AerolVM's own fields are in extendedFileInfo instead.
type daytonaFileInfoResponse struct {
	Group       string `json:"group"`
	IsDir       bool   `json:"isDir"`
	ModTime     string `json:"modTime"`
	Mode        string `json:"mode"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	Size        int32  `json:"size"`
}

// extendedFileInfo is the file info the AerolVM SDKs ask for with
// extended=true: Daytona's fields plus the full path, the size as 64 bits
// (Daytona's size stops at 2 GiB) and where a symlink points.
type extendedFileInfo struct {
	daytonaFileInfoResponse
	Path          string  `json:"path"`
	SizeBytes     int64   `json:"size_bytes"`
	SymlinkTarget *string `json:"symlink_target,omitempty"`
}

func buildDaytonaFileInfo(path string, info os.FileInfo) daytonaFileInfoResponse {
	owner, group := fileOwnerGroup(info)
	return daytonaFileInfoResponse{
		Group:       group,
		IsDir:       info.IsDir(),
		ModTime:     info.ModTime().UTC().Format(time.RFC3339),
		Mode:        info.Mode().String(),
		Name:        filepath.Base(path),
		Owner:       owner,
		Permissions: fmt.Sprintf("%04o", info.Mode().Perm()),
		Size:        clampInt32(info.Size()),
	}
}

// fileInfoBody is the info for one path in the shape the caller asked for.
func fileInfoBody(path string, info os.FileInfo, extended bool) any {
	base := buildDaytonaFileInfo(path, info)
	if !extended {
		return base
	}
	out := extendedFileInfo{daytonaFileInfoResponse: base, Path: path, SizeBytes: info.Size()}
	if info.Mode()&fs.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			out.SymlinkTarget = &target
		}
	}
	return out
}

// The REST file routes. The AerolVM SDKs reach them through
// /v1/sandboxes/{id}/toolbox/files/..., and the Daytona facade forwards its
// SDK's file calls to the same handlers (CEO review R2). The options Daytona
// never sends (extended, depth, limit, overwrite, parents) default to
// Daytona's behaviour, so its SDK sees no change; the AerolVM SDKs send them
// explicitly.

// handleDaytonaFileInfo is GET /files/info?path=&extended=. A symlink is
// followed, as Daytona's getFileDetails always did.
func (s *server) handleDaytonaFileInfo(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	target, err := resolveDaytonaPath(query.Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	extended, err := parseOptionalBool(query.Get("extended"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "extended must be true or false")
		return
	}
	info, err := statPath(target, true)
	if err != nil {
		writeFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, fileInfoBody(target, info, extended))
}

// handleDaytonaListFiles is GET /files?path=&depth=&limit=&extended=. No
// depth is one level and no limit is no cap, as Daytona's listFiles has
// always been.
func (s *server) handleDaytonaListFiles(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	target, err := resolveDaytonaPath(query.Get("path"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	extended, err := parseOptionalBool(query.Get("extended"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "extended must be true or false")
		return
	}
	depth, err := parsePositiveInt(query.Get("depth"), 1)
	if err != nil {
		writeError(w, http.StatusBadRequest, "depth must be a whole number of at least 1")
		return
	}
	limit, err := parsePositiveInt(query.Get("limit"), 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "limit must be a whole number of at least 1")
		return
	}
	entries, truncated, err := listFolder(target, fileOptions{Depth: depth, EntryCap: limit})
	if err != nil {
		writeFilesystemError(w, err)
		return
	}
	items := make([]any, 0, len(entries))
	for _, entry := range entries {
		items = append(items, fileInfoBody(entry.path, entry.info, extended))
	}
	if truncated {
		w.Header().Set(listTruncatedHeader, "true")
	}
	writeJSON(w, http.StatusOK, items)
}

// handleDaytonaMoveFile is POST /files/move?source=&destination=&overwrite=.
// No overwrite replaces the destination, as Daytona's moveFiles always did.
func (s *server) handleDaytonaMoveFile(w http.ResponseWriter, r *http.Request) {
	source, destination, ok := sourceAndDestination(w, r)
	if !ok {
		return
	}
	overwrite, err := parseBoolDefault(r.URL.Query().Get("overwrite"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "overwrite must be true or false")
		return
	}
	if err := movePath(source, destination, fileOptions{Overwrite: overwrite}); err != nil {
		writeFilesystemError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCopyFile is POST /files/copy?source=&destination=&overwrite=&recursive=.
// The route is new, so its defaults are the careful ones: no overwrite, and
// a folder only with recursive=true.
func (s *server) handleCopyFile(w http.ResponseWriter, r *http.Request) {
	source, destination, ok := sourceAndDestination(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	overwrite, err := parseOptionalBool(query.Get("overwrite"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "overwrite must be true or false")
		return
	}
	recursive, err := parseOptionalBool(query.Get("recursive"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "recursive must be true or false")
		return
	}
	if err := copyPath(source, destination, fileOptions{Overwrite: overwrite, Recursive: recursive}); err != nil {
		writeFilesystemError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDaytonaDeleteFile is DELETE /files?path=&recursive=. A folder needs
// recursive=true, so an agent cannot wipe a tree by passing a folder where it
// meant a file; deleting it without the flag is a 409, not a silent no-op.
func (s *server) handleDaytonaDeleteFile(w http.ResponseWriter, r *http.Request) {
	target, err := resolveDaytonaPath(r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	recursive, err := parseOptionalBool(r.URL.Query().Get("recursive"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "recursive must be true or false")
		return
	}
	if err := removePath(target, fileOptions{Recursive: recursive}); err != nil {
		writeFilesystemError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDaytonaCreateFolder is POST /files/folder?path=&mode=&parents=. No
// parents makes missing parents and accepts an existing folder, as Daytona's
// createFolder does; parents=false is mkdir's plain form.
func (s *server) handleDaytonaCreateFolder(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	target, err := resolveDaytonaPath(query.Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode, err := parseFileMode(query.Get("mode"), 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	parents, err := parseBoolDefault(query.Get("parents"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, "parents must be true or false")
		return
	}
	if err := makeDir(target, fileOptions{CreateParents: parents, Mode: mode}); err != nil {
		if errors.Is(err, fs.ErrExist) {
			if info, statErr := os.Lstat(target); statErr == nil && info.IsDir() {
				writeErrorCode(w, http.StatusConflict, target+" already exists", errCodeFolderExists)
				return
			}
		}
		writeFilesystemError(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func sourceAndDestination(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	source, err := resolveDaytonaPath(r.URL.Query().Get("source"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "source: "+err.Error())
		return "", "", false
	}
	destination, err := resolveDaytonaPath(r.URL.Query().Get("destination"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, "destination: "+err.Error())
		return "", "", false
	}
	return source, destination, true
}

// parseBoolDefault reads an optional boolean query value.
func parseBoolDefault(raw string, fallback bool) (bool, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	return strconv.ParseBool(strings.TrimSpace(raw))
}

// parsePositiveInt reads an optional whole number of at least 1.
func parsePositiveInt(raw string, fallback int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("invalid value %q", raw)
	}
	return value, nil
}

// writeFilesystemError answers a failed file operation on a REST route.
func writeFilesystemError(w http.ResponseWriter, err error) {
	var requestErr *fileRequestError
	var kindErr *fileKindError
	status, code := http.StatusInternalServerError, ""
	switch {
	case errors.As(err, &requestErr):
		status = http.StatusBadRequest
	case errors.As(err, &kindErr):
		status = http.StatusConflict
	case errors.Is(err, os.ErrNotExist):
		status, code = http.StatusNotFound, errCodeFileNotFound
	case errors.Is(err, os.ErrPermission):
		status = http.StatusForbidden
	case errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.EISDIR), errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, os.ErrExist):
		// The path is the wrong kind (file vs folder) or already taken.
		status = http.StatusConflict
	case isDiskFull(err):
		// A full sandbox disk is not a toolboxd fault; say so plainly.
		writeError(w, http.StatusInsufficientStorage, "sandbox disk is full: "+err.Error())
		return
	}
	writeErrorCode(w, status, err.Error(), code)
}

func isDiskFull(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

func writeErrorCode(w http.ResponseWriter, status int, message, code string) {
	writeJSON(w, status, models.ErrorResponse{Error: message, Code: code})
}
