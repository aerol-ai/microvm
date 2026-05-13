package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

type daytonaMatchResponse struct {
	Content string `json:"content"`
	File    string `json:"file"`
	Line    int32  `json:"line"`
}

type daytonaSearchFilesResponse struct {
	Files []string `json:"files"`
}

type daytonaGitStatusResponse struct {
	Ahead           *int32                 `json:"ahead,omitempty"`
	Behind          *int32                 `json:"behind,omitempty"`
	BranchPublished *bool                  `json:"branchPublished,omitempty"`
	CurrentBranch   string                 `json:"currentBranch"`
	FileStatus      []daytonaGitFileStatus `json:"fileStatus"`
}

type daytonaGitFileStatus struct {
	Extra    string `json:"extra"`
	Name     string `json:"name"`
	Staging  string `json:"staging"`
	Worktree string `json:"worktree"`
}

type daytonaGitCommitInfo struct {
	Author    string `json:"author"`
	Email     string `json:"email"`
	Hash      string `json:"hash"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type daytonaListBranchesResponse struct {
	Branches []string `json:"branches"`
}

type daytonaGitCommitResponse struct {
	Hash string `json:"hash"`
}

type daytonaGitAddRequest struct {
	Files []string `json:"files"`
	Path  string   `json:"path"`
}

type daytonaGitCheckoutRequest struct {
	Branch string `json:"branch"`
	Path   string `json:"path"`
}

type daytonaGitBranchRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type daytonaGitDeleteBranchRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type daytonaGitCloneRequest struct {
	Branch   *string `json:"branch,omitempty"`
	CommitID *string `json:"commit_id,omitempty"`
	Password *string `json:"password,omitempty"`
	Path     string  `json:"path"`
	URL      string  `json:"url"`
	Username *string `json:"username,omitempty"`
}

type daytonaGitCommitRequest struct {
	AllowEmpty *bool  `json:"allow_empty,omitempty"`
	Author     string `json:"author"`
	Email      string `json:"email"`
	Message    string `json:"message"`
	Path       string `json:"path"`
}

type gitCommandError struct {
	message string
}

func (e *gitCommandError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func (s *server) handleDaytonaFileInfo(w http.ResponseWriter, r *http.Request) {
	targetPath, err := resolveDaytonaPath(r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		writeFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, buildDaytonaFileInfo(targetPath, info))
}

func (s *server) handleDaytonaListFiles(w http.ResponseWriter, r *http.Request) {
	targetPath, err := resolveDaytonaPath(r.URL.Query().Get("path"), true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := os.ReadDir(targetPath)
	if err != nil {
		writeFilesystemError(w, err)
		return
	}
	items := make([]daytonaFileInfoResponse, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			writeFilesystemError(w, err)
			return
		}
		items = append(items, buildDaytonaFileInfo(filepath.Join(targetPath, entry.Name()), info))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *server) handleDaytonaMoveFile(w http.ResponseWriter, r *http.Request) {
	source, err := resolveDaytonaPath(r.URL.Query().Get("source"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	destination, err := resolveDaytonaPath(r.URL.Query().Get("destination"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.Rename(source, destination); err != nil {
		writeFilesystemError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaSearchFiles(w http.ResponseWriter, r *http.Request) {
	root, err := resolveDaytonaPath(r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
	if pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		writeError(w, http.StatusBadRequest, "invalid pattern")
		return
	}
	matches := []string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if matchesPattern(root, path, entry.Name(), pattern) {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		writeFilesystemError(w, err)
		return
	}
	sort.Strings(matches)
	writeJSON(w, http.StatusOK, daytonaSearchFilesResponse{Files: matches})
}

func (s *server) handleDaytonaFindInFiles(w http.ResponseWriter, r *http.Request) {
	root, err := resolveDaytonaPath(r.URL.Query().Get("path"), false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pattern := r.URL.Query().Get("pattern")
	if pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}
	matches := []daytonaMatchResponse{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			if strings.Contains(line, pattern) {
				matches = append(matches, daytonaMatchResponse{Content: line, File: path, Line: int32(lineNumber)})
			}
		}
		return scanner.Err()
	})
	if err != nil {
		writeFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, matches)
}

func (s *server) handleDaytonaGitRoute(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/git/add":
		s.handleDaytonaGitAdd(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/git/checkout":
		s.handleDaytonaGitCheckout(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/git/clone":
		s.handleDaytonaGitClone(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/git/commit":
		s.handleDaytonaGitCommit(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/git/branches":
		s.handleDaytonaGitCreateBranch(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == "/git/branches":
		s.handleDaytonaGitDeleteBranch(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/git/branches":
		s.handleDaytonaGitListBranches(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/git/history":
		s.handleDaytonaGitHistory(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/git/status":
		s.handleDaytonaGitStatus(w, r)
	case r.Method == http.MethodPost && (r.URL.Path == "/git/pull" || r.URL.Path == "/git/push"):
		writeError(w, http.StatusNotImplemented, "git remote sync is not implemented")
	default:
		return false
	}
	return true
}

func (s *server) handleDaytonaGitAdd(w http.ResponseWriter, r *http.Request) {
	var req daytonaGitAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	repoPath, err := resolveGitPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Files) == 0 {
		writeError(w, http.StatusBadRequest, "files is required")
		return
	}
	args := append([]string{"add", "--"}, req.Files...)
	if _, err := runGit(repoPath, args...); err != nil {
		writeGitError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaGitCheckout(w http.ResponseWriter, r *http.Request) {
	var req daytonaGitCheckoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	repoPath, err := resolveGitPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Branch) == "" {
		writeError(w, http.StatusBadRequest, "branch is required")
		return
	}
	if _, err := runGit(repoPath, "checkout", req.Branch); err != nil {
		writeGitError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaGitClone(w http.ResponseWriter, r *http.Request) {
	var req daytonaGitCloneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	clonePath, err := resolveDaytonaPath(req.Path, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	if err := os.MkdirAll(filepath.Dir(clonePath), 0o755); err != nil {
		writeFilesystemError(w, err)
		return
	}
	cloneURL := gitURLWithCredentials(req.URL, valueOrEmptyString(req.Username), valueOrEmptyString(req.Password))
	args := []string{"clone"}
	if branch := strings.TrimSpace(valueOrEmptyString(req.Branch)); branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, cloneURL, clonePath)
	if _, err := runGitNoRepo(args...); err != nil {
		writeGitError(w, err)
		return
	}
	if commitID := strings.TrimSpace(valueOrEmptyString(req.CommitID)); commitID != "" {
		if _, err := runGit(clonePath, "checkout", commitID); err != nil {
			writeGitError(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaGitCommit(w http.ResponseWriter, r *http.Request) {
	var req daytonaGitCommitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	repoPath, err := resolveGitPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Author) == "" || strings.TrimSpace(req.Email) == "" || strings.TrimSpace(req.Message) == "" {
		writeError(w, http.StatusBadRequest, "author, email, and message are required")
		return
	}
	args := []string{"-C", repoPath, "-c", "user.name=" + req.Author, "-c", "user.email=" + req.Email, "commit", "-m", req.Message}
	if req.AllowEmpty != nil && *req.AllowEmpty {
		args = append(args, "--allow-empty")
	}
	if _, err := runGitNoRepo(args...); err != nil {
		writeGitError(w, err)
		return
	}
	hash, err := runGit(repoPath, "rev-parse", "HEAD")
	if err != nil {
		writeGitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, daytonaGitCommitResponse{Hash: strings.TrimSpace(hash)})
}

func (s *server) handleDaytonaGitCreateBranch(w http.ResponseWriter, r *http.Request) {
	var req daytonaGitBranchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	repoPath, err := resolveGitPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if _, err := runGit(repoPath, "branch", req.Name); err != nil {
		writeGitError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaGitDeleteBranch(w http.ResponseWriter, r *http.Request) {
	var req daytonaGitDeleteBranchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	repoPath, err := resolveGitPath(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if _, err := runGit(repoPath, "branch", "-D", req.Name); err != nil {
		writeGitError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDaytonaGitListBranches(w http.ResponseWriter, r *http.Request) {
	repoPath, err := resolveGitPath(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	output, err := runGit(repoPath, "branch", "--format=%(refname:short)")
	if err != nil {
		writeGitError(w, err)
		return
	}
	branches := []string{}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			branches = append(branches, trimmed)
		}
	}
	writeJSON(w, http.StatusOK, daytonaListBranchesResponse{Branches: branches})
}

func (s *server) handleDaytonaGitHistory(w http.ResponseWriter, r *http.Request) {
	repoPath, err := resolveGitPath(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	output, err := runGit(repoPath, "log", "--date=iso-strict", "--pretty=format:%H%x00%an%x00%ae%x00%cI%x00%s")
	if err != nil {
		writeGitError(w, err)
		return
	}
	commits := []daytonaGitCommitInfo{}
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "\x00", 5)
		if len(parts) != 5 {
			continue
		}
		commits = append(commits, daytonaGitCommitInfo{Hash: parts[0], Author: parts[1], Email: parts[2], Timestamp: parts[3], Message: parts[4]})
	}
	writeJSON(w, http.StatusOK, commits)
}

func (s *server) handleDaytonaGitStatus(w http.ResponseWriter, r *http.Request) {
	repoPath, err := resolveGitPath(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	output, err := runGit(repoPath, "status", "--porcelain=v1", "-b")
	if err != nil {
		writeGitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, parseGitStatus(output))
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

func resolveDaytonaPath(raw string, defaultToWorkDir bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		if !defaultToWorkDir {
			return "", errors.New("path is required")
		}
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return cwd, nil
	}
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed), nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Clean(filepath.Join(cwd, trimmed)), nil
}

func resolveGitPath(raw string) (string, error) {
	path, err := resolveDaytonaPath(raw, false)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

func matchesPattern(root, fullPath, name, pattern string) bool {
	if ok, _ := filepath.Match(pattern, name); ok {
		return true
	}
	rel, err := filepath.Rel(root, fullPath)
	if err == nil {
		if ok, _ := filepath.Match(pattern, rel); ok {
			return true
		}
	}
	return false
}

func fileOwnerGroup(info os.FileInfo) (string, string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", ""
	}
	uid := strconv.FormatUint(uint64(stat.Uid), 10)
	gid := strconv.FormatUint(uint64(stat.Gid), 10)
	owner := uid
	group := gid
	if found, err := user.LookupId(uid); err == nil && strings.TrimSpace(found.Username) != "" {
		owner = found.Username
	}
	if found, err := user.LookupGroupId(gid); err == nil && strings.TrimSpace(found.Name) != "" {
		group = found.Name
	}
	return owner, group
}

func clampInt32(value int64) int32 {
	if value > int64(^uint32(0)>>1) {
		return int32(^uint32(0) >> 1)
	}
	if value < 0 {
		return 0
	}
	return int32(value)
}

func writeFilesystemError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, os.ErrPermission):
		status = http.StatusForbidden
	}
	writeError(w, status, err.Error())
}

func writeGitError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	var gitErr *gitCommandError
	switch {
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, os.ErrPermission):
		status = http.StatusForbidden
	case errors.As(err, &gitErr):
		status = http.StatusBadRequest
	}
	writeError(w, status, err.Error())
}

func runGit(repoPath string, args ...string) (string, error) {
	return runGitNoRepo(append([]string{"-C", repoPath}, args...)...)
}

func runGitNoRepo(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return "", &gitCommandError{message: message}
	}
	return string(output), nil
}

func gitURLWithCredentials(rawURL, username, password string) string {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" && password == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return rawURL
	}
	if password != "" {
		parsed.User = url.UserPassword(username, password)
	} else {
		parsed.User = url.User(username)
	}
	return parsed.String()
}

func valueOrEmptyString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func parseGitStatus(output string) daytonaGitStatusResponse {
	response := daytonaGitStatusResponse{CurrentBranch: "HEAD", FileStatus: []daytonaGitFileStatus{}}
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "## ") {
			parseGitBranchHeader(strings.TrimPrefix(line, "## "), &response)
			continue
		}
		if len(line) < 3 {
			continue
		}
		statusCode := line[:2]
		name := strings.TrimSpace(line[3:])
		extra := ""
		if strings.Contains(name, " -> ") {
			parts := strings.SplitN(name, " -> ", 2)
			extra = parts[0]
			name = parts[1]
		}
		response.FileStatus = append(response.FileStatus, daytonaGitFileStatus{
			Extra:    extra,
			Name:     name,
			Staging:  mapGitStatus(statusCode[0], statusCode),
			Worktree: mapGitStatus(statusCode[1], statusCode),
		})
	}
	return response
}

func parseGitBranchHeader(header string, response *daytonaGitStatusResponse) {
	branchPart := header
	if split := strings.SplitN(header, "...", 2); len(split) == 2 {
		branchPart = split[0]
		published := true
		if strings.Contains(split[1], "[gone]") {
			published = false
		}
		response.BranchPublished = boolPtr(published)
		if index := strings.Index(split[1], "["); index >= 0 {
			parseAheadBehind(strings.Trim(split[1][index:], "[]"), response)
		}
	} else {
		response.BranchPublished = boolPtr(false)
	}
	branchPart = strings.TrimSpace(strings.SplitN(branchPart, " ", 2)[0])
	if branchPart != "" {
		response.CurrentBranch = branchPart
	}
}

func parseAheadBehind(raw string, response *daytonaGitStatusResponse) {
	for _, item := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(item)
		switch {
		case strings.HasPrefix(trimmed, "ahead "):
			if value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "ahead "))); err == nil {
				response.Ahead = int32Ptr(int32(value))
			}
		case strings.HasPrefix(trimmed, "behind "):
			if value, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(trimmed, "behind "))); err == nil {
				response.Behind = int32Ptr(int32(value))
			}
		}
	}
}

func mapGitStatus(value byte, code string) string {
	if strings.Contains(code, "U") || code == "AA" || code == "DD" {
		return "Updated but unmerged"
	}
	switch value {
	case ' ':
		return "Unmodified"
	case '?':
		return "Untracked"
	case 'M', 'T':
		return "Modified"
	case 'A':
		return "Added"
	case 'D':
		return "Deleted"
	case 'R':
		return "Renamed"
	case 'C':
		return "Copied"
	default:
		return "Modified"
	}
}

func boolPtr(value bool) *bool {
	return &value
}
