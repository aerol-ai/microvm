package main

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	envdPrefix               = "/envd"
	connectEnvelopeHeaderLen = 5
	connectFlagEndStream     = 0x02
	connectFlagCompressed    = 0x01
	envdFileTypeFile         = "FILE_TYPE_FILE"
	envdFileTypeDirectory    = "FILE_TYPE_DIRECTORY"
)

var errEnvdProcessTagConflict = errors.New("process tag already in use")

type envdCompat struct {
	mu    sync.RWMutex
	byPID map[int]*envdProcessState
	byTag map[string]int
}

type envdProcessState struct {
	PID       int
	SessionID string
	Tag       string
	Config    envdProcessConfig
	PTY       bool
	Stdin     bool
}

type envdProcessConfig struct {
	Cmd  string            `json:"cmd,omitempty"`
	Args []string          `json:"args,omitempty"`
	Envs map[string]string `json:"envs,omitempty"`
	Cwd  string            `json:"cwd,omitempty"`
}

type envdPTY struct {
	Size *envdPTYSize `json:"size,omitempty"`
}

type envdPTYSize struct {
	Cols uint32 `json:"cols,omitempty"`
	Rows uint32 `json:"rows,omitempty"`
}

type envdProcessSelector struct {
	PID *int   `json:"pid,omitempty"`
	Tag string `json:"tag,omitempty"`
}

type envdStartRequest struct {
	Process envdProcessConfig `json:"process"`
	PTY     *envdPTY          `json:"pty,omitempty"`
	Tag     string            `json:"tag,omitempty"`
	Stdin   *bool             `json:"stdin,omitempty"`
}

type envdConnectRequest struct {
	Process envdProcessSelector `json:"process"`
}

type envdUpdateRequest struct {
	Process envdProcessSelector `json:"process"`
	PTY     *envdPTY            `json:"pty,omitempty"`
}

type envdSendInputRequest struct {
	Process envdProcessSelector `json:"process"`
	Input   envdProcessInput    `json:"input"`
}

type envdProcessInput struct {
	Stdin string `json:"stdin,omitempty"`
	PTY   string `json:"pty,omitempty"`
}

type envdSendSignalRequest struct {
	Process envdProcessSelector `json:"process"`
	Signal  string              `json:"signal"`
}

type envdCloseStdinRequest struct {
	Process envdProcessSelector `json:"process"`
}

type envdListResponse struct {
	Processes []envdProcessInfo `json:"processes"`
}

type envdProcessInfo struct {
	Config envdProcessConfig `json:"config"`
	PID    int               `json:"pid"`
	Tag    string            `json:"tag,omitempty"`
}

type envdProcessEvent struct {
	Start     *envdProcessStartEvent `json:"start,omitempty"`
	Data      *envdProcessDataEvent  `json:"data,omitempty"`
	End       *envdProcessEndEvent   `json:"end,omitempty"`
	Keepalive *struct{}              `json:"keepalive,omitempty"`
}

type envdProcessStartEvent struct {
	PID int `json:"pid"`
}

type envdProcessDataEvent struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	PTY    string `json:"pty,omitempty"`
}

type envdProcessEndEvent struct {
	ExitCode int    `json:"exitCode"`
	Exited   bool   `json:"exited"`
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

type envdProcessStreamResponse struct {
	Event envdProcessEvent `json:"event"`
}

type envdEmptyResponse struct{}

type envdStatRequest struct {
	Path string `json:"path"`
}

type envdStatResponse struct {
	Entry envdEntryInfo `json:"entry"`
}

type envdMakeDirRequest struct {
	Path string `json:"path"`
}

type envdMakeDirResponse struct {
	Entry envdEntryInfo `json:"entry"`
}

type envdMoveRequest struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

type envdMoveResponse struct {
	Entry envdEntryInfo `json:"entry"`
}

type envdListDirRequest struct {
	Path  string `json:"path"`
	Depth uint32 `json:"depth,omitempty"`
}

type envdListDirResponse struct {
	Entries []envdEntryInfo `json:"entries"`
}

type envdRemoveRequest struct {
	Path string `json:"path"`
}

type envdEntryInfo struct {
	Name          string  `json:"name"`
	Type          string  `json:"type"`
	Path          string  `json:"path"`
	Size          int64   `json:"size"`
	Mode          uint32  `json:"mode"`
	Permissions   string  `json:"permissions"`
	Owner         string  `json:"owner"`
	Group         string  `json:"group"`
	ModifiedTime  string  `json:"modifiedTime"`
	SymlinkTarget *string `json:"symlinkTarget,omitempty"`
}

type envdWriteInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Path string `json:"path"`
}

type envdErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type connectJSONStream struct {
	w http.ResponseWriter
}

func newEnvdCompat() *envdCompat {
	return &envdCompat{
		byPID: map[int]*envdProcessState{},
		byTag: map[string]int{},
	}
}

func (c *envdCompat) registerSession(sess *sessions.Session, tag string, cfg envdProcessConfig, pty, stdin bool) (*envdProcessState, error) {
	if c == nil {
		return nil, errors.New("envd state is not available")
	}
	if sess == nil {
		return nil, errors.New("session is required")
	}
	pid := sess.PID()
	if pid <= 0 {
		return nil, errors.New("session pid is not available")
	}
	tag = strings.TrimSpace(tag)

	c.mu.Lock()
	defer c.mu.Unlock()
	if tag != "" {
		if existingPID, ok := c.byTag[tag]; ok {
			if _, ok := c.byPID[existingPID]; ok {
				return nil, errEnvdProcessTagConflict
			}
		}
	}
	state := &envdProcessState{
		PID:       pid,
		SessionID: sess.ID(),
		Tag:       tag,
		Config: envdProcessConfig{
			Cmd:  strings.TrimSpace(cfg.Cmd),
			Args: append([]string{}, cfg.Args...),
			Envs: cloneEnvdStringMap(cfg.Envs),
			Cwd:  strings.TrimSpace(cfg.Cwd),
		},
		PTY:   pty,
		Stdin: stdin,
	}
	c.byPID[pid] = state
	if tag != "" {
		c.byTag[tag] = pid
	}
	return cloneEnvdProcessState(state), nil
}

func (c *envdCompat) removeSession(pid int, sessionID string) {
	if c == nil || pid <= 0 {
		return
	}
	c.mu.Lock()
	state, ok := c.byPID[pid]
	if ok && state.SessionID == sessionID {
		delete(c.byPID, pid)
		if state.Tag != "" && c.byTag[state.Tag] == pid {
			delete(c.byTag, state.Tag)
		}
	}
	c.mu.Unlock()
}

func (c *envdCompat) lookup(selector envdProcessSelector) (*envdProcessState, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if selector.PID != nil {
		state, ok := c.byPID[*selector.PID]
		if !ok {
			return nil, false
		}
		return cloneEnvdProcessState(state), true
	}
	tag := strings.TrimSpace(selector.Tag)
	if tag == "" {
		return nil, false
	}
	pid, ok := c.byTag[tag]
	if !ok {
		return nil, false
	}
	state, ok := c.byPID[pid]
	if !ok {
		return nil, false
	}
	return cloneEnvdProcessState(state), true
}

func (c *envdCompat) list() []*envdProcessState {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	items := make([]*envdProcessState, 0, len(c.byPID))
	for _, state := range c.byPID {
		items = append(items, cloneEnvdProcessState(state))
	}
	c.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].PID < items[j].PID })
	return items
}

func cloneEnvdProcessState(state *envdProcessState) *envdProcessState {
	if state == nil {
		return nil
	}
	cloned := *state
	cloned.Config = envdProcessConfig{
		Cmd:  state.Config.Cmd,
		Args: append([]string{}, state.Config.Args...),
		Envs: cloneEnvdStringMap(state.Config.Envs),
		Cwd:  state.Config.Cwd,
	}
	return &cloned
}

func cloneEnvdStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func (s *server) handleEnvdRoute(w http.ResponseWriter, r *http.Request) bool {
	if !validateEnvdRequestedUser(w, r) {
		return true
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == envdPrefix+"/health":
		s.handleEnvdHealth(w, r)
	case r.Method == http.MethodGet && r.URL.Path == envdPrefix+"/files":
		s.handleEnvdFileRead(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/files":
		s.handleEnvdFileWrite(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/List":
		s.handleEnvdProcessList(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/Start":
		s.handleEnvdProcessStart(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/Connect":
		s.handleEnvdProcessConnect(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/Update":
		s.handleEnvdProcessUpdate(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/SendInput":
		s.handleEnvdProcessSendInput(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/SendSignal":
		s.handleEnvdProcessSendSignal(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/CloseStdin":
		s.handleEnvdProcessCloseStdin(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/process.Process/StreamInput":
		writeEnvdError(w, http.StatusNotImplemented, "process stream input is not implemented")
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/Stat":
		s.handleEnvdFilesystemStat(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/MakeDir":
		s.handleEnvdFilesystemMakeDir(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/Move":
		s.handleEnvdFilesystemMove(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/ListDir":
		s.handleEnvdFilesystemListDir(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/Remove":
		s.handleEnvdFilesystemRemove(w, r)
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/WatchDir":
		writeEnvdError(w, http.StatusNotImplemented, "filesystem watchers are not implemented")
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/CreateWatcher":
		writeEnvdError(w, http.StatusNotImplemented, "filesystem watchers are not implemented")
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/GetWatcherEvents":
		writeEnvdError(w, http.StatusNotImplemented, "filesystem watchers are not implemented")
	case r.Method == http.MethodPost && r.URL.Path == envdPrefix+"/filesystem.Filesystem/RemoveWatcher":
		writeEnvdError(w, http.StatusNotImplemented, "filesystem watchers are not implemented")
	default:
		return false
	}
	return true
}

func validateEnvdRequestedUser(w http.ResponseWriter, r *http.Request) bool {
	username, err := requestedEnvdUsername(r)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return false
	}
	if username == "" || isSupportedEnvdUser(username) {
		return true
	}
	writeEnvdError(w, http.StatusNotImplemented, fmt.Sprintf("envd user %q is not supported", username))
	return false
}

func requestedEnvdUsername(r *http.Request) (string, error) {
	if r == nil {
		return "", nil
	}
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	if basic := strings.TrimSpace(r.Header.Get("X-E2B-User-Authorization")); basic != "" {
		basicUsername, err := parseEnvdBasicUsername(basic)
		if err != nil {
			return "", err
		}
		if username != "" && basicUsername != "" && username != basicUsername {
			return "", errors.New("conflicting envd users")
		}
		if username == "" {
			username = basicUsername
		}
	}
	return username, nil
}

func parseEnvdBasicUsername(header string) (string, error) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("invalid envd user authorization")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	if err != nil {
		return "", errors.New("invalid envd user authorization")
	}
	username, _, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return "", errors.New("invalid envd user authorization")
	}
	return strings.TrimSpace(username), nil
}

func isSupportedEnvdUser(username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return true
	}
	if username == "root" {
		return os.Geteuid() == 0
	}
	for _, current := range []string{os.Getenv("USER"), os.Getenv("LOGNAME")} {
		if current != "" && username == current {
			return true
		}
	}
	return false
}

func (s *server) handleEnvdHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version.Version})
}

func (s *server) handleEnvdFileRead(w http.ResponseWriter, r *http.Request) {
	targetPath, err := resolveDaytonaPath(r.URL.Query().Get("path"), false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *server) handleEnvdFileWrite(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "application/octet-stream") {
		s.handleEnvdOctetStreamWrite(w, r)
		return
	}
	s.handleEnvdMultipartWrite(w, r)
}

func (s *server) handleEnvdOctetStreamWrite(w http.ResponseWriter, r *http.Request) {
	targetPath, err := resolveDaytonaPath(r.URL.Query().Get("path"), false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	var reader io.Reader = r.Body
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			writeEnvdError(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer gz.Close()
		reader = gz
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	file, err := os.Create(targetPath)
	if err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	defer file.Close()
	if _, err := io.Copy(file, reader); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, []envdWriteInfo{buildEnvdWriteInfo(targetPath)})
}

func (s *server) handleEnvdMultipartWrite(w http.ResponseWriter, r *http.Request) {
	maxBytes := envInt64("SB_UPLOAD_MAX_BYTES", 256*1024*1024)
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeEnvdError(w, http.StatusBadRequest, "file is required")
		return
	}
	targetOverride := strings.TrimSpace(r.URL.Query().Get("path"))
	results := make([]envdWriteInfo, 0, len(files))
	for index, header := range files {
		targetPath := header.Filename
		if index == 0 && targetOverride != "" {
			targetPath = targetOverride
		}
		resolvedPath, err := resolveDaytonaPath(targetPath, false)
		if err != nil {
			writeEnvdError(w, http.StatusBadRequest, err.Error())
			return
		}
		file, err := header.Open()
		if err != nil {
			writeEnvdFilesystemError(w, err)
			return
		}
		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0o755); err != nil {
			file.Close()
			writeEnvdFilesystemError(w, err)
			return
		}
		output, err := os.Create(resolvedPath)
		if err != nil {
			file.Close()
			writeEnvdFilesystemError(w, err)
			return
		}
		_, copyErr := io.Copy(output, file)
		closeErr := output.Close()
		file.Close()
		if copyErr != nil {
			writeEnvdFilesystemError(w, copyErr)
			return
		}
		if closeErr != nil {
			writeEnvdFilesystemError(w, closeErr)
			return
		}
		results = append(results, buildEnvdWriteInfo(resolvedPath))
	}
	writeJSON(w, http.StatusOK, results)
}

func (s *server) handleEnvdProcessList(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeEnvdError(w, http.StatusServiceUnavailable, "sessions are disabled")
		return
	}
	states := s.envd.list()
	processes := make([]envdProcessInfo, 0, len(states))
	for _, state := range states {
		sess, err := s.sessions.Get(state.SessionID)
		if err != nil {
			s.envd.removeSession(state.PID, state.SessionID)
			continue
		}
		if code, signal := sess.ExitInfo(); code >= 0 || signal != "" {
			s.envd.removeSession(state.PID, state.SessionID)
			continue
		}
		processes = append(processes, envdProcessInfo{Config: state.Config, PID: state.PID, Tag: state.Tag})
	}
	writeJSON(w, http.StatusOK, envdListResponse{Processes: processes})
}

func (s *server) handleEnvdProcessStart(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeEnvdError(w, http.StatusServiceUnavailable, "sessions are disabled")
		return
	}
	var req envdStartRequest
	if err := readConnectJSONRequest(r, &req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Process.Cmd) == "" {
		writeEnvdError(w, http.StatusBadRequest, "process.cmd is required")
		return
	}
	argv := append([]string{req.Process.Cmd}, req.Process.Args...)
	createReq := models.CreateSessionRequest{
		Name:    uniqueEnvdSessionName(req.Tag),
		Argv:    argv,
		WorkDir: strings.TrimSpace(req.Process.Cwd),
		Env:     cloneEnvdStringMap(req.Process.Envs),
		PTY:     req.PTY != nil,
	}
	if req.PTY != nil && req.PTY.Size != nil {
		createReq.Cols = int(req.PTY.Size.Cols)
		createReq.Rows = int(req.PTY.Size.Rows)
	}
	sess, err := s.sessions.Create(r.Context(), createReq)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	stdinEnabled := req.Stdin != nil && *req.Stdin
	state, err := s.envd.registerSession(sess, req.Tag, req.Process, req.PTY != nil, stdinEnabled)
	if err != nil {
		_ = s.sessions.Delete(sess.ID())
		status := http.StatusInternalServerError
		if errors.Is(err, errEnvdProcessTagConflict) {
			status = http.StatusConflict
		}
		writeEnvdError(w, status, err.Error())
		return
	}
	go func(pid int, sessionID string, done <-chan struct{}) {
		<-done
		s.envd.removeSession(pid, sessionID)
	}(state.PID, state.SessionID, sess.Done())
	if err := s.streamEnvdProcessSession(w, r, sess, state); err != nil {
		s.logger.Debug("envd process start stream ended", "pid", state.PID, "error", err)
	}
}

func (s *server) handleEnvdProcessConnect(w http.ResponseWriter, r *http.Request) {
	state, sess, ok := s.lookupEnvdProcessSession(w, r)
	if !ok {
		return
	}
	if err := s.streamEnvdProcessSession(w, r, sess, state); err != nil {
		s.logger.Debug("envd process connect stream ended", "pid", state.PID, "error", err)
	}
}

func (s *server) handleEnvdProcessUpdate(w http.ResponseWriter, r *http.Request) {
	var req envdUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	_, sess, ok := s.lookupEnvdProcessSessionFromSelector(w, req.Process)
	if !ok {
		return
	}
	if req.PTY == nil || req.PTY.Size == nil {
		writeJSON(w, http.StatusOK, envdEmptyResponse{})
		return
	}
	if err := sess.Resize(int(req.PTY.Size.Cols), int(req.PTY.Size.Rows)); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envdEmptyResponse{})
}

func (s *server) handleEnvdProcessSendInput(w http.ResponseWriter, r *http.Request) {
	var req envdSendInputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	state, sess, ok := s.lookupEnvdProcessSessionFromSelector(w, req.Process)
	if !ok {
		return
	}
	payload, isPTY, err := req.Input.decode()
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !state.PTY && isPTY {
		writeEnvdError(w, http.StatusBadRequest, "pty input is not valid for a pipe process")
		return
	}
	if state.PTY && !isPTY {
		writeEnvdError(w, http.StatusBadRequest, "stdin input is not valid for a PTY process")
		return
	}
	if !state.PTY && !state.Stdin {
		writeEnvdError(w, http.StatusFailedDependency, "stdin is not enabled for this process")
		return
	}
	if _, err := sess.Write(payload); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envdEmptyResponse{})
}

func (s *server) handleEnvdProcessSendSignal(w http.ResponseWriter, r *http.Request) {
	var req envdSendSignalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	_, sess, ok := s.lookupEnvdProcessSessionFromSelector(w, req.Process)
	if !ok {
		return
	}
	signalName, err := mapEnvdSignal(req.Signal)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := sess.Signal(signalName); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envdEmptyResponse{})
}

func (s *server) handleEnvdProcessCloseStdin(w http.ResponseWriter, r *http.Request) {
	var req envdCloseStdinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	state, sess, ok := s.lookupEnvdProcessSessionFromSelector(w, req.Process)
	if !ok {
		return
	}
	if !state.PTY && !state.Stdin {
		writeJSON(w, http.StatusOK, envdEmptyResponse{})
		return
	}
	if err := sess.CloseStdin(); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envdEmptyResponse{})
}

func (s *server) streamEnvdProcessSession(w http.ResponseWriter, r *http.Request, sess *sessions.Session, state *envdProcessState) error {
	stream := startConnectJSONStream(w)
	if err := stream.Send(envdProcessStreamResponse{Event: envdProcessEvent{Start: &envdProcessStartEvent{PID: state.PID}}}); err != nil {
		return err
	}
	frames, cancel := sess.Subscribe()
	defer cancel()
	keepaliveTicker := newKeepaliveTicker(r)
	if keepaliveTicker != nil {
		defer keepaliveTicker.Stop()
	}
	for {
		select {
		case <-r.Context().Done():
			return r.Context().Err()
		case <-sess.Done():
			s.drainEnvdProcessFrames(stream, frames, state.PTY)
			code, signal := sess.ExitInfo()
			end := envdProcessEndEvent{ExitCode: code, Exited: true, Status: signal}
			if code != 0 {
				if signal != "" {
					end.Error = signal
				} else {
					end.Error = fmt.Sprintf("process exited with code %d", code)
				}
			}
			if err := stream.Send(envdProcessStreamResponse{Event: envdProcessEvent{End: &end}}); err != nil {
				return err
			}
			return stream.End()
		case frame, ok := <-frames:
			if !ok {
				continue
			}
			if err := stream.Send(envdProcessStreamResponse{Event: envdProcessEvent{Data: buildEnvdProcessDataEvent(frame, state.PTY)}}); err != nil {
				return err
			}
		case <-keepaliveChan(keepaliveTicker):
			if err := stream.Send(envdProcessStreamResponse{Event: envdProcessEvent{Keepalive: &struct{}{}}}); err != nil {
				return err
			}
		}
	}
}

func (s *server) drainEnvdProcessFrames(stream *connectJSONStream, frames <-chan sessions.Frame, isPTY bool) {
	for {
		select {
		case frame, ok := <-frames:
			if !ok {
				return
			}
			if err := stream.Send(envdProcessStreamResponse{Event: envdProcessEvent{Data: buildEnvdProcessDataEvent(frame, isPTY)}}); err != nil {
				return
			}
		default:
			return
		}
	}
}

func buildEnvdProcessDataEvent(frame sessions.Frame, isPTY bool) *envdProcessDataEvent {
	encoded := base64.StdEncoding.EncodeToString(frame.Data)
	data := &envdProcessDataEvent{}
	if isPTY {
		data.PTY = encoded
		return data
	}
	if frame.Stream == sessions.StreamStderr {
		data.Stderr = encoded
	} else {
		data.Stdout = encoded
	}
	return data
}

func (s *server) lookupEnvdProcessSession(w http.ResponseWriter, r *http.Request) (*envdProcessState, *sessions.Session, bool) {
	var req envdConnectRequest
	if err := readConnectJSONRequest(r, &req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return nil, nil, false
	}
	return s.lookupEnvdProcessSessionFromSelector(w, req.Process)
}

func (s *server) lookupEnvdProcessSessionFromSelector(w http.ResponseWriter, selector envdProcessSelector) (*envdProcessState, *sessions.Session, bool) {
	if s.sessions == nil {
		writeEnvdError(w, http.StatusServiceUnavailable, "sessions are disabled")
		return nil, nil, false
	}
	state, ok := s.envd.lookup(selector)
	if !ok {
		writeEnvdError(w, http.StatusNotFound, "process not found")
		return nil, nil, false
	}
	sess, err := s.sessions.Get(state.SessionID)
	if err != nil {
		s.envd.removeSession(state.PID, state.SessionID)
		writeEnvdError(w, http.StatusNotFound, "process not found")
		return nil, nil, false
	}
	if code, signal := sess.ExitInfo(); code >= 0 || signal != "" {
		s.envd.removeSession(state.PID, state.SessionID)
		writeEnvdError(w, http.StatusNotFound, "process not found")
		return nil, nil, false
	}
	return state, sess, true
}

func (s *server) handleEnvdFilesystemStat(w http.ResponseWriter, r *http.Request) {
	var req envdStatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	targetPath, err := resolveDaytonaPath(req.Path, false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	entry, err := buildEnvdEntryInfo(targetPath)
	if err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envdStatResponse{Entry: entry})
}

func (s *server) handleEnvdFilesystemMakeDir(w http.ResponseWriter, r *http.Request) {
	var req envdMakeDirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	targetPath, err := resolveDaytonaPath(req.Path, false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	if info, err := os.Stat(targetPath); err == nil {
		if info.IsDir() {
			writeEnvdError(w, http.StatusConflict, "directory already exists")
			return
		}
		writeEnvdError(w, http.StatusConflict, "path already exists")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		writeEnvdFilesystemError(w, err)
		return
	}
	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	entry, err := buildEnvdEntryInfo(targetPath)
	if err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envdMakeDirResponse{Entry: entry})
}

func (s *server) handleEnvdFilesystemMove(w http.ResponseWriter, r *http.Request) {
	var req envdMoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	source, err := resolveDaytonaPath(req.Source, false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	destination, err := resolveDaytonaPath(req.Destination, false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	if err := os.Rename(source, destination); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	entry, err := buildEnvdEntryInfo(destination)
	if err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envdMoveResponse{Entry: entry})
}

func (s *server) handleEnvdFilesystemListDir(w http.ResponseWriter, r *http.Request) {
	var req envdListDirRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Depth == 0 {
		req.Depth = 1
	}
	targetPath, err := resolveDaytonaPath(req.Path, false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := listEnvdEntries(targetPath, int(req.Depth))
	if err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envdListDirResponse{Entries: entries})
}

func (s *server) handleEnvdFilesystemRemove(w http.ResponseWriter, r *http.Request) {
	var req envdRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvdError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	targetPath, err := resolveDaytonaPath(req.Path, false)
	if err != nil {
		writeEnvdError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := os.Lstat(targetPath); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	if err := os.RemoveAll(targetPath); err != nil {
		writeEnvdFilesystemError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, envdEmptyResponse{})
}

func buildEnvdWriteInfo(path string) envdWriteInfo {
	return envdWriteInfo{Name: filepath.Base(path), Type: "file", Path: path}
}

func buildEnvdEntryInfo(path string) (envdEntryInfo, error) {
	return buildEnvdEntryInfoAt(path, path)
}

func buildEnvdEntryInfoAt(path, displayPath string) (envdEntryInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return envdEntryInfo{}, err
	}
	owner, group := fileOwnerGroup(info)
	entry := envdEntryInfo{
		Name:         filepath.Base(displayPath),
		Type:         envdFileTypeFile,
		Path:         displayPath,
		Size:         info.Size(),
		Mode:         uint32(info.Mode()),
		Permissions:  envdPermissionString(info.Mode()),
		Owner:        owner,
		Group:        group,
		ModifiedTime: info.ModTime().UTC().Format(time.RFC3339Nano),
	}
	if info.IsDir() {
		entry.Type = envdFileTypeDirectory
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			entry.SymlinkTarget = &target
		}
	}
	return entry, nil
}

func envdPermissionString(mode os.FileMode) string {
	text := mode.String()
	if len(text) == 0 {
		return ""
	}
	return text[1:]
}

func listEnvdEntries(root string, depth int) ([]envdEntryInfo, error) {
	walkRoot := root
	if resolvedRoot, err := filepath.EvalSymlinks(root); err == nil {
		if info, statErr := os.Stat(resolvedRoot); statErr == nil && info.IsDir() {
			walkRoot = resolvedRoot
		}
	}
	entries := []envdEntryInfo{}
	err := filepath.WalkDir(walkRoot, func(path string, entry iofs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == walkRoot {
			return nil
		}
		rel, err := filepath.Rel(walkRoot, path)
		if err != nil {
			return err
		}
		level := strings.Count(rel, string(os.PathSeparator)) + 1
		if level > depth {
			if entry.IsDir() {
				return iofs.SkipDir
			}
			return nil
		}
		displayPath := filepath.Join(root, rel)
		info, err := buildEnvdEntryInfoAt(path, displayPath)
		if err != nil {
			return err
		}
		entries = append(entries, info)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func (in envdProcessInput) decode() ([]byte, bool, error) {
	if in.PTY != "" {
		payload, err := base64.StdEncoding.DecodeString(in.PTY)
		if err != nil {
			return nil, false, errors.New("invalid pty input encoding")
		}
		return payload, true, nil
	}
	if in.Stdin == "" {
		return nil, false, errors.New("input is required")
	}
	payload, err := base64.StdEncoding.DecodeString(in.Stdin)
	if err != nil {
		return nil, false, errors.New("invalid stdin input encoding")
	}
	return payload, false, nil
}

func mapEnvdSignal(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "SIGNAL_SIGTERM", "15", "SIGTERM", "TERM":
		return "TERM", nil
	case "SIGNAL_SIGKILL", "9", "SIGKILL", "KILL":
		return "KILL", nil
	case "SIGNAL_UNSPECIFIED", "", "0":
		return "TERM", nil
	default:
		return "", fmt.Errorf("unsupported signal %q", raw)
	}
}

func uniqueEnvdSessionName(tag string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Sprintf("envd-%d", time.Now().UTC().UnixNano())
	}
	return fmt.Sprintf("envd-%s-%d", tag, time.Now().UTC().UnixNano())
}

func readConnectJSONRequest(r *http.Request, dst any) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if len(body) < connectEnvelopeHeaderLen {
		return errors.New("invalid connect request envelope")
	}
	flags := body[0]
	if flags&connectFlagCompressed != 0 {
		return errors.New("compressed connect requests are not supported")
	}
	size := binary.BigEndian.Uint32(body[1:connectEnvelopeHeaderLen])
	end := connectEnvelopeHeaderLen + int(size)
	if end > len(body) {
		return errors.New("truncated connect request envelope")
	}
	if err := json.Unmarshal(body[connectEnvelopeHeaderLen:end], dst); err != nil {
		return err
	}
	return nil
}

func startConnectJSONStream(w http.ResponseWriter) *connectJSONStream {
	w.Header().Set("Content-Type", "application/connect+json")
	w.WriteHeader(http.StatusOK)
	flushResponse(w)
	return &connectJSONStream{w: w}
}

func (s *connectJSONStream) Send(value any) error {
	return writeConnectEnvelope(s.w, 0, value)
}

func (s *connectJSONStream) End() error {
	return writeConnectEnvelope(s.w, connectFlagEndStream, map[string]any{})
}

func writeConnectEnvelope(w http.ResponseWriter, flags byte, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	header := make([]byte, connectEnvelopeHeaderLen)
	header[0] = flags
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	flushResponse(w)
	return nil
}

func newKeepaliveTicker(r *http.Request) *time.Ticker {
	raw := strings.TrimSpace(r.Header.Get("Keepalive-Ping-Interval"))
	if raw == "" {
		return nil
	}
	seconds, err := time.ParseDuration(raw + "s")
	if err != nil || seconds <= 0 {
		return nil
	}
	return time.NewTicker(seconds)
}

func keepaliveChan(ticker *time.Ticker) <-chan time.Time {
	if ticker == nil {
		return nil
	}
	return ticker.C
}

func flushResponse(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
}

func writeEnvdError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, envdErrorResponse{Code: status, Message: message})
}

func writeEnvdFilesystemError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, os.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, os.ErrPermission):
		status = http.StatusForbidden
	case errors.Is(err, os.ErrExist):
		status = http.StatusConflict
	}
	writeEnvdError(w, status, err.Error())
}
