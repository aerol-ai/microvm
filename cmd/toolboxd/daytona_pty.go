package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/gorilla/websocket"
)

// Daytona SDK terminals (process.createPty and friends), plan E8. The wire
// shapes are the Daytona toolbox client's (toolbox-api-client-go v0.177.0,
// api_process.go and model_pty_*.go) and the SDK's WebSocket handling
// (sdk-go v0.177.0, pty_handle.go):
//
//	POST   /process/pty               create  → 201 {"sessionId"}
//	GET    /process/pty               list    → 200 {"sessions":[info]}
//	GET    /process/pty/{id}          info    → 200 info
//	POST   /process/pty/{id}/resize   resize  → 200 info
//	DELETE /process/pty/{id}          kill    → 200 {}
//	GET    /process/pty/{id}/connect  WebSocket
//
// The generated client decodes these bodies with DisallowUnknownFields and a
// list of required fields, so each one carries exactly the fields below.
//
// A terminal is a toolboxd session (cmd/toolboxd/sessions): sessions already
// give it an id, a replay buffer, fan-out to several clients, resize,
// signals, and a process that outlives a dropped connection, so a client
// reconnects to the same shell. The TTY exec stream does not fit: it kills
// the command when its socket drops and keeps no list. Terminals live in
// toolboxd next to the session state they own, not in the Daytona facade,
// so no session wire format leaks into sandboxd and no frames are rewritten
// on the cluster-forwarded path (plan E8, design-twice).
//
// WebSocket protocol on connect, as the Daytona SDK reads it:
//
//	server → client: first a text frame {"type":"control","status":"connected"},
//	                 then the terminal's output as binary frames (the replay
//	                 buffer first, then live output), and when the shell
//	                 exits a close frame (1000) whose reason is
//	                 {"exitCode":N} plus "exitReason" for a signal.
//	client → server: binary or text frames are keyboard input. Resize and
//	                 kill go through the REST routes.

const (
	// daytonaPTYLimit is how many terminals one sandbox may hold. Each one
	// keeps a replay buffer (SB_SESSION_BUFFER_BYTES, 1 MiB by default) in
	// toolboxd, which is PID 1 of the sandbox: an agent that opens terminals
	// in a loop would otherwise grow toolboxd until the OOM killer takes it
	// and every toolbox call fails. 32 bounds that memory at 32 MiB with the
	// default buffer (about 3% of a default 1 GiB sandbox) and is far above
	// what an agent or a terminal UI uses at once. A finished terminal counts
	// until its buffer is freed, so the bound holds (R11).
	daytonaPTYLimit = 32
	// daytonaPTYRetention is how long a finished terminal keeps its replay
	// buffer: long enough for a client whose connection dropped as the shell
	// exited to reconnect and read the last output, short enough that a
	// finished terminal does not hold its slot for long.
	daytonaPTYRetention = 30 * time.Second
	// daytonaPTYKeepFinished is how many finished terminals keep their exit
	// status after their buffer is freed. Older ones are forgotten, so a
	// sandbox that churns terminals for days does not grow without bound.
	daytonaPTYKeepFinished = 32
	// daytonaPTYHangupGrace is how long kill waits for the shell to exit on
	// SIGHUP, passing it on to its jobs, before it sends SIGKILL.
	daytonaPTYHangupGrace = time.Second
	// daytonaPTYKillWait bounds how long kill waits for the process to be
	// gone after SIGKILL, so a terminal reads as gone when kill returns.
	daytonaPTYKillWait = 2 * time.Second
	// daytonaPTYDefaultTerm is TERM for a terminal whose client set none.
	// Full-screen programs (top, vim, less) refuse to run without it.
	daytonaPTYDefaultTerm = "xterm-256color"
	// daytonaPTYIDMaxLen bounds a client-chosen terminal id.
	daytonaPTYIDMaxLen = 128
	// daytonaPTYMaxWinsize is the largest window size a terminal takes: the
	// kernel stores it in 16 bits.
	daytonaPTYMaxWinsize = 65535
)

// daytonaPTYUpgrader answers a failed upgrade in toolboxd's JSON error shape,
// like every other terminal error, instead of gorilla's plain text.
var daytonaPTYUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
	Error: func(w http.ResponseWriter, _ *http.Request, status int, reason error) {
		writeError(w, status, reason.Error())
	},
}

// daytonaPTYCreateRequest is Daytona's PtyCreateRequest.
type daytonaPTYCreateRequest struct {
	ID   string            `json:"id,omitempty"`
	Cwd  string            `json:"cwd,omitempty"`
	Envs map[string]string `json:"envs,omitempty"`
	Cols int               `json:"cols,omitempty"`
	Rows int               `json:"rows,omitempty"`
	// LazyStart asks Daytona to start the shell on the first connect, so
	// the client sees its first output. The shell starts at once here: the
	// replay buffer hands a client that connects later everything the
	// shell has written, which is what lazy start is for.
	LazyStart bool `json:"lazyStart,omitempty"`
}

// daytonaPTYCreateResponse is Daytona's PtyCreateResponse.
type daytonaPTYCreateResponse struct {
	SessionID string `json:"sessionId"`
}

// daytonaPTYResizeRequest is Daytona's PtyResizeRequest.
type daytonaPTYResizeRequest struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// daytonaPTYInfo is Daytona's PtySessionInfo. Every field is required and
// no other field is allowed.
type daytonaPTYInfo struct {
	Active    bool              `json:"active"`
	Cols      int               `json:"cols"`
	CreatedAt string            `json:"createdAt"`
	Cwd       string            `json:"cwd"`
	Envs      map[string]string `json:"envs"`
	ID        string            `json:"id"`
	LazyStart bool              `json:"lazyStart"`
	Rows      int               `json:"rows"`
}

// daytonaPTYList is Daytona's PtyListResponse.
type daytonaPTYList struct {
	Sessions []daytonaPTYInfo `json:"sessions"`
}

// daytonaPTYControl is the SDK's control message.
type daytonaPTYControl struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// daytonaPTYExit is the close-frame reason the SDK parses for the exit.
type daytonaPTYExit struct {
	ExitCode   int    `json:"exitCode"`
	ExitReason string `json:"exitReason,omitempty"`
}

// daytonaPTY is one terminal. ready closes once sess or err is set; until
// then the terminal is being created and holds its id and its slot.
type daytonaPTY struct {
	id        string
	cwd       string
	envs      map[string]string
	createdAt time.Time

	ready chan struct{}
	sess  *sessions.Session
	err   error

	// released is set when the replay buffer is freed, after the
	// retention; the terminal then no longer counts toward the limit.
	released bool
}

// daytonaPTYs is the sandbox's terminals by Daytona id. The ids are the
// client's own (the SDK connects with the id it created, not the one
// returned), so they are kept here rather than as session names: a name
// can be taken by a v1, SSH or Daytona session of the same name.
type daytonaPTYs struct {
	mgr          *sessions.Manager
	logger       *slog.Logger
	limit        int
	retention    time.Duration
	keepFinished int

	mu   sync.Mutex
	byID map[string]*daytonaPTY
}

func newDaytonaPTYs(mgr *sessions.Manager, logger *slog.Logger) *daytonaPTYs {
	if logger == nil {
		logger = slog.Default()
	}
	return &daytonaPTYs{
		mgr:          mgr,
		logger:       logger,
		limit:        daytonaPTYLimit,
		retention:    daytonaPTYRetention,
		keepFinished: daytonaPTYKeepFinished,
		byID:         map[string]*daytonaPTY{},
	}
}

// daytonaPTYs returns the server's terminals, made on first use so every
// server (main's and the tests') has them.
func (s *server) daytonaPTYs() *daytonaPTYs {
	s.ptyOnce.Do(func() {
		if s.ptys == nil {
			s.ptys = newDaytonaPTYs(s.sessions, s.logger)
		}
	})
	return s.ptys
}

func isDaytonaPTYPath(path string) bool {
	return path == "/process/pty" || strings.HasPrefix(path, "/process/pty/")
}

// errDaytonaPTY is a terminal error with the HTTP status it answers.
type errDaytonaPTY struct {
	status  int
	message string
}

func (e *errDaytonaPTY) Error() string { return e.message }

func ptyError(status int, format string, args ...any) error {
	return &errDaytonaPTY{status: status, message: fmt.Sprintf(format, args...)}
}

func writeDaytonaPTYError(w http.ResponseWriter, err error) {
	var ptyErr *errDaytonaPTY
	if errors.As(err, &ptyErr) {
		writeError(w, ptyErr.status, ptyErr.message)
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

func (s *server) handleDaytonaPTYRoute(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeError(w, http.StatusNotImplemented, "sessions are disabled")
		return
	}
	ptys := s.daytonaPTYs()
	if r.URL.Path == "/process/pty" {
		switch r.Method {
		case http.MethodPost:
			s.handleDaytonaPTYCreate(w, r, ptys)
		case http.MethodGet:
			writeJSON(w, http.StatusOK, daytonaPTYList{Sessions: ptys.list()})
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	id, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/process/pty/"), "/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "terminal id is required")
		return
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		pty, err := ptys.get(r.Context(), id)
		if err != nil {
			writeDaytonaPTYError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, pty.info())
	case action == "" && r.Method == http.MethodDelete:
		if err := ptys.kill(r.Context(), id); err != nil {
			writeDaytonaPTYError(w, err)
			return
		}
		// The generated Go client decodes this body as a map of objects,
		// so an empty object is the one body every Daytona SDK accepts.
		writeJSON(w, http.StatusOK, struct{}{})
	case action == "resize" && r.Method == http.MethodPost:
		var req daytonaPTYResizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		info, err := ptys.resize(r.Context(), id, req.Cols, req.Rows)
		if err != nil {
			writeDaytonaPTYError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, info)
	case action == "connect" && r.Method == http.MethodGet:
		s.handleDaytonaPTYConnect(w, r, ptys, id)
	case action == "" || action == "resize" || action == "connect":
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		writeRouteNotFound(w)
	}
}

func (s *server) handleDaytonaPTYCreate(w http.ResponseWriter, r *http.Request, ptys *daytonaPTYs) {
	var req daytonaPTYCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id, created, err := ptys.create(r.Context(), req)
	if err != nil {
		writeDaytonaPTYError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, daytonaPTYCreateResponse{SessionID: id})
}

// validDaytonaPTYID refuses an id that cannot travel in a URL path segment:
// the SDK puts it in /process/pty/{id}/connect without escaping it.
func validDaytonaPTYID(id string) error {
	if len(id) > daytonaPTYIDMaxLen {
		return ptyError(http.StatusBadRequest, "terminal id is longer than %d characters", daytonaPTYIDMaxLen)
	}
	for _, c := range []byte(id) {
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`/\?#%`, c) >= 0 {
			return ptyError(http.StatusBadRequest, "terminal id %q has a character that cannot go in a URL path; use letters, digits, '-', '_' or '.'", id)
		}
	}
	return nil
}

func validDaytonaPTYSize(cols, rows int) error {
	if cols < 0 || rows < 0 || cols > daytonaPTYMaxWinsize || rows > daytonaPTYMaxWinsize {
		return ptyError(http.StatusBadRequest, "terminal size %dx%d is out of range (1 to %d)", cols, rows, daytonaPTYMaxWinsize)
	}
	return nil
}

func newDaytonaPTYID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return "pty-" + hex.EncodeToString(buf)
}

// create starts a terminal and reports whether it made a new one. Creating
// an id whose terminal is still running is idempotent: a retry after a lost
// reply, or a duplicate sent at the same time, gets that terminal (200)
// rather than a second shell, and exactly one caller sees 201. Reusing the
// id with a different folder or environment is a conflict (409). An id
// whose terminal has finished starts a fresh one.
func (p *daytonaPTYs) create(ctx context.Context, req daytonaPTYCreateRequest) (string, bool, error) {
	id := strings.TrimSpace(req.ID)
	if id == "" {
		id = newDaytonaPTYID()
	}
	if err := validDaytonaPTYID(id); err != nil {
		return "", false, err
	}
	if err := validDaytonaPTYSize(req.Cols, req.Rows); err != nil {
		return "", false, err
	}
	cwd := req.Cwd
	if cwd == "" {
		// The shell starts in toolboxd's folder; report it, as Daytona does.
		cwd, _ = os.Getwd()
	} else if info, err := os.Stat(cwd); err != nil || !info.IsDir() {
		return "", false, ptyError(http.StatusBadRequest, "cwd %q is not a folder in the sandbox", cwd)
	}
	envs := maps.Clone(req.Envs)
	if envs == nil {
		envs = map[string]string{}
	}

	var pty *daytonaPTY
	for pty == nil {
		p.mu.Lock()
		p.pruneLocked()
		existing, ok := p.byID[id]
		if ok && existing.isPending() {
			p.mu.Unlock()
			select {
			case <-existing.ready:
			case <-ctx.Done():
				return "", false, ctx.Err()
			}
			// The creator failed and dropped its claim: try again.
			continue
		}
		if ok && !existing.exited() {
			p.mu.Unlock()
			if existing.cwd != cwd || !maps.Equal(existing.envs, envs) {
				return "", false, ptyError(http.StatusConflict, "terminal %q is already running with another cwd or envs; kill it first or use another id", id)
			}
			return id, false, nil
		}
		if ok {
			// Finished: the id is free again.
			p.forgetLocked(existing)
		}
		if held := p.heldLocked(); held >= p.limit {
			p.mu.Unlock()
			p.logger.Warn("daytona terminal refused: limit reached", "terminal", id, "held", held, "limit", p.limit)
			return "", false, ptyError(http.StatusTooManyRequests,
				"this sandbox already has %d terminals (running, or finished in the last %s); kill one with killPtySession and try again",
				held, p.retention)
		}
		pty = &daytonaPTY{id: id, cwd: cwd, envs: envs, createdAt: time.Now().UTC(), ready: make(chan struct{})}
		p.byID[id] = pty
		p.mu.Unlock()
	}

	env := maps.Clone(envs)
	if _, ok := env["TERM"]; !ok {
		env["TERM"] = daytonaPTYDefaultTerm
	}
	sess, err := p.mgr.Create(ctx, models.CreateSessionRequest{
		// A unique name, as envd does: Create would otherwise take over the
		// name from a v1, SSH or Daytona session that already holds it.
		Name:    fmt.Sprintf("daytona-pty-%s-%d", id, time.Now().UTC().UnixNano()),
		WorkDir: req.Cwd,
		Env:     env,
		PTY:     true,
		Cols:    req.Cols,
		Rows:    req.Rows,
	})

	p.mu.Lock()
	pty.sess, pty.err = sess, err
	if err != nil && p.byID[id] == pty {
		delete(p.byID, id)
	}
	close(pty.ready)
	p.mu.Unlock()
	if err != nil {
		return "", false, daytonaPTYStartError(err)
	}
	go p.watch(pty)
	return id, true, nil
}

// daytonaPTYStartError is the answer for a shell that would not start. An
// image without a shell is the sandbox's own property, refused as v1
// sessions refuse it (400); anything else is toolboxd's failure.
func daytonaPTYStartError(err error) error {
	if errors.Is(err, sessions.ErrNoShell) {
		return ptyError(http.StatusBadRequest, "%s", err.Error())
	}
	return fmt.Errorf("start terminal: %w", err)
}

// watch frees a finished terminal's replay buffer after the retention. Its
// exit status stays, so info and connect still report how it ended.
func (p *daytonaPTYs) watch(pty *daytonaPTY) {
	<-pty.sess.Done()
	time.AfterFunc(p.retention, func() { p.release(pty) })
}

func (p *daytonaPTYs) release(pty *daytonaPTY) {
	if pty.sess.ReleaseReplay() {
		code, signal := pty.sess.ExitInfo()
		p.logger.Info("daytona terminal buffer freed", "terminal", pty.id, "session_id", pty.sess.ID(), "exit_code", code, "signal", signal)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pty.released = true
	if p.byID[pty.id] != pty {
		return
	}
	var finished []*daytonaPTY
	for _, other := range p.byID {
		if other.released {
			finished = append(finished, other)
		}
	}
	if len(finished) <= p.keepFinished {
		return
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].createdAt.Before(finished[j].createdAt) })
	for _, old := range finished[:len(finished)-p.keepFinished] {
		p.forgetLocked(old)
	}
}

// heldLocked counts the terminals that hold a replay buffer: running,
// being created, or finished within the retention.
func (p *daytonaPTYs) heldLocked() int {
	held := 0
	for _, pty := range p.byID {
		if !pty.released {
			held++
		}
	}
	return held
}

// pruneLocked forgets terminals whose session was deleted another way (the
// v1 /sessions API lists and deletes them too), so they free their slot.
func (p *daytonaPTYs) pruneLocked() {
	for _, pty := range p.byID {
		if pty.isPending() {
			continue
		}
		if current, err := p.mgr.Get(pty.sess.ID()); err != nil || current != pty.sess {
			delete(p.byID, pty.id)
		}
	}
}

// forgetLocked drops a finished terminal and its session record.
func (p *daytonaPTYs) forgetLocked(pty *daytonaPTY) {
	if p.byID[pty.id] == pty {
		delete(p.byID, pty.id)
	}
	_ = p.mgr.Delete(pty.sess.ID())
}

func (pty *daytonaPTY) isPending() bool {
	select {
	case <-pty.ready:
		return false
	default:
		return true
	}
}

// exited reads the session's exit flag rather than Done: the exit reaches a
// connected client (its stream closes) before Done closes, and info or
// resize right after must already see the terminal as finished.
func (pty *daytonaPTY) exited() bool {
	return pty.sess.Exited()
}

func (pty *daytonaPTY) info() daytonaPTYInfo {
	cols, rows := pty.sess.Size()
	return daytonaPTYInfo{
		Active:    !pty.exited(),
		Cols:      cols,
		CreatedAt: pty.createdAt.Format(time.RFC3339Nano),
		Cwd:       pty.cwd,
		Envs:      maps.Clone(pty.envs),
		ID:        pty.id,
		Rows:      rows,
	}
}

// get returns a terminal that exists, waiting for one being created.
func (p *daytonaPTYs) get(ctx context.Context, id string) (*daytonaPTY, error) {
	for {
		p.mu.Lock()
		p.pruneLocked()
		pty, ok := p.byID[id]
		p.mu.Unlock()
		if !ok {
			return nil, ptyError(http.StatusNotFound, "terminal %q not found", id)
		}
		select {
		case <-pty.ready:
			if pty.err == nil {
				return pty, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (p *daytonaPTYs) list() []daytonaPTYInfo {
	p.mu.Lock()
	p.pruneLocked()
	ptys := make([]*daytonaPTY, 0, len(p.byID))
	for _, pty := range p.byID {
		if !pty.isPending() {
			ptys = append(ptys, pty)
		}
	}
	p.mu.Unlock()
	sort.Slice(ptys, func(i, j int) bool { return ptys[i].createdAt.Before(ptys[j].createdAt) })
	out := make([]daytonaPTYInfo, 0, len(ptys))
	for _, pty := range ptys {
		out = append(out, pty.info())
	}
	return out
}

func (p *daytonaPTYs) resize(ctx context.Context, id string, cols, rows int) (daytonaPTYInfo, error) {
	if cols < 1 || rows < 1 {
		return daytonaPTYInfo{}, ptyError(http.StatusBadRequest, "cols and rows must be at least 1")
	}
	if err := validDaytonaPTYSize(cols, rows); err != nil {
		return daytonaPTYInfo{}, err
	}
	pty, err := p.get(ctx, id)
	if err != nil {
		return daytonaPTYInfo{}, err
	}
	if pty.exited() {
		return daytonaPTYInfo{}, ptyError(http.StatusConflict, "terminal %q has exited", id)
	}
	if err := pty.sess.Resize(cols, rows); err != nil {
		return daytonaPTYInfo{}, ptyError(http.StatusConflict, "resize terminal %q: %v", id, err)
	}
	return pty.info(), nil
}

// kill ends a terminal and everything running in it, then forgets it. It
// hangs up first, as closing a terminal window does, so the shell passes
// SIGHUP to its jobs; the jobs sit in process groups of their own, which
// SIGKILL to the shell's group would miss. SIGKILL follows for a shell that
// ignores the hangup.
func (p *daytonaPTYs) kill(ctx context.Context, id string) error {
	pty, err := p.get(ctx, id)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.byID[id] == pty {
		delete(p.byID, id)
	}
	p.mu.Unlock()

	sess := pty.sess
	if !pty.exited() {
		// SIGHUP first, so the shell can pass it to its jobs and they can
		// exit cleanly; then everything still holding the terminal is
		// killed. A job started under job control (`server &`) sits in a
		// process group of its own that a kill of the shell's group misses,
		// and it keeps the terminal open, so without this the session never
		// finishes and a connected client never sees the end. The kill runs
		// before Hangup: it finds the holders by the terminal's number,
		// which stays ours only while the master is open.
		_ = sess.Signal("HUP")
		waitDone(sess.Done(), daytonaPTYHangupGrace)
		if !pty.exited() {
			sess.KillTerminal()
		}
		sess.Hangup()
	}
	if err := p.mgr.Delete(sess.ID()); err != nil && !errors.Is(err, sessions.ErrNotFound) {
		return err
	}
	waitDone(sess.Done(), daytonaPTYKillWait)
	return nil
}

func waitDone(done <-chan struct{}, limit time.Duration) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// handleDaytonaPTYConnect attaches a client to a terminal. A dropped
// connection only detaches it: the shell keeps running, and a client that
// connects again gets the replay buffer and then live output.
func (s *server) handleDaytonaPTYConnect(w http.ResponseWriter, r *http.Request, ptys *daytonaPTYs, id string) {
	pty, err := ptys.get(r.Context(), id)
	if err != nil {
		writeDaytonaPTYError(w, err)
		return
	}
	conn, err := daytonaPTYUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Warn("daytona terminal upgrade failed", "terminal", id, "error", err)
		return
	}
	defer conn.Close()

	sess := pty.sess
	frames, unsubscribe := sess.Subscribe()
	defer unsubscribe()
	// Pings keep proxies that close idle WebSockets from cutting a quiet
	// terminal, and a client that vanished is noticed by the read deadline.
	extend, stopLiveness := armExecStreamLiveness(conn, s.execStreamLiveness())
	defer stopLiveness()

	if err := conn.WriteJSON(daytonaPTYControl{Type: "control", Status: "connected"}); err != nil {
		return
	}

	clientGone := make(chan struct{})
	go func() {
		defer close(clientGone)
		// Closing unblocks a frame write stuck on a client that stopped
		// reading.
		defer conn.Close()
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			extend()
			// Input after the shell exited has nowhere to go; the exit
			// reaches the client through the frames below.
			_, _ = sess.Write(data)
		}
	}()

	for {
		select {
		case <-clientGone:
			return
		case frame, ok := <-frames:
			if !ok {
				code, signal := sess.ExitInfo()
				reason := daytonaPTYExitReason(code, signal)
				_ = conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, reason),
					time.Now().Add(time.Second))
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, frame.Data); err != nil {
				return
			}
		}
	}
}

// daytonaPTYExitReason is the close-frame reason for a finished terminal. A
// close reason holds at most 123 bytes, so a long signal text is dropped
// rather than the exit code.
func daytonaPTYExitReason(code int, signal string) string {
	exit := daytonaPTYExit{ExitCode: code}
	if signal != "" {
		exit.ExitReason = "terminated by signal: " + signal
	}
	reason, _ := json.Marshal(exit)
	if len(reason) > 123 {
		reason, _ = json.Marshal(daytonaPTYExit{ExitCode: code})
	}
	return string(reason)
}
