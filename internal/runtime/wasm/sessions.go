package wasm

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/logring"
	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
)

// Daytona-style process sessions on WASM (issue #178). toolboxd runs a
// session's commands in a shell; a WASM sandbox has none, so each command
// is a streaming run of the sandbox's own module (StartStream) inside the
// wasm engine, with its command line as argv. What carries over from
// toolboxd is the contract: commands of one session run strictly one after
// another, a sync exec waits for its result, an async one returns its id at
// once, logs can be read in windows or followed live, input goes to the
// running command, and deleting a session kills what it runs. What cannot
// carry over is shell state: no working directory or environment passes
// from one command to the next.
//
// Everything a session keeps lives in sandboxd's heap, so all of it is
// capped: output per stream per command (the newest bytes are kept, offsets
// stay the stream's own), sessions per sandbox, finished commands per
// session (the oldest go first), and log storage per sandbox (finished
// commands' logs are dropped, oldest first, to make room). The state lives
// on the sandbox instance, not the toolhost, which is rebuilt per request,
// and it ends with the sandbox: stop, destroy, passivate and migrate close
// it (killStreams).

const (
	defaultSessionLogBytes       = 1 << 20
	defaultMaxSessionsPerSandbox = 16
	defaultSessionCommandsKept   = 64
	defaultSessionLogBudget      = 16 << 20

	// maxFollowersPerCommand and followerQueueBytes bound the live log
	// subscribers: a follower that stops reading has frames dropped, not
	// queued without end, and at most this many queue per command.
	maxFollowersPerCommand = 8
	followerQueueBytes     = 256 << 10

	// defaultSessionInputWait is how long /input waits for a command to
	// take its bytes. A command that does not read its stdin would
	// otherwise hold the request, and its body, for as long as it runs.
	defaultSessionInputWait = 10 * time.Second
)

// sessionLimits are the caps (Config.Session*), defaults filled in.
type sessionLimits struct {
	logBytes int   // kept per stream per command
	sessions int   // sessions per sandbox
	kept     int   // finished commands kept per session; also commands waiting
	budget   int64 // log storage per sandbox
	// inputWait bounds an /input write (defaultSessionInputWait).
	inputWait time.Duration
}

func (d *Driver) sessionLimits() sessionLimits {
	l := sessionLimits{
		logBytes:  d.cfg.SessionLogBytes,
		sessions:  d.cfg.MaxSessionsPerSandbox,
		kept:      d.cfg.SessionCommandsKept,
		budget:    d.cfg.SessionLogBudget,
		inputWait: defaultSessionInputWait,
	}
	if l.logBytes <= 0 {
		l.logBytes = defaultSessionLogBytes
	}
	if l.sessions <= 0 {
		l.sessions = defaultMaxSessionsPerSandbox
	}
	if l.kept <= 0 {
		l.kept = defaultSessionCommandsKept
	}
	if l.budget <= 0 {
		l.budget = defaultSessionLogBudget
	}
	return l
}

// sessionStarter starts one command's run.
type sessionStarter func(ctx context.Context, argv []string) (*Stream, error)

// sessionSet is one sandbox's sessions. One mutex guards all of it: the
// writers are at most one run per session, and every critical section is
// short (no worker round trips inside it).
type sessionSet struct {
	start  sessionStarter
	limits sessionLimits

	mu       sync.Mutex
	closed   bool
	sessions map[string]*session
	used     int64     // log storage allocated, every command
	retained list.List // finished commands still holding log storage, oldest first
	// entry are live follows of the entrypoint's output (entrypoint.go).
	entry map[*entrypointFollow]struct{}
}

type session struct {
	id       string
	commands map[string]*sessionCommand
	order    []*sessionCommand // oldest first
	// turn is held by the command that runs: one at a time, as toolboxd's
	// execMu. gone closes when the session is deleted or the sandbox stops,
	// so commands still waiting for their turn give up.
	turn       chan struct{}
	gone       chan struct{}
	deleted    bool
	unfinished int // waiting or running
	finished   int
}

type commandState int

const (
	commandWaiting commandState = iota
	commandRunning
	commandFinished
)

type sessionCommand struct {
	id   string
	text string
	// argv is what the run starts with; it goes once the run has started
	// or failed to, so a kept command holds its text once, not twice.
	argv     []string
	state    commandState
	exitCode int32
	stdout   logring.Ring
	stderr   logring.Ring
	// followers are live log subscribers; nil once the command ended.
	followers map[*logFollower]struct{}
	run       *Stream
	// stdinBusy is held by the one input write in flight, which happens
	// outside the set's lock: a write blocks while the guest is not
	// reading. Another input is refused while it is held, never queued.
	stdinBusy chan struct{}
	retained  *list.Element
}

// logFollower is one live subscriber's queue. Frames are queued under the
// set's lock and handed to the subscriber by its own goroutine, so a slow
// subscriber never blocks the run that produces them.
type logFollower struct {
	queue    [][]byte
	queued   int
	ended    bool // the command ended: send what is queued, then stop
	left     bool // the subscriber is gone
	wake     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
}

func newSessionSet(start sessionStarter, limits sessionLimits) *sessionSet {
	return &sessionSet{start: start, limits: limits, sessions: map[string]*session{}}
}

func newSessionCommandID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *sessionSet) create(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, toolhost.ErrSessionStopped
	}
	if _, ok := s.sessions[id]; ok {
		return false, nil
	}
	if len(s.sessions) >= s.limits.sessions {
		return false, toolhost.ErrTooManySessions
	}
	s.sessions[id] = &session{
		id:       id,
		commands: map[string]*sessionCommand{},
		turn:     make(chan struct{}, 1),
		gone:     make(chan struct{}),
	}
	return true, nil
}

func (s *sessionSet) list() []toolhost.SessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]toolhost.SessionInfo, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.sessions[id].info())
	}
	return out
}

func (s *sessionSet) get(id string) (toolhost.SessionInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[id]
	if sess == nil {
		return toolhost.SessionInfo{}, toolhost.ErrSessionNotFound
	}
	return sess.info(), nil
}

// info is the session as the toolhost shows it. Caller holds the lock.
func (sess *session) info() toolhost.SessionInfo {
	out := toolhost.SessionInfo{ID: sess.id, Commands: make([]toolhost.CommandInfo, 0, len(sess.order))}
	for _, c := range sess.order {
		out.Commands = append(out.Commands, c.info())
	}
	return out
}

func (c *sessionCommand) info() toolhost.CommandInfo {
	info := toolhost.CommandInfo{ID: c.id, Command: c.text, Running: c.state == commandRunning}
	if c.state == commandFinished {
		code := c.exitCode
		info.ExitCode = &code
	}
	return info
}

// lookup finds a session's command. Caller holds the lock.
func (s *sessionSet) lookup(sessionID, commandID string) (*session, *sessionCommand, error) {
	sess := s.sessions[sessionID]
	if sess == nil {
		return nil, nil, toolhost.ErrSessionNotFound
	}
	c := sess.commands[commandID]
	if c == nil {
		return nil, nil, toolhost.ErrCommandNotFound
	}
	return sess, c, nil
}

func (s *sessionSet) command(sessionID, commandID string) (toolhost.CommandInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, c, err := s.lookup(sessionID, commandID)
	if err != nil {
		return toolhost.CommandInfo{}, err
	}
	return c.info(), nil
}

// delete removes a session and kills its running command. Commands still
// waiting for their turn give up.
func (s *sessionSet) delete(id string) error {
	s.mu.Lock()
	sess := s.sessions[id]
	if sess == nil {
		s.mu.Unlock()
		return toolhost.ErrSessionNotFound
	}
	delete(s.sessions, id)
	run := s.endSessionLocked(sess)
	s.mu.Unlock()
	killRun(run)
	return nil
}

// endSessionLocked marks sess gone, frees the logs it keeps and returns its
// running command's run, which the caller kills outside the lock.
func (s *sessionSet) endSessionLocked(sess *session) *Stream {
	sess.deleted = true
	close(sess.gone)
	var run *Stream
	for _, c := range sess.order {
		switch {
		case c.state == commandFinished:
			s.releaseLogsLocked(c)
		case c.run != nil:
			run = c.run
		}
	}
	return run
}

// killRun ends a run over a fresh connection (its own may be stalled on
// stdin the guest never reads), then drops it.
func killRun(run *Stream) {
	if run == nil {
		return
	}
	_ = run.Kill()
	_ = run.Close()
}

// close ends every session with the sandbox (stop, destroy, passivate,
// migrate). Their runs are killed by the caller's killAll too; dropping
// them here as well makes close complete on its own.
func (s *sessionSet) close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	var runs []*Stream
	for _, sess := range s.sessions {
		if run := s.endSessionLocked(sess); run != nil {
			runs = append(runs, run)
		}
	}
	s.sessions = map[string]*session{}
	follows := s.entry
	s.entry = nil
	s.mu.Unlock()
	// In parallel: closing a run that has not exited is a kill round trip
	// to the worker, and a hung worker must not stretch a stop by one
	// timeout per session.
	var wg sync.WaitGroup
	for _, run := range runs {
		wg.Add(1)
		go func(run *Stream) {
			defer wg.Done()
			_ = run.Close()
		}(run)
	}
	wg.Wait()
	for f := range follows {
		f.close()
	}
}

// exec registers a command and runs it after the session's earlier ones.
// A command that can start now starts before exec returns, so a refused
// start (no free run slot, a worker that cannot stream) is this request's
// error; an async command queued behind another reports a refused start as
// its own result instead.
func (s *sessionSet) exec(ctx context.Context, sessionID string, cmd toolhost.SessionCommand, async bool) (toolhost.CommandResult, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return toolhost.CommandResult{}, toolhost.ErrSessionStopped
	}
	sess := s.sessions[sessionID]
	if sess == nil {
		s.mu.Unlock()
		return toolhost.CommandResult{}, toolhost.ErrSessionNotFound
	}
	if sess.unfinished >= s.limits.kept {
		s.mu.Unlock()
		return toolhost.CommandResult{}, toolhost.ErrTooManyCommands
	}
	idle := sess.unfinished == 0
	c := &sessionCommand{id: newSessionCommandID(), text: cmd.Text, argv: cmd.Argv,
		followers: map[*logFollower]struct{}{}, stdinBusy: make(chan struct{}, 1)}
	sess.commands[c.id] = c
	sess.order = append(sess.order, c)
	sess.unfinished++
	s.mu.Unlock()

	if async && !idle {
		go s.runQueued(sess, c)
		return toolhost.CommandResult{ID: c.id}, nil
	}
	run, err := s.begin(ctx, sess, c)
	if err != nil {
		s.drop(sess, c)
		return toolhost.CommandResult{}, err
	}
	if async {
		go s.pump(sess, c, run, false)
		return toolhost.CommandResult{ID: c.id}, nil
	}
	return s.pump(sess, c, run, true), nil
}

// begin waits for the session's turn and starts c's run. On error the turn
// is not held.
func (s *sessionSet) begin(ctx context.Context, sess *session, c *sessionCommand) (*Stream, error) {
	select {
	case sess.turn <- struct{}{}:
	case <-sess.gone:
		return nil, s.goneError()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	run, err := s.start(ctx, c.argv)
	s.mu.Lock()
	c.argv = nil
	if err != nil {
		s.mu.Unlock()
		<-sess.turn
		return nil, err
	}
	if sess.deleted {
		s.mu.Unlock()
		killRun(run)
		<-sess.turn
		return nil, s.goneError()
	}
	c.state, c.run = commandRunning, run
	s.mu.Unlock()
	return run, nil
}

// goneError says why a session went away under a waiting command.
func (s *sessionSet) goneError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return toolhost.ErrSessionStopped
	}
	return toolhost.ErrSessionNotFound
}

// runQueued is an async command queued behind another. Nobody waits on its
// request any more, so a refused start becomes its result: exit code -1
// and the reason on stderr.
func (s *sessionSet) runQueued(sess *session, c *sessionCommand) {
	run, err := s.begin(context.Background(), sess, c)
	if err != nil {
		s.mu.Lock()
		s.writeLocked(c, true, []byte(err.Error()+"\n"))
		s.mu.Unlock()
		s.finish(sess, c, -1, false)
		return
	}
	s.pump(sess, c, run, false)
}

// pump moves c's output into its logs and followers until the run ends,
// records the exit and frees the session's turn. With result it returns
// the command's result, read before anything can evict it.
func (s *sessionSet) pump(sess *session, c *sessionCommand, run *Stream, result bool) toolhost.CommandResult {
	// Killed, or the run's connection dropped (the session was deleted,
	// the sandbox stopped, the worker died): -1, as the exec stream
	// reports a killed run.
	exit := int32(-1)
	for {
		ev, err := run.Recv()
		if err != nil {
			break
		}
		if ev.Exit != nil {
			if ev.Exit.Error != "" {
				// A trap (out of memory, unreachable) has no stderr of
				// its own; say what happened.
				s.output(c, nil, []byte(ev.Exit.Error+"\n"))
			}
			if !ev.Exit.Killed && !ev.Exit.TimedOut {
				exit = int32(ev.Exit.ExitCode)
			}
			break
		}
		s.output(c, ev.Stdout, ev.Stderr)
	}
	_ = run.Close()
	res := s.finish(sess, c, exit, result)
	<-sess.turn
	return res
}

func (s *sessionSet) output(c *sessionCommand, stdout, stderr []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(stdout) > 0 {
		s.writeLocked(c, false, stdout)
	}
	if len(stderr) > 0 {
		s.writeLocked(c, true, stderr)
	}
}

// writeLocked keeps p in c's log and sends it to c's followers.
func (s *sessionSet) writeLocked(c *sessionCommand, stderr bool, p []byte) {
	ring := &c.stdout
	if stderr {
		ring = &c.stderr
	}
	ring.Write(p, s.limits.logBytes, s.growLocked)
	if len(c.followers) == 0 {
		return
	}
	frame := toolboxwire.FrameLog(stderr, p)
	for f := range c.followers {
		// An empty queue always takes a frame, so a follower that keeps
		// up gets even a large chunk; a full one drops it.
		if f.queued > 0 && f.queued+len(frame) > followerQueueBytes {
			continue
		}
		f.queue = append(f.queue, frame)
		f.queued += len(frame)
		f.signal()
	}
}

// growLocked grants a log up to want more bytes of the sandbox's budget,
// dropping finished commands' logs, oldest first, to make room.
func (s *sessionSet) growLocked(want int) int {
	for s.used+int64(want) > s.limits.budget {
		front := s.retained.Front()
		if front == nil {
			break
		}
		s.releaseLogsLocked(front.Value.(*sessionCommand))
	}
	got := min(int64(want), s.limits.budget-s.used)
	if got <= 0 {
		return 0
	}
	s.used += got
	return int(got)
}

// releaseLogsLocked frees c's log storage. Its lengths stay: a read past
// what was dropped is empty, at the stream's real end.
func (s *sessionSet) releaseLogsLocked(c *sessionCommand) {
	if c.retained != nil {
		s.retained.Remove(c.retained)
		c.retained = nil
	}
	s.used -= int64(c.stdout.Release() + c.stderr.Release())
}

// finish records c's end, ends its followers and keeps the session within
// its finished-command cap.
func (s *sessionSet) finish(sess *session, c *sessionCommand, exit int32, result bool) toolhost.CommandResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.state, c.exitCode, c.run = commandFinished, exit, nil
	for f := range c.followers {
		f.ended = true
		f.signal()
	}
	c.followers = nil
	sess.unfinished--
	var res toolhost.CommandResult
	if result {
		res = toolhost.CommandResult{ID: c.id, ExitCode: exit, Stdout: string(c.stdout.Bytes()), Stderr: string(c.stderr.Bytes())}
	}
	if sess.deleted {
		s.releaseLogsLocked(c)
		return res
	}
	if c.stdout.Size()+c.stderr.Size() > 0 {
		c.retained = s.retained.PushBack(c)
	}
	sess.finished++
	for sess.finished > s.limits.kept {
		s.forgetOldestFinishedLocked(sess)
	}
	return res
}

// forgetOldestFinishedLocked drops the session's oldest finished command.
func (s *sessionSet) forgetOldestFinishedLocked(sess *session) {
	for i, c := range sess.order {
		if c.state != commandFinished {
			continue
		}
		s.releaseLogsLocked(c)
		delete(sess.commands, c.id)
		sess.order = append(sess.order[:i], sess.order[i+1:]...)
		sess.finished--
		return
	}
}

// drop forgets a command whose start was refused to the request that made
// it: the caller gets the error, so no record of it stays.
func (s *sessionSet) drop(sess *session, c *sessionCommand) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(sess.commands, c.id)
	for i, o := range sess.order {
		if o == c {
			sess.order = append(sess.order[:i], sess.order[i+1:]...)
			break
		}
	}
	sess.unfinished--
	for f := range c.followers {
		f.ended = true
		f.signal()
	}
	c.followers = nil
	s.releaseLogsLocked(c)
}

func (s *sessionSet) logs(sessionID, commandID string, q toolboxwire.LogQuery) (stdout, stderr toolboxwire.LogWindow, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, c, err := s.lookup(sessionID, commandID)
	if err != nil {
		return toolboxwire.LogWindow{}, toolboxwire.LogWindow{}, err
	}
	final := c.state == commandFinished
	return ringWindow(&c.stdout, q.StdoutOffset, q.Limit, final), ringWindow(&c.stderr, q.StderrOffset, q.Limit, final), nil
}

// ringWindow is toolboxwire.CutLogWindowAt over a ring, copying only the
// window (one byte past the limit, so the cut is seen) rather than all
// that is kept.
func ringWindow(r *logring.Ring, from, limit int64, final bool) toolboxwire.LogWindow {
	base := r.Base()
	lo := int(min(max(from-base, 0), int64(r.Len())))
	hi := r.Len()
	// limit is the caller's, any non-negative int64. Compare it with the
	// window before adding to it: limit+1 overflows at the largest int64,
	// and the window then read as empty, so a reader asking for
	// "everything" never moved forward. Past the check limit is below
	// hi-lo, an int, so the conversion is exact.
	if limit > 0 && limit < int64(hi-lo)-1 {
		hi = lo + int(limit) + 1
	}
	w := toolboxwire.CutLogWindowAt(r.Slice(lo, hi), base+int64(lo), from, limit, final)
	w.Length = r.Total()
	return w
}

// follow subscribes to c's output: what is kept so far, then live frames
// until it ends.
func (s *sessionSet) follow(sessionID, commandID string) (*toolhost.LogFollow, error) {
	s.mu.Lock()
	_, c, err := s.lookup(sessionID, commandID)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	replay := toolboxwire.LogReplay(c.stdout.Bytes(), c.stderr.Bytes())
	if c.state == commandFinished {
		s.mu.Unlock()
		frames := make(chan []byte)
		close(frames)
		return &toolhost.LogFollow{Replay: replay, Frames: frames, Close: func() {}}, nil
	}
	if len(c.followers) >= maxFollowersPerCommand {
		s.mu.Unlock()
		return nil, toolhost.ErrTooManyFollowers
	}
	f := &logFollower{wake: make(chan struct{}, 1), stop: make(chan struct{})}
	c.followers[f] = struct{}{}
	s.mu.Unlock()

	frames := make(chan []byte)
	go s.feed(f, frames)
	return &toolhost.LogFollow{Replay: replay, Frames: frames, Close: func() { s.unfollow(c, f) }}, nil
}

func (f *logFollower) signal() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// feed hands f's queued frames to its subscriber, and closes frames once
// the command ended and the queue is empty.
func (s *sessionSet) feed(f *logFollower, frames chan<- []byte) {
	defer close(frames)
	for {
		frame, ok := s.next(f)
		if !ok {
			return
		}
		select {
		case frames <- frame:
		case <-f.stop:
			return
		}
	}
}

func (s *sessionSet) next(f *logFollower) ([]byte, bool) {
	for {
		s.mu.Lock()
		if len(f.queue) > 0 {
			frame := f.queue[0]
			f.queue[0] = nil
			f.queue = f.queue[1:]
			f.queued -= len(frame)
			s.mu.Unlock()
			return frame, true
		}
		if f.ended || f.left {
			s.mu.Unlock()
			return nil, false
		}
		s.mu.Unlock()
		select {
		case <-f.wake:
		case <-f.stop:
			return nil, false
		}
	}
}

// unfollow ends a subscription the subscriber has left.
func (s *sessionSet) unfollow(c *sessionCommand, f *logFollower) {
	f.stopOnce.Do(func() { close(f.stop) })
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(c.followers, f)
	f.left, f.queue, f.queued = true, nil, 0
}

// input writes to the running command's stdin. The write itself blocks
// while the guest does not read, so it runs on its own goroutine and the
// caller waits for it at most inputWait, or until ctx ends: past that the
// write stays pending (holding data, the command's one input in flight)
// until the command reads it or ends, and further input is refused with
// ErrInputPending instead of queuing. Ending the command (it exits, its
// session is deleted, the sandbox stops) closes its run, which fails the
// pending write.
func (s *sessionSet) input(ctx context.Context, sessionID, commandID string, data []byte) error {
	s.mu.Lock()
	_, c, err := s.lookup(sessionID, commandID)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	run := c.run
	if c.state != commandRunning || run == nil {
		s.mu.Unlock()
		return toolhost.ErrCommandNotRunning
	}
	s.mu.Unlock()
	select {
	case c.stdinBusy <- struct{}{}:
	default:
		return toolhost.ErrInputPending
	}
	done := make(chan error, 1)
	go func() {
		defer func() { <-c.stdinBusy }()
		done <- run.WriteStdin(data)
	}()
	wait := time.NewTimer(s.limits.inputWait)
	defer wait.Stop()
	select {
	case err := <-done:
		if err == nil {
			return nil
		}
		// The command ended between the check and the write: the caller
		// gets the same answer as if it had asked a moment later.
		s.mu.Lock()
		defer s.mu.Unlock()
		if c.state != commandRunning {
			return toolhost.ErrCommandNotRunning
		}
		return err
	case <-wait.C:
		return toolhost.ErrInputTimeout
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sessionsFor is the sandbox's session set, made on first use. A sandbox
// that is stopped, or being stopped, has none: a set made then would
// outlive the stop's kill pass, and a restart would find its sessions.
func (d *Driver) sessionsFor(sandboxID string) (*sessionSet, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	inst := d.byID[sandboxID]
	if inst == nil {
		return nil, fmt.Errorf("wasm sandbox %q not found", sandboxID)
	}
	if !inst.acceptsRuns() {
		return nil, toolhost.ErrSessionStopped
	}
	if inst.sessions == nil {
		inst.sessions = newSessionSet(func(ctx context.Context, argv []string) (*Stream, error) {
			// A session command lasts until it exits, is killed or its
			// session is deleted, as in a toolboxd shell; stdin stays open
			// for /input.
			st, err := d.StartStream(ctx, sandboxID, StreamSpec{Args: argv, Stdin: true, NoDeadline: true})
			if err != nil {
				return nil, toolhostProcessError(err)
			}
			return st, nil
		}, d.sessionLimits())
	}
	return inst.sessions, nil
}
