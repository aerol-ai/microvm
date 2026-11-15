package codeinterp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultQueueLimit is how many runs may wait for one context. It matches
// Daytona's per-context queue.
const DefaultQueueLimit = 128

// DefaultGrace is how long an interrupted run has to stop before its
// kernel is killed.
const DefaultGrace = 2 * time.Second

// ContextInfo is what the adapters report about a context.
type ContextInfo struct {
	ID        string
	Language  string
	Cwd       string
	CreatedAt time.Time
	// Active is false after the kernel died or was killed (a timeout). The
	// next run starts a fresh one, so the context's state is gone.
	Active bool
	// Default is true for a language's default context.
	Default bool
}

// Limit caps contexts across every Manager in one sandbox: the Daytona and
// E2B adapters each have a Manager, and the cap is the sandbox's.
type Limit struct {
	mu   sync.Mutex
	max  int
	used int
}

// NewLimit returns a cap of max contexts; max <= 0 means no cap.
func NewLimit(max int) *Limit { return &Limit{max: max} }

func (l *Limit) acquire() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 && l.used >= l.max {
		return false
	}
	l.used++
	return true
}

func (l *Limit) release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.used > 0 {
		l.used--
	}
	l.mu.Unlock()
}

// Options configure a Manager.
type Options struct {
	Launcher Launcher
	// Limit is shared with the sandbox's other Managers. Nil means no cap.
	Limit *Limit
	// DefaultCwd is used when a create names no cwd.
	DefaultCwd string
	// DefaultID names a language's default context. Daytona calls its
	// python default "default"; E2B gives defaults random ids. Nil means a
	// random id.
	DefaultID func(language string) string
	// ProtectDefaults makes Delete of a default context fail with
	// ErrDefaultContext (Daytona). Otherwise the default is removed and a
	// new one is made on next use (E2B).
	ProtectDefaults bool
	// ListDefaults includes default contexts in List (E2B does, Daytona
	// does not).
	ListDefaults bool
	// Languages the launcher supports; nil means AllLanguages.
	Languages []string
	// QueueLimit is the per-context queue; 0 means DefaultQueueLimit.
	QueueLimit int
	// IdleTTL stops the kernel of a context unused for this long (WASM keeps
	// kernels in sandboxd's memory). The context stays; its next run starts
	// a new kernel. 0 means never.
	IdleTTL time.Duration

	newID func() string
	now   func() time.Time
}

// RunPolicy says how a run reacts to time and to its client going away.
type RunPolicy struct {
	// Timeout interrupts the run after this long. 0 means no timeout.
	Timeout time.Duration
	// Grace is the time between the interrupt and the kill. 0 means
	// DefaultGrace.
	Grace time.Duration
	// InterruptOnCancel interrupts the run when ctx is cancelled (E2B: the
	// client went away). Without it the run continues and the adapter drops
	// its output (Daytona).
	InterruptOnCancel bool
}

// RunResult is how a run ended.
type RunResult struct {
	Outcome
	// TimedOut is true when the policy's timeout fired.
	TimedOut bool
	// Restarted is true when the context was restarted or deleted while the
	// run was in flight.
	Restarted bool
}

type entry struct {
	info ContextInfo
	seq  uint64

	// slot is the context's run lock: one run at a time, others wait in
	// line (Go channel sends are FIFO for waiters in practice; strict order
	// is not promised by either protocol).
	slot    chan struct{}
	waiting atomic.Int32

	mu       sync.Mutex
	kernel   Kernel
	gen      uint64 // bumped on restart/delete so a finishing run knows
	running  bool
	failed   bool
	deleted  bool
	lastUsed time.Time
}

// Manager owns one adapter's contexts.
type Manager struct {
	opts Options

	mu       sync.Mutex
	closed   bool
	seq      uint64
	contexts map[string]*entry
	defaults map[string]string // language -> context id

	stopReaper chan struct{}
	reaperDone chan struct{}
}

// NewManager returns a Manager. It starts no kernels.
func NewManager(opts Options) *Manager {
	if opts.QueueLimit <= 0 {
		opts.QueueLimit = DefaultQueueLimit
	}
	if opts.newID == nil {
		opts.newID = randomID
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.Languages == nil {
		opts.Languages = AllLanguages
	}
	m := &Manager{
		opts:     opts,
		contexts: map[string]*entry{},
		defaults: map[string]string{},
	}
	if opts.IdleTTL > 0 {
		m.stopReaper = make(chan struct{})
		m.reaperDone = make(chan struct{})
		go m.reap()
	}
	return m
}

// randomID returns a UUID-shaped random id. Both protocols treat ids as
// opaque strings; E2B's are kernel UUIDs, so ours look the same.
func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (m *Manager) supports(lang string) bool {
	for _, l := range m.opts.Languages {
		if l == lang {
			return true
		}
	}
	return false
}

func (m *Manager) language(name string) (string, error) {
	lang, err := NormalizeLanguage(name)
	if err != nil {
		return "", err
	}
	if !m.supports(lang) {
		return "", errUnsupported(lang)
	}
	return lang, nil
}

func errUnsupported(lang string) error {
	return &unsupportedError{lang: lang}
}

type unsupportedError struct{ lang string }

func (e *unsupportedError) Error() string { return "unsupported language: " + e.lang }
func (e *unsupportedError) Unwrap() error { return ErrUnsupportedLanguage }

// newEntry registers a context. The caller has taken a Limit slot.
func (m *Manager) newEntry(id, lang, cwd string, isDefault bool) (*entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	m.seq++
	e := &entry{
		info: ContextInfo{ID: id, Language: lang, Cwd: cwd, CreatedAt: m.opts.now(), Active: true, Default: isDefault},
		seq:  m.seq,
		slot: make(chan struct{}, 1),
	}
	e.lastUsed = e.info.CreatedAt
	m.contexts[id] = e
	if isDefault {
		m.defaults[lang] = id
	}
	return e, nil
}

func (m *Manager) cwdOr(cwd string) string {
	if cwd == "" {
		return m.opts.DefaultCwd
	}
	return cwd
}

// Create makes a context and starts its kernel, so a bad cwd or a missing
// interpreter fails here and not on the first run.
func (m *Manager) Create(ctx context.Context, language, cwd string) (ContextInfo, error) {
	lang, err := m.language(language)
	if err != nil {
		return ContextInfo{}, err
	}
	if !m.opts.Limit.acquire() {
		return ContextInfo{}, ErrLimit
	}
	cwd = m.cwdOr(cwd)
	k, err := m.opts.Launcher.Launch(ctx, Spec{Language: lang, Cwd: cwd})
	if err != nil {
		m.opts.Limit.release()
		return ContextInfo{}, err
	}
	e, err := m.newEntry(m.opts.newID(), lang, cwd, false)
	if err != nil {
		_ = k.Close()
		m.opts.Limit.release()
		return ContextInfo{}, err
	}
	e.mu.Lock()
	e.kernel = k
	info := e.info
	e.mu.Unlock()
	return info, nil
}

// Default returns a language's default context, registering it on first
// use. Its kernel starts on its first run.
func (m *Manager) Default(language string) (ContextInfo, error) {
	lang, err := m.language(language)
	if err != nil {
		return ContextInfo{}, err
	}
	m.mu.Lock()
	if id, ok := m.defaults[lang]; ok {
		e := m.contexts[id]
		m.mu.Unlock()
		return e.snapshot(), nil
	}
	m.mu.Unlock()
	if !m.opts.Limit.acquire() {
		return ContextInfo{}, ErrLimit
	}
	id := ""
	if m.opts.DefaultID != nil {
		id = m.opts.DefaultID(lang)
	}
	if id == "" {
		id = m.opts.newID()
	}
	m.mu.Lock()
	// Another caller may have registered it while the lock was released.
	if existing, ok := m.defaults[lang]; ok {
		e := m.contexts[existing]
		m.mu.Unlock()
		m.opts.Limit.release()
		return e.snapshot(), nil
	}
	m.mu.Unlock()
	e, err := m.newEntry(id, lang, m.opts.DefaultCwd, true)
	if err != nil {
		m.opts.Limit.release()
		return ContextInfo{}, err
	}
	return e.snapshot(), nil
}

func (e *entry) snapshot() ContextInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	info := e.info
	info.Active = !e.failed
	return info
}

func (m *Manager) lookup(id string) (*entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	e, ok := m.contexts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return e, nil
}

// Get returns one context.
func (m *Manager) Get(id string) (ContextInfo, error) {
	e, err := m.lookup(id)
	if err != nil {
		return ContextInfo{}, err
	}
	return e.snapshot(), nil
}

// List returns contexts in creation order.
func (m *Manager) List() []ContextInfo {
	m.mu.Lock()
	entries := make([]*entry, 0, len(m.contexts))
	for _, e := range m.contexts {
		if e.info.Default && !m.opts.ListDefaults {
			continue
		}
		entries = append(entries, e)
	}
	m.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].seq < entries[j].seq })
	out := make([]ContextInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.snapshot())
	}
	return out
}

// Delete removes a context and kills its kernel. A run in flight ends with
// RunResult.Restarted.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	e, ok := m.contexts[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if e.info.Default && m.opts.ProtectDefaults {
		m.mu.Unlock()
		return ErrDefaultContext
	}
	delete(m.contexts, id)
	if e.info.Default && m.defaults[e.info.Language] == id {
		delete(m.defaults, e.info.Language)
	}
	m.mu.Unlock()
	m.opts.Limit.release()

	e.mu.Lock()
	e.deleted = true
	e.gen++
	k := e.kernel
	e.kernel = nil
	e.mu.Unlock()
	if k != nil {
		_ = k.Close()
	}
	return nil
}

// Restart kills the context's kernel and starts a new one with the same id
// and cwd. A run in flight ends with RunResult.Restarted.
func (m *Manager) Restart(ctx context.Context, id string) (ContextInfo, error) {
	e, err := m.lookup(id)
	if err != nil {
		return ContextInfo{}, err
	}
	e.mu.Lock()
	e.gen++
	old := e.kernel
	e.kernel = nil
	lang, cwd := e.info.Language, e.info.Cwd
	e.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	k, err := m.opts.Launcher.Launch(ctx, Spec{Language: lang, Cwd: cwd})
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.failed = true
		return e.infoLocked(), err
	}
	if e.deleted {
		_ = k.Close()
		return ContextInfo{}, ErrNotFound
	}
	if e.kernel != nil {
		// A run started a kernel while this one was launching; keep that one.
		_ = k.Close()
	} else {
		e.kernel = k
	}
	e.failed = false
	return e.infoLocked(), nil
}

func (e *entry) infoLocked() ContextInfo {
	info := e.info
	info.Active = !e.failed
	return info
}

// Interrupt interrupts the context's run in flight, if any.
func (m *Manager) Interrupt(id string) error {
	e, err := m.lookup(id)
	if err != nil {
		return err
	}
	e.mu.Lock()
	k, running := e.kernel, e.running
	e.mu.Unlock()
	if k == nil || !running {
		return nil
	}
	return k.Interrupt()
}

// Run executes req in the context and streams events to sink. It waits in
// the context's queue first; ctx cancelled while waiting abandons the run.
func (m *Manager) Run(ctx context.Context, id string, req Request, sink Sink, p RunPolicy) (RunResult, error) {
	e, err := m.lookup(id)
	if err != nil {
		return RunResult{}, err
	}
	if int(e.waiting.Add(1)) > m.opts.QueueLimit {
		e.waiting.Add(-1)
		return RunResult{}, ErrQueueFull
	}
	select {
	case e.slot <- struct{}{}:
		e.waiting.Add(-1)
	case <-ctx.Done():
		e.waiting.Add(-1)
		return RunResult{}, ctx.Err()
	}
	defer func() { <-e.slot }()

	k, gen, err := m.kernelFor(ctx, e)
	if err != nil {
		return RunResult{}, err
	}
	e.mu.Lock()
	e.running = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		e.running = false
		e.lastUsed = m.opts.now()
		e.mu.Unlock()
	}()

	type done struct {
		out Outcome
		err error
	}
	finished := make(chan done, 1)
	go func() {
		out, err := k.Execute(req, sink)
		finished <- done{out, err}
	}()

	var timeout, grace <-chan time.Time
	if p.Timeout > 0 {
		t := time.NewTimer(p.Timeout)
		defer t.Stop()
		timeout = t.C
	}
	graceFor := p.Grace
	if graceFor <= 0 {
		graceFor = DefaultGrace
	}
	cancelled := ctx.Done()
	var res RunResult
	for {
		select {
		case d := <-finished:
			res.Outcome = d.out
			m.afterRun(e, k, gen, &res)
			return res, d.err
		case <-timeout:
			timeout = nil
			res.TimedOut = true
			_ = k.Interrupt()
			g := time.NewTimer(graceFor)
			defer g.Stop()
			grace = g.C
		case <-grace:
			grace = nil
			// The code ignored the interrupt; kill the kernel. The context
			// keeps its id and starts a new kernel on its next run.
			_ = k.Close()
		case <-cancelled:
			cancelled = nil
			if p.InterruptOnCancel {
				_ = k.Interrupt()
			}
		}
	}
}

// kernelFor returns the context's kernel, starting one when it has none
// (first run of a default context, or after a death). It runs with the
// context's run slot held, so two runs never start two kernels.
func (m *Manager) kernelFor(ctx context.Context, e *entry) (Kernel, uint64, error) {
	e.mu.Lock()
	if e.deleted {
		e.mu.Unlock()
		return nil, 0, ErrNotFound
	}
	if e.kernel != nil {
		select {
		case <-e.kernel.Done():
			// Died between runs (killed by the user, out of memory).
			e.kernel = nil
		default:
			k, gen := e.kernel, e.gen
			e.mu.Unlock()
			return k, gen, nil
		}
	}
	lang, cwd, gen := e.info.Language, e.info.Cwd, e.gen
	e.mu.Unlock()

	k, err := m.opts.Launcher.Launch(ctx, Spec{Language: lang, Cwd: cwd})
	e.mu.Lock()
	defer e.mu.Unlock()
	if err != nil {
		e.failed = true
		return nil, 0, err
	}
	if e.deleted || e.gen != gen {
		_ = k.Close()
		if e.deleted {
			return nil, 0, ErrNotFound
		}
		// Restarted while launching: use the restart's kernel if it has one.
		if e.kernel != nil {
			return e.kernel, e.gen, nil
		}
		e.kernel = k
	} else {
		e.kernel = k
	}
	e.failed = false
	return e.kernel, e.gen, nil
}

// afterRun records how the run left the kernel.
func (m *Manager) afterRun(e *entry, k Kernel, gen uint64, res *RunResult) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.gen != gen {
		// Restarted or deleted under the run: the run's kernel is gone on
		// purpose and the context (if any) already has its next one.
		res.Restarted = true
		return
	}
	dead := res.Died
	if !dead {
		select {
		case <-k.Done():
			dead = true
		default:
		}
	}
	if dead {
		res.Died = true
		if e.kernel == k {
			e.kernel = nil
		}
		e.failed = true
	}
}

// reap stops idle kernels.
func (m *Manager) reap() {
	defer close(m.reaperDone)
	period := m.opts.IdleTTL / 4
	if period < time.Second {
		period = time.Second
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-m.stopReaper:
			return
		case <-t.C:
			m.reapOnce()
		}
	}
}

func (m *Manager) reapOnce() {
	now := m.opts.now()
	m.mu.Lock()
	entries := make([]*entry, 0, len(m.contexts))
	for _, e := range m.contexts {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	for _, e := range entries {
		e.mu.Lock()
		var k Kernel
		if e.kernel != nil && !e.running && now.Sub(e.lastUsed) >= m.opts.IdleTTL {
			k = e.kernel
			e.kernel = nil
			e.gen++
			// The state is gone; report it the way a timeout kill does.
			e.failed = true
		}
		e.mu.Unlock()
		if k != nil {
			_ = k.Close()
		}
	}
}

// Close kills every kernel and refuses further calls.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	entries := make([]*entry, 0, len(m.contexts))
	for _, e := range m.contexts {
		entries = append(entries, e)
	}
	m.contexts = map[string]*entry{}
	m.defaults = map[string]string{}
	m.mu.Unlock()
	if m.stopReaper != nil {
		close(m.stopReaper)
		<-m.reaperDone
	}
	for _, e := range entries {
		m.opts.Limit.release()
		e.mu.Lock()
		e.deleted = true
		e.gen++
		k := e.kernel
		e.kernel = nil
		e.mu.Unlock()
		if k != nil {
			_ = k.Close()
		}
	}
}

// IsNotFound reports whether err means an unknown context.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }
