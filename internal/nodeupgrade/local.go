package nodeupgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// Local is the single-node upgrade API's work (plans/kubectl-style-cluster-ops.md
// §6.1): uploads land in the FileStore, POST starts `sandboxd upgrade node`
// in its own systemd unit (Launch), and GET reads the latest operation
// back. It is used only with cluster mode off; a cluster upgrades through
// the rollout instead, and the routes refuse before they reach this.
type Local struct {
	// StateDir is the node's upgrade state directory (StateDirFor).
	StateDir string
	// Host launches the upgrader and asks systemd whether its unit runs.
	Host Host
	// Binary returns the sandboxd that runs the upgrade (os.Executable).
	Binary func() (string, error)
	// RunningVersion is this sandboxd's build.
	RunningVersion string
	// GOOS and GOARCH name this node's platform; empty is runtime's.
	GOOS, GOARCH string
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu sync.Mutex
	// pending is the operation this process launched last. Its upgrader
	// writes the first record a moment after systemd-run returns; until
	// then only this tells a retried POST that an upgrade is starting.
	pending *launched
}

type launched struct {
	op, version, from string
	rollback          bool
	at                time.Time
}

const (
	// UploadMaxAge is how long an upload no operation uses is kept (§6.6:
	// one hour). A HEAD that finds a file renews it, so the CLI's "the node
	// has it, skip the upload" stays true until its POST.
	UploadMaxAge = time.Hour
	// pendingGrace is how long a launched operation with no record and no
	// running unit still counts as starting, for a systemd that is slow to
	// report the unit.
	pendingGrace = 30 * time.Second
	// fromDirName holds one directory per operation, made from uploads. It
	// starts with a dot so it can never be a version's staging directory
	// (versionRe needs a letter or digit first).
	fromDirName = ".from"
)

// ErrRunning is returned by Start while another operation holds the node.
type ErrRunning struct {
	Op      string
	Version string
}

func (e *ErrRunning) Error() string {
	if e.Op == "" {
		return "another upgrade is running on this node"
	}
	return fmt.Sprintf("upgrade %s (to %s) is running on this node", e.Op, e.Version)
}

// ErrFilesMissing is returned by Start for an upload request whose files
// were not all uploaded first.
type ErrFilesMissing struct{ Names []string }

func (e *ErrFilesMissing) Error() string {
	return "these files were not uploaded: " + strings.Join(e.Names, ", ") +
		"; PUT each to " + upgradewire.NodeUpgradeFilesPath + "/{sha256} first"
}

func (l *Local) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Local) goos() string {
	if l.GOOS != "" {
		return l.GOOS
	}
	return runtime.GOOS
}

func (l *Local) goarch() string {
	if l.GOARCH != "" {
		return l.GOARCH
	}
	return runtime.GOARCH
}

// Platform is this node's OS and CPU type, as release asset names spell
// them: "linux/amd64".
func (l *Local) Platform() string { return l.goos() + "/" + l.goarch() }

func (l *Local) store() FileStore {
	return FileStore{Dir: FileStoreDir(l.StateDir), MaxBytes: upgradewire.MaxUploadBytes}
}

// PutFile stores one uploaded file under its SHA-256. created is false when
// the node already had it.
func (l *Local) PutFile(sum string, r io.Reader) (created bool, size int64, err error) {
	l.prune()
	return l.store().Put(sum, r)
}

// HasFile reports whether the file is stored, and renews its hour when it
// is (UploadMaxAge).
func (l *Local) HasFile(sum string) bool {
	s := l.store()
	if !s.Has(sum) {
		return false
	}
	if p, err := s.Path(sum); err == nil {
		now := l.now()
		_ = os.Chtimes(p, now, now)
	}
	return true
}

// Start begins the upgrade req asks for. started is false, with the node's
// version in resp, when the node already runs req.Version: a repeat is a
// no-op. A retry while the same version is still being installed returns
// that operation again with started true, so a CLI that lost the first
// answer gets the same op.
func (l *Local) Start(ctx context.Context, req upgradewire.NodeUpgradeRequest) (resp upgradewire.NodeUpgradeResponse, started bool, err error) {
	ureq, err := l.request(req)
	if err != nil {
		return resp, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if p := l.activePending(ctx); p != nil {
		if p.version == ureq.Version && p.rollback == ureq.Rollback {
			r, _ := l.statusOf(ctx, p)
			return r, true, nil
		}
		return resp, false, &ErrRunning{Op: p.op, Version: p.version}
	}
	if ureq.Version == l.RunningVersion {
		return l.alreadyRunning(), false, nil
	}
	if op, held := l.lockHolder(); held {
		return resp, false, &ErrRunning{Op: op, Version: l.opVersion(op)}
	}
	l.prune()

	ureq.Op = NewOpID(l.now())
	if req.Source == upgradewire.SourceUpload {
		s := l.store()
		var missing []string
		for name, sum := range ureq.SHA256 {
			if !s.Has(sum) {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return resp, false, &ErrFilesMissing{Names: missing}
		}
		ureq.From = filepath.Join(l.StateDir, fromDirName, ureq.Op)
		if err := s.Materialize(ureq.From, ureq.SHA256); err != nil {
			_ = os.RemoveAll(ureq.From)
			return resp, false, fmt.Errorf("prepare uploaded files: %w", err)
		}
	}
	binary, err := l.Binary()
	if err != nil {
		l.dropFrom(ureq.From)
		return resp, false, fmt.Errorf("find the sandboxd binary: %w", err)
	}
	if _, err := Launch(ctx, l.Host, binary, ureq); err != nil {
		l.dropFrom(ureq.From)
		return resp, false, err
	}
	now := l.now().UTC()
	l.pending = &launched{op: ureq.Op, version: ureq.Version, from: l.RunningVersion, rollback: ureq.Rollback, at: now}
	return upgradewire.NodeUpgradeResponse{Op: ureq.Op, State: upgradewire.NodeOpPending, Version: ureq.Version,
		From: l.RunningVersion, Rollback: ureq.Rollback, StartedAt: now, UpdatedAt: now}, true, nil
}

func (l *Local) dropFrom(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

// request checks req and turns it into the upgrader's Request for this
// node. Files for another CPU type are dropped: a bundle or a cluster-wide
// file list names every CPU type, and each node installs only its own.
func (l *Local) request(req upgradewire.NodeUpgradeRequest) (Request, error) {
	out := Request{Version: req.Version, Rollback: req.Rollback, AllowUnversioned: req.AllowUnversioned}
	if !versionRe.MatchString(req.Version) {
		return out, usageErr("version %q is not a release tag", req.Version)
	}
	switch req.Source {
	case "", upgradewire.SourceRelease, upgradewire.SourceUpload:
	default:
		return out, usageErr("source %q is not %s or %s", req.Source, upgradewire.SourceRelease, upgradewire.SourceUpload)
	}
	if req.HealthTimeout != "" {
		d, err := time.ParseDuration(req.HealthTimeout)
		if err != nil || d < 0 {
			return out, usageErr("health_timeout %q is not a duration such as 2m", req.HealthTimeout)
		}
		out.HealthTimeout = d
	}
	kept := map[string]string{}
	for name, sum := range req.Files {
		if !upgradewire.SHA256Re.MatchString(sum) {
			return out, usageErr("files: %s: %q is not a lower-case hex SHA-256", name, sum)
		}
		if _, err := roleOf(name, l.goos(), l.goarch()); err != nil {
			if errors.Is(err, ErrUsage) {
				return out, err
			}
			continue // another CPU type's file
		}
		kept[name] = sum
	}
	if len(req.Files) > 0 {
		if len(kept) == 0 {
			return out, usageErr("the request names no file for this node's platform (%s)", l.Platform())
		}
		out.SHA256 = kept
	}
	if req.Source == upgradewire.SourceUpload && len(out.SHA256) == 0 {
		return out, usageErr("source %s needs the uploaded files' hashes", upgradewire.SourceUpload)
	}
	if _, err := out.validate(l.goos(), l.goarch()); err != nil {
		return out, err
	}
	return out, nil
}

// alreadyRunning answers a request for the version this node runs: the
// operation that installed it when that is the latest one, else a record
// with no operation.
func (l *Local) alreadyRunning() upgradewire.NodeUpgradeResponse {
	if st := l.latestState(); st != nil && st.Version == l.RunningVersion && st.Phase == PhaseDone {
		return toResponse(st)
	}
	now := l.now().UTC()
	return upgradewire.NodeUpgradeResponse{State: upgradewire.NodeOpDone, Version: l.RunningVersion,
		From: l.RunningVersion, StartedAt: now, UpdatedAt: now}
}

// Latest returns the newest operation on this node; ok is false when there
// never was one.
func (l *Local) Latest(ctx context.Context) (resp upgradewire.NodeUpgradeResponse, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.latestState()
	if p := l.pending; p != nil && (st == nil || (st.Op != p.op && !st.StartedAt.After(p.at))) {
		// The upgrader this process launched has written no record yet.
		return l.statusOf(ctx, p)
	}
	if st == nil {
		return resp, false
	}
	return toResponse(st), true
}

// statusOf is a launched operation's answer: its record once the upgrader
// wrote one, else pending while it can still be starting.
func (l *Local) statusOf(ctx context.Context, p *launched) (upgradewire.NodeUpgradeResponse, bool) {
	if st, err := LoadState(l.StateDir, p.op); err == nil {
		return toResponse(st), true
	}
	r := upgradewire.NodeUpgradeResponse{Op: p.op, State: upgradewire.NodeOpPending, Version: p.version,
		From: p.from, Rollback: p.rollback, StartedAt: p.at, UpdatedAt: p.at}
	if !l.starting(ctx, p) {
		r.State = upgradewire.NodeOpFailed
		r.Error = "the upgrader stopped before it wrote a record; see journalctl -u " + LaunchUnit(p.op)
	}
	return r, true
}

// starting reports whether a launched operation with no record yet may
// still write one: its unit runs, or it was launched a moment ago.
func (l *Local) starting(ctx context.Context, p *launched) bool {
	return l.Host.UnitActive(ctx, LaunchUnit(p.op)) || l.now().Sub(p.at) < pendingGrace
}

// activePending is the operation this process launched, while it still
// runs.
func (l *Local) activePending(ctx context.Context) *launched {
	p := l.pending
	if p == nil {
		return nil
	}
	if st, err := LoadState(l.StateDir, p.op); err == nil {
		if st.terminal() {
			return nil
		}
		return p
	}
	if l.starting(ctx, p) {
		return p
	}
	return nil
}

func (l *Local) latestState() *State {
	states, err := listStates(l.StateDir)
	if err != nil || len(states) == 0 {
		return nil
	}
	return states[len(states)-1]
}

func (l *Local) opVersion(op string) string {
	if st, err := LoadState(l.StateDir, op); err == nil {
		return st.Version
	}
	return ""
}

// lockHolder reports whether an upgrader holds the node's lock, and its op.
// It takes the lock for a moment to find out, so it runs only where no
// upgrader this process launched can be starting (Start checks
// activePending first).
func (l *Local) lockHolder() (string, bool) {
	if _, err := os.Stat(l.StateDir); err != nil {
		return "", false
	}
	lk, err := acquireLock(l.StateDir, "")
	if err == nil {
		lk.release()
		return "", false
	}
	if !errors.Is(err, ErrBusy) {
		return "", false
	}
	raw, _ := os.ReadFile(filepath.Join(l.StateDir, "lock"))
	return strings.TrimSpace(string(raw)), true
}

// prune deletes uploads no operation used within UploadMaxAge, and the
// per-operation directories of finished operations past that age.
func (l *Local) prune() {
	now := l.now()
	_, _ = l.store().Prune(now, UploadMaxAge, nil)
	base := filepath.Join(l.StateDir, fromDirName)
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < UploadMaxAge {
			continue
		}
		if st, err := LoadState(l.StateDir, e.Name()); err == nil && !st.terminal() {
			continue
		}
		_ = os.RemoveAll(filepath.Join(base, e.Name()))
	}
}

func toResponse(st *State) upgradewire.NodeUpgradeResponse {
	return upgradewire.NodeUpgradeResponse{Op: st.Op, State: string(st.Phase), Version: st.Version, From: st.FromVersion,
		Rollback: st.Rollback, Error: st.Error, StartedAt: st.StartedAt, UpdatedAt: st.UpdatedAt}
}
