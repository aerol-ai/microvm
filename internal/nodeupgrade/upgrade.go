package nodeupgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/release"
)

// Markers the usage text of a sandboxd command carries. The upgrader and
// install.sh look for them in a binary before running it with that
// command (containsMarker says why).
const (
	VersionCommandMarker = "usage: sandboxd version"
	UpgradeCommandMarker = "usage: sandboxd upgrade node"
)

const (
	// spaceMargin is kept free on every file system the upgrade writes to.
	spaceMargin = 64 << 20
	// unknownFileEstimate stands in for the size of a file not yet
	// downloaded with nothing installed to compare it with.
	unknownFileEstimate = 160 << 20
	// revertTimeout bounds the failure path, which runs even after the
	// caller's context is cancelled (a SIGTERM to the upgrader).
	revertTimeout = 5 * time.Minute
)

// Upgrader runs one node upgrade (§6.3 steps 1-9).
type Upgrader struct {
	Paths Paths
	Host  Host
	// Out receives progress lines; nil discards them.
	Out io.Writer
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// GOOS and GOARCH name this node's platform; empty is runtime's.
	GOOS, GOARCH string
	// SelfHostSetupSHA256 is the hash of the install.sh built into this
	// binary: the host setup assumed when no host apply was recorded.
	SelfHostSetupSHA256 string
	// Backup copies the database; nil is VACUUM INTO.
	Backup func(ctx context.Context, dbPath, dest string) error
	// PollInterval is the health poll period; zero is one second.
	PollInterval time.Duration
	// BeforeStop runs once everything is staged and checked, just before
	// a running sandboxd is stopped. An error ends the op as failed with
	// nothing on the node changed. `sandboxd upgrade node` uses it on a
	// Raft server to keep quorum and hand off leadership (§6.3); nil skips
	// it.
	BeforeStop func(ctx context.Context, allowDowntime bool) error
	// hook is called at named points of apply; the crash-safety tests stop
	// the upgrader there. Nil in production.
	hook func(point string)
}

func (u *Upgrader) at(point string) {
	if u.hook != nil {
		u.hook(point)
	}
}

func (u *Upgrader) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Upgrader) goos() string {
	if u.GOOS != "" {
		return u.GOOS
	}
	return runtime.GOOS
}

func (u *Upgrader) goarch() string {
	if u.GOARCH != "" {
		return u.GOARCH
	}
	return runtime.GOARCH
}

func (u *Upgrader) logf(format string, a ...any) {
	if u.Out != nil {
		fmt.Fprintf(u.Out, format+"\n", a...)
	}
}

func (u *Upgrader) save(st *State) error {
	if err := st.save(u.Paths.StateDir, u.now()); err != nil {
		return fmt.Errorf("record op %s: %w", st.Op, err)
	}
	return nil
}

// Run carries out req. It returns the operation's record and, when the
// node does not end on the requested version, an error; a record with
// result noop means the node already had every file.
func (u *Upgrader) Run(ctx context.Context, req Request) (*State, error) {
	specs, err := req.validate(u.goos(), u.goarch())
	if err != nil {
		return nil, err
	}
	if req.Op == "" {
		req.Op = NewOpID(u.now())
	}
	if req.HealthTimeout == 0 {
		req.HealthTimeout = DefaultHealthTimeout
	}
	if err := os.MkdirAll(u.Paths.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("upgrade state directory: %w", err)
	}
	lk, err := acquireLock(u.Paths.StateDir, req.Op)
	if err != nil {
		return nil, err
	}
	defer lk.release()

	// The same op again (a retried call) answers with what it did. An
	// unfinished one whose upgrader died is resolved as boot recovery
	// would, now that this process holds the lock.
	if prev, err := loadState(statePath(u.Paths.StateDir, req.Op)); err == nil {
		if !prev.terminal() {
			u.logf("op %s was left at %s by an upgrader that is gone; resolving it", prev.Op, prev.Phase)
			if _, err := u.resolve(ctx, prev, !u.Host.UnitActive(ctx, sandboxdUnit)); err != nil {
				return prev, err
			}
		}
		return prev, finishedErr(prev)
	}
	// Any other unfinished op was left by an upgrader that is gone (this
	// process holds the lock): settle it first, as boot recovery would, so
	// this op starts from settled files and the old record can never be
	// settled later, after this op moved the node on. The single-node API
	// starts a new op once it sees the old upgrader is gone.
	if err := u.resolveAbandoned(ctx); err != nil {
		return nil, err
	}

	now := u.now().UTC()
	st := &State{
		Format:     stateFormat,
		Op:         req.Op,
		Version:    req.Version,
		Rollback:   req.Rollback,
		Phase:      PhaseStaging,
		WasActive:  u.Host.UnitActive(ctx, sandboxdUnit),
		SingleNode: u.singleNode(),
		DBPath:     u.Paths.DBPath,
		StartedAt:  now,
	}
	files, rolledBack, err := u.fileSet(req, specs)
	if err != nil {
		return u.failEarly(st, err)
	}
	st.Files = files
	changed := false
	for i := range st.Files {
		f := &st.Files[i]
		if f.Path == "" {
			continue
		}
		cur, err := fileSHA256(f.Path)
		if err != nil {
			return u.failEarly(st, fmt.Errorf("read installed %s: %w", f.Path, err))
		}
		if cur != f.SHA256 {
			f.Changed = true
			f.PrevSHA256 = cur
			changed = true
		}
	}
	if !changed {
		st.Phase, st.Result = PhaseDone, ResultNoop
		u.logf("%s is already installed; nothing to do", req.Version)
		return st, u.save(st)
	}

	st.FromVersion = u.installedVersion(ctx)
	if err := checkOrder(st.FromVersion, req); err != nil {
		return u.failEarly(st, err)
	}
	if err := u.preflight(); err != nil {
		return u.failEarly(st, err)
	}
	stageDir := filepath.Join(u.Paths.StateDir, req.Version)
	if err := u.checkSpace(st, stageDir, false); err != nil {
		return u.failEarly(st, err)
	}
	if err := u.save(st); err != nil {
		return nil, err
	}
	for i := range st.Files {
		if err := u.stage(ctx, &st.Files[i], stageDir, req.Version); err != nil {
			return u.failEarly(st, err)
		}
	}
	meta, err := u.readMeta(st, stageDir)
	if err != nil {
		return u.failEarly(st, err)
	}
	if err := u.checkStagedVersion(ctx, st, stageDir); err != nil {
		return u.failEarly(st, err)
	}
	if err := u.checkSpace(st, stageDir, true); err != nil {
		return u.failEarly(st, err)
	}
	if err := u.planHostApply(st, meta, req); err != nil {
		return u.failEarly(st, err)
	}
	u.planServices(ctx, st, meta, rolledBack)
	if err := u.planRollbackRestore(ctx, st, rolledBack); err != nil {
		return u.failEarly(st, err)
	}
	if err := u.save(st); err != nil {
		return nil, err
	}
	// Last, so a refusal costs nothing and a staging failure never moves
	// leadership for nothing.
	if st.WasActive && u.BeforeStop != nil {
		if err := u.BeforeStop(ctx, req.AllowDowntime); err != nil {
			return u.failEarly(st, err)
		}
	}
	return u.apply(ctx, st, stageDir, req)
}

// finishedErr is the error a finished op answers a repeat call with.
func finishedErr(st *State) error {
	if st.Phase == PhaseFailed {
		return fmt.Errorf("op %s failed: %s", st.Op, st.Error)
	}
	return nil
}

// failEarly ends an op that failed before anything on the node changed.
func (u *Upgrader) failEarly(st *State, cause error) (*State, error) {
	st.Phase, st.Result, st.Error = PhaseFailed, ResultFailed, cause.Error()
	if err := u.save(st); err != nil {
		return st, errors.Join(cause, err)
	}
	return st, cause
}

// fileSet is the files the op installs, with where each one comes from.
// With no hashes (a rollback) they are the *.prev files the last upgrade
// kept, and rolledBack is that upgrade's record.
func (u *Upgrader) fileSet(req Request, specs []fileSpec) ([]FileState, *State, error) {
	if len(specs) == 0 {
		return u.prevSet(req)
	}
	var files []FileState
	for _, s := range specs {
		f := FileState{Role: s.role, Asset: s.asset, SHA256: s.sha256}
		switch s.role {
		case roleSandboxd:
			f.Path = u.Paths.Sandboxd
		case roleToolboxd:
			f.Path = u.Paths.Toolboxd
		case roleCaddy:
			if u.Paths.Caddy == "" {
				u.logf("skipping %s: this node runs no Caddy", s.asset)
				continue
			}
			f.Path = u.Paths.Caddy
		}
		if req.From != "" {
			f.source = filepath.Join(req.From, s.asset)
		}
		files = append(files, f)
	}
	return files, nil, nil
}

// prevSet finds the files to roll back to: the *.prev files of the newest
// upgrade whose files are the ones installed now (§6.8). Each *.prev must
// still be the file that upgrade replaced.
func (u *Upgrader) prevSet(req Request) ([]FileState, *State, error) {
	states, err := listStates(u.Paths.StateDir)
	if err != nil {
		return nil, nil, err
	}
	for i := len(states) - 1; i >= 0; i-- {
		s := states[i]
		if s.Phase != PhaseDone || (s.Result != ResultUpgraded && s.Result != ResultCompletedAtBoot) {
			continue
		}
		installed := true
		for _, f := range s.Files {
			if f.Path == "" || !f.Changed {
				continue
			}
			if cur, _ := fileSHA256(f.Path); cur != f.SHA256 {
				installed = false
				break
			}
		}
		if !installed {
			continue
		}
		if s.Version == req.Version {
			// Already on it (a repeated rollback): the current files, so
			// Run finds nothing changed.
			return currentSet(s), nil, nil
		}
		if s.FromVersion != "" && s.FromVersion != req.Version {
			return nil, nil, fmt.Errorf("the files the last upgrade kept are %s, not %s; give %s's files with --sha256", s.FromVersion, req.Version, req.Version)
		}
		var files []FileState
		for _, f := range s.Files {
			if f.Path == "" || !f.Changed {
				continue
			}
			if f.PrevSHA256 == "" {
				return nil, nil, fmt.Errorf("op %s installed %s where there was none, so there is nothing to put back", s.Op, f.Path)
			}
			prev := f.Path + ".prev"
			if got, err := fileSHA256(prev); err != nil || got != f.PrevSHA256 {
				return nil, nil, fmt.Errorf("%s %w (op %s); give %s's files with --sha256", prev, errPrevMismatch, s.Op, req.Version)
			}
			files = append(files, FileState{Role: f.Role, Asset: f.Role, Path: f.Path, SHA256: f.PrevSHA256, source: prev})
		}
		u.logf("rolling back op %s: putting back the files it replaced", s.Op)
		return files, s, nil
	}
	return nil, nil, fmt.Errorf("no upgrade on this node kept *.prev files of %s; give its files with --sha256 (and --from)", req.Version)
}

func currentSet(s *State) []FileState {
	var files []FileState
	for _, f := range s.Files {
		if f.Path != "" {
			files = append(files, FileState{Role: f.Role, Asset: f.Asset, Path: f.Path, SHA256: f.SHA256})
		}
	}
	return files
}

// installedVersion is the version of the sandboxd on disk: asked of the
// binary when it has `sandboxd version`, else of the running daemon's
// /health, else unknown ("").
func (u *Upgrader) installedVersion(ctx context.Context) string {
	if containsMarker(u.Paths.Sandboxd, []byte(VersionCommandMarker)) {
		if v, err := u.binaryVersion(ctx, u.Paths.Sandboxd); err == nil {
			return v
		}
	}
	if v, err := u.Host.HealthVersion(ctx, u.Paths.HealthURL); err == nil {
		return v
	}
	return ""
}

func (u *Upgrader) binaryVersion(ctx context.Context, bin string) (string, error) {
	out, err := u.Host.Run(ctx, bin, "version", "-o", "json")
	if err != nil {
		return "", fmt.Errorf("%s version: %w: %s", bin, err, strings.TrimSpace(string(out)))
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(out, &info); err != nil || info.Version == "" {
		return "", fmt.Errorf("%s version -o json printed no version", bin)
	}
	return info.Version, nil
}

// checkOrder refuses a downgrade unless the request is a rollback (§6.3
// step 3, §8).
func checkOrder(installed string, req Request) error {
	if req.Rollback {
		return nil
	}
	cur, err1 := release.ParseVersion(installed)
	tgt, err2 := release.ParseVersion(req.Version)
	if err1 != nil || err2 != nil {
		if req.AllowUnversioned {
			return nil
		}
		if installed == "" {
			return errors.New("cannot tell which version is installed, so a downgrade cannot be ruled out: start sandboxd, or pass --allow-unversioned to skip the check")
		}
		return fmt.Errorf("cannot order %s and %s: one is not a release tag; pass --allow-unversioned for a dev or test build", installed, req.Version)
	}
	if tgt.Compare(cur) < 0 {
		return fmt.Errorf("%s is older than the installed %s; a downgrade is a rollback: pass --rollback", req.Version, installed)
	}
	return nil
}

// preflight checks the tools the upgrade and later launches need
// (§6.7).
func (u *Upgrader) preflight() error {
	for _, bin := range []string{"systemctl", "systemd-run"} {
		if _, err := u.Host.LookPath(bin); err != nil {
			return fmt.Errorf("%s not found: sandboxd upgrade node needs systemd", bin)
		}
	}
	return nil
}

// checkSpace checks every file system the upgrade writes to has room for
// the staged files (before staging), the new copies beside the installed
// files (the *.prev is a hard link to the old file, which keeps its
// blocks), and the database backup (§6.7).
func (u *Upgrader) checkSpace(st *State, stageDir string, staged bool) error {
	type need struct {
		bytes uint64
		dir   string
		free  uint64
	}
	needs := map[uint64]*need{}
	var errs []error
	add := func(dir string, n uint64) {
		free, dev, err := u.Host.FreeBytes(dir)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if needs[dev] == nil {
			needs[dev] = &need{dir: dir, free: free}
		}
		needs[dev].bytes += n
	}
	for _, f := range st.Files {
		size := uint64(f.Size)
		if !staged {
			size = estimateSize(f)
			add(stageDir, size)
		}
		if f.Changed && f.Path != "" {
			add(filepath.Dir(f.Path), size)
		}
	}
	add(u.Paths.StateDir, dbBytes(u.Paths.DBPath))
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	for _, n := range needs {
		if n.free < n.bytes+spaceMargin {
			return fmt.Errorf("not enough free space on the file system of %s: the upgrade needs %d MiB (staged files, new copies beside the installed ones, database backup) plus %d MiB spare, and %d MiB is free",
				n.dir, n.bytes>>20, spaceMargin>>20, n.free>>20)
		}
	}
	return nil
}

// estimateSize guesses a file's size before staging: the source when it is
// local, else the installed file, which a release replaces with one of
// similar size.
func estimateSize(f FileState) uint64 {
	if f.source != "" {
		if n := fileSize(f.source); n > 0 {
			return uint64(n)
		}
	}
	if f.Path != "" {
		if n := fileSize(f.Path); n > 0 {
			return uint64(n) + uint64(n)/4
		}
	}
	if f.Role == roleRelease {
		return 1 << 20
	}
	return unknownFileEstimate
}

// stage puts one file under stageDir, hashing it as it streams, and keeps
// it only when the hash matches. A file already staged with the right hash
// is reused, so a retry skips the download (§6.7).
func (u *Upgrader) stage(ctx context.Context, f *FileState, stageDir, version string) error {
	dst := filepath.Join(stageDir, f.Asset)
	if got, _ := fileSHA256(dst); got == f.SHA256 {
		f.Size = fileSize(dst)
		u.logf("%s: already staged", f.Asset)
		return nil
	}
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return err
	}
	var (
		r    io.ReadCloser
		from string
		err  error
	)
	if f.source != "" {
		from = f.source
		r, err = os.Open(f.source)
	} else {
		from = u.Paths.ReleaseURL + "/" + url.PathEscape(version) + "/" + url.PathEscape(f.Asset)
		r, _, err = u.Host.Fetch(ctx, from)
	}
	if err != nil {
		return fmt.Errorf("get %s: %w", f.Asset, err)
	}
	defer r.Close()
	mode := os.FileMode(0o755)
	if f.Role == roleRelease {
		mode = 0o644
	}
	part := dst + ".part"
	n, sum, err := streamToFile(r, part, mode)
	if err != nil {
		return fmt.Errorf("get %s from %s: %w", f.Asset, from, err)
	}
	if sum != f.SHA256 {
		_ = os.Remove(part)
		return fmt.Errorf("%s from %s has sha256 %s, want %s; nothing was changed", f.Asset, from, sum, f.SHA256)
	}
	if err := os.Rename(part, dst); err != nil {
		_ = os.Remove(part)
		return err
	}
	f.Size = n
	u.logf("%s: staged and verified (%d bytes)", f.Asset, n)
	return nil
}

func (u *Upgrader) stagedPath(stageDir string, f *FileState) string {
	return filepath.Join(stageDir, f.Asset)
}

// readMeta parses the staged release.json, if the request carried one, and
// checks it describes the requested version.
func (u *Upgrader) readMeta(st *State, stageDir string) (*release.Metadata, error) {
	f := st.file(roleRelease)
	if f == nil {
		return nil, nil
	}
	raw, err := os.ReadFile(u.stagedPath(stageDir, f))
	if err != nil {
		return nil, err
	}
	meta, err := release.Parse(raw)
	if err != nil {
		return nil, err
	}
	if meta.Version != st.Version {
		return nil, fmt.Errorf("release.json describes %s, not %s", meta.Version, st.Version)
	}
	if !st.Rollback {
		if _, err := release.ParseVersion(st.FromVersion); err == nil {
			if err := meta.UpgradeAllowedFrom(st.FromVersion); err != nil {
				return nil, err
			}
		}
	}
	return &meta, nil
}

// checkStagedVersion asks the staged sandboxd its version, when it can be
// asked, so a wrong version argument fails before anything stops.
func (u *Upgrader) checkStagedVersion(ctx context.Context, st *State, stageDir string) error {
	f := st.file(roleSandboxd)
	if f == nil || !f.Changed {
		return nil
	}
	bin := u.stagedPath(stageDir, f)
	if !containsMarker(bin, []byte(VersionCommandMarker)) {
		return nil
	}
	v, err := u.binaryVersion(ctx, bin)
	if err != nil {
		return err
	}
	if v != st.Version {
		return fmt.Errorf("the staged sandboxd is %s, not %s", v, st.Version)
	}
	return nil
}

// InstalledHostSetup is the hash of the install.sh that last set this host
// up: the recorded one, else fallback.
func InstalledHostSetup(stateDir, fallback string) string {
	raw, err := os.ReadFile(filepath.Join(stateDir, hostSetupName))
	if err == nil {
		if s := strings.TrimSpace(string(raw)); hashRe.MatchString(s) {
			return s
		}
	}
	return fallback
}

// RecordHostSetup records the hash of the install.sh that set this host up.
func RecordHostSetup(stateDir, sum string) error {
	if !hashRe.MatchString(sum) {
		return fmt.Errorf("host setup hash %q is not a hex SHA-256", sum)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(stateDir, hostSetupName), []byte(sum+"\n"), 0o600)
}

// planHostApply decides whether the swap runs `sandboxd host apply` (§6.3
// step 7): only when the target's install.sh differs from the one that set
// the host up. A rollback never does: every host change keeps working
// with the previous binary.
func (u *Upgrader) planHostApply(st *State, meta *release.Metadata, req Request) error {
	st.HostApply = HostApplyNotNeeded
	if meta == nil || req.Rollback {
		return nil
	}
	st.HostSetupSHA256 = meta.HostSetupSHA256
	if meta.HostSetupSHA256 == InstalledHostSetup(u.Paths.StateDir, u.SelfHostSetupSHA256) {
		return nil
	}
	if req.SkipHostApply {
		st.HostApply = HostApplySkipped
		return nil
	}
	if meta.HostSetupNeedsNetwork {
		return errors.New("this release's host changes need packages or network access, which host apply does not do; re-run install.sh on this node instead")
	}
	st.HostApply = HostApplyPending
	return nil
}

// planServices decides which services the swap restarts: Caddy when its
// file changed, and the egress gateway only when the target sandboxd no
// longer speaks the running gateway's protocol (§6.3), since that restart
// pauses hostname-filtered egress on the node.
func (u *Upgrader) planServices(ctx context.Context, st *State, meta *release.Metadata, rolledBack *State) {
	if f := st.file(roleCaddy); f != nil && f.Changed && u.Host.UnitActive(ctx, caddyUnit) {
		st.CaddyRestart = true
	}
	if !u.Host.UnitActive(ctx, gatewayUnit) {
		return
	}
	if rolledBack != nil {
		// The gateway the rolled-back upgrade restarted runs the newer
		// binary; the older sandboxd may not speak to it.
		st.GatewayRestart = rolledBack.GatewayRestarted
		return
	}
	if meta == nil {
		return
	}
	g, err := u.Host.GatewayProtocol(ctx, u.Paths.GatewaySocket)
	if err != nil {
		u.logf("warning: could not ask the egress gateway its protocol (%v); leaving it running", err)
		return
	}
	st.GatewayProtocol = g
	if !slices.Contains(meta.EgressGatewayProtocol, g) {
		st.GatewayRestart = true
		u.logf("the egress gateway speaks protocol %d and %s speaks %v: it restarts with the new binary", g, st.Version, meta.EgressGatewayProtocol)
	}
}

// progress is what apply has done that the failure path must undo.
type progress struct {
	stopped bool // sandboxd was stopped
	started bool // the new sandboxd was started
	// healthTimeout bounds the wait for the old sandboxd after a revert,
	// as it bounds the wait for the new one.
	healthTimeout time.Duration
}

// apply is everything from stopping sandboxd on (§6.3 steps 4-8). Any
// failure goes to revert.
func (u *Upgrader) apply(ctx context.Context, st *State, stageDir string, req Request) (*State, error) {
	p := progress{healthTimeout: req.HealthTimeout}
	marker := StoreOpenedMarkerPath(u.Paths.DBPath)
	if st.WasActive {
		st.Phase = PhaseStopping
		if err := u.save(st); err != nil {
			return u.revert(st, err, p)
		}
		if n := u.keepFirecrackerVMsRunning(ctx); n > 0 {
			u.logf("moved %d Firecracker VM processes out of sandboxd's cgroup", n)
		}
		p.stopped = true
		if err := u.Host.StopUnit(ctx, sandboxdUnit); err != nil {
			return u.revert(st, err, p)
		}
		u.logf("stopped sandboxd")
	}
	// Only the new binary may write it from here on (WriteStoreOpenedMarker).
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		return u.revert(st, err, p)
	}

	st.Phase = PhaseBackup
	if err := u.save(st); err != nil {
		return u.revert(st, err, p)
	}
	if _, err := os.Stat(u.Paths.DBPath); err == nil {
		dest := filepath.Join(u.Paths.StateDir, st.Op+backupSuffix)
		backup := u.Backup
		if backup == nil {
			backup = sqliteBackup
		}
		start := u.now()
		if err := backup(ctx, u.Paths.DBPath, dest); err != nil {
			return u.revert(st, fmt.Errorf("back up the database: %w", err), p)
		}
		st.BackupPath = dest
		u.logf("backed up %s to %s in %s", u.Paths.DBPath, dest, u.now().Sub(start).Round(time.Millisecond))
	}
	if st.RestoreBackup != "" {
		// Before the swap: a crash from here on, with sandboxd not yet
		// swapped, is reverted at boot by the newer binary, which puts
		// BackupPath back with the files (resolve).
		if st.BackupPath == "" {
			return u.revert(st, errors.New("no backup of the current database was taken, so the rollback cannot put an older one in its place"), p)
		}
		st.RestoreStarted = true
		if err := u.save(st); err != nil {
			return u.revert(st, err, p)
		}
		if err := restoreBackup(st.RestoreBackup, u.Paths.DBPath); err != nil {
			return u.revert(st, fmt.Errorf("put back the database backup %s: %w", st.RestoreBackup, err), p)
		}
		u.at("restored")
		u.logf("put back the database backup %s, from before the one-way schema migrations %s cannot open", st.RestoreBackup, st.Version)
	}

	st.Phase = PhaseSwapping
	if err := u.save(st); err != nil {
		return u.revert(st, err, p)
	}
	for _, role := range swapOrder {
		f := st.file(role)
		if f == nil || !f.Changed {
			continue
		}
		if err := swapIn(u.stagedPath(stageDir, f), f.Path); err != nil {
			return u.revert(st, err, p)
		}
		u.at("swapped-unrecorded:" + role)
		f.Swapped = true
		if err := u.save(st); err != nil {
			return u.revert(st, err, p)
		}
		u.at("swapped:" + role)
		u.logf("installed %s (old file kept as %s.prev)", f.Path, f.Path)
	}

	if st.HostApply == HostApplyPending {
		st.Phase = PhaseHost
		if err := u.save(st); err != nil {
			return u.revert(st, err, p)
		}
		// The new sandboxd applies the install.sh built into it, which is
		// the one the target's release.json hashes.
		out, err := u.Host.Run(ctx, u.Paths.Sandboxd, "host", "apply", "--env-file", u.Paths.EnvFile)
		if err != nil {
			return u.revert(st, fmt.Errorf("sandboxd host apply: %w: %s", err, tail(out)), p)
		}
		st.HostApply = HostApplyDone
		u.logf("applied the release's host setup")
	}
	if st.GatewayRestart {
		if err := u.Host.RestartUnit(ctx, gatewayUnit); err != nil {
			return u.revert(st, err, p)
		}
		st.GatewayRestarted = true
		u.logf("restarted the egress gateway")
	}
	if st.CaddyRestart {
		if err := u.Host.RestartUnit(ctx, caddyUnit); err != nil {
			return u.revert(st, err, p)
		}
		st.CaddyRestarted = true
		u.logf("restarted caddy")
	}

	if st.WasActive {
		st.Phase = PhaseStarting
		if err := u.save(st); err != nil {
			return u.revert(st, err, p)
		}
		p.started = true
		// restart, not start: a sandboxd someone started meanwhile still
		// runs the old binary.
		if err := u.Host.RestartUnit(ctx, sandboxdUnit); err != nil {
			return u.revert(st, err, p)
		}
		u.at("started")
		if err := u.waitHealthy(ctx, st.Version, req.HealthTimeout); err != nil {
			return u.revert(st, err, p)
		}
		u.logf("sandboxd is up on %s", st.Version)
	} else {
		u.logf("sandboxd was stopped before the upgrade; leaving it stopped")
	}

	if st.HostApply == HostApplyDone || st.HostApply == HostApplySkipped {
		if err := RecordHostSetup(u.Paths.StateDir, st.HostSetupSHA256); err != nil {
			u.logf("warning: %v", err)
		}
	}
	// The older database a rollback put back is the one in use now.
	st.Phase, st.Result, st.RestoreStarted = PhaseDone, ResultUpgraded, false
	if err := u.save(st); err != nil {
		return st, err
	}
	// The staged files are installed now; the *.prev copies and the backup
	// are what a rollback needs.
	_ = os.RemoveAll(stageDir)
	pruneBackups(u.Paths.StateDir)
	return st, nil
}

// waitHealthy waits until sandboxd answers /health with version (any
// version when it is empty).
func (u *Upgrader) waitHealthy(ctx context.Context, version string, timeout time.Duration) error {
	interval := u.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	deadline := u.now().Add(timeout)
	last := "no answer"
	for {
		v, err := u.Host.HealthVersion(ctx, u.Paths.HealthURL)
		switch {
		case err == nil && (version == "" || v == version):
			return nil
		case err == nil:
			last = "version " + v
		default:
			last = err.Error()
		}
		if !u.now().Before(deadline) {
			return fmt.Errorf("sandboxd did not report version %s on %s within %s (last: %s)", orAny(version), u.Paths.HealthURL, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func orAny(v string) string {
	if v == "" {
		return "(any)"
	}
	return v
}

// revert is the failure path (§6.3 step 9): put the *.prev files back, and
// restore the database backup only when the new binary never got past
// opening and migrating its store. Past that point boot work such as the
// secret outbox may already have reached peers, and the previous binary
// reads the database as it is (only n1_safe migrations run before
// finalize, CEO D16). A rollback never restores a backup (§6.8).
//
// A single node (cluster mode off) is the exception (oneway.go): it has no
// peers, and it runs one-way migrations at boot, so when they ran since the
// backup the backup goes back too, or the previous binary could not open
// the database. A single-node rollback that put an older backup in place
// puts the database as it found it back.
func (u *Upgrader) revert(st *State, cause error, p progress) (*State, error) {
	ctx, cancel := context.WithTimeout(context.Background(), revertTimeout)
	defer cancel()
	u.logf("upgrade failed: %v; putting the previous files back", cause)
	st.Phase, st.Error = PhaseRevert, cause.Error()
	var problems []error
	if err := u.save(st); err != nil {
		problems = append(problems, err)
	}
	u.at("reverting")
	if p.started {
		if err := u.Host.StopUnit(ctx, sandboxdUnit); err != nil {
			problems = append(problems, err)
		}
	}
	restoreDB := p.started && !st.Rollback && st.BackupPath != ""
	why := "the new sandboxd never opened its store"
	if restoreDB {
		if _, err := os.Stat(StoreOpenedMarkerPath(u.Paths.DBPath)); err == nil {
			restoreDB = false
			// A single node has no peers to have reached, and the
			// previous binary refuses one-way migrations it does not know
			// (oneway.go).
			if since := u.singleNodeOneWaySince(ctx, st, st.BackupPath, u.Paths.DBPath); len(since) > 0 {
				restoreDB = true
				why = fmt.Sprintf("one-way schema migrations %v ran since it was taken, which %s cannot open", since, orAny(st.FromVersion))
			}
		}
	}
	if st.RestoreStarted && st.BackupPath != "" {
		// This rollback put an older backup in place: put back the
		// database as the op found it, for the binary going back in.
		restoreDB = true
		why = "the rollback had put an older backup in its place"
	}
	for i := len(swapOrder) - 1; i >= 0; i-- {
		f := st.file(swapOrder[i])
		if f == nil || !f.Swapped {
			continue
		}
		if err := putBack(f.Path, f.PrevSHA256); err != nil {
			problems = append(problems, fmt.Errorf("put back %s: %w", f.Path, err))
			continue
		}
		f.Swapped = false
	}
	if restoreDB {
		if err := restoreBackup(st.BackupPath, u.Paths.DBPath); err != nil {
			problems = append(problems, fmt.Errorf("restore %s: %w", st.BackupPath, err))
		} else {
			st.BackupRestored, st.RestoreStarted = true, false
			u.logf("restored the database from %s: %s", st.BackupPath, why)
		}
	}
	if st.GatewayRestarted {
		if err := u.Host.RestartUnit(ctx, gatewayUnit); err != nil {
			problems = append(problems, err)
		}
	}
	if st.CaddyRestarted {
		if err := u.Host.RestartUnit(ctx, caddyUnit); err != nil {
			problems = append(problems, err)
		}
	}
	if p.stopped {
		if err := u.Host.RestartUnit(ctx, sandboxdUnit); err != nil {
			problems = append(problems, err)
		} else if err := u.waitHealthy(ctx, st.FromVersion, p.healthTimeout); err != nil {
			problems = append(problems, fmt.Errorf("after putting the previous files back: %w", err))
		}
	}
	st.Phase, st.Result = PhaseFailed, ResultFailed
	msg := cause.Error()
	if len(problems) > 0 {
		msg += "; while reverting: " + errors.Join(problems...).Error()
	}
	st.Error = msg
	if err := u.save(st); err != nil {
		return st, errors.Join(errors.New(msg), err)
	}
	return st, errors.New(msg)
}

func tail(out []byte) string {
	s := strings.TrimSpace(string(out))
	if len(s) > 2000 {
		s = "..." + s[len(s)-2000:]
	}
	return s
}
