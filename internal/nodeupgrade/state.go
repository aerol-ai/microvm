package nodeupgrade

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Phase is where an operation is. Every phase but done and failed is
// unfinished: Recover completes or reverts an unfinished op it finds at
// boot with no upgrader holding the lock.
type Phase string

const (
	PhaseStaging  Phase = "staging"
	PhaseStopping Phase = "stopping"
	PhaseBackup   Phase = "backup"
	PhaseSwapping Phase = "swapping"
	PhaseHost     Phase = "host-apply"
	PhaseStarting Phase = "starting"
	PhaseRevert   Phase = "reverting"
	PhaseDone     Phase = "done"
	PhaseFailed   Phase = "failed"
)

// Results of a finished operation.
const (
	ResultUpgraded = "upgraded"
	ResultNoop     = "noop"
	ResultFailed   = "failed"
	// ResultCompletedAtBoot and ResultRevertedAtBoot are Recover's.
	ResultCompletedAtBoot = "completed-at-boot"
	ResultRevertedAtBoot  = "reverted-at-boot"
)

// Host-apply outcomes recorded in State.HostApply.
const (
	HostApplyNotNeeded = "not-needed"
	HostApplySkipped   = "skipped"
	HostApplyPending   = "pending"
	HostApplyDone      = "done"
)

const stateFormat = 1

// State is one operation's record, /var/lib/sandboxd/upgrade/<op>.json. It
// is rewritten after every step, so a crash leaves the step it was on.
type State struct {
	Format      int    `json:"format"`
	Op          string `json:"op"`
	Version     string `json:"version"`
	FromVersion string `json:"from_version,omitempty"`
	Rollback    bool   `json:"rollback,omitempty"`
	Phase       Phase  `json:"phase"`
	Result      string `json:"result,omitempty"`
	Error       string `json:"error,omitempty"`
	// WasActive is whether sandboxd ran when the op began. A stopped
	// sandboxd is left stopped.
	WasActive bool        `json:"was_active"`
	Files     []FileState `json:"files"`
	// BackupPath is the database backup taken before the swap.
	BackupPath string `json:"backup_path,omitempty"`
	// BackupRestored is true when the failure path put it back.
	BackupRestored bool `json:"backup_restored,omitempty"`
	// HostApply is not-needed, skipped, pending or done; HostSetupSHA256 is
	// the target's install.sh hash from its release.json.
	HostApply       string `json:"host_apply,omitempty"`
	HostSetupSHA256 string `json:"host_setup_sha256,omitempty"`
	// Services the swap restarts: Caddy when its file changed, the egress
	// gateway when the target sandboxd no longer speaks its protocol.
	CaddyRestart     bool `json:"caddy_restart,omitempty"`
	CaddyRestarted   bool `json:"caddy_restarted,omitempty"`
	GatewayRestart   bool `json:"gateway_restart,omitempty"`
	GatewayRestarted bool `json:"gateway_restarted,omitempty"`
	// GatewayProtocol is the protocol the running gateway spoke, 0 when no
	// gateway ran or it could not be asked.
	GatewayProtocol int       `json:"gateway_protocol,omitempty"`
	StartedAt       time.Time `json:"started_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// FileState is one file of an operation.
type FileState struct {
	Role  string `json:"role"`
	Asset string `json:"asset"`
	// Path is where it is installed; empty for release.json.
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256"`
	// Size is the staged file's size.
	Size int64 `json:"size,omitempty"`
	// PrevSHA256 is the file it replaces, kept as Path.prev; empty when
	// nothing was installed there.
	PrevSHA256 string `json:"prev_sha256,omitempty"`
	// Changed is true when the installed file differed from SHA256.
	Changed bool `json:"changed"`
	Swapped bool `json:"swapped,omitempty"`
	// source is where staging reads it from: a local file (--from, or a
	// *.prev for a rollback) or "" to download.
	source string
}

func (s *State) terminal() bool { return s.Phase == PhaseDone || s.Phase == PhaseFailed }

func (s *State) file(role string) *FileState {
	for i := range s.Files {
		if s.Files[i].Role == role {
			return &s.Files[i]
		}
	}
	return nil
}

func statePath(dir, op string) string { return filepath.Join(dir, op+".json") }

// save writes the record in one rename.
func (s *State) save(dir string, now time.Time) error {
	s.UpdatedAt = now.UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(statePath(dir, s.Op), append(data, '\n'), 0o600)
}

func loadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Format != stateFormat {
		return nil, fmt.Errorf("%s has format %d; this sandboxd reads format %d", path, s.Format, stateFormat)
	}
	return &s, nil
}

// LoadState reads one operation's record.
func LoadState(stateDir, op string) (*State, error) {
	if !opRe.MatchString(op) {
		return nil, fmt.Errorf("op %q is not an operation ID", op)
	}
	return loadState(statePath(stateDir, op))
}

// listStates returns every readable record in dir, oldest first. A record
// that does not parse is skipped: one bad file must not stop a boot.
func listStates(dir string) ([]*State, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*State
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || !opRe.MatchString(strings.TrimSuffix(name, ".json")) {
			continue
		}
		s, err := loadState(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out, nil
}

// ErrBusy is returned when another upgrade holds the node's lock.
var ErrBusy = errors.New("another upgrade is running on this node")

// lock is the one-upgrade-at-a-time lock file, held with flock for the
// life of the process: a crash releases it, so a stale file never blocks
// the next upgrade.
type lock struct{ f *os.File }

func acquireLock(dir, op string) (*lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(f.Name())
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			if h := strings.TrimSpace(string(holder)); h != "" {
				return nil, fmt.Errorf("%w (op %s)", ErrBusy, h)
			}
			return nil, ErrBusy
		}
		return nil, err
	}
	if op != "" {
		_ = f.Truncate(0)
		_, _ = f.WriteAt([]byte(op+"\n"), 0)
	}
	return &lock{f: f}, nil
}

func (l *lock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = l.f.Truncate(0)
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
