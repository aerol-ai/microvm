package rootd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootfolder"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runscwrap"
	"github.com/aerol-ai/microvm/internal/runtime/movebundle"
)

// gVisor checkpoint moves (M1 PR 13; C21 of plans/kubernetes-v2-
// architecture.md §10.5). A running gVisor sandbox moves to another worker
// with its memory. In privilege mode single sandboxd runs runsc checkpoint
// itself, as root, on the gVisor shim's state, and stages the bundle another
// worker sent it in its own run folder, where the restored sandbox's runsc
// reads it as root. In split mode the agent can do neither: runsc's state is
// root's, and a folder the agent writes is one where it could change a file
// between the gate's check and runsc's read. So the helper does both, in its
// moves folder (Policy.MovesDir), which only root can open:
//
//	<MovesDir>/out/<id>  CheckpointMove: runsc checkpoint's image
//	<MovesDir>/in/<id>   ImportMove: a bundle staged for the restore
//
// The agent names a sandbox by its ID alone and never a path. Export reads
// the out folder as a move bundle (internal/runtime/movebundle, the same
// format single mode sends; runsc itself restores only between workers of
// one mode, cluster.CheckpointMovesLabel), and Import writes only what
// that format carries: a manifest for this sandbox, then the regular files
// it names, each once, by flat names, and no sparse entry. The bundle is
// bounded in bytes (a refusal), both what the stream carries and what is
// written to disk, the staged bundles in number (busy), and a bundle that
// is not whole is never staged. The restored container's spec names <MovesDir>/in/<its own ID>,
// which the gate checks (rootpolicy.CheckRestorePath).

// MovesConfig is gVisor checkpoint moves' settings, from the helper's own
// environment: on with sandboxd's SB_GVISOR_CHECKPOINT_MOVES, nil (no move
// call served) without it.
type MovesConfig struct {
	// Runsc is the runsc the helper checkpoints with: an absolute path, in
	// no folder the agent writes (SB_ROOTD_RUNSC, /usr/local/bin/runsc).
	Runsc string
	// StateRoot is the gVisor shim's runsc state root, one folder per
	// containerd namespace; the helper checkpoints only in its own
	// namespace's (SB_ROOTD_RUNSC_ROOT, /run/containerd/runsc).
	StateRoot string
	// MaxBundleBytes bounds one imported bundle (SB_ROOTD_MOVE_MAX_BYTES),
	// the bytes its stream carries and the bytes its files take when
	// written: by default twice the node's memory, above what one
	// sandbox's memory and root overlay can hold.
	MaxBundleBytes int64
	// MaxStaged bounds the bundles staged or arriving at once
	// (SB_ROOTD_MOVE_MAX_STAGED, 8: a worker's moves in parallel).
	MaxStaged int
}

const (
	defaultRunsc          = "/usr/local/bin/runsc"
	defaultRunscStateRoot = "/run/containerd/runsc"
	defaultMaxStagedMoves = 8
	// moveChunk is the size of one message of a bundle's bytes, well
	// under gRPC's 4 MiB default message limit.
	moveChunk = 1 << 20
	// runscOutputMax bounds the runsc output a failed checkpoint answers
	// with.
	runscOutputMax = 4 << 10
	// importTmp names a bundle while it arrives, before it is whole.
	importTmp = "import"
)

// moveFeatures are the move calls, served with MovesConfig.
var moveFeatures = []string{rootdpb.FeatureCheckpointMove, rootdpb.FeatureExportMove, rootdpb.FeatureImportMove,
	rootdpb.FeatureStagedMove, rootdpb.FeatureDropMove}

// moveSweepGrace is how old a move folder must be before the sweep takes
// it: a move hands a sandbox over within minutes. A var for tests.
var moveSweepGrace = time.Hour

// errMoveTooLarge: the bundle went past MovesConfig.MaxBundleBytes.
var errMoveTooLarge = errors.New("the move bundle is too large")

// moveCalls serves the move calls.
type moveCalls struct {
	cfg       MovesConfig
	policy    rootpolicy.Policy
	locks     *keyedLocks
	log       *slog.Logger
	out, in   int // the two sides' folders, open for the server's life
	outDir    string
	inDir     string
	namespace string
	// run runs runsc with args and answers its output; tests stand in.
	run func(ctx context.Context, bin string, args ...string) ([]byte, error)
	// mu orders the staged count's check with the make of an import's
	// folder, so two imports cannot both take the last place.
	mu sync.Mutex
}

// runRunsc runs runsc with a fixed environment of its own: nothing of the
// helper's settings reaches it.
func runRunsc(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd.CombinedOutput()
}

// newMoveCalls opens the moves folder's two sides, making them where
// missing, each root's alone, and clears what an import cut short by a
// crash left. Nil when this helper serves no move.
func newMoveCalls(cfg Config, locks *keyedLocks, log *slog.Logger) (*moveCalls, error) {
	if cfg.Moves == nil {
		return nil, nil
	}
	m := &moveCalls{cfg: *cfg.Moves, policy: cfg.Policy, locks: locks, log: log, out: -1, in: -1, namespace: cfg.Policy.Namespace,
		outDir: filepath.Join(cfg.Policy.MovesDir, rootpolicy.MovesOut), inDir: filepath.Join(cfg.Policy.MovesDir, rootpolicy.MovesIn), run: runRunsc}
	for _, side := range []struct {
		dir string
		fd  *int
	}{{m.outDir, &m.out}, {m.inDir, &m.in}} {
		fd, err := openFolder(side.dir)
		if err == nil {
			err = setFolderMode(fd, 0o700, -1)
		}
		if err != nil {
			m.close()
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			return nil, fmt.Errorf("root helper: moves folder %s: %w", side.dir, err)
		}
		*side.fd = fd
	}
	if names, err := folderNames(m.in); err == nil {
		for _, n := range names {
			if strings.HasPrefix(n, ".") {
				_ = removeFolder(m.in, n)
			}
		}
	}
	return m, nil
}

func (m *moveCalls) close() {
	if m == nil {
		return
	}
	for _, fd := range []*int{&m.out, &m.in} {
		if *fd >= 0 {
			_ = unix.Close(*fd)
			*fd = -1
		}
	}
}

// moveKey is the per-object lock key of a sandbox's move folders (D11).
func moveKey(id string) string { return "move/" + id }

// checkpoint runs runsc checkpoint on the sandbox into its out folder, in
// place of any checkpoint saved for it before. The folder is made fresh,
// root's alone, before runsc writes in it, and goes again if runsc fails or
// writes no checkpoint.
func (m *moveCalls) checkpoint(ctx context.Context, req *rootdpb.CheckpointMoveRequest) (*rootdpb.CheckpointMoveResponse, error) {
	id := req.GetSandboxId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	unlock, err := m.locks.lock(ctx, moveKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := removeFolder(m.out, id); err != nil {
		return nil, fmt.Errorf("root helper: clear %s's checkpoint: %w", id, err)
	}
	if err := unix.Mkdirat(m.out, id, 0o700); err != nil {
		return nil, fmt.Errorf("root helper: checkpoint folder of %s: %w", id, err)
	}
	dir, err := movebundle.Inside(m.outDir, id)
	if err != nil {
		_ = removeFolder(m.out, id)
		return nil, badRequest("%v", err)
	}
	// "--" ends runsc's options: a sandbox ID may begin with '-'
	// (rootpolicy.ValidateID), and it is always the container's ID.
	out, err := m.run(ctx, m.cfg.Runsc, "--root="+filepath.Join(m.cfg.StateRoot, m.namespace), "checkpoint", "--image-path="+dir, "--", id)
	if err == nil && !hasCheckpointAt(m.out, id) {
		err = errors.New("it wrote no checkpoint")
	}
	if err != nil {
		_ = removeFolder(m.out, id)
		if len(out) > runscOutputMax {
			out = out[:runscOutputMax]
		}
		return nil, fmt.Errorf("root helper: runsc checkpoint %s: %w: %s", id, err, strings.TrimSpace(string(out)))
	}
	return &rootdpb.CheckpointMoveResponse{}, nil
}

// hasCheckpointAt reports whether the folder id in the open folder base
// holds a checkpoint: runsc's first file there, a regular file, reached
// with no link followed.
func hasCheckpointAt(base int, id string) bool {
	dfd, err := unix.Openat(base, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(dfd) }()
	var st unix.Stat_t
	return unix.Fstatat(dfd, runscwrap.CheckpointFile, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG
}

// export sends the sandbox's saved checkpoint as a move bundle, in chunks.
func (m *moveCalls) export(ctx context.Context, req *rootdpb.ExportMoveRequest, send func(*rootdpb.MoveChunk) error) error {
	id := req.GetSandboxId()
	if err := checkID(id); err != nil {
		return err
	}
	unlock, err := m.locks.lock(ctx, moveKey(id))
	if err != nil {
		return err
	}
	defer unlock()
	if !hasCheckpointAt(m.out, id) {
		return &fileError{code: codes.NotFound, msg: fmt.Sprintf("root helper: no checkpoint of %s (it was not stopped for a move, or it ran since)", id)}
	}
	dir, err := movebundle.Inside(m.outDir, id)
	if err != nil {
		return badRequest("%v", err)
	}
	w := bufio.NewWriterSize(chunkWriter(send), moveChunk)
	if err := movebundle.WriteDir(ctx, w, dir, id); err != nil {
		return fmt.Errorf("root helper: export %s: %w", id, err)
	}
	return w.Flush()
}

// chunkWriter sends what is written to it as move chunks, each a copy: a
// sent message must not change after it is sent.
type chunkWriter func(*rootdpb.MoveChunk) error

func (send chunkWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k := min(len(p), moveChunk)
		if err := send(&rootdpb.MoveChunk{Data: bytes.Clone(p[:k])}); err != nil {
			return n, err
		}
		n, p = n+k, p[k:]
	}
	return n, nil
}

// importBundle takes a bundle in from recv and stages it in the sandbox's
// in folder, in place of any staged before. The bundle arrives in a folder
// of its own, hidden, and is renamed into place only once it is whole and
// holds a checkpoint; anything short of that is removed.
func (m *moveCalls) importBundle(ctx context.Context, recv func() (*rootdpb.ImportMoveRequest, error)) (*rootdpb.ImportMoveResponse, error) {
	first, err := recv()
	if err != nil {
		return nil, fmt.Errorf("root helper: import: %w", err)
	}
	if err := noUnknownFields(first); err != nil {
		return nil, err
	}
	id := first.GetSandboxId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	unlock, err := m.locks.lock(ctx, moveKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	tmp, err := m.reserve(id)
	if err != nil {
		return nil, err
	}
	staged := false
	defer func() {
		if !staged {
			_ = removeFolder(m.in, tmp)
		}
	}()
	dir, err := movebundle.Inside(m.inDir, tmp)
	if err != nil {
		return nil, badRequest("%v", err)
	}
	// The bound holds twice: importReader counts what the stream carries,
	// and ReadDir what it writes (a tar entry's size on disk is its header's,
	// not the stream's bytes).
	r := &importReader{recv: recv, buf: first.GetData(), max: m.cfg.MaxBundleBytes}
	if r.n = int64(len(r.buf)); r.n > r.max {
		return nil, m.importErr(ctx, id, errMoveTooLarge)
	}
	if _, err = movebundle.ReadDir(ctx, r, dir, id, m.cfg.MaxBundleBytes); err == nil {
		err = r.rest()
	}
	if err != nil {
		return nil, m.importErr(ctx, id, err)
	}
	if !hasCheckpointAt(m.in, tmp) {
		return nil, &fileError{code: codes.InvalidArgument, reason: string(rootpolicy.RuleMoveBundle),
			msg: fmt.Sprintf("root helper: the bundle for %s holds no checkpoint", id)}
	}
	if err := removeFolder(m.in, id); err != nil {
		return nil, fmt.Errorf("root helper: clear %s's staged checkpoint: %w", id, err)
	}
	if err := unix.Renameat(m.in, tmp, m.in, id); err != nil {
		return nil, fmt.Errorf("root helper: stage %s: %w", id, err)
	}
	staged = true
	return &rootdpb.ImportMoveResponse{RestorePath: rootpolicy.MoveFolder(m.policy, rootpolicy.MovesIn, id)}, nil
}

// reserve makes an arriving bundle's hidden folder, when the bundles staged
// or arriving, the sandbox's own staged one aside (an import replaces it),
// leave room for one more.
func (m *moveCalls) reserve(id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	names, err := folderNames(m.in)
	if err != nil {
		return "", err
	}
	if n := len(slices.DeleteFunc(names, func(s string) bool { return s == id })); n >= m.cfg.MaxStaged {
		return "", &fileError{code: codes.ResourceExhausted,
			msg: fmt.Sprintf("root helper: %d move bundles are staged or arriving, this node's most (SB_ROOTD_MOVE_MAX_STAGED)", n)}
	}
	tmp, err := rootfolder.TmpName(importTmp)
	if err != nil {
		return "", err
	}
	if err := unix.Mkdirat(m.in, tmp, 0o700); err != nil {
		return "", fmt.Errorf("root helper: import folder: %w", err)
	}
	return tmp, nil
}

// streamErr is the import stream's own failure: the agent went away, or
// cancelled the import because its source failed. Neither is the bundle's
// fault.
type streamErr struct{ err error }

func (e *streamErr) Error() string { return "the import stream: " + e.err.Error() }
func (e *streamErr) Unwrap() error { return e.err }

// importErr says why an import failed: a bundle too large, or one that is
// not a move bundle for this sandbox, is a refusal (the agent sends only
// what another worker's agent made with movebundle.WriteDir); the stream
// ending under it, the caller giving up, or a write that failed on the
// helper's side (the disk full) is not.
func (m *moveCalls) importErr(ctx context.Context, id string, err error) error {
	var se *streamErr
	var pe *fs.PathError
	var fe *fileError
	switch {
	case errors.As(err, &fe):
		// The helper's own answer (a newer agent's field): as it is.
		return fe
	case errors.Is(err, errMoveTooLarge), errors.Is(err, movebundle.ErrTooLarge):
		return refusedRule(codes.InvalidArgument, rootpolicy.CheckMoveBundleSize(m.cfg.MaxBundleBytes+1, m.cfg.MaxBundleBytes))
	case ctx.Err() != nil, errors.As(err, &se):
		return fmt.Errorf("root helper: import %s: %w", id, err)
	case errors.As(err, &pe):
		return fmt.Errorf("root helper: import %s: %w", id, err)
	}
	return &fileError{code: codes.InvalidArgument, reason: string(rootpolicy.RuleMoveBundle),
		msg: fmt.Sprintf("root helper: the bundle for %s is not one: %v", id, err)}
}

// importReader reads a bundle's bytes from the import stream, counting
// them against the bound. Every message after the first carries bytes
// alone.
type importReader struct {
	recv   func() (*rootdpb.ImportMoveRequest, error)
	buf    []byte
	n, max int64
	err    error
}

func (r *importReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		r.err = r.next()
	}
	k := copy(p, r.buf)
	r.buf = r.buf[k:]
	return k, nil
}

// next takes the stream's next message into buf.
func (r *importReader) next() error {
	msg, err := r.recv()
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if err != nil {
		return &streamErr{err: err}
	}
	if err := noUnknownFields(msg); err != nil {
		return err
	}
	if msg.GetSandboxId() != "" {
		return errors.New("a message after the first names a sandbox")
	}
	if r.n += int64(len(msg.GetData())); r.n > r.max {
		return errMoveTooLarge
	}
	r.buf = msg.GetData()
	return nil
}

// rest checks the stream ends with the bundle: the tar's end is the
// stream's.
func (r *importReader) rest() error {
	var b [1]byte
	switch n, err := r.Read(b[:]); {
	case n > 0:
		return errors.New("the stream goes on past the bundle's end")
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

// staged answers the sandbox's staged checkpoint folder, "" for none.
func (m *moveCalls) staged(ctx context.Context, req *rootdpb.StagedMoveRequest) (*rootdpb.StagedMoveResponse, error) {
	id := req.GetSandboxId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	unlock, err := m.locks.lock(ctx, moveKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if !hasCheckpointAt(m.in, id) {
		return &rootdpb.StagedMoveResponse{}, nil
	}
	return &rootdpb.StagedMoveResponse{RestorePath: rootpolicy.MoveFolder(m.policy, rootpolicy.MovesIn, id)}, nil
}

// drop removes the sandbox's checkpoints on the sides asked for. Gone
// already counts as done.
func (m *moveCalls) drop(ctx context.Context, req *rootdpb.DropMoveRequest) (*rootdpb.DropMoveResponse, error) {
	id := req.GetSandboxId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	var bases []int
	for _, s := range req.GetSides() {
		switch s {
		case rootdpb.MoveSide_MOVE_SIDE_OUT:
			bases = append(bases, m.out)
		case rootdpb.MoveSide_MOVE_SIDE_IN:
			bases = append(bases, m.in)
		default:
			return nil, badRequest("root helper: move side %v is not one", s)
		}
	}
	if len(bases) == 0 {
		return nil, badRequest("root helper: a drop names no side")
	}
	unlock, err := m.locks.lock(ctx, moveKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	for _, b := range bases {
		if err := removeFolder(b, id); err != nil {
			return nil, fmt.Errorf("root helper: drop %s's checkpoint: %w", id, err)
		}
	}
	return &rootdpb.DropMoveResponse{}, nil
}

// sweep removes move folders a crash left: a staged bundle older than
// grace (its restore read it long ago, or never came), and a checkpoint
// older than grace whose container is gone. live is containerd's
// containers.
func (m *moveCalls) sweep(ctx context.Context, live map[string]bool, grace time.Duration) []string {
	var removed []string
	cutoff := time.Now().Add(-grace)
	for _, side := range []struct {
		fd int
		// evenLive: a staged bundle goes once old, container or not; a
		// checkpoint waits for its stopped container to go.
		evenLive bool
	}{{m.out, false}, {m.in, true}} {
		names, err := folderNames(side.fd)
		if err != nil {
			continue
		}
		for _, id := range names {
			if rootpolicy.ValidateID(id) != nil || (live[id] && !side.evenLive) {
				continue
			}
			unlock, err := m.locks.lock(ctx, moveKey(id))
			if err != nil {
				return removed
			}
			var st unix.Stat_t
			if unix.Fstatat(side.fd, id, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && time.Unix(st.Mtim.Unix()).Before(cutoff) {
				if removeFolder(side.fd, id) == nil {
					removed = append(removed, id)
				}
			}
			unlock()
		}
	}
	return removed
}
