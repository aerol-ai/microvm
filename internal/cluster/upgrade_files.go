package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	"golang.org/x/time/rate"
)

// Release files inside the cluster (plans/kubectl-style-cluster-ops.md §6.3,
// §6.6; CEO D12, D15).
//
//	operator ──PUT /v1/cluster/upgrade/files/{sha256}──► leader's FileStore      (source upload)
//	server   ──GET <SB_RELEASE_URL>/<version>/<asset>──► its FileStore            (source release)
//	server   ──GET /v1/cluster/internal/upgrade/files/{sha256}──► leader / server (source upload)
//	worker   ──GET /v1/cluster/internal/upgrade/files/{sha256}──► a server        (always)
//
// Files are named by their SHA-256, so a repeated upload or copy is a
// no-op, and every reader checks the bytes against the name again
// (FileStore.Put). A server serves at most maxFileCopies copies at once
// (503 + Retry-After past that) at SB_UPGRADE_SERVE_MBPS, and the leader
// serves no worker or ingress node while another server is up: Raft keeps
// its one-second heartbeat, so copy traffic must never fill the leader's
// link. At most the server tier (MaxServerTierNodes) ever touches the
// release URL.

// PublicInternalUpgradeFilesPath + {sha256} serves one release file to a
// peer.
const PublicInternalUpgradeFilesPath = "/v1/cluster/internal/upgrade/files/"

const (
	// maxFileCopies is how many copies one server serves at once.
	maxFileCopies = 20
	// fileCopyRetryAfter is the Retry-After a busy server answers.
	fileCopyRetryAfter = 2
	// serveChunk is the read size; the rate limiter's burst must cover it.
	serveChunk = 256 << 10
	// uploadPruneAge is how long an upload no rollout uses is kept (§6.6).
	uploadPruneAge = time.Hour
	// maxUploadTotalBytes caps what operators may push to the leader at
	// once (§8: 2 GiB in total, plus the hourly prune).
	maxUploadTotalBytes = upgradewire.MaxUploadTotalBytes
)

// ErrUploadQuota refuses an upload past maxUploadTotalBytes.
var ErrUploadQuota = errors.New("cluster: the leader holds 2 GiB of uploads already; apply or wait an hour for unused ones to be pruned")

// upgradeFileServer serves release files from this node's FileStore.
type upgradeFileServer struct {
	sem     chan struct{}
	limiter *rate.Limiter
	paths   func() (nodeupgrade.Paths, error)
	// leaderBusy reports whether this node leads and must refuse callerID
	// (a non-server while another server is up).
	leaderRefuses func(callerID string) bool
}

func newUpgradeFileServer(mbps int, paths func() (nodeupgrade.Paths, error), leaderRefuses func(string) bool) *upgradeFileServer {
	if mbps <= 0 {
		mbps = 200
	}
	bytesPerSec := float64(mbps) * 1e6
	return &upgradeFileServer{
		sem:           make(chan struct{}, maxFileCopies),
		limiter:       rate.NewLimiter(rate.Limit(bytesPerSec), serveChunk),
		paths:         paths,
		leaderRefuses: leaderRefuses,
	}
}

// ServeFile answers one peer's GET.
func (s *upgradeFileServer) ServeFile(w http.ResponseWriter, r *http.Request, callerID, sum string) {
	if !upgradewire.SHA256Re.MatchString(sum) {
		upgradeServeRefused.Add("bad_hash", 1)
		http.Error(w, "file name must be 64 lower-case hex digits", http.StatusBadRequest)
		return
	}
	if s.leaderRefuses != nil && s.leaderRefuses(callerID) {
		upgradeServeRefused.Add("leader", 1)
		w.Header().Set("Retry-After", strconv.Itoa(fileCopyRetryAfter))
		http.Error(w, "the leader serves no copies while another server is up; ask another server", http.StatusServiceUnavailable)
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		upgradeServeRefused.Add("busy", 1)
		w.Header().Set("Retry-After", strconv.Itoa(fileCopyRetryAfter))
		http.Error(w, fmt.Sprintf("this server is serving %d copies already; retry", maxFileCopies), http.StatusServiceUnavailable)
		return
	}
	p, err := s.paths()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}
	// A file this server never staged may still be one it runs, or ran: a
	// rollback copies the previous version from a server's own *.prev
	// (§6.6).
	if !store.Has(sum) && !nodeupgrade.PutLocalCopy(p, store, sum) {
		upgradeServeRefused.Add("missing", 1)
		http.Error(w, "this server does not hold "+sum, http.StatusNotFound)
		return
	}
	f, err := store.Open(sum)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Aerolvm-Sha256", sum)
	w.WriteHeader(http.StatusOK)
	n, _ := copyRateLimited(r.Context(), w, f, s.limiter)
	upgradeServedBytes.Add(n)
}

// copyRateLimited copies src to dst, waiting on lim for every chunk.
func copyRateLimited(ctx context.Context, dst io.Writer, src io.Reader, lim *rate.Limiter) (int64, error) {
	buf := make([]byte, serveChunk)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if lim != nil {
				if err := lim.WaitN(ctx, n); err != nil {
					return total, err
				}
			}
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// leaderRefusesCopy is the leader exclusion (CEO D15): the leader serves a
// server (an upload's first copies) but no worker or ingress node while
// another server is alive.
func (c *Cluster) leaderRefusesCopy(callerID string) bool {
	if c == nil || c.raft == nil || c.raft.raft == nil || !c.IsLeader() {
		return false
	}
	if m, ok := c.LookupMember(callerID); ok && CanServeControlPlaneRole(m.Role) {
		return false
	}
	for _, m := range c.LocalMembers() {
		if m.NodeID != c.nodeID && m.Alive && m.InternalURL != "" && CanServeControlPlaneRole(m.Role) {
			return true
		}
	}
	return false
}

// UpgradeFiles is the leader's upload store capability (pkg/api/v1).
type UpgradeFiles interface {
	// ServeUpgradeFile answers a peer's copy request.
	ServeUpgradeFile(w http.ResponseWriter, r *http.Request, callerID, sum string)
	// PutUpgradeFile stores one operator upload on the leader; created is
	// false when the leader already had it.
	PutUpgradeFile(ctx context.Context, sum string, body io.Reader) (created bool, size int64, err error)
	// HasUpgradeFile reports whether the leader holds the file.
	HasUpgradeFile(sum string) (bool, error)
}

// ServeUpgradeFile answers a peer's copy request (servers only).
func (c *Cluster) ServeUpgradeFile(w http.ResponseWriter, r *http.Request, callerID, sum string) {
	c.files.ServeFile(w, r, callerID, sum)
}

// PutUpgradeFile stores one upload, refusing past the 2 GiB total.
func (c *Cluster) PutUpgradeFile(_ context.Context, sum string, body io.Reader) (bool, int64, error) {
	p, err := c.upgrade.paths()
	if err != nil {
		return false, 0, err
	}
	store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir), MaxBytes: upgradewire.MaxUploadBytes}
	if store.Has(sum) {
		path, _ := store.Path(sum)
		fi, err := os.Stat(path)
		if err != nil {
			return false, 0, err
		}
		// A repeated upload keeps the file for another hour.
		now := time.Now()
		_ = os.Chtimes(path, now, now)
		return false, fi.Size(), nil
	}
	if storeBytes(store.Dir) >= maxUploadTotalBytes {
		return false, 0, ErrUploadQuota
	}
	return store.Put(sum, body)
}

// HasUpgradeFile reports whether this leader holds sum.
func (c *Cluster) HasUpgradeFile(sum string) (bool, error) {
	if !upgradewire.SHA256Re.MatchString(sum) {
		return false, nodeupgrade.ErrBadHash
	}
	p, err := c.upgrade.paths()
	if err != nil {
		return false, err
	}
	return nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}.Has(sum), nil
}

// storeBytes adds up the regular files in dir.
func storeBytes(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total
}

// rolloutKeepSet is what every node's prune keeps: the open rollout's
// files, target and previous version. A stopped or failed rollout still
// keeps them, since apply may restart it; a finalized or rolled-back one
// keeps nothing (§6.7).
func rolloutKeepSet(r *RolloutRecord) map[string]bool {
	if rolloutTerminal(r) {
		return map[string]bool{}
	}
	return rolloutFileSet(r)
}

// pruneKeepingRollout prunes the file store of a worker or ingress node,
// which holds no rollout record. A late worker batch can come hours after
// staging and must find its files still there: an apply allows only
// materializeTimeout to copy a missing one, and a whole batch copying at
// once from the servers would not make it. So the node asks a server for
// the open rollout (the fence route, which answers the current rollout
// for an empty ID) and keeps its files. It asks only when a file is old
// enough to prune, and prunes nothing while no server answers.
func (u *upgradeNode) pruneKeepingRollout(ctx context.Context, now time.Time) int {
	p, err := u.paths()
	if err != nil || u.fence == nil || !storeHasOlder(nodeupgrade.FileStoreDir(p.StateDir), now.Add(-uploadPruneAge)) {
		return 0
	}
	f, err := u.fence(ctx, "")
	if err != nil {
		if u.logger != nil {
			u.logger.Warn("cluster: upgrade file prune skipped; no server said which rollout is open", "err", err)
		}
		return 0
	}
	return pruneUpgradeFiles(u.paths, rolloutKeepSet(f.Rollout), now)
}

// storeHasOlder reports whether dir holds a regular file last changed
// before cutoff.
func storeHasOlder(dir string, cutoff time.Time) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && info.ModTime().Before(cutoff) {
			return true
		}
	}
	return false
}

// pruneUpgradeFiles deletes stored files no rollout uses that are older
// than an hour (§6.6), on every node. A finalized or rolled-back rollout
// keeps nothing.
func pruneUpgradeFiles(paths func() (nodeupgrade.Paths, error), keep map[string]bool, now time.Time) int {
	p, err := paths()
	if err != nil {
		return 0
	}
	n, _ := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}.Prune(now, uploadPruneAge, keep)
	return n
}
