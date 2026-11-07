package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	"golang.org/x/time/rate"
)

// Tests for the release-file server (upgrade_files.go): the hash path
// check, the 20-copy limit, leader exclusion, serving a node's own *.prev,
// the rate cap, and the upload quota.

func fileServerRig(t *testing.T, mbps int, leaderRefuses func(string) bool) (*upgradeFileServer, nodeupgrade.Paths) {
	t.Helper()
	dir := t.TempDir()
	p := nodeupgrade.Paths{StateDir: filepath.Join(dir, "upgrade"), Sandboxd: filepath.Join(dir, "sandboxd")}
	return newUpgradeFileServer(mbps, func() (nodeupgrade.Paths, error) { return p, nil }, leaderRefuses), p
}

func serveFile(s *upgradeFileServer, caller, sum string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, PublicInternalUpgradeFilesPath+sum, nil)
	s.ServeFile(rr, req, caller, sum)
	return rr
}

func TestUpgradeFileServer(t *testing.T) {
	s, p := fileServerRig(t, 0, func(caller string) bool { return caller == "worker-at-leader" })
	body := []byte("release file")
	sum := sumOf(body)
	store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}
	if _, _, err := store.Put(sum, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if rr := serveFile(s, "w1", "../../etc/passwd"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad path = %d", rr.Code)
	}
	if rr := serveFile(s, "worker-at-leader", sum); rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
		t.Fatalf("leader exclusion = %d", rr.Code)
	}
	rr := serveFile(s, "w1", sum)
	if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), body) || rr.Header().Get("X-Aerolvm-Sha256") != sum || rr.Header().Get("Content-Length") != "12" {
		t.Fatalf("serve = %d %q", rr.Code, rr.Body.String())
	}
	if rr := serveFile(s, "w1", strings.Repeat("0", 64)); rr.Code != http.StatusNotFound {
		t.Fatalf("missing = %d", rr.Code)
	}
	// A file the server runs (or ran: *.prev) is served from its own copy.
	prev := []byte("previous sandboxd")
	if err := os.WriteFile(p.Sandboxd+".prev", prev, 0o755); err != nil {
		t.Fatal(err)
	}
	if rr := serveFile(s, "w1", sumOf(prev)); rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), prev) {
		t.Fatalf("serve *.prev = %d", rr.Code)
	}
	// Past 20 copies at once: 503 with Retry-After.
	for i := 0; i < maxFileCopies; i++ {
		s.sem <- struct{}{}
	}
	if rr := serveFile(s, "w1", sum); rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") != "2" {
		t.Fatalf("21st copy = %d", rr.Code)
	}
	for i := 0; i < maxFileCopies; i++ {
		<-s.sem
	}
	broken := newUpgradeFileServer(1, func() (nodeupgrade.Paths, error) { return nodeupgrade.Paths{}, os.ErrNotExist }, nil)
	if rr := serveFile(broken, "w1", sum); rr.Code != http.StatusInternalServerError {
		t.Fatalf("no paths = %d", rr.Code)
	}
}

// The rate cap holds: with a fake-slow limiter the copy takes as long as
// the cap says (CEO D15).
func TestCopyRateLimited(t *testing.T) {
	src := bytes.Repeat([]byte("x"), 3*serveChunk)
	lim := rate.NewLimiter(rate.Limit(float64(4*serveChunk)), serveChunk) // 4 chunks/s, burst 1 chunk
	var dst bytes.Buffer
	start := time.Now()
	n, err := copyRateLimited(context.Background(), &dst, bytes.NewReader(src), lim)
	elapsed := time.Since(start)
	if err != nil || n != int64(len(src)) || !bytes.Equal(dst.Bytes(), src) {
		t.Fatalf("copy = %d %v", n, err)
	}
	if elapsed < 400*time.Millisecond {
		t.Fatalf("3 chunks at 4 chunks/s took %s; the cap did not hold", elapsed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := copyRateLimited(ctx, &dst, bytes.NewReader(src), rate.NewLimiter(1, serveChunk)); err == nil {
		t.Fatal("a cancelled copy finished")
	}
	if _, err := copyRateLimited(context.Background(), failWriter{}, bytes.NewReader(src), nil); err == nil {
		t.Fatal("a failed write was ignored")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// R8: a worker holds no rollout record. It used to prune every staged file
// after an hour, so in a big fleet a late worker batch had to copy all its
// files again within the 45 s an apply allows, all at once. It now keeps
// the open rollout's files (target and previous version), asking a server
// for the rollout only when something is old enough to prune, and prunes
// nothing when no server answers.
func TestWorkerPruneKeepsTheOpenRolloutsFiles(t *testing.T) {
	g := newUpgradeNodeRig(t, false)
	store := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(g.paths.StateDir)}
	old := time.Now().Add(-2 * time.Hour)
	put := func(b []byte) string {
		t.Helper()
		if _, _, err := store.Put(sumOf(b), bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
		path, _ := store.Path(sumOf(b))
		_ = os.Chtimes(path, old, old)
		return sumOf(b)
	}
	target, prev, stray := put([]byte("v2 sandboxd")), put([]byte("v1 sandboxd")), put([]byte("an old upload"))
	r := stepRollout(upgradewire.StateRunning, upgradewire.NodeStaged, map[string]string{"sandboxd_linux_amd64": target})
	r.PrevFiles = map[string]string{"sandboxd_linux_amd64": prev}
	reads := 0
	g.u.fence = func(_ context.Context, rolloutID string) (UpgradeFence, error) {
		reads++
		if rolloutID != "" {
			t.Fatalf("the prune asked for rollout %q, want the current one", rolloutID)
		}
		return UpgradeFence{Leader: "lead", Term: 1, Rollout: r}, g.fenceErr
	}
	if n := g.u.pruneKeepingRollout(context.Background(), time.Now()); n != 1 || !store.Has(target) || !store.Has(prev) || store.Has(stray) {
		t.Fatalf("pruned %d; target kept %v, previous kept %v, stray kept %v", n, store.Has(target), store.Has(prev), store.Has(stray))
	}
	// A stopped rollout may be applied again: still kept.
	r.State = upgradewire.StateStopped
	if n := g.u.pruneKeepingRollout(context.Background(), time.Now()); n != 0 {
		t.Fatalf("a stopped rollout's files were pruned: %d", n)
	}
	// No server answers: nothing goes.
	g.fenceErr = errors.New("no server answered")
	g.u.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	if n := g.u.pruneKeepingRollout(context.Background(), time.Now()); n != 0 || !store.Has(target) {
		t.Fatalf("pruned %d with no rollout to check", n)
	}
	saved := g.u.fence
	g.u.fence = nil
	if n := g.u.pruneKeepingRollout(context.Background(), time.Now()); n != 0 {
		t.Fatalf("pruned %d before the node can read a rollout", n)
	}
	g.u.fence = saved
	if storeHasOlder(filepath.Join(t.TempDir(), "nowhere"), time.Now()) {
		t.Fatal("a missing store holds an old file")
	}
	// Finalized: everything old goes.
	g.fenceErr = nil
	r.State = upgradewire.StateFinalized
	if n := g.u.pruneKeepingRollout(context.Background(), time.Now()); n != 2 || store.Has(target) || store.Has(prev) {
		t.Fatalf("after finalize pruned %d", n)
	}
	// Nothing old enough: no call to a server at all.
	reads = 0
	put([]byte("fresh"))
	path, _ := store.Path(sumOf([]byte("fresh")))
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	if n := g.u.pruneKeepingRollout(context.Background(), now); n != 0 || reads != 0 {
		t.Fatalf("a store with nothing old asked a server %d times, pruned %d", reads, n)
	}
}

func TestUploadStoreQuotaAndPrune(t *testing.T) {
	dir := t.TempDir()
	p := nodeupgrade.Paths{StateDir: filepath.Join(dir, "upgrade")}
	c := &Cluster{upgrade: &upgradeNode{paths: func() (nodeupgrade.Paths, error) { return p, nil }}}
	body := []byte("upload")
	created, size, err := c.PutUpgradeFile(context.Background(), sumOf(body), bytes.NewReader(body))
	if err != nil || !created || size != 6 {
		t.Fatalf("put = %v %d %v", created, size, err)
	}
	if created, _, err := c.PutUpgradeFile(context.Background(), sumOf(body), bytes.NewReader(body)); err != nil || created {
		t.Fatalf("repeat put = %v %v", created, err)
	}
	if ok, err := c.HasUpgradeFile(sumOf(body)); !ok || err != nil {
		t.Fatalf("has = %v %v", ok, err)
	}
	if _, err := c.HasUpgradeFile("bad"); err == nil {
		t.Fatal("has with a bad hash")
	}
	if _, _, err := c.PutUpgradeFile(context.Background(), strings.Repeat("1", 64), bytes.NewReader(body)); err == nil {
		t.Fatal("a body that does not hash to its name was kept")
	}
	// Over 2 GiB in the store: refused. A sparse file stands in for it.
	big := filepath.Join(nodeupgrade.FileStoreDir(p.StateDir), strings.Repeat("b", 64))
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxUploadTotalBytes); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, _, err := c.PutUpgradeFile(context.Background(), sumOf([]byte("more")), bytes.NewReader([]byte("more"))); err != ErrUploadQuota {
		t.Fatalf("over quota = %v", err)
	}
	// Prune: an hour-old file no rollout keeps goes; kept ones stay.
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(big, old, old)
	keepPath, _ := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}.Path(sumOf(body))
	_ = os.Chtimes(keepPath, old, old)
	if n := pruneUpgradeFiles(c.upgrade.paths, map[string]bool{sumOf(body): true}, time.Now()); n != 1 {
		t.Fatalf("pruned %d", n)
	}
	if _, err := os.Stat(keepPath); err != nil {
		t.Fatal("a kept file was pruned")
	}
	if pruneUpgradeFiles(func() (nodeupgrade.Paths, error) { return p, os.ErrNotExist }, nil, time.Now()) != 0 {
		t.Fatal("prune without paths")
	}
	if storeBytes(filepath.Join(dir, "nowhere")) != 0 {
		t.Fatal("store bytes of nothing")
	}
}
