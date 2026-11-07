package nodeupgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/release"
)

// fakeHost stands in for systemd, the network and the processes. A
// "binary" is a text file naming its version (fakeBinary); restarting the
// sandboxd unit "execs" whatever file is installed at that moment, so the
// health answer and the store-opened marker follow the files on disk the
// way a real restart does.
type fakeHost struct {
	t     *testing.T
	paths *Paths

	mu     sync.Mutex
	calls  []string
	active map[string]bool
	// running is the version the sandboxd process reports; "" is down.
	running string
	// missing names tools LookPath does not find.
	missing map[string]bool
	free    map[string]uint64 // directory → free bytes; default plenty
	freeErr error
	// fail makes a unit verb or a run fail: "stop sandboxd", "restart
	// caddy", "host apply".
	fail map[string]error
	// A started sandboxd whose file holds "BROKEN" dies before its store
	// opens (no marker, no health); one holding "UNHEALTHY" opens its
	// store and then never answers (boot).
	gateway    int
	gatewayErr error
	fetches    []string
	fetch      map[string][]byte // URL → body
	drains     []string
	nextPID    int
	cgroup     string
	hostApply  func() ([]byte, error)
	// openStore, when set, is the started binary opening its database
	// (content is the binary's file); false means it refused the database
	// and died before its marker, as on ErrSchemaFromNewerRelease.
	openStore func(content string) bool
}

func newFakeHost(t *testing.T, p *Paths) *fakeHost {
	return &fakeHost{t: t, paths: p, active: map[string]bool{sandboxdUnit: true, caddyUnit: true},
		missing: map[string]bool{}, free: map[string]uint64{}, fail: map[string]error{}, fetch: map[string][]byte{}, nextPID: 9000}
}

func (h *fakeHost) record(s string) {
	h.mu.Lock()
	h.calls = append(h.calls, s)
	h.mu.Unlock()
}

func (h *fakeHost) callLog() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.calls, "\n")
}

func (h *fakeHost) UnitActive(_ context.Context, unit string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active[unit]
}

func (h *fakeHost) unit(verb, unit string) error {
	h.record(verb + " " + unit)
	if err := h.fail[verb+" "+unit]; err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	switch verb {
	case "stop":
		h.active[unit] = false
		if unit == sandboxdUnit {
			h.running = ""
		}
	case "start", "restart":
		h.active[unit] = true
		if unit == sandboxdUnit {
			h.boot()
		}
	}
	return nil
}

// boot "execs" the installed sandboxd.
func (h *fakeHost) boot() {
	raw, _ := os.ReadFile(h.paths.Sandboxd)
	content := string(raw)
	h.running = ""
	if strings.Contains(content, "BROKEN") {
		return // dies before its store opens
	}
	if h.openStore != nil && !h.openStore(content) {
		return
	}
	_ = WriteStoreOpenedMarker(h.paths.DBPath, binaryVersion(content))
	if strings.Contains(content, "UNHEALTHY") {
		return // opened its store, then never became healthy
	}
	h.running = binaryVersion(content)
}

func (h *fakeHost) StopUnit(_ context.Context, unit string) error    { return h.unit("stop", unit) }
func (h *fakeHost) StartUnit(_ context.Context, unit string) error   { return h.unit("start", unit) }
func (h *fakeHost) RestartUnit(_ context.Context, unit string) error { return h.unit("restart", unit) }

func (h *fakeHost) UnitControlGroup(_ context.Context, unit string) string {
	h.record("cgroup " + unit)
	return h.cgroup
}

func (h *fakeHost) LookPath(name string) (string, error) {
	if h.missing[name] {
		return "", errors.New("not found")
	}
	return "/usr/bin/" + name, nil
}

func (h *fakeHost) FreeBytes(path string) (uint64, uint64, error) {
	if h.freeErr != nil {
		return 0, 0, h.freeErr
	}
	for dir, free := range h.free {
		if path == dir {
			return free, 1, nil
		}
	}
	return 1 << 40, 1, nil
}

func (h *fakeHost) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	h.record("run " + filepath.Base(name) + " " + strings.Join(args, " "))
	if len(args) >= 1 && args[0] == "version" {
		raw, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf(`{"version": %q}`, binaryVersion(string(raw)))), nil
	}
	if len(args) >= 2 && args[0] == "host" && args[1] == "apply" {
		if err := h.fail["host apply"]; err != nil {
			return []byte("install.sh said no"), err
		}
		if h.hostApply != nil {
			return h.hostApply()
		}
		return []byte("applied"), nil
	}
	return nil, nil
}

func (h *fakeHost) Fetch(_ context.Context, url string) (io.ReadCloser, int64, error) {
	h.mu.Lock()
	h.fetches = append(h.fetches, url)
	body, ok := h.fetch[url]
	h.mu.Unlock()
	if !ok {
		return nil, 0, fmt.Errorf("GET %s: 404 Not Found", url)
	}
	return io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
}

func (h *fakeHost) HealthVersion(context.Context, string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running == "" {
		return "", errors.New("connection refused")
	}
	return h.running, nil
}

func (h *fakeHost) GatewayProtocol(context.Context, string) (int, error) {
	h.record("probe gateway")
	return h.gateway, h.gatewayErr
}

func (h *fakeHost) StartDrain(path string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drains = append(h.drains, path)
	h.nextPID++
	return h.nextPID, nil
}

// fakeBinary is a "binary" for version, optionally carrying the usage text
// of `sandboxd version`.
func fakeBinary(version string, withVersionCmd bool, extra ...string) []byte {
	s := "#!fake sandboxd " + version + "\n"
	if withVersionCmd {
		s += VersionCommandMarker + " [-o text|json]\n"
	}
	return []byte(s + strings.Join(extra, "\n"))
}

func binaryVersion(content string) string {
	first, _, _ := strings.Cut(content, "\n")
	f := strings.Fields(first)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// release is one set of files a test upgrades to.
type releaseFiles struct {
	version  string
	sandboxd []byte
	toolboxd []byte
	caddy    []byte // nil: the request carries no caddy
	meta     *release.Metadata
}

func newRelease(version string) releaseFiles {
	return releaseFiles{
		version:  version,
		sandboxd: fakeBinary(version, true),
		toolboxd: []byte("toolboxd " + version + "\n"),
		caddy:    []byte("caddy for " + version + "\n"),
	}
}

func (r releaseFiles) withMeta(mut func(*release.Metadata)) releaseFiles {
	m := release.Metadata{
		Version: r.version, UpgradeFromMin: "v0.6.0", OneWayMigrations: []int{},
		HostSetupSHA256: strings.Repeat("a", 64), EgressGatewayProtocol: []int{1},
		FSMOpsVersion: 9,
	}
	if mut != nil {
		mut(&m)
	}
	r.meta = &m
	return r
}

func (r releaseFiles) files(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{
		"sandboxd_linux_amd64": r.sandboxd,
		"toolboxd_linux_amd64": r.toolboxd,
	}
	if r.caddy != nil {
		out["caddy_linux_amd64"] = r.caddy
	}
	if r.meta != nil {
		raw, err := json.Marshal(r.meta)
		if err != nil {
			t.Fatal(err)
		}
		out["release.json"] = raw
	}
	return out
}

// rig is one node: installed binaries, a database, a state directory, a
// --from directory, a fake host and an Upgrader.
type rig struct {
	t     *testing.T
	dir   string
	paths Paths
	host  *fakeHost
	u     *Upgrader
	out   *bytes.Buffer
	now   time.Time
}

func newRig(t *testing.T, installed releaseFiles) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{t: t, dir: dir, out: &bytes.Buffer{}, now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	r.paths = Paths{
		EnvFile:       filepath.Join(dir, "etc", "sandboxd.env"),
		NodeJSON:      filepath.Join(dir, "etc", "node.json"),
		StateDir:      filepath.Join(dir, "var", "upgrade"),
		DBPath:        filepath.Join(dir, "var", "state.db"),
		Sandboxd:      filepath.Join(dir, "bin", "sandboxd"),
		Toolboxd:      filepath.Join(dir, "bin", "toolboxd"),
		Caddy:         filepath.Join(dir, "usr", "caddy"),
		CgroupRoot:    filepath.Join(dir, "cgroup"),
		ProcRoot:      filepath.Join(dir, "proc"),
		HealthURL:     "http://127.0.0.1:21212/health",
		GatewaySocket: filepath.Join(dir, "gw.sock"),
		ReleaseURL:    "https://releases.example/download",
	}
	writeFile(t, r.paths.Sandboxd, installed.sandboxd)
	writeFile(t, r.paths.Toolboxd, installed.toolboxd)
	writeFile(t, r.paths.Caddy, installed.caddy)
	writeFile(t, r.paths.DBPath, []byte("db before the upgrade"))
	r.host = newFakeHost(t, &r.paths)
	r.host.running = installed.version
	r.u = &Upgrader{
		Paths: r.paths, Host: r.host, Out: r.out,
		Now:  func() time.Time { r.now = r.now.Add(time.Second); return r.now },
		GOOS: "linux", GOARCH: "amd64",
		Backup: func(_ context.Context, db, dest string) error {
			return copyFile(db, dest, 0o600)
		},
		PollInterval: time.Millisecond,
	}
	return r
}

// from writes a release's files to a --from directory and returns the
// request for it.
func (r *rig) from(rel releaseFiles) Request {
	r.t.Helper()
	dir := filepath.Join(r.dir, "from-"+rel.version)
	req := Request{Version: rel.version, From: dir, SHA256: map[string]string{}, HealthTimeout: 50 * time.Millisecond}
	for name, data := range rel.files(r.t) {
		writeFile(r.t, filepath.Join(dir, name), data)
		req.SHA256[name] = sum(data)
	}
	return req
}

// served puts a release's files on the fake release URL and returns the
// request for it.
func (r *rig) served(rel releaseFiles) Request {
	r.t.Helper()
	req := Request{Version: rel.version, SHA256: map[string]string{}, HealthTimeout: 50 * time.Millisecond}
	for name, data := range rel.files(r.t) {
		r.host.fetch[r.paths.ReleaseURL+"/"+rel.version+"/"+name] = data
		req.SHA256[name] = sum(data)
	}
	return req
}

func (r *rig) assertInstalled(rel releaseFiles, caddy []byte) {
	r.t.Helper()
	for path, want := range map[string][]byte{r.paths.Sandboxd: rel.sandboxd, r.paths.Toolboxd: rel.toolboxd, r.paths.Caddy: caddy} {
		if got := readFile(r.t, path); got != string(want) {
			r.t.Fatalf("%s = %q, want %q", path, got, want)
		}
	}
}

func (r *rig) assertPrev(path string, want []byte) {
	r.t.Helper()
	if got := readFile(r.t, path+".prev"); got != string(want) {
		r.t.Fatalf("%s.prev = %q, want %q", path, got, want)
	}
}

// order checks the calls happened in this order (others may sit between).
func (r *rig) order(steps ...string) {
	r.t.Helper()
	log := r.host.callLog()
	at := 0
	for _, s := range steps {
		i := strings.Index(log[at:], s)
		if i < 0 {
			r.t.Fatalf("calls do not have %q after offset %d; want order %q; calls:\n%s", s, at, steps, log)
		}
		at += i + len(s)
	}
}

func (r *rig) never(step string) {
	r.t.Helper()
	if strings.Contains(r.host.callLog(), step) {
		r.t.Fatalf("%q ran; calls:\n%s", step, r.host.callLog())
	}
}
