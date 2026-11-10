package nodeops

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// fakeHost stands in for systemd and sandboxd's /health.
type fakeHost struct {
	mu       sync.Mutex
	active   bool
	calls    []string
	stopErr  error
	startErr error
	// healthFails is how many /health asks fail before one answers.
	healthFails int
	healthURL   string
	// onStart runs when sandboxd is started (sandboxd applying peers.json).
	onStart func()
}

func (h *fakeHost) UnitActive(_ context.Context, unit string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "is-active "+unit)
	return h.active
}

func (h *fakeHost) StopUnit(_ context.Context, unit string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, "stop "+unit)
	if h.stopErr != nil {
		return h.stopErr
	}
	h.active = false
	return nil
}

func (h *fakeHost) StartUnit(_ context.Context, unit string) error {
	h.mu.Lock()
	h.calls = append(h.calls, "start "+unit)
	if h.startErr != nil {
		h.mu.Unlock()
		return h.startErr
	}
	h.active = true
	fn := h.onStart
	h.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

func (h *fakeHost) HealthVersion(_ context.Context, url string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.healthURL = url
	if h.healthFails != 0 {
		if h.healthFails > 0 {
			h.healthFails--
		}
		return "", errors.New("connection refused")
	}
	return "v-test", nil
}

func (h *fakeHost) called(verb string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if strings.HasPrefix(c, verb+" ") {
			return true
		}
	}
	return false
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// makeDB makes a WAL database with rows still in the WAL: the connection
// stays open, so nothing is checkpointed into the main file. A plain file
// copy of state.db (what the script did) would miss them.
func makeDB(t *testing.T, path string, rows ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("PRAGMA wal_autocheckpoint=0; CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if _, err := db.Exec("INSERT INTO t VALUES (?)", r); err != nil {
			t.Fatal(err)
		}
	}
}

func dbRows(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs, err := db.Query("SELECT v FROM t ORDER BY v")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var v string
		if err := rs.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// readArchive returns each regular file's body and every entry's header by
// name, without "./".
func readArchive(t *testing.T, path string) (map[string]string, map[string]*tar.Header) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	hdrs := map[string]*tar.Header{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, hdrs
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(h.Name, "./"), "/")
		hdrs[name] = h
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			files[name] = string(b)
		}
	}
}

// tarEntry is one entry of a hand-made archive.
type tarEntry struct {
	name, body, link string
	typ              byte
	mode             int64
}

// writeTar makes an archive the way `tar -C root -czf out .` does, or a
// broken one, for the restore checks.
func writeTar(t *testing.T, path string, entries ...tarEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
			if strings.HasSuffix(e.name, "/") {
				typ = tar.TypeDir
			}
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
			if typ == tar.TypeDir {
				mode = 0o755
			}
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: mode, Linkname: e.link, ModTime: time.Unix(1700000000, 0)}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// ReadNode must read the env files as systemd hands them to sandboxd:
// cluster.env after sandboxd.env, a later line over an earlier one, quotes
// and whitespace stripped, comments skipped.
func TestReadNode(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want Node
	}{
		"install.sh defaults": {
			want: Node{StateDB: defaultDBPath, RaftDir: "/var/lib/sandboxd/raft", KeyFile: defaultKeyFile,
				KeyRing: defaultKeyFile + ".ring", WrappedKey: defaultWrappedKey, HealthURL: "http://127.0.0.1:21212/health"},
		},
		"every override": {
			env: map[string]string{
				"sandboxd.env": "SB_DB_PATH=/data/state.db\nSB_API_PORT=9000\nSB_CREDENTIAL_ENCRYPTION_KEY_PATH=/k/key\n" +
					"SB_CREDENTIAL_ENCRYPTION_KEY = \"c2VjcmV0\"\r\nSB_NODE_ROLE=Server\n# SB_NODE_ID=commented\n",
				"cluster.env": "SB_NODE_ID=node-a\nSB_RAFT_BIND_ADDR=0.0.0.0:7000\nSB_RAFT_ADVERTISE_ADDR='10.0.0.5:7000'\n" +
					"SB_CREDENTIAL_KEY_CUSTODY=Wrapped\nSB_CREDENTIAL_ENCRYPTION_KEY_WRAPPED_PATH=/k/w\n",
			},
			want: Node{StateDB: "/data/state.db", RaftDir: "/data/raft", KeyFile: "/k/key", KeyRing: "/k/key.ring",
				WrappedKey: "/k/w", Custody: "wrapped", EnvKey: true, NodeID: "node-a", NodeRole: "server",
				RaftAddress: "10.0.0.5:7000", HealthURL: "http://127.0.0.1:9000/health"},
		},
		"explicit raft dir and ring, bind address as the fallback": {
			env: map[string]string{
				"cluster.env": "SB_RAFT_DATA_DIR=/r\nSB_CREDENTIAL_KEY_RING_PATH=/ring\nSB_RAFT_BIND_ADDR=10.0.0.9:7000\n",
			},
			want: Node{StateDB: defaultDBPath, RaftDir: "/r", KeyFile: defaultKeyFile, KeyRing: "/ring",
				WrappedKey: defaultWrappedKey, RaftAddress: "10.0.0.9:7000", HealthURL: "http://127.0.0.1:21212/health"},
		},
		"cluster.env empties a value": {
			env:  map[string]string{"sandboxd.env": "SB_CREDENTIAL_KEY_CUSTODY=wrapped\n", "cluster.env": "SB_CREDENTIAL_KEY_CUSTODY=\n"},
			want: Node{StateDB: defaultDBPath, RaftDir: "/var/lib/sandboxd/raft", KeyFile: defaultKeyFile, KeyRing: defaultKeyFile + ".ring", WrappedKey: defaultWrappedKey, HealthURL: "http://127.0.0.1:21212/health"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for f, body := range tc.env {
				write(t, filepath.Join(dir, f), body)
			}
			got, err := ReadNode(dir)
			if err != nil {
				t.Fatal(err)
			}
			tc.want.ConfigDir = dir
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ReadNode =\n%+v\nwant\n%+v", got, tc.want)
			}
		})
	}
	// The real /etc/sandboxd may exist (and be root's) where this runs.
	if n, err := ReadNode(""); err == nil && n.ConfigDir != DefaultConfigDir {
		t.Fatalf("ReadNode(\"\") = %+v %v", n, err)
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sandboxd.env"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNode(dir); err == nil {
		t.Fatal("an unreadable env file was ignored")
	}
}

func TestHoldsRaft(t *testing.T) {
	for role, want := range map[string]bool{
		"": true, "server": true, "mixed": true, "worker,server": true, " ingress , mixed": true,
		"worker": false, "ingress": false, "worker,ingress": false,
	} {
		if got := holdsRaft(role); got != want {
			t.Errorf("holdsRaft(%q) = %v, want %v", role, got, want)
		}
	}
}
