package nodeupgrade

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Tests for staging (stage.go): the systemd-run and space checks, hashing
// into the store, a repeat that fetches nothing, the locally-held copy a
// rollback uses, and the lock probe.

func stageRig(t *testing.T) (Paths, *fakeHost, FileStore) {
	t.Helper()
	dir := t.TempDir()
	p := Paths{
		StateDir: filepath.Join(dir, "upgrade"), DBPath: filepath.Join(dir, "state.db"),
		Sandboxd: filepath.Join(dir, "bin", "sandboxd"), Toolboxd: filepath.Join(dir, "bin", "toolboxd"),
	}
	_ = os.MkdirAll(filepath.Dir(p.Sandboxd), 0o755)
	_ = os.WriteFile(p.Sandboxd, []byte("installed sandboxd"), 0o755)
	_ = os.WriteFile(p.Toolboxd, []byte("installed toolboxd"), 0o755)
	_ = os.WriteFile(p.DBPath, bytes.Repeat([]byte("d"), 1024), 0o600)
	h := newFakeHost(t, &p)
	return p, h, FileStore{Dir: FileStoreDir(p.StateDir)}
}

func TestStage(t *testing.T) {
	p, h, store := stageRig(t)
	sd, tb, arm := []byte("new sandboxd"), []byte("new toolboxd"), []byte("arm build")
	files := map[string]string{"sandboxd_linux_amd64": sum(sd), "toolboxd_linux_amd64": sum(tb), "sandboxd_linux_arm64": sum(arm)}
	src := map[string][]byte{"sandboxd_linux_amd64": sd, "toolboxd_linux_amd64": tb, "sandboxd_linux_arm64": arm}
	fetches := 0
	fetch := func(_ context.Context, asset, _ string) (io.ReadCloser, error) {
		fetches++
		return io.NopCloser(bytes.NewReader(src[asset])), nil
	}
	req := StageRequest{Files: files, Install: map[string]string{"sandboxd_linux_amd64": sum(sd), "toolboxd_linux_amd64": sum(tb)}, Fetch: fetch}
	res, err := Stage(context.Background(), p, h, store, req)
	if err != nil || len(res.Fetched) != 3 || res.Bytes != int64(len(sd)+len(tb)+len(arm)) || fetches != 3 {
		t.Fatalf("stage = %+v %v", res, err)
	}
	for _, sum := range files {
		if !store.Has(sum) {
			t.Fatalf("%s not staged", sum)
		}
	}
	// A repeat fetches nothing.
	res, err = Stage(context.Background(), p, h, store, req)
	if err != nil || len(res.Present) != 3 || fetches != 3 {
		t.Fatalf("repeat = %+v %v", res, err)
	}
}

func TestStageRefusals(t *testing.T) {
	p, h, store := stageRig(t)
	good := sum([]byte("x"))
	fetchOK := func(context.Context, string, string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("x")), nil
	}
	cases := []struct {
		name string
		req  StageRequest
		edit func()
		want string
	}{
		{"no files", StageRequest{}, nil, "at least one file"},
		{"bad hash", StageRequest{Files: map[string]string{"sandboxd": "XY"}}, nil, "not a hex SHA-256"},
		{"bad name", StageRequest{Files: map[string]string{"../x": good}}, nil, "bad file name"},
		{"no systemd-run", StageRequest{Files: map[string]string{"sandboxd": good}, Fetch: fetchOK}, func() { h.missing["systemd-run"] = true }, "systemd-run not found"},
		{"no space", StageRequest{Files: map[string]string{"sandboxd": good}, Install: map[string]string{"sandboxd": good}, Fetch: fetchOK},
			func() { h.free[store.Dir] = 10; h.free[p.StateDir] = 10; h.free[filepath.Dir(p.Sandboxd)] = 10 }, "not enough free space"},
		{"statfs fails", StageRequest{Files: map[string]string{"sandboxd": good}, Fetch: fetchOK}, func() { h.freeErr = errors.New("statfs") }, "statfs"},
		{"no source", StageRequest{Files: map[string]string{"sandboxd": good}}, nil, "no source"},
		{"fetch fails", StageRequest{Files: map[string]string{"sandboxd": good}, Fetch: func(context.Context, string, string) (io.ReadCloser, error) {
			return nil, errors.New("404")
		}}, nil, "get sandboxd: 404"},
		{"tampered", StageRequest{Files: map[string]string{"sandboxd": sum([]byte("y"))}, Fetch: fetchOK}, nil, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.missing, h.free, h.freeErr = map[string]bool{}, map[string]uint64{}, nil
			if tc.edit != nil {
				tc.edit()
			}
			_, err := Stage(context.Background(), p, h, store, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.name == "no systemd-run" && !errors.Is(err, ErrStageTool) {
				t.Fatalf("not ErrStageTool: %v", err)
			}
		})
	}
}

func TestStageHelpers(t *testing.T) {
	p, _, store := stageRig(t)
	p.Caddy = filepath.Join(filepath.Dir(p.Sandboxd), "caddy")
	for asset, want := range map[string]string{"sandboxd_linux_arm64": p.Sandboxd, "v1.2.3_toolboxd_linux_amd64": p.Toolboxd, "caddy": p.Caddy, "release.json": "", "junk": ""} {
		if got := installedPath(p, asset); got != want {
			t.Fatalf("installedPath(%s) = %q, want %q", asset, got, want)
		}
	}
	if stagedSizeEstimate(p, "release.json") != 1<<20 || stagedSizeEstimate(p, "caddy") != unknownFileEstimate {
		t.Fatal("size estimates")
	}
	if n := stagedSizeEstimate(p, "sandboxd"); n != uint64(len("installed sandboxd"))+uint64(len("installed sandboxd"))/4 {
		t.Fatalf("installed estimate = %d", n)
	}
	got, err := InstalledFiles(p)
	if err != nil || got["sandboxd"] != sum([]byte("installed sandboxd")) || got["toolboxd"] == "" || got["caddy"] != "" {
		t.Fatalf("installed = %v %v", got, err)
	}
	// A node's own *.prev (or installed file) is put into the store.
	prev := []byte("previous sandboxd")
	_ = os.WriteFile(p.Sandboxd+".prev", prev, 0o755)
	if !PutLocalCopy(p, store, sum(prev)) || !store.Has(sum(prev)) {
		t.Fatal("*.prev not stored")
	}
	if !PutLocalCopy(p, store, sum([]byte("installed toolboxd"))) {
		t.Fatal("installed file not stored")
	}
	if PutLocalCopy(p, store, sum([]byte("nowhere"))) {
		t.Fatal("a missing file was stored")
	}
}

func TestLockHolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "upgrade")
	if op, busy := LockHolder(dir); busy || op != "" {
		t.Fatalf("free lock = %q %v", op, busy)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteAt([]byte("op-9\n"), 0)
	if op, busy := LockHolder(dir); !busy || op != "op-9" {
		t.Fatalf("held lock = %q %v", op, busy)
	}
	if _, busy := LockHolder("/dev/null/x"); busy {
		t.Fatal("an unusable directory reads as busy")
	}
}
