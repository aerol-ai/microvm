package rootd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The WASM compile caches privilege mode single left (agentfolders.go
// singleWasmCache). Single gives each cache to the WASM worker's uid; on a
// node switched to split, sandboxd cannot share such a folder with the
// worker's group and the helper does not hand it to a worker, so every
// worker compiled its module again on each start (the M1 VM drill, which
// ran single, split, single, split on one machine). These tests play the
// worker with the test user's own files.

// singleCacheMove is selfMove with the test user's files as the WASM
// worker's (root is a uid that owns nothing here) and the cache root in
// data.
func singleCacheMove(t *testing.T, data string) AgentFolders {
	t.Helper()
	f := selfMove(t)
	movedFromUID = f.UID + 1
	f.WasmWorkerUID = f.UID
	f.WasmCacheRoot = filepath.Join(data, "wasm", "modules", "cache", "wazero-compile")
	f.Dirs = []string{data}
	return f
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestGiveToAgentForgetsSingleWasmCaches(t *testing.T) {
	base := realTemp(t)
	data := filepath.Join(base, "data")
	f := singleCacheMove(t, data)
	root := f.WasmCacheRoot

	owner := filepath.Join(root, "owners", "owner-0123456789abcdef")
	write(t, filepath.Join(owner, "wazero-v1", "abc"), "compiled")
	write(t, filepath.Join(owner, "wazero-v1", "deep", "er", "x"), "x")
	operator := filepath.Join(root, "owners", "operator")
	if err := os.MkdirAll(filepath.Join(operator, "wazero-v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A shared entry linked into the operator's cache: removing the
	// cache's name leaves the shared one.
	shared := filepath.Join(root, "shared", "wazero-v1", "def")
	write(t, shared, "sealed")
	if err := os.Link(shared, filepath.Join(operator, "wazero-v1", "def")); err != nil {
		t.Fatal(err)
	}
	slot := filepath.Join(root, "slots", "fedcba9876543210")
	write(t, filepath.Join(slot, "slot"), "/run/sandboxd/wasm/pool/p/s")
	write(t, filepath.Join(slot, "cache", "wazero-v1", "ghi"), "compiled")
	// A link in a cache is removed as a link: what it names stays.
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(outside, "keep"), "keep")
	if err := os.Symlink(outside, filepath.Join(owner, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "keep"), filepath.Join(owner, "wazero-v1", "file-link")); err != nil {
		t.Fatal(err)
	}
	// The worker's, but not where the driver puts a cache: kept.
	kept := []string{
		filepath.Join(root, "owners", "not-a-cache-name", "x"),
		filepath.Join(root, "owners", "owner-0123456789abcdef0", "x"),
		filepath.Join(root, "slots", "fedcba9876543210", "other", "x"),
		filepath.Join(root, "slots", "short", "cache", "x"),
		filepath.Join(root, "legacy", "x"),
		filepath.Join(data, "elsewhere", "owners", "operator", "x"),
		filepath.Join(data, "wasm", "work", "guest.txt"),
	}
	for _, p := range kept {
		write(t, p, "x")
	}

	res, err := GiveToAgent(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.ForgottenCaches != 3 || len(res.CacheErrors) != 0 {
		t.Fatalf("result %+v, want 3 caches removed and no errors", res)
	}
	for _, p := range []string{owner, operator, filepath.Join(slot, "cache")} {
		if exists(t, p) {
			t.Errorf("%s is still there", p)
		}
	}
	for _, p := range append(kept, shared, filepath.Join(outside, "keep"), filepath.Join(slot, "slot")) {
		if !exists(t, p) {
			t.Errorf("%s was removed", p)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(outside, "keep")); err != nil || string(raw) != "keep" {
		t.Errorf("the file a link named changed: %q, %v", raw, err)
	}

	// Again: nothing left to remove.
	again, err := GiveToAgent(f)
	if err != nil || again.ForgottenCaches != 0 {
		t.Fatalf("second walk %+v, %v", again, err)
	}
}

// Split's own caches are the agent's, never the worker's: the walk leaves
// them, and with the removal turned off it removes nothing.
func TestGiveToAgentKeepsSplitWasmCaches(t *testing.T) {
	data := filepath.Join(realTemp(t), "data")
	for _, tc := range []struct {
		name string
		edit func(*AgentFolders)
	}{
		{"the agent's caches", func(f *AgentFolders) { f.WasmWorkerUID = f.UID + 2 }},
		{"no cache root", func(f *AgentFolders) { f.WasmCacheRoot = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := singleCacheMove(t, data)
			tc.edit(&f)
			cache := filepath.Join(data, "wasm", "modules", "cache", "wazero-compile", "owners", "operator", "v", "x")
			write(t, cache, "x")
			res, err := GiveToAgent(f)
			if err != nil || res.ForgottenCaches != 0 || !exists(t, cache) {
				t.Fatalf("result %+v, %v; cache there: %v", res, err, exists(t, cache))
			}
		})
	}
}

// A cache the walk cannot remove is left and named; sandboxd still starts.
func TestGiveToAgentLeavesACacheItCannotRemove(t *testing.T) {
	data := filepath.Join(realTemp(t), "data")
	f := singleCacheMove(t, data)
	cache := filepath.Join(f.WasmCacheRoot, "owners", "operator")
	p := cache
	for i := 0; i <= maxAgentFolderDepth; i++ {
		p = filepath.Join(p, strconv.Itoa(i))
	}
	write(t, filepath.Join(p, "x"), "x")
	res, err := GiveToAgent(f)
	if err != nil {
		t.Fatalf("the walk failed: %v", err)
	}
	if res.ForgottenCaches != 0 || len(res.CacheErrors) != 1 || !strings.Contains(res.CacheErrors[0], "folders deep") {
		t.Fatalf("result %+v, want one cache left as too deep", res)
	}
	if !exists(t, cache) {
		t.Fatal("the cache it could not empty was removed")
	}

	// A file it may not unlink (a folder closed to writes; root may, so
	// this half needs another user).
	if os.Geteuid() == 0 {
		return
	}
	data = filepath.Join(realTemp(t), "data")
	f = singleCacheMove(t, data)
	closed := filepath.Join(f.WasmCacheRoot, "owners", "operator", "v")
	write(t, filepath.Join(closed, "x"), "x")
	if err := os.Chmod(closed, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	res, err = GiveToAgent(f)
	if err != nil || len(res.CacheErrors) != 1 || !strings.Contains(res.CacheErrors[0], "permission denied") ||
		!exists(t, filepath.Join(closed, "x")) {
		t.Fatalf("result %+v, %v; want the closed cache left and named", res, err)
	}
}

func TestSingleWasmCache(t *testing.T) {
	f := AgentFolders{WasmCacheRoot: "/c", WasmWorkerUID: 61000}
	for path, want := range map[string]bool{
		"/c/owners/operator":                     true,
		"/c/owners/owner-0123456789abcdef":       true,
		"/c/slots/0123456789abcdef/cache":        true,
		"/c/owners/slots/0123456789abcdef/cache": false,
		"/c/owners/":                             false,
		"/c/owners/operator/x":                   false,
		"/c/owners/owner-xyz":                    false,
		"/c/slots/0123456789abcdef":              false,
		"/c/slots/0123456789abcdef/cache/x":      false,
		"/c/operator":                            false,
		"/c":                                     false,
		"/cc/owners/operator":                    false,
		"/d/owners/operator":                     false,
	} {
		if got := f.singleWasmCache(path, 61000); got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
	if f.singleWasmCache("/c/owners/operator", 65531) {
		t.Error("the agent's cache counted as single's")
	}
	if (AgentFolders{WasmWorkerUID: 61000}).singleWasmCache("/c/owners/operator", 61000) {
		t.Error("no cache root, yet a cache counted")
	}
}

func TestWasmCacheSettings(t *testing.T) {
	const def = "/var/lib/sandboxd/wasm/modules/cache/wazero-compile"
	for _, tc := range []struct {
		name string
		env  map[string]string
		root string
		uid  uint32
	}{
		{"sandboxd's defaults", nil, def, 61000},
		{"its own folder", map[string]string{"SB_WASM_COMPILE_CACHE_DIR": "/srv/wc/"}, "/srv/wc", 61000},
		{"no cache", map[string]string{"SB_WASM_COMPILE_CACHE_DIR": " "}, "", 0},
		{"the module cache's", map[string]string{"SB_WASM_CACHE_DIR": "/c"}, "/c/wazero-compile", 61000},
		{"the modules folder's", map[string]string{"SB_WASM_MODULES_DIR": "/m"}, "/m/cache/wazero-compile", 61000},
		{"a relative folder", map[string]string{"SB_WASM_MODULES_DIR": "m"}, "", 0},
		{"another worker uid", map[string]string{"SB_WASM_WORKER_UID": "62000"}, def, 62000},
		{"a uid that is not a number", map[string]string{"SB_WASM_WORKER_UID": "x"}, "", 0},
		{"root's uid", map[string]string{"SB_WASM_WORKER_UID": "0"}, "", 0},
		{"the agent's uid", map[string]string{"SB_WASM_WORKER_UID": "65531"}, "", 0},
		{"past MaxInt32", map[string]string{"SB_WASM_WORKER_UID": "2147483648"}, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, uid := wasmCacheSettings(func(k string) string { return tc.env[k] }, 65531)
			if root != tc.root || uid != tc.uid {
				t.Fatalf("got %q %d, want %q %d", root, uid, tc.root, tc.uid)
			}
		})
	}
	f, err := AgentFoldersFromEnv(func(string) string { return "" }, "70000")
	if err != nil || f.WasmCacheRoot != def || f.WasmWorkerUID != 61000 {
		t.Fatalf("got %+v, %v", f, err)
	}
}
