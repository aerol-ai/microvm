//go:build integration

package suite

// Real-SDK checks for the code interpreter: the official Daytona and E2B
// SDKs, and the AerolVM TypeScript and Python SDKs built from this tree, run
// as subprocesses against the deployment (scripts in testdata/sdkcompat).
// The Go cases prove the wire; these prove that what users actually install
// works, including the parts the Go cases cannot see (each SDK's own frame
// parsing, timeout mapping and auth headers).
//
// Dependencies are installed into a cache OUTSIDE the repository
// (AEROL_SDK_CACHE, default ~/.cache/aerolvm-itest-sdk): run.sh hashes the
// working tree into its build id, so node_modules or a venv under the repo
// would change the build of every later run. Each install is keyed by its
// pins (or, for the AerolVM SDKs, by a hash of their sources) and reused
// until that key changes. A machine without node or python skips these
// cases; AEROL_REQUIRE_SDK=1 turns that skip into a failure.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Pinned SDK versions. Daytona 2.0.0 was withdrawn from npm and PyPI, so
// 0.231.1 is the newest real release. The E2B interpreter SDKs ride on the
// e2b base SDK; npm's override pins it under @e2b/code-interpreter too.
const (
	sdkDaytonaVersion  = "0.231.1" // @daytona/sdk and daytona
	sdkE2BCIJSVersion  = "2.9.1"   // @e2b/code-interpreter
	sdkE2BJSVersion    = "2.64.0"  // e2b (npm)
	sdkE2BCIPyVersion  = "2.11.10" // e2b-code-interpreter
	sdkE2BPyVersion    = "2.64.0"  // e2b (PyPI)
	sdkPythonVersion   = "3.12"    // the venvs' python when uv is there to fetch it
	sdkScriptTimeout   = 15 * time.Minute
	sdkInstallTimeout  = 10 * time.Minute
	sdkRequireEnv      = "AEROL_REQUIRE_SDK"
	sdkCacheEnv        = "AEROL_SDK_CACHE"
	sdkcompatScriptDir = "testdata/sdkcompat"
)

// sdkUnavailable skips a case whose toolchain is missing, or fails it when
// the run demands every SDK case (AEROL_REQUIRE_SDK=1).
func sdkUnavailable(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	if os.Getenv(sdkRequireEnv) == "1" {
		t.Fatalf("%s (%s=1 requires every SDK case to run)", msg, sdkRequireEnv)
	}
	t.Skip(msg)
}

func sdkCacheRoot(t *testing.T) string {
	t.Helper()
	if dir := strings.TrimSpace(os.Getenv(sdkCacheEnv)); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		sdkUnavailable(t, "no home folder for the SDK cache (set %s): %v", sdkCacheEnv, err)
	}
	return filepath.Join(home, ".cache", "aerolvm-itest-sdk")
}

func shortHash(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// sdkCommand runs argv in dir and returns its combined output.
func sdkCommand(ctx context.Context, dir string, env []string, argv ...string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return out.String(), nil
}

// sdkPrepared returns dir after build has filled it once for key. A lock
// file serializes test binaries racing for the same install, and a .ready
// file holding key marks a finished one, so a run that died mid-install is
// redone rather than trusted.
func sdkPrepared(t *testing.T, dir, key string, build func(ctx context.Context, dir string) error) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatalf("SDK cache: %v", err)
	}
	lock, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatalf("SDK cache lock: %v", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("SDK cache lock: %v", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	marker := filepath.Join(dir, ".ready")
	if got, err := os.ReadFile(marker); err == nil && string(got) == key {
		return dir
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("SDK cache: clear %s: %v", dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("SDK cache: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sdkInstallTimeout)
	defer cancel()
	t.Logf("installing into %s (%s)", dir, key)
	if err := build(ctx, dir); err != nil {
		t.Fatalf("install into %s: %v", dir, err)
	}
	if err := os.WriteFile(marker, []byte(key), 0o644); err != nil {
		t.Fatalf("SDK cache: %v", err)
	}
	return dir
}

// sdkNode returns the node binary, or skips when node or npm is missing.
func sdkNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		sdkUnavailable(t, "node is not installed: %v", err)
	}
	if _, err := exec.LookPath("npm"); err != nil {
		sdkUnavailable(t, "npm is not installed: %v", err)
	}
	return node
}

var sdkInstallMu sync.Mutex

// sdkJSDeps installs the pinned Daytona and E2B JavaScript SDKs.
func sdkJSDeps(t *testing.T) string {
	t.Helper()
	sdkNode(t)
	sdkInstallMu.Lock()
	defer sdkInstallMu.Unlock()
	pkg := map[string]any{
		"name": "aerolvm-itest-sdkcompat", "private": true, "type": "module",
		"dependencies": map[string]string{
			"@daytona/sdk":          sdkDaytonaVersion,
			"@e2b/code-interpreter": sdkE2BCIJSVersion,
			"e2b":                   sdkE2BJSVersion,
		},
		// "$e2b" is npm's spelling for "the version of the direct
		// dependency", so the interpreter SDK cannot pull a second e2b.
		"overrides": map[string]string{"e2b": "$e2b"},
	}
	raw, _ := json.MarshalIndent(pkg, "", "  ")
	dir := filepath.Join(sdkCacheRoot(t), "js-"+shortHash(string(raw)))
	return sdkPrepared(t, dir, string(raw), func(ctx context.Context, dir string) error {
		if err := os.WriteFile(filepath.Join(dir, "package.json"), raw, 0o644); err != nil {
			return err
		}
		out, err := sdkCommand(ctx, dir, nil, "npm", "install", "--no-audit", "--no-fund", "--loglevel=error")
		if err != nil {
			return fmt.Errorf("%w\n%s", err, out)
		}
		return nil
	})
}

// sdkVenv makes a venv in dir/venv with pkgs installed and returns its
// python. uv is preferred: it can fetch python 3.12 when the machine has
// only a newer one the SDKs do not support yet.
func sdkVenv(t *testing.T, name string, pkgs ...string) string {
	t.Helper()
	uv, uvErr := exec.LookPath("uv")
	py, pyErr := exec.LookPath("python3")
	if uvErr != nil && pyErr != nil {
		sdkUnavailable(t, "neither uv nor python3 is installed")
	}
	sdkInstallMu.Lock()
	defer sdkInstallMu.Unlock()
	key := strings.Join(append([]string{name, sdkPythonVersion}, pkgs...), " ")
	dir := filepath.Join(sdkCacheRoot(t), name+"-"+shortHash(key))
	sdkPrepared(t, dir, key, func(ctx context.Context, dir string) error {
		venv := filepath.Join(dir, "venv")
		python := filepath.Join(venv, "bin", "python")
		var steps [][]string
		if uvErr == nil {
			steps = [][]string{
				{uv, "venv", "--quiet", "--python", sdkPythonVersion, venv},
				append([]string{uv, "pip", "install", "--quiet", "--python", python}, pkgs...),
			}
		} else {
			steps = [][]string{
				{py, "-m", "venv", venv},
				append([]string{python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check"}, pkgs...),
			}
		}
		for _, argv := range steps {
			if out, err := sdkCommand(ctx, dir, nil, argv...); err != nil {
				return fmt.Errorf("%w\n%s", err, out)
			}
		}
		return nil
	})
	return filepath.Join(dir, "venv", "bin", "python")
}

// repoSDKSource copies the files of one repo SDK (relative to sdk/<name>)
// into dst and returns a hash of what it copied, so a changed SDK is
// rebuilt. Generated folders are skipped: they are not the source.
func repoSDKSource(t *testing.T, name string, include []string, dst string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "sdk", name))
	if err != nil {
		t.Fatal(err)
	}
	skip := map[string]bool{"node_modules": true, "dist": true, "dist-test": true, "__pycache__": true, "build": true}
	var files []string
	for _, inc := range include {
		err := filepath.WalkDir(filepath.Join(root, inc), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if skip[d.Name()] || strings.HasSuffix(d.Name(), ".egg-info") {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			files = append(files, rel)
			return nil
		})
		if err != nil {
			t.Fatalf("read sdk/%s: %v", name, err)
		}
	}
	sort.Strings(files)
	h := sha256.New()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(data))
		h.Write(data)
		if dst == "" {
			continue
		}
		out := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// sdkAerolTS builds sdk/typescript in the cache and returns its
// dist/index.js.
func sdkAerolTS(t *testing.T) string {
	t.Helper()
	sdkNode(t)
	sdkInstallMu.Lock()
	defer sdkInstallMu.Unlock()
	include := []string{"package.json", "package-lock.json", "tsconfig.json", "src"}
	sum := repoSDKSource(t, "typescript", include, "")
	dir := filepath.Join(sdkCacheRoot(t), "aerolvm-ts-"+sum)
	sdkPrepared(t, dir, "aerolvm-ts "+sum, func(ctx context.Context, dir string) error {
		repoSDKSource(t, "typescript", include, dir)
		for _, argv := range [][]string{
			{"npm", "ci", "--no-audit", "--no-fund", "--loglevel=error"},
			{"npm", "run", "build", "--silent"},
		} {
			if out, err := sdkCommand(ctx, dir, nil, argv...); err != nil {
				return fmt.Errorf("%w\n%s", err, out)
			}
		}
		return nil
	})
	return filepath.Join(dir, "dist", "index.js")
}

// sdkAerolPy installs sdk/python (with its async extra) into a venv and
// returns the venv's python.
func sdkAerolPy(t *testing.T) string {
	t.Helper()
	include := []string{"pyproject.toml", "README.md", "microvm"}
	sum := repoSDKSource(t, "python", include, "")
	src := filepath.Join(sdkCacheRoot(t), "aerolvm-py-src-"+sum)
	sdkInstallMu.Lock()
	sdkPrepared(t, src, "aerolvm-py-src "+sum, func(_ context.Context, dir string) error {
		repoSDKSource(t, "python", include, dir)
		return nil
	})
	sdkInstallMu.Unlock()
	return sdkVenv(t, "aerolvm-py-"+sum, src+"[async]")
}

// sdkScript copies a script from testdata/sdkcompat into dir (node resolves
// packages from the script's own folder) and runs it with interpreter. The
// script prints pass when every check held; anything else fails the case
// with the script's whole output.
func sdkScript(t *testing.T, dir, name, pass string, env []string, interpreter ...string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(sdkcompatScriptDir, name))
	if err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, name)
	if err := os.WriteFile(script, src, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), sdkScriptTimeout)
	defer cancel()
	argv := append(append([]string{}, interpreter...), script)
	out, err := sdkCommand(ctx, dir, env, argv...)
	t.Logf("%s output:\n%s", name, out)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("%s did not finish within %v (its sandbox may be left behind)", name, sdkScriptTimeout)
	}
	if err != nil || !strings.Contains(out, pass) {
		t.Fatalf("%s failed (%v); the first FAIL line above names the check", name, err)
	}
}

// The scripts take the deployment from the environment, as a user would
// configure each SDK.
func daytonaScriptEnv() []string {
	return []string{"SB_API_URL=" + strings.TrimRight(sc.BaseURL, "/"), "SB_PAT_TOKEN=" + sc.PAT, "CI_IMAGE=" + interpImage}
}

func e2bScriptEnv() []string {
	base := strings.TrimRight(sc.BaseURL, "/")
	// E2B_DEBUG=true would point both SDKs at localhost.
	return []string{"E2B_API_URL=" + base + "/e2b", "E2B_SANDBOX_URL=" + base + "/e2b/runtime", "E2B_API_KEY=" + sc.PAT, "E2B_DEBUG=false"}
}

// UC-718 — the official Daytona TypeScript SDK.
func TestSDKCompatInterpDaytonaTS(t *testing.T) {
	harness.Require(t, sc, "UC-718")
	dir := sdkJSDeps(t)
	sdkScript(t, dir, "daytona_ci.mjs", "DAYTONA_TS_PASS", daytonaScriptEnv(), sdkNode(t))
}

// UC-719 — the official Daytona Python SDK.
func TestSDKCompatInterpDaytonaPython(t *testing.T) {
	harness.Require(t, sc, "UC-719")
	python := sdkVenv(t, "py-daytona", "daytona=="+sdkDaytonaVersion)
	sdkScript(t, filepath.Dir(filepath.Dir(filepath.Dir(python))), "daytona_ci.py", "DAYTONA_PY_PASS", daytonaScriptEnv(), python, "-I")
}

// UC-720 — the official E2B Code Interpreter JS SDK.
func TestSDKCompatInterpE2BJS(t *testing.T) {
	harness.Require(t, sc, "UC-720")
	dir := sdkJSDeps(t)
	sdkScript(t, dir, "e2b_ci.mjs", "E2B_JS_PASS", e2bScriptEnv(), sdkNode(t))
}

// UC-721 — the official E2B Code Interpreter Python SDK.
func TestSDKCompatInterpE2BPython(t *testing.T) {
	harness.Require(t, sc, "UC-721")
	python := sdkVenv(t, "py-e2b", "e2b-code-interpreter=="+sdkE2BCIPyVersion, "e2b=="+sdkE2BPyVersion)
	sdkScript(t, filepath.Dir(filepath.Dir(filepath.Dir(python))), "e2b_ci.py", "E2B_PY_PASS", e2bScriptEnv(), python, "-I")
}

// UC-722 — the AerolVM TypeScript SDK from sdk/typescript.
func TestSDKCompatInterpAerolTS(t *testing.T) {
	harness.Require(t, sc, "UC-722")
	entry := sdkAerolTS(t)
	env := append(daytonaScriptEnv(), "SDK_PATH="+entry)
	sdkScript(t, filepath.Dir(filepath.Dir(entry)), "aerolvm_ci.mjs", "AEROLVM_TS_PASS", env, sdkNode(t))
}

// UC-723 — the AerolVM Python SDK from sdk/python, sync and async.
func TestSDKCompatInterpAerolPython(t *testing.T) {
	harness.Require(t, sc, "UC-723")
	python := sdkAerolPy(t)
	sdkScript(t, filepath.Dir(filepath.Dir(filepath.Dir(python))), "aerolvm_ci.py", "AEROLVM_PY_PASS", daytonaScriptEnv(), python, "-I")
}
