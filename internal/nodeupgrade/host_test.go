package nodeupgrade

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSystemctl writes a systemctl that logs its arguments; is-active
// succeeds only for "up", and any verb on "broken" fails.
func fakeSystemctl(t *testing.T) (path, log string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found")
	}
	dir := t.TempDir()
	log = filepath.Join(dir, "calls")
	path = filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\necho \"$*\" >> " + log + "\n" +
		"case \"$*\" in\n" +
		"  'is-active --quiet up') exit 0 ;;\n" +
		"  'is-active --quiet '*) exit 3 ;;\n" +
		"  'show -p ControlGroup --value sandboxd') echo /system.slice/sandboxd.service ;;\n" +
		"  *broken*) echo 'unit broken' >&2; exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, log
}

func TestSystemHostSystemctl(t *testing.T) {
	sc, log := fakeSystemctl(t)
	h := &SystemHost{Systemctl: sc}
	ctx := context.Background()
	if !h.UnitActive(ctx, "up") || h.UnitActive(ctx, "down") {
		t.Fatal("is-active answers are wrong")
	}
	for _, f := range []func(context.Context, string) error{h.StopUnit, h.StartUnit, h.RestartUnit} {
		if err := f(ctx, "sandboxd"); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.RestartUnit(ctx, "broken"); err == nil || !strings.Contains(err.Error(), "unit broken") {
		t.Fatalf("a failing systemctl: %v", err)
	}
	if cg := h.UnitControlGroup(ctx, "sandboxd"); cg != "/system.slice/sandboxd.service" {
		t.Fatalf("cgroup = %q", cg)
	}
	if cg := (&SystemHost{Systemctl: filepath.Join(t.TempDir(), "none")}).UnitControlGroup(ctx, "x"); cg != "" {
		t.Fatalf("cgroup without systemctl = %q", cg)
	}
	calls := readFile(t, log)
	for _, want := range []string{"stop sandboxd", "start sandboxd", "restart sandboxd", "restart broken"} {
		if !strings.Contains(calls, want+"\n") {
			t.Fatalf("calls miss %q:\n%s", want, calls)
		}
	}
	if (&SystemHost{}).systemctl() != "systemctl" {
		t.Fatal("default systemctl")
	}
}

func TestSystemHostFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sandboxd" {
			_, _ = io.WriteString(w, "binary")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	h := &SystemHost{}
	ctx := context.Background()
	body, _, err := h.Fetch(ctx, srv.URL+"/v1/sandboxd")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(body)
	_ = body.Close()
	if string(b) != "binary" {
		t.Fatalf("body = %q", b)
	}
	if _, _, err := h.Fetch(ctx, srv.URL+"/v1/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	local := filepath.Join(t.TempDir(), "toolboxd")
	writeFile(t, local, []byte("from a mirror"))
	body, size, err := h.Fetch(ctx, "file://"+local)
	if err != nil || size != int64(len("from a mirror")) {
		t.Fatalf("file URL: %d %v", size, err)
	}
	_ = body.Close()
	for _, bad := range []string{"ftp://x/y", "file:///no/such/file", "http://[::1", "http://127.0.0.1:1/x"} {
		if _, _, err := h.Fetch(ctx, bad); err == nil {
			t.Fatalf("fetched %s", bad)
		}
	}
	if (&SystemHost{HTTP: srv.Client()}).client() != srv.Client() {
		t.Fatal("custom client ignored")
	}
}

func TestSystemHostHealthVersion(t *testing.T) {
	answer := `{"status":"ok","version":"v0.6.12"}`
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, answer)
	}))
	defer srv.Close()
	h := &SystemHost{}
	ctx := context.Background()
	if v, err := h.HealthVersion(ctx, srv.URL); err != nil || v != "v0.6.12" {
		t.Fatalf("%q %v", v, err)
	}
	for _, tc := range []struct {
		code   int
		answer string
	}{{http.StatusInternalServerError, answer}, {http.StatusOK, "{"}, {http.StatusOK, `{"status":"ok"}`}} {
		code, answer = tc.code, tc.answer
		if _, err := h.HealthVersion(ctx, srv.URL); err == nil {
			t.Fatalf("%d %s accepted", tc.code, tc.answer)
		}
	}
	if _, err := h.HealthVersion(ctx, "http://127.0.0.1:1/health"); err == nil {
		t.Fatal("no server accepted")
	}
	if _, err := h.HealthVersion(ctx, "http://[::1"); err == nil {
		t.Fatal("bad URL accepted")
	}
}

func TestSystemHostLocalEffects(t *testing.T) {
	h := &SystemHost{}
	ctx := context.Background()
	if out, err := h.Run(ctx, "sh", "-c", "printf 'a b'"); err != nil || string(out) != "a b" {
		t.Fatalf("run: %q %v", out, err)
	}
	if _, err := h.LookPath("sh"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	free, dev, err := h.FreeBytes(filepath.Join(dir, "not", "yet"))
	if err != nil || free == 0 {
		t.Fatalf("free %d dev %d: %v", free, dev, err)
	}
	_, dev2, _ := h.FreeBytes(dir)
	if dev != dev2 {
		t.Fatalf("a missing child and its parent are on different devices: %d %d", dev, dev2)
	}
	src := filepath.Join(dir, "pipe-stand-in")
	writeFile(t, src, []byte("x"))
	pid, err := h.StartDrain(src)
	if err != nil || pid <= 0 {
		t.Fatalf("drain: %d %v", pid, err)
	}
	if _, err := h.StartDrain(filepath.Join(dir, "missing")); err != nil {
		// cat starts and then fails on its own; Start itself succeeds.
		t.Fatalf("drain start: %v", err)
	}
	// Give the drains a moment to exit so the test leaves no children.
	time.Sleep(20 * time.Millisecond)
	if _, err := h.GatewayProtocol(ctx, filepath.Join(dir, "no.sock")); err == nil {
		t.Fatal("probed a gateway that is not there")
	}
}

func TestResolvePaths(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "sandboxd.env")
	writeFile(t, env, []byte("# comment\nSB_DB_PATH=/data/state.db\nSB_TOOLBOX_BINARY_PATH='/opt/aerolvm/bin/toolboxd'\nSB_API_PORT=\"21300\"\n; other\nnoequals\nSB_ENABLE_CADDY=true\n"))
	getenv := func(k string) string {
		if k == "SB_RELEASE_URL" {
			return "https://mirror.example/aerolvm/"
		}
		return ""
	}
	p, err := ResolvePaths(env, getenv, func() (string, error) { return "/opt/caddy", nil })
	if err != nil {
		t.Fatal(err)
	}
	want := Paths{
		EnvFile: env, NodeJSON: filepath.Join(dir, "node.json"), StateDir: "/data/upgrade", DBPath: "/data/state.db",
		Sandboxd: "/opt/aerolvm/bin/sandboxd", Toolboxd: "/opt/aerolvm/bin/toolboxd", Caddy: "/opt/caddy",
		CgroupRoot: "/sys/fs/cgroup", ProcRoot: "/proc", HealthURL: "http://127.0.0.1:21300/health",
		GatewaySocket: defaultGateway, ReleaseURL: "https://mirror.example/aerolvm",
	}
	if p != want {
		t.Fatalf("paths =\n%+v\nwant\n%+v", p, want)
	}
	// No env file: install.sh's defaults. Caddy off: no caddy.
	p, err = ResolvePaths(filepath.Join(dir, "missing.env"), func(k string) string {
		if k == "SB_ENABLE_CADDY" {
			return "false"
		}
		return ""
	}, nil)
	if err != nil || p.Caddy != "" || p.Sandboxd != "/usr/local/bin/sandboxd" || p.ReleaseURL != DefaultReleaseURL || p.DBPath != defaultDBPath {
		t.Fatalf("defaults: %+v %v", p, err)
	}
	p, _ = ResolvePaths(filepath.Join(dir, "missing.env"), func(string) string { return "" }, func() (string, error) { return "", os.ErrNotExist })
	if p.Caddy != defaultCaddy {
		t.Fatalf("caddy fallback = %q", p.Caddy)
	}
	if p, _ := ResolvePaths("", func(string) string { return "" }, nil); p.EnvFile != DefaultEnvFile {
		t.Fatalf("default env file = %q", p.EnvFile)
	}
	if _, err := ResolvePaths(dir, func(string) string { return "" }, nil); err == nil {
		t.Fatal("read a directory as an env file")
	}
}
