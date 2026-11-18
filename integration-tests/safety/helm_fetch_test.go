package safety

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// k8s/helm-fetch.sh: every chart the EKS runs fetch comes with no registry
// credentials and within a time limit (bank-1's third run waited 9.5
// minutes on Docker Desktop's credential helper, which never answered).

// placeholderConfig is the config helm_fetch hands Helm: no helper, no
// store, one entry for a host that cannot exist.
const placeholderConfig = `{"auths": {"credentials.invalid": {}}}`

// fetchShell runs snippet with helm-fetch.sh sourced, under set -euo
// pipefail like its callers. It returns the output and the exit code.
func fetchShell(t *testing.T, snippet string, env ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", "-c", `set -euo pipefail
source "$1"
`+snippet, "bash", k8sFile(t, "helm-fetch.sh"))
	cmd.Env = append(os.Environ(), env...)
	out, _ := cmd.CombinedOutput()
	return string(out), cmd.ProcessState.ExitCode()
}

// alive reports whether the PID written in file is still a process.
func alive(t *testing.T, file string) bool {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("no PID in %s: %v", file, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return syscall.Kill(pid, 0) == nil
}

func TestRunBounded(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want int
	}{
		{"true", 0},
		{"sh -c 'exit 3'", 3},
	} {
		out, code := fetchShell(t, `rc=0; run_bounded 5 `+tc.cmd+` || rc=$?; echo "rc=$rc"`)
		if code != 0 || !strings.Contains(out, "rc="+strconv.Itoa(tc.want)) {
			t.Errorf("run_bounded 5 %s: %s (exit %d), want rc=%d", tc.cmd, out, code, tc.want)
		}
	}
	// A command that ignores TERM and has a child: past the limit both go
	// (TERM, then KILL), and the answer is 124. Both end on their own after
	// 60 s, so a broken limit fails the test instead of hanging it.
	dir := t.TempDir()
	start := time.Now()
	out, code := fetchShell(t, `rc=0
run_bounded 1 bash -c 'trap "" TERM; echo $$ > "$1/parent"; sleep 60 & echo $! > "$1/kid"; for i in $(seq 60); do sleep 1; done' bash "$DIR" || rc=$?
echo "rc=$rc"`, "DIR="+dir)
	if code != 0 || !strings.Contains(out, "rc=124") {
		t.Fatalf("a hanging command: %s (exit %d), want rc=124", out, code)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("the limit of 1 s took %s to fire", d)
	}
	time.Sleep(200 * time.Millisecond)
	for _, f := range []string{"parent", "kid"} {
		if alive(t, filepath.Join(dir, f)) {
			t.Errorf("the %s process outlived the limit", f)
		}
	}
}

// The stub Helm records what helm_fetch gives it: the credential folder,
// its contents, and its arguments.
func TestHelmFetchGivesHelmNoCredentials(t *testing.T) {
	dir := t.TempDir()
	helm := filepath.Join(dir, "helm")
	if err := os.WriteFile(helm, []byte(`#!/bin/sh
echo "$DOCKER_CONFIG" > "$REC/docker_config"
echo "$HELM_REGISTRY_CONFIG" > "$REC/registry_config"
ls -A "$DOCKER_CONFIG" > "$REC/listing"
cat "$DOCKER_CONFIG/config.json" > "$REC/config"
echo "$*" > "$REC/args"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	out, code := fetchShell(t, `helm_fetch "$HELM_STUB" "$DEST" "a chart" oci://public.ecr.aws/x/chart --version 1.2.3; echo fetched`,
		"HELM_STUB="+helm, "DEST="+dest, "REC="+dir, "DOCKER_CONFIG=/nonexistent/user-docker", "HELM_REGISTRY_CONFIG=/nonexistent/user-helm.json")
	if code != 0 || !strings.Contains(out, "fetched") {
		t.Fatalf("exit %d: %s", code, out)
	}
	read := func(f string) string {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	cfg := read("docker_config")
	if strings.HasPrefix(cfg, "/nonexistent") || read("registry_config") != cfg+"/config.json" {
		t.Errorf("Helm got the user's registry config: DOCKER_CONFIG=%s HELM_REGISTRY_CONFIG=%s", cfg, read("registry_config"))
	}
	if read("listing") != "config.json" || read("config") != placeholderConfig {
		t.Errorf("the folder holds %q with %q, want only config.json with the placeholder", read("listing"), read("config"))
	}
	if read("args") != "pull oci://public.ecr.aws/x/chart --version 1.2.3 -d "+dest {
		t.Errorf("helm args: %q", read("args"))
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Errorf("the credential folder %s is still there after the fetch", cfg)
	}
	// A failed fetch removes it too, and names the chart.
	if err := os.WriteFile(helm, []byte("#!/bin/sh\necho \"$DOCKER_CONFIG\" > \"$REC/docker_config\"\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code = fetchShell(t, `helm_fetch "$HELM_STUB" "$DEST" "a chart" x`, "HELM_STUB="+helm, "DEST="+dest, "REC="+dir)
	if code == 0 || !strings.Contains(out, "helm: fetching a chart failed (exit 7)") {
		t.Errorf("a failed fetch: exit %d: %s", code, out)
	}
	if _, err := os.Stat(read("docker_config")); !os.IsNotExist(err) {
		t.Errorf("the credential folder is still there after a failed fetch")
	}
	// The limit must be whole seconds, at least 1.
	for _, bad := range []string{"0", "ten", "1.5"} {
		out, code = fetchShell(t, `helm_fetch "$HELM_STUB" "$DEST" "a chart" x`, "HELM_STUB="+helm, "DEST="+dest, "REC="+dir, "HELM_FETCH_SECONDS="+bad)
		if code == 0 || !strings.Contains(out, "HELM_FETCH_SECONDS wants whole seconds") {
			t.Errorf("HELM_FETCH_SECONDS=%s: exit %d: %s", bad, code, out)
		}
	}
}

// The real Helm, against a registry on this machine that asks for a token
// the way public.ecr.aws does, with credential helpers on PATH that log
// every call: under a config naming a store, Helm runs the helper; through
// helm_fetch it runs none. Offline.
func TestHelmFetchRunsNoCredentialHelper(t *testing.T) {
	helm := realHelm(t)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/token"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"t","access_token":"t"}`))
		case r.Header.Get("Authorization") != "":
			http.NotFound(w, r)
		default:
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="fake",scope="repository:x/chart:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	shims, log := t.TempDir(), filepath.Join(t.TempDir(), "helpers.log")
	for _, h := range []string{"desktop", "osxkeychain", "secretservice", "pass", "ecr-login"} {
		body := "#!/bin/sh\necho \"docker-credential-" + h + " $*\" >> \"" + log + "\"\necho \"credentials not found in native keychain\"\nexit 1\n"
		if err := os.WriteFile(filepath.Join(shims, "docker-credential-"+h), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	userCfg := t.TempDir()
	if err := os.WriteFile(filepath.Join(userCfg, "config.json"), []byte(`{"credsStore": "desktop"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"PATH=" + shims + string(os.PathListSeparator) + os.Getenv("PATH"), "DOCKER_CONFIG=" + userCfg,
		"HELM_REGISTRY_CONFIG=" + filepath.Join(userCfg, "registry.json"), "H=" + helm, "REF=oci://" + host + "/x/chart", "DEST=" + t.TempDir()}

	// The control: Helm on its own runs the store's helper.
	out, _ := fetchShell(t, `"$H" pull "$REF" --version 1.0.0 --plain-http -d "$DEST" || true`, env...)
	if !strings.Contains(readLog(t, log), "docker-credential-desktop get") {
		t.Skipf("this Helm did not run the configured helper; the check below would prove nothing:\n%s\n%s", out, readLog(t, log))
	}
	if err := os.Remove(log); err != nil {
		t.Fatal(err)
	}
	out, _ = fetchShell(t, `helm_fetch "$H" "$DEST" "the test chart" "$REF" --version 1.0.0 --plain-http || true`, env...)
	if calls := readLog(t, log); calls != "" {
		t.Errorf("helm_fetch let Helm run a credential helper:\n%s", calls)
	}
	// It reached the registry, anonymously: the fake one has no chart.
	if !strings.Contains(out, "not found") {
		t.Errorf("Helm did not reach the registry:\n%s", out)
	}
}

// cluster.sh up fetches Karpenter's chart through helm_fetch (no
// credentials, the placeholder config) and installs it from the file.
func TestClusterUpFetchesKarpenterWithNoCredentials(t *testing.T) {
	const a = "198.51.100.1"
	r := runClusterUp(t, apiProbe{dns: "1 " + a, tcp: a + " 1", api: a + " 1", helm: `
if [ "$1" = pull ]; then
  echo "$DOCKER_CONFIG" > "$STUB_DIR/docker_config"
  ls -A "$DOCKER_CONFIG" > "$STUB_DIR/listing"
  cat "$DOCKER_CONFIG/config.json" > "$STUB_DIR/config"
  for a; do prev=$last; last=$a; done
  : > "$last/karpenter-1.15.1.tgz"
fi`})
	if r.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", r.code, r.out, r.log)
	}
	pull := strings.Index(r.log, "helm pull oci://public.ecr.aws/karpenter/karpenter --version 1.15.1 -d ")
	install := strings.Index(r.log, "helm upgrade --install karpenter ")
	if pull < 0 || install < pull || !strings.Contains(r.log, ".state/bank-1/karpenter-1.15.1.tgz --namespace kube-system") {
		t.Fatalf("Karpenter was not fetched first and installed from the file:\n%s", r.log)
	}
	if strings.Contains(r.log, "upgrade --install karpenter oci://") {
		t.Errorf("the install still pulls from the registry:\n%s", r.log)
	}
	got := func(f string) string {
		b, err := os.ReadFile(filepath.Join(r.world, f))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	if got("listing") != "config.json" || got("config") != placeholderConfig {
		t.Errorf("the public pull ran with %q holding %q, want only the placeholder config", got("listing"), got("config"))
	}
	if _, err := os.Stat(got("docker_config")); !os.IsNotExist(err) {
		t.Errorf("the credential folder is still there after up")
	}
}

// A fetch that hangs: past HELM_FETCH_SECONDS up fails naming the chart and
// the limit, installs nothing, and the hanging Helm and its child are gone.
func TestClusterUpStopsAHangingChartFetch(t *testing.T) {
	const a = "198.51.100.1"
	start := time.Now()
	r := runClusterUp(t, apiProbe{dns: "1 " + a, tcp: a + " 1", api: a + " 1", env: []string{"HELM_FETCH_SECONDS=2"}, helm: `
if [ "$1" = pull ]; then
  trap '' TERM
  echo $$ > "$STUB_DIR/helm.pid"
  sleep 60 & echo $! > "$STUB_DIR/kid.pid"
  i=0; while [ $i -lt 60 ]; do sleep 1; i=$((i + 1)); done
fi`})
	if r.code == 0 || !strings.Contains(r.out,
		"helm: fetching Karpenter's chart (oci://public.ecr.aws/karpenter/karpenter 1.15.1) did not finish within 2s (HELM_FETCH_SECONDS); stopped it") ||
		!strings.Contains(r.out, "could not fetch Karpenter's chart; nothing was installed") {
		t.Fatalf("exit %d, want a failure naming the chart and the limit\n%s\n%s", r.code, r.out, r.log)
	}
	if strings.Contains(r.log, "helm upgrade") {
		t.Errorf("something was installed after the failed fetch:\n%s", r.log)
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("up took %s to give up on a 2 s limit", d)
	}
	time.Sleep(200 * time.Millisecond)
	for _, f := range []string{"helm.pid", "kid.pid"} {
		if alive(t, filepath.Join(r.world, f)) {
			t.Errorf("%s outlived the limit", f)
		}
	}
}

// Every chart fetch in the EKS and kind run scripts goes through helm_fetch:
// a command that names a chart repository (--repo) or an OCI chart
// (oci://) starts with helm_fetch. The installs then read the fetched file.
func TestEveryChartFetchGoesThroughHelmFetch(t *testing.T) {
	for _, f := range []string{"cluster.sh", "eks-bank.sh", "drills-lib.sh", "drills-eks.sh", "drills-local.sh", "cell.sh"} {
		raw, err := os.ReadFile(k8sFile(t, f))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		fetches := map[int]bool{} // the commands, by their first line
		for i, l := range lines {
			code := strings.TrimSpace(l)
			if strings.HasPrefix(code, "#") || !(strings.Contains(code, "--repo ") || strings.Contains(code, "oci://")) {
				continue
			}
			// Back to the command's first line over \ continuations.
			start := i
			for start > 0 && strings.HasSuffix(strings.TrimRight(lines[start-1], " "), "\\") {
				start--
			}
			if !strings.Contains(lines[start], "helm_fetch ") {
				t.Errorf("%s:%d fetches a chart outside helm_fetch: %s", f, i+1, code)
			}
			fetches[start] = true
		}
		want := map[string]int{"cluster.sh": 1, "eks-bank.sh": 2, "drills-lib.sh": 1}[f]
		if len(fetches) != want {
			t.Errorf("%s: %d chart fetches, want %d", f, len(fetches), want)
		}
	}
}
