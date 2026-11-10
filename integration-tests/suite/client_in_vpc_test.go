//go:build integration

package suite

// Large uploads to the cluster run from a test node inside AWS, never from
// this machine (user, 2026-11-10). One stream from the laptop to us-east-1
// moves 95-700 KB/s, so each 115 MB build upload took 20-75 minutes and
// UC-656 and UC-667 timed out run after run. Here the files go to S3 once
// (scripts/stage-to-node.sh, the path every harness file takes to a node,
// with parallel parts), the node fetches them inside AWS in seconds, and
// the node runs the same client against the same public API URL a
// customer's machine uses (443 on the ingress). What a case tests is the
// same: the aerolvm CLI, the upload route, the cluster's handling of both.
// Only where the client sits moves.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// clientRoot is where staged client files live on the node.
const clientRoot = "/var/tmp/aerolvm-client"

var linuxCLI struct {
	once sync.Once
	path string
	err  error
}

// stagedCLI records the nodes that already have the Linux aerolvm.
var stagedCLI = struct {
	sync.Mutex
	on map[string]bool
}{on: map[string]bool{}}

// clientNode is the node uploads run from: the first SSH-reachable node by
// name. On a single node it is that node. Its sandboxd may restart during
// an upgrade, but the client runs in its own SSH session, not in
// sandboxd's cgroup, so it rides that out as a laptop would; every API
// call goes through the ingress either way.
func clientNode(t *testing.T) harness.IntegrationNode {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Fatal("no integration targets: large uploads run from a node, so this case needs one")
	}
	nodes := append([]harness.IntegrationNode(nil), targets.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	for _, n := range nodes {
		if _, ok := harness.SSHTarget(n); ok {
			return n
		}
	}
	t.Fatal("no SSH-reachable node to run uploads from")
	return harness.IntegrationNode{}
}

// stageOnNode puts local files in dir on node through S3, never scp
// (scripts/stage-to-node.sh: each file lands under its own name, checked
// against its SHA-256).
func stageOnNode(t *testing.T, node harness.IntegrationNode, dir string, files ...string) {
	t.Helper()
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Fatalf("no SSH address for %s", node.Name)
	}
	args := []string{"../scripts/stage-to-node.sh", "--scenario", sc.Name, dir}
	args = append(append(args, files...), "--", target)
	// A retry is safe: the S3 copy is reused and the node fetches again.
	// It covers an SSH connect that times out while this machine's link is
	// busy (2026-11-10: two gates staging at once timed one out).
	var out []byte
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if out, err = exec.Command("bash", args...).CombinedOutput(); err == nil {
			return
		}
		t.Logf("staging on %s, attempt %d: %v\n%s", node.Name, attempt, err, out)
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("staging %v on %s through S3: %v\n%s", files, node.Name, err, out)
}

// linuxAerolvm builds aerolvm for the nodes (linux/amd64, the only arch
// the harness provisions) once per run.
func linuxAerolvm(t *testing.T) string {
	t.Helper()
	linuxCLI.once.Do(func() {
		dir, err := os.MkdirTemp("", "aerolvm-linux-")
		if err != nil {
			linuxCLI.err = err
			return
		}
		linuxCLI.path = filepath.Join(dir, "aerolvm")
		cmd := exec.Command("go", "build", "-trimpath", "-o", linuxCLI.path, "../../cmd/aerolvm")
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			linuxCLI.err = fmt.Errorf("go build ./cmd/aerolvm for linux/amd64: %v\n%s", err, out)
		}
	})
	if linuxCLI.err != nil {
		t.Fatal(linuxCLI.err)
	}
	return linuxCLI.path
}

// ensureCLIOnNode stages the Linux aerolvm on node once and returns its
// path there.
func ensureCLIOnNode(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	remote := clientRoot + "/bin/aerolvm"
	stagedCLI.Lock()
	defer stagedCLI.Unlock()
	if !stagedCLI.on[node.Name] {
		if arch := strings.TrimSpace(sshRoot(t, node, "uname -m")); arch != "x86_64" {
			t.Fatalf("%s is %s; the client build is linux/amd64", node.Name, arch)
		}
		stageOnNode(t, node, clientRoot+"/bin", linuxAerolvm(t))
		stagedCLI.on[node.Name] = true
	}
	return remote
}

// stageDirOnNode stages every regular file of a local build folder on node
// and returns the folder there, named after the local path so two builds
// never mix.
func stageDirOnNode(t *testing.T, node harness.IntegrationNode, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	if len(files) == 0 {
		t.Fatalf("%s has no files to stage", dir)
	}
	abs, _ := filepath.Abs(dir)
	sum := sha256.Sum256([]byte(abs))
	remote := clientRoot + "/from-" + hex.EncodeToString(sum[:6])
	stageOnNode(t, node, remote, files...)
	return remote
}

var exitMarker = regexp.MustCompile(`\n__AEROLVM_EXIT__=(-?\d+)\n?$`)

const stderrMarker = "\n__AEROLVM_STDERR__\n"

// aerolvmOnNode runs aerolvm with args on the client node, like
// aerolvmLong does here: the same API URL and token, a fresh config
// directory, a 75-minute limit. A "--from <dir>" argument is staged on the
// node first and pointed at the staged copy. The token goes on stdin, so
// it never reaches the node's process list or sudo's log.
func aerolvmOnNode(t *testing.T, args ...string) cliResult {
	t.Helper()
	node := clientNode(t)
	cli := ensureCLIOnNode(t, node)
	remoteArgs := append([]string(nil), args...)
	for i := 0; i+1 < len(remoteArgs); i++ {
		if remoteArgs[i] == "--from" {
			remoteArgs[i+1] = stageDirOnNode(t, node, remoteArgs[i+1])
		}
	}
	quoted := make([]string, len(remoteArgs))
	for i, a := range remoteArgs {
		quoted[i] = shellQuote(a)
	}
	script := strings.Join([]string{
		`read -r tok`,
		`d=$(mktemp -d)`,
		`SB_API_URL=` + shellQuote(sc.BaseURL) + ` SB_PAT_TOKEN="$tok" XDG_CONFIG_HOME="$d" timeout 75m ` +
			shellQuote(cli) + ` ` + strings.Join(quoted, " ") + ` >"$d/out" 2>"$d/err"`,
		`code=$?`,
		`cat "$d/out"`,
		`printf '\n__AEROLVM_STDERR__\n'`,
		`cat "$d/err"`,
		`printf '\n__AEROLVM_EXIT__=%d\n' "$code"`,
		`rm -rf "$d"`,
	}, "\n")
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRunStdin(t, target, "bash -c "+shellQuote(script), sc.PAT+"\n")
	res := parseNodeCLI(out)
	if err != nil && res.code == -1 {
		t.Fatalf("aerolvm %v on %s: %v\n%s", args, node.Name, err, out)
	}
	t.Logf("aerolvm %s (on %s, inside AWS) = %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), node.Name, res.code, res.stdout, res.stderr)
	return res
}

// parseNodeCLI splits aerolvmOnNode's output into stdout, stderr and the
// exit code; a run cut short (no exit marker) reads as code -1.
func parseNodeCLI(out string) cliResult {
	res := cliResult{code: -1}
	m := exitMarker.FindStringSubmatchIndex(out)
	if m == nil {
		res.stdout = out
		return res
	}
	res.code, _ = strconv.Atoi(out[m[2]:m[3]])
	body := out[:m[0]]
	if i := strings.LastIndex(body, stderrMarker); i >= 0 {
		res.stdout, res.stderr = body[:i], body[i+len(stderrMarker):]
	} else {
		res.stdout = body
	}
	return res
}

// putFileFromNode PUTs a file already staged on the client node to the
// cluster's upload route (…/files/{sha256}), as putFile does from here,
// and returns the status and body.
func putFileFromNode(t *testing.T, node harness.IntegrationNode, remoteFile, sum string) (int, string) {
	t.Helper()
	url := sc.BaseURL + upgradewire.ClusterUpgradeFilesPath + "/" + sum
	// The status curl received counts even when curl then exits non-zero:
	// for a file it already has the server answers 200 without reading the
	// rest of the body, and curl, still sending, reports the stream it
	// closed (HTTP/2 error 92) after printing that 200. Only no status at
	// all (000) is a failed call; curl's own error then goes in the body.
	script := strings.Join([]string{
		`d=$(mktemp -d)`,
		`code=$(curl -sS -m 1200 -o "$d/body" -w '%{http_code}' -X PUT -H @- ` +
			`-H 'Content-Type: application/octet-stream' --data-binary @` + shellQuote(remoteFile) + ` ` + shellQuote(url) + ` 2>"$d/err")`,
		`[ -n "$code" ] || code=000`,
		`cat "$d/body"`,
		`[ "$code" = 000 ] && cat "$d/err"`,
		`printf '\n__AEROLVM_EXIT__=%d\n' "$((10#$code))"`,
		`rm -rf "$d"`,
	}, "\n")
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRunStdin(t, target, "bash -c "+shellQuote(script), "Authorization: Bearer "+sc.PAT+"\n")
	res := parseNodeCLI(out)
	if err != nil && res.code == -1 {
		t.Fatalf("PUT %s from %s: %v\n%s", sum, node.Name, err, out)
	}
	return res.code, res.stdout
}
