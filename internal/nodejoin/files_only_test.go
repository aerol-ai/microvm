package nodejoin

import (
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// Finding F14: init and join on a machine with no systemd (a Kubernetes
// pod's init container) write the cluster's files and stop: no root, no
// systemd drop-in, no reload or restart. A later init, against the sandboxd
// that started with those files, admits the node and registers the tokens,
// still without root.
func TestInitFilesOnly(t *testing.T) {
	r := newInitRig(t)
	r.host.notRoot = true
	res, err := r.run(t, InitOptions{FilesOnly: true})
	if err != nil {
		t.Fatalf("init --files-only: %v\n%s", err, r.out.String())
	}
	ca, err := cluster.LoadClusterCA(r.paths.CADir)
	if err != nil || ca == nil || res.ClusterID != cluster.CACertHash(ca.Certificate()) || res.NodeID != "node-a" {
		t.Fatalf("CA %v %v, result %+v", ca, err, res)
	}
	if env, _ := readEnvFile(r.paths.ClusterEnv); env["SB_ENABLE_CLUSTER"] != "true" || env["SB_NODE_ID"] != "node-a" {
		t.Fatalf("cluster.env = %v", env)
	}
	if exists(r.paths.DropIn) {
		t.Fatal("wrote a systemd drop-in nothing loads")
	}
	if r.host.reloads != 0 || r.host.restarts != 0 || len(r.api.adopts) != 0 || len(r.api.tokens) != 0 {
		t.Fatalf("touched systemd or the API: reloads %d restarts %d adopts %d tokens %d", r.host.reloads, r.host.restarts, len(r.api.adopts), len(r.api.tokens))
	}
	if !strings.Contains(r.out.String(), "files written (--files-only)") {
		t.Fatalf("output: %s", r.out.String())
	}

	// Again with --files-only: nothing to do, nothing changed.
	cert := readFile(t, r.paths.TLSDir+"/node.crt")
	again, err := r.run(t, InitOptions{FilesOnly: true})
	if err != nil || !again.Again || again.ClusterID != res.ClusterID || readFile(t, r.paths.TLSDir+"/node.crt") != cert {
		t.Fatalf("second files-only run = %+v %v", again, err)
	}

	// The pod's sandboxd is up and leads: init without the flag, not root,
	// admits the node and registers the default token.
	r.api.mu.Lock()
	r.api.leader = "node-a"
	r.api.mu.Unlock()
	done, err := r.run(t, InitOptions{})
	if err != nil || !done.Again || len(r.api.adopts) != 1 || len(r.api.tokens) != 1 || r.host.restarts != 0 {
		t.Fatalf("follow-up init = %+v %v, adopts %d tokens %d restarts %d\n%s", done, err, len(r.api.adopts), len(r.api.tokens), r.host.restarts, r.out.String())
	}
}

// Without the flag, a user who is not root still cannot start a cluster,
// and one who cannot read sandboxd.env is told to use root, not shown a
// permission error.
func TestInitStillNeedsRoot(t *testing.T) {
	r := newInitRig(t)
	r.host.notRoot = true
	if _, err := r.run(t, InitOptions{}); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("non-root init without files = %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads every file; the permission case needs another user")
	}
	mustWrite(t, r.paths.ClusterEnv, "SB_ENABLE_CLUSTER=true\n")
	if err := os.Chmod(r.paths.EnvFile, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(r.paths.EnvFile, 0o600) })
	if _, err := r.run(t, InitOptions{}); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("unreadable sandboxd.env = %v", err)
	}
	// With the files there but not this node's seed, a non-root run that
	// would write files is refused before writing.
	_ = os.Chmod(r.paths.EnvFile, 0o600)
	if _, err := r.run(t, InitOptions{}); err == nil {
		t.Fatal("non-root init over another state succeeded")
	}
}

func TestJoinFilesOnly(t *testing.T) {
	r := newJoinRig(t)
	r.host.notRoot = true
	tok := r.srv.token(cluster.JoinRoleWorker)
	res, err := r.run(t, JoinOptions{Token: tok, CACertHash: cluster.CACertHash(r.srv.ca.Certificate()), FilesOnly: true})
	if err != nil {
		t.Fatalf("join --files-only: %v\n%s", err, r.out.String())
	}
	if res.NodeID != "node-a" || res.Role != cluster.JoinRoleWorker {
		t.Fatalf("result = %+v", res)
	}
	if env, _ := readEnvFile(r.paths.ClusterEnv); env["SB_ENABLE_CLUSTER"] != "true" || env["SB_NODE_ROLE"] != "worker" {
		t.Fatalf("cluster.env = %v", env)
	}
	if !exists(r.paths.TLSDir + "/node.crt") {
		t.Fatal("no node certificate")
	}
	if exists(r.paths.DropIn) || r.host.reloads != 0 || r.host.restarts != 0 {
		t.Fatalf("touched systemd: drop-in %v reloads %d restarts %d", exists(r.paths.DropIn), r.host.reloads, r.host.restarts)
	}
	if !strings.Contains(r.out.String(), "files written (--files-only)") {
		t.Fatalf("output: %s", r.out.String())
	}
	// Without the flag, join still needs root.
	r2 := newJoinRig(t)
	r2.host.notRoot = true
	if _, err := r2.run(t, JoinOptions{Token: r2.srv.token(cluster.JoinRoleWorker)}); err == nil || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("non-root join = %v", err)
	}
}
