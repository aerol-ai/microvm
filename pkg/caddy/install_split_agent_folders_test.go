package caddy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On a node already in privilege mode split, sandboxd's user owns
// /var/lib/sandboxd, /run/sandboxd and the certificate folders, and can swap
// any name in them for a link. Root's tools follow links, so a re-run of
// install.sh must not make, change, write or remove anything inside them as
// root: what has to happen there runs as that user (runuser).
//
// The test runs the real install.sh twice on the rig's fake machine: a split
// install, then a re-run after "the agent" left links where root used to
// act. Every file command is logged with the user it runs as, and the
// links' targets are checked afterwards.

// fileCommandLog wraps the file commands install.sh runs, so each is logged
// as "fs <user> <command> <args>" before it runs, and stands in for runuser
// (which the rig's machine has not got), logging "runuser <user> <command>".
const fileCommandLog = `__fslog() { local c="$1"; shift; echo "fs ${AS_USER:-root} $c $*" >>"$LOG"; command "$c" "$@"; }
mkdir() { __fslog mkdir "$@"; }
chmod() { __fslog chmod "$@"; }
chown() { __fslog chown "$@"; }
chgrp() { __fslog chgrp "$@"; }
rm() { __fslog rm "$@"; }
cp() { __fslog cp "$@"; }
mv() { __fslog mv "$@"; }
ln() { __fslog ln "$@"; }
touch() { __fslog touch "$@"; }
tee() { __fslog tee "$@"; }
find() { __fslog find "$@"; }
install() { __fslog install "$@"; }
test() { __fslog test "$@"; }
runuser() {
	[[ "$1" == -u && "$3" == -- ]] || { echo "runuser: want -u USER --" >&2; return 2; }
	local who="$2"
	shift 3
	echo "runuser $who $*" >>"$LOG"
	AS_USER="$who" "$@"
}
`

// logFileCommands puts fileCommandLog into the rig's script, after its own
// stubs, so its install wrapper is the one that runs.
func (r *runRig) logFileCommands() {
	r.t.Helper()
	raw, err := os.ReadFile(r.script)
	if err != nil {
		r.t.Fatal(err)
	}
	const anchor = "\ncurl() { echo \"curl $*\" >>\"$LOG\"; command curl \"$@\"; }\n"
	if strings.Count(string(raw), anchor) != 1 {
		r.t.Fatal("the rig's stubs moved; update logFileCommands")
	}
	src := strings.Replace(string(raw), anchor, anchor+fileCommandLog, 1)
	if err := os.WriteFile(r.script, []byte(src), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// agentFolders are the rig's stand-ins for the folders sandboxd's user owns
// in split.
func (r *runRig) agentFolders() []string {
	return []string{r.path("varlib"), r.path("run"), r.path("sandboxd/tls"), r.path("sandboxd/cluster-ca")}
}

// rootInAgentFolders returns the logged root file commands that name a path
// inside one of the agent's folders (the folders themselves are root's to
// make: their parents are root's).
func (r *runRig) rootInAgentFolders(calls string) []string {
	var bad []string
	for _, line := range strings.Split(calls, "\n") {
		if !strings.HasPrefix(line, "fs root ") {
			continue
		}
		for _, d := range r.agentFolders() {
			if strings.Contains(line, d+"/") {
				bad = append(bad, line)
				break
			}
		}
	}
	return bad
}

func TestInstallSplitRerunLeavesTheAgentFoldersToTheAgent(t *testing.T) {
	r := newRunRig(t)
	r.stubEngineSteps()
	r.logFileCommands()
	providerEnv := r.write("provider.env", "SB_SECRET_PROVIDER=awskms\nSB_SECRET_AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:111122223333:key/k\n", 0o600)
	args := append(r.splitRelease("helper v0.7.8\n"), "--with-containerd-engine", "--privilege-mode", "split",
		"--key-custody", "wrapped", "--secret-provider-env", providerEnv)
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), args...); err != nil {
		t.Fatalf("install.sh: %v\n%s\ncalls:\n%s", err, out, r.calls())
	}

	// sandboxd has run as its user since: its folders are its own. It left
	// a link where root used to make the mounts folder, and a server key
	// from file custody that this run's wrapped custody must wrap.
	outside := r.path("outside")
	if err := os.MkdirAll(filepath.Join(outside, "mounts"), 0o755); err != nil {
		t.Fatal(err)
	}
	mounts := r.path("varlib/mounts")
	if err := os.RemoveAll(mounts); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "mounts"), mounts); err != nil {
		t.Fatal(err)
	}
	r.write("varlib/credential_encryption.key", "plaintext key\n", 0o600)

	r.resetLog()
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=true"), r.splitRelease("helper v0.7.8\n")...); err != nil {
		t.Fatalf("re-run: %v\n%s\ncalls:\n%s", err, out, r.calls())
	}
	calls := r.calls()
	for _, c := range r.rootInAgentFolders(calls) {
		t.Errorf("the split re-run acted as root inside a folder sandboxd's user owns: %s", c)
	}
	if fi, err := os.Stat(filepath.Join(outside, "mounts")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("root changed what the agent's link names: %v %v", fi.Mode().Perm(), err)
	}
	if fi, err := os.Lstat(mounts); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the agent's link was replaced: %v", err)
	}
	// The key custody step ran, as sandboxd's user, with sandboxd.env on stdin.
	for _, want := range []string{
		"runuser sandboxd " + r.path("bin") + "/sandboxd key wrap --env-file /dev/stdin",
		"runuser sandboxd rm -f " + r.path("varlib/credential_encryption.key"),
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("the re-run did not run %q; calls:\n%s", want, calls)
		}
	}

	// The check finds root's file commands in those folders: a first split
	// install, before the agent ever ran, may still make them as root.
	if got := r.rootInAgentFolders("fs root chmod 0700 " + mounts + "\nfs sandboxd rm -f " + mounts + "/x\nfs root mkdir -p " + r.path("varlib") + "\n"); len(got) != 1 {
		t.Errorf("the check found %q, want only root's chmod inside the folder", got)
	}
}

// Single mode keeps making the mounts folder and wrapping a key as root, as
// before: sandboxd is root there.
func TestInstallSingleStillMakesTheMountsFolderAsRoot(t *testing.T) {
	r := newRunRig(t)
	r.logFileCommands()
	if out, err := r.run(r.env("SANDBOXD_ACTIVE=false"), r.splitRelease("helper v0.7.8\n")...); err != nil {
		t.Fatalf("install.sh: %v\n%s\ncalls:\n%s", err, out, r.calls())
	}
	calls := r.calls()
	for _, want := range []string{"fs root mkdir -p " + r.path("varlib/mounts"), "fs root chmod 0700 " + r.path("varlib/mounts")} {
		if !strings.Contains(calls, want) {
			t.Errorf("single did not run %q; calls:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "runuser ") {
		t.Errorf("single ran a step as another user; calls:\n%s", calls)
	}
}
