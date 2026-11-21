package rootd

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runscwrap"
	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
)

// The helper makes the files runc, runsc and the containerd shim open as
// root because a container names them (plans/security-gaps-m1-m4.md §3,
// "What building the gate taught us"): the host files a spec binds in,
// the names of ready sockets, task stdio FIFOs and the runsc shim configs.
// runc and the shim follow links in those paths. If one sat in a folder
// the agent can write, a broken agent could swap it for a link between the
// gate's check and root's open, and root would bind, append to or read
// whatever the link names. So every one of them is made here, in the
// helper's own folders, which only root can write:
//
//	<Files.Hosts>/<id>/{hostname,hosts,resolv.conf,egress-ca.pem}  0644
//	<Files.Ready>/<id>/{ready.sock,<nonce>.sock}  the agent's socket, linked
//	<Policy.FIFODir>/<id>/{stdout,stderr}  FIFOs, 0640 to the agent's group
//	<Files.Runsc>/{config.toml,restore.toml}  0644
//
// The ready folders are 0700: the agent's own ready folder is what keeps
// other users off its socket, and the helper's link gives that socket a
// second name, which only root (runc, the gate) needs to reach. The FIFO
// folders are 0750 to the agent's group, which opens the FIFOs; others
// have no business there either.
//
// The folders are opened once, at start, one name at a time with no link
// followed (openFolder), and every later step goes through those open
// folders, never a path: create a temporary name, set its mode, rename it
// into place. A name below means what this code left there.
//
// The agent sends typed values, never a path, a file name or a file's
// content. Each value is checked here and the file is written here; the
// answer is the paths the agent puts in its specs, which the gate then
// accepts because they sit in these folders.

// File names in a container's folders. The ones a spec binds are
// rootpolicy's, which the gate accepts by name.
const (
	hostnameFile     = rootpolicy.HostnameFile
	hostsFile        = rootpolicy.HostsFile
	resolvConfFile   = rootpolicy.ResolvConfFile
	egressCAFile     = rootpolicy.EgressCAFile
	stdoutFIFO       = "stdout"
	stderrFIFO       = "stderr"
	runscDefaultFile = "config.toml"
	runscRestoreFile = "restore.toml"
)

// Folder modes. A container's host files folder is open to all, as the
// files in it are; the others are closed (see above).
const (
	hostsFolderMode = 0o755
	readyFolderMode = 0o700
	fifoFolderMode  = 0o750
)

// Bounds on what one request may ask for. Root writes the files, so a
// request must not be able to fill a disk.
const (
	maxNameLen       = 253 // a DNS name
	maxHostEntries   = 64
	maxNamesPerEntry = 16
	maxEgressCADER   = 64 << 10
	// The resolver settings: past these the rest is dropped, not refused
	// (renderResolvConf). Resolvers read far fewer: glibc and musl use
	// the first three nameservers.
	maxNameservers  = 64
	maxSearch       = 64
	maxOptions      = 64
	maxResolverWord = 253
)

// Reasons the helper's own calls refuse a request. Like the gate's, each
// is a short, stable code for a metric label.
const (
	// ReasonBadRequest: a value failed its check.
	ReasonBadRequest = "bad_request"
	// ReasonNotAgentSocket: what the agent's ready folder holds under a
	// container's name is not a socket the agent owns.
	ReasonNotAgentSocket = "not_agent_socket"
)

// runscFlags are the runsc flags every gVisor sandbox gets. [runsc_config]
// is the section the shim turns into runsc flags; host-uds=open lets the
// sandbox reach its bind-mounted ready socket. The containerd driver
// writes the same flags today (runsc_config.go); a test there pins them.
const runscFlags = "[runsc_config]\n  host-uds = \"open\"\n"

const runscHeader = "# Managed by the AerolVM root helper (do not edit).\n"

// runscWrapper is aerolvm-runsc, which the runtime image installs next to
// runsc. A restored sandbox's shim runs it in place of runsc.
const runscWrapper = "/usr/local/bin/" + runscwrap.CommandName

// fileError is a call the helper answers with a status of its own. With a
// reason it is a refusal (eng review D9): the agent only sends what its
// own code built, so a refused value means drift or a broken agent.
type fileError struct {
	code   codes.Code
	reason string
	msg    string
}

func (e *fileError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &fileError{code: codes.InvalidArgument, reason: ReasonBadRequest, msg: fmt.Sprintf(format, args...)}
}

// files makes the files in the helper's folders.
type files struct {
	dirs    FileDirs
	fifoDir string
	// gid is the agent's group, which may read the FIFOs.
	gid int
	// agentUID must own every ready socket the helper names.
	agentUID uint32
	// owner is root, or the test's own user, as for the socket's folder.
	owner uint32
	// The helper's folders, open for the server's whole life.
	hosts, ready, fifo, runsc int
}

// openFiles makes the helper's folders where missing and opens each.
// Every folder from / down must pass openFolder's rule, or the helper does
// not start: a folder someone else can write is a place a link can be
// swapped in.
func openFiles(cfg Config) (*files, error) {
	f := &files{dirs: cfg.Files, fifoDir: cfg.Policy.FIFODir, gid: cfg.SocketGID, agentUID: cfg.AgentUID,
		owner: uint32(os.Geteuid()), hosts: -1, ready: -1, fifo: -1, runsc: -1}
	for _, d := range []struct {
		dir string
		fd  *int
	}{{f.dirs.Hosts, &f.hosts}, {f.dirs.Ready, &f.ready}, {f.fifoDir, &f.fifo}, {f.dirs.Runsc, &f.runsc}} {
		// openFolder makes a missing folder through the checked folder
		// above it: making the path first would follow a link someone put
		// on the way (review N2).
		fd, err := openFolder(d.dir)
		if err != nil {
			f.close()
			return nil, fmt.Errorf("root helper: folder %s: %w", d.dir, err)
		}
		*d.fd = fd
	}
	// Closed whatever made them, or an older helper: through the open
	// handles, never a path.
	for _, d := range []struct {
		fd   int
		dir  string
		mode uint32
		gid  int
	}{{f.ready, f.dirs.Ready, readyFolderMode, -1}, {f.fifo, f.fifoDir, fifoFolderMode, f.gid}} {
		if err := setFolderMode(d.fd, d.mode, d.gid); err != nil {
			f.close()
			return nil, fmt.Errorf("root helper: folder %s: %w", d.dir, err)
		}
	}
	// A crash between a runsc config's temporary file and its rename
	// leaves that file in the shared runsc folder for good (a container's
	// own folder goes with RemoveContainerFiles). Clear those now. Best
	// effort: a leftover is harmless, so it never stops the helper.
	sweepTmpNames(f.runsc, runscDefaultFile, runscRestoreFile)
	return f, nil
}

func (f *files) close() {
	for _, fd := range []*int{&f.hosts, &f.ready, &f.fifo, &f.runsc} {
		if *fd >= 0 {
			_ = unix.Close(*fd)
			*fd = -1
		}
	}
}

// ensureHostFiles writes a container's host files from typed values.
func (f *files) ensureHostFiles(req *rootdpb.EnsureHostFilesRequest) (*rootdpb.EnsureHostFilesResponse, error) {
	id := req.GetContainerId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	hostname, err := checkName("hostname", req.GetHostname())
	if err != nil {
		return nil, err
	}
	hosts, err := renderHosts(req.GetHosts())
	if err != nil {
		return nil, err
	}
	resolv := renderResolvConf(req)
	ca, err := renderEgressCA(req.GetEgressCaDer())
	if err != nil {
		return nil, err
	}
	dfd, err := f.ensureFolder(f.hosts, id, hostsFolderMode, -1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	for _, w := range []struct {
		name string
		body []byte
	}{{hostnameFile, []byte(hostname + "\n")}, {hostsFile, hosts}, {resolvConfFile, resolv}} {
		if err := f.writeFile(dfd, w.name, w.body, 0o644); err != nil {
			return nil, err
		}
	}
	dir := filepath.Join(f.dirs.Hosts, id)
	resp := &rootdpb.EnsureHostFilesResponse{
		HostnamePath:   filepath.Join(dir, hostnameFile),
		HostsPath:      filepath.Join(dir, hostsFile),
		ResolvConfPath: filepath.Join(dir, resolvConfFile),
	}
	if ca == nil {
		// The request is the whole truth: a CA an earlier call asked for
		// goes when this one does not.
		if err := unix.Unlinkat(dfd, egressCAFile, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return nil, err
		}
		return resp, nil
	}
	if err := f.writeFile(dfd, egressCAFile, ca, 0o644); err != nil {
		return nil, err
	}
	resp.EgressCaPath = filepath.Join(dir, egressCAFile)
	return resp, nil
}

// ensureTaskFIFOs makes fresh FIFOs for a container's next task. Fresh
// ones each time, renamed over the old: a reader of the last task's FIFOs
// keeps those and gets its end of file, and never reads the next task's
// output.
func (f *files) ensureTaskFIFOs(req *rootdpb.EnsureTaskFIFOsRequest) (*rootdpb.EnsureTaskFIFOsResponse, error) {
	id := req.GetContainerId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	dfd, err := f.ensureFolder(f.fifo, id, fifoFolderMode, f.gid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	dir := filepath.Join(f.fifoDir, id)
	for _, name := range []string{stdoutFIFO, stderrFIFO} {
		if err := f.makeFIFO(dfd, dir, name); err != nil {
			return nil, err
		}
	}
	return &rootdpb.EnsureTaskFIFOsResponse{StdoutPath: filepath.Join(dir, stdoutFIFO), StderrPath: filepath.Join(dir, stderrFIFO)}, nil
}

// makeFIFO puts a new FIFO at name: root's, 0640 to the agent's group. The
// shim opens it as root to write; the agent opens it to read.
func (f *files) makeFIFO(dfd int, dir, name string) error {
	tmp, err := tmpName(name)
	if err != nil {
		return err
	}
	err = mkfifoAt(dfd, dir, tmp, 0o600)
	if err == nil {
		err = unix.Fchownat(dfd, tmp, -1, f.gid, unix.AT_SYMLINK_NOFOLLOW)
	}
	if err == nil {
		// fchmodat follows a link at tmp, and needs not refuse one here:
		// tmp is the FIFO just made, in a folder no one else can change.
		err = unix.Fchmodat(dfd, tmp, 0o640, 0)
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("root helper: FIFO %s: %w", filepath.Join(dir, name), err)
	}
	return nil
}

// ensureRunscConfig writes one of the two runsc shim configs. Their whole
// content is the helper's: a runsc config names the binary the shim runs
// as root and can turn on host networking, so no part of it comes from the
// agent, which only says which of the two it needs.
func (f *files) ensureRunscConfig(req *rootdpb.EnsureRunscConfigRequest) (*rootdpb.EnsureRunscConfigResponse, error) {
	name, body, err := runscConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	if err := f.writeFile(f.runsc, name, []byte(body), 0o644); err != nil {
		return nil, err
	}
	return &rootdpb.EnsureRunscConfigResponse{Path: f.dirs.runscPath(name)}, nil
}

func runscConfig(c rootdpb.RunscConfig) (name, body string, err error) {
	switch c {
	case rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT:
		return runscDefaultFile, runscHeader + runscFlags, nil
	case rootdpb.RunscConfig_RUNSC_CONFIG_RESTORE:
		return runscRestoreFile, runscHeader + "binary_name = \"" + runscWrapper + "\"\n" + runscFlags, nil
	}
	return "", "", badRequest("runsc config %v is not one the helper writes", c)
}

// ensureReadySocket gives the agent's ready socket for a container a name
// in the helper's folder, for the spec to bind.
//
// The agent binds and keeps the socket itself, in its own ready folder,
// so it alone accepts on it: a helper restart, or the signed swap of eng
// review D4, never drops a ready wait or a parked slot's held connection.
// gRPC cannot hand over a listening socket, and a relay through the helper
// would end every held connection at each swap. A hard link needs neither:
// the helper links the agent's name into its own folder, under a random
// temporary name, following no link. Only then does it look at what it
// linked, which the agent can no longer change: it must be a socket the
// agent owns. Anything else (a link, a file, root's own socket) is
// unlinked and refused. The check after the link is what makes it safe;
// the agent's folder may hold anything.
//
// It costs one call per create that uses a ready socket, and needs the
// agent's ready folder on the same filesystem as the helper's.
func (f *files) ensureReadySocket(req *rootdpb.EnsureReadySocketRequest) (*rootdpb.EnsureReadySocketResponse, error) {
	id, nonce := req.GetContainerId(), req.GetNonce()
	if err := checkID(id); err != nil {
		return nil, err
	}
	// pkg/docker's names: <id>.<nonce>.sock for a create, <id>.sock for a
	// warm-pool slot's park socket.
	agentName, name := id+".sock", rootpolicy.ReadySocketFile(nonce)
	if nonce != "" {
		if err := rootpolicy.CheckReadyNonce(nonce); err != nil {
			return nil, badRequest("%v", err)
		}
		agentName = id + "." + nonce + ".sock"
	}
	afd, err := openPath(f.dirs.AgentReady)
	if err != nil {
		return nil, &fileError{code: codes.FailedPrecondition, msg: fmt.Sprintf("root helper: the agent's ready folder: %v", err)}
	}
	defer func() { _ = unix.Close(afd) }()
	dfd, err := f.ensureFolder(f.ready, id, readyFolderMode, -1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }()
	tmp, err := tmpName(name)
	if err != nil {
		return nil, err
	}
	// No AT_SYMLINK_FOLLOW: a link at agentName is linked as the link.
	switch err := unix.Linkat(afd, agentName, dfd, tmp, 0); {
	case errors.Is(err, unix.ENOENT):
		return nil, &fileError{code: codes.NotFound, msg: fmt.Sprintf("root helper: no ready socket %s in %s", agentName, f.dirs.AgentReady)}
	case errors.Is(err, unix.EPERM):
		// A folder, which no one may hard-link: not a socket either.
		return nil, &fileError{code: codes.PermissionDenied, reason: ReasonNotAgentSocket,
			msg: fmt.Sprintf("root helper: %s in the agent's ready folder cannot be linked: %v", agentName, err)}
	case errors.Is(err, unix.EXDEV):
		return nil, &fileError{code: codes.FailedPrecondition,
			msg: fmt.Sprintf("root helper: the agent's ready folder %s and the helper's %s must be on one filesystem", f.dirs.AgentReady, f.dirs.Ready)}
	case err != nil:
		return nil, fmt.Errorf("root helper: link ready socket %s: %w", agentName, err)
	}
	var st unix.Stat_t
	err = unix.Fstatat(dfd, tmp, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err != nil:
	case uint32(st.Mode)&unix.S_IFMT != unix.S_IFSOCK:
		err = fmt.Errorf("%s in the agent's ready folder is not a socket (mode %o)", agentName, st.Mode)
	case st.Uid != f.agentUID:
		err = fmt.Errorf("the socket %s in the agent's ready folder belongs to uid %d, not the agent's %d", agentName, st.Uid, f.agentUID)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return nil, &fileError{code: codes.PermissionDenied, reason: ReasonNotAgentSocket, msg: "root helper: " + err.Error()}
	}
	err = unix.Renameat(dfd, tmp, dfd, name)
	// When name already is this socket (a repeated call), tmp and name are
	// two links to one file, and rename then does nothing and leaves tmp:
	// remove it. After a real rename tmp is gone and this does nothing.
	_ = unix.Unlinkat(dfd, tmp, 0)
	if err != nil {
		return nil, fmt.Errorf("root helper: ready socket %s: %w", name, err)
	}
	return &rootdpb.EnsureReadySocketResponse{Path: filepath.Join(f.dirs.Ready, id, name)}, nil
}

// removeContainerFiles removes everything the helper made for a container.
// Gone already counts as done.
func (f *files) removeContainerFiles(req *rootdpb.RemoveContainerFilesRequest) (*rootdpb.RemoveContainerFilesResponse, error) {
	id := req.GetContainerId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	for _, base := range []int{f.hosts, f.fifo, f.ready} {
		if err := removeFolder(base, id); err != nil {
			return nil, fmt.Errorf("root helper: remove %s's files: %w", id, err)
		}
	}
	return &rootdpb.RemoveContainerFilesResponse{}, nil
}

// ensureFolder makes sure <base>/<id> is a folder of root's that no one
// else can write, with mode mode (and group gid, when not -1), and opens
// it. Only root writes base, so a link or a file at that name was never
// this code's; it is refused, not followed. The mode is set through the
// opened folder, after the check, whatever this process's umask: the agent
// must reach a FIFO folder to open its FIFOs, and no one else a ready one.
func (f *files) ensureFolder(base int, id string, mode uint32, gid int) (int, error) {
	if err := unix.Mkdirat(base, id, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("root helper: folder %s: %w", id, err)
	}
	fd, err := unix.Openat(base, id, folderFlags, 0)
	if err != nil {
		return -1, fmt.Errorf("root helper: folder %s: %w", id, err)
	}
	// Checked before its mode is set: a folder someone else can write is
	// refused, never closed after the fact, as what it holds may be theirs.
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err == nil {
		err = rootpolicy.CheckFolder(id, uint32(st.Mode), st.Uid, f.owner, false)
	}
	if err == nil {
		err = setFolderMode(fd, mode, gid)
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("root helper: folder %s: %w", id, err)
	}
	return fd, nil
}

// setFolderMode gives the open folder fd mode, and group gid when gid is
// not -1, unless it has them already. It goes through fd, never a path: an
// O_PATH handle (Linux) cannot be chmodded, so it opens "." through it,
// which is the same folder.
func setFolderMode(fd int, mode uint32, gid int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if uint32(st.Mode)&0o7777 == mode && (gid < 0 || int(st.Gid) == gid) {
		return nil
	}
	dfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }()
	if gid >= 0 && int(st.Gid) != gid {
		// Before the chmod: a change of group can clear mode bits.
		if err := unix.Fchown(dfd, -1, gid); err != nil {
			return err
		}
	}
	return unix.Fchmod(dfd, mode)
}

// sweepTmpNames removes the temporary names tmpName gave the files names in
// the folder fd, which only a crash leaves behind. Errors are ignored: the
// caller treats this as best effort.
func sweepTmpNames(fd int, names ...string) {
	dfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	dir := os.NewFile(uintptr(dfd), ".")
	defer func() { _ = dir.Close() }()
	found, _ := dir.Readdirnames(-1)
	for _, n := range found {
		for _, name := range names {
			if isTmpName(n, name) {
				_ = unix.Unlinkat(dfd, n, 0)
			}
		}
	}
}

// writeFile makes sure name in dfd holds body, mode mode, root's. A file
// already right is left alone, so a repeated call changes nothing; else
// the new content goes to a temporary name and is renamed over name, which
// replaces whatever was there (a link included) and never writes through
// it.
func (f *files) writeFile(dfd int, name string, body []byte, mode uint32) error {
	if f.sameFile(dfd, name, body, mode) {
		return nil
	}
	tmp, err := tmpName(name)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("root helper: write %s: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), tmp)
	_, err = file.Write(body)
	if err == nil {
		err = file.Chmod(os.FileMode(mode))
	}
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("root helper: write %s: %w", name, err)
	}
	return nil
}

// sameFile reports whether name is already a plain file of root's (one
// link, mode mode) holding body.
func (f *files) sameFile(dfd int, name string, body []byte, mode uint32) bool {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		uint32(st.Mode)&0o7777 != mode || st.Uid != f.owner || st.Size != int64(len(body)) {
		return false
	}
	got := make([]byte, len(body))
	if _, err := io.ReadFull(file, got); err != nil || !bytes.Equal(got, body) {
		return false
	}
	// A file that grew since the stat is not body.
	var more [1]byte
	n, err := file.Read(more[:])
	return n == 0 && err == io.EOF
}

// removeFolder removes <base>/<id> and the files in it. Only root writes
// either, so it holds only what this code made; the names go one by one,
// none followed.
func removeFolder(base int, id string) error {
	fd, err := unix.Openat(base, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil
	case errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP):
		// Not a folder: the name alone goes.
		if err := unix.Unlinkat(base, id, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return nil
	case err != nil:
		return err
	}
	dir := os.NewFile(uintptr(fd), id)
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%s/%s: %w", id, name, err)
		}
	}
	if err := unix.Unlinkat(base, id, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

// openPath opens dir from / one name at a time, following no link, and
// checks nothing else: the agent's own folder, which it may change at
// will. What the helper takes from it is checked after the fact. It makes
// nothing: a folder root made there would be root's, on the agent's side.
func openPath(dir string) (int, error) {
	return walkFolder(dir, false, func(string, *unix.Stat_t, bool) error { return nil })
}

func checkID(id string) error {
	if err := rootpolicy.ValidateID(id); err != nil {
		return badRequest("%v", err)
	}
	return nil
}

// checkName allows a host or domain name: letters, digits, '-', '_' and
// '.', which covers every sandbox and slot ID. Nothing else reaches a
// file, a newline least of all.
func checkName(what, s string) (string, error) {
	if s == "" || len(s) > maxNameLen {
		return "", badRequest("%s %q: want 1 to %d characters", what, s, maxNameLen)
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", badRequest("%s %q: invalid character %q", what, s, r)
		}
	}
	return s, nil
}

// checkAddr allows an IP address without a zone, written as Go writes it.
func checkAddr(what, s string) (string, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", badRequest("%s %q is not an IP address", what, s)
	}
	return a.String(), nil
}

func renderHosts(entries []*rootdpb.HostEntry) ([]byte, error) {
	if len(entries) > maxHostEntries {
		return nil, badRequest("%d hosts entries; at most %d", len(entries), maxHostEntries)
	}
	var b strings.Builder
	for _, e := range entries {
		addr, err := checkAddr("hosts address", e.GetAddress())
		if err != nil {
			return nil, err
		}
		if n := len(e.GetNames()); n == 0 || n > maxNamesPerEntry {
			return nil, badRequest("hosts entry %s has %d names; want 1 to %d", addr, n, maxNamesPerEntry)
		}
		b.WriteString(addr)
		for _, n := range e.GetNames() {
			name, err := checkName("hosts name", n)
			if err != nil {
				return nil, err
			}
			b.WriteString(" " + name)
		}
		b.WriteString("\n")
	}
	return []byte(b.String()), nil
}

// renderResolvConf renders through internal/runtime/resolvconf, the same
// renderer the agent uses for a resolv.conf of its own.
//
// The resolver settings are the host's resolv.conf as the agent read it
// (resolvconf.Parse), which the driver copies as it finds it today: an odd
// word there is the host's, not a sign of drift or a broken agent, so it
// must not fail a create or raise a refusal. A value the helper cannot
// write safely is dropped, and what it keeps is written as the agent sent
// it, so the file is the driver's byte for byte. Safe is what cannot start
// a line of its own or become two words: a nameserver that parses as an
// address with no zone, and words with no space or control character.
func renderResolvConf(req *rootdpb.EnsureHostFilesRequest) []byte {
	c := resolvconf.Config{
		Nameservers: keepFirst(req.GetNameservers(), maxNameservers, isNameserver),
		Search:      keepFirst(req.GetSearch(), maxSearch, isResolverWord),
		Options:     keepFirst(req.GetDnsOptions(), maxOptions, isResolverWord),
	}
	return []byte(c.Render())
}

// keepFirst keeps the first max values ok accepts.
func keepFirst(in []string, max int, ok func(string) bool) []string {
	var out []string
	for _, s := range in {
		if len(out) == max {
			break
		}
		if ok(s) {
			out = append(out, s)
		}
	}
	return out
}

// isNameserver allows an IP address with no zone. netip's grammar for one
// has no space or control character, so the agent's own spelling of it
// ("2001:DB8::1") is safe to write as it is.
func isNameserver(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

// isResolverWord allows one word of a search or options line: 1 to
// maxResolverWord bytes, none of them a space or a control character, a
// newline least of all.
func isResolverWord(s string) bool {
	if s == "" || len(s) > maxResolverWord {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// renderEgressCA writes the node's egress CA as PEM, from a certificate
// that parses and is a CA. Nil when the request has none.
func renderEgressCA(der []byte) ([]byte, error) {
	if len(der) == 0 {
		return nil, nil
	}
	if len(der) > maxEgressCADER {
		return nil, badRequest("egress CA is %d bytes; at most %d", len(der), maxEgressCADER)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, badRequest("egress CA: %v", err)
	}
	if !cert.IsCA {
		return nil, badRequest("egress CA: the certificate is not a CA")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}
