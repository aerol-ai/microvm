package rootd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
)

const testCID = "sb-1"

// localhostEntries are the hosts lines the containerd driver writes today.
func localhostEntries() []*rootdpb.HostEntry {
	return []*rootdpb.HostEntry{
		{Address: "127.0.0.1", Names: []string{"localhost"}},
		{Address: "::1", Names: []string{"localhost", "ip6-localhost", "ip6-loopback"}},
	}
}

// testCert makes a self-signed certificate, a CA or not.
func testCert(t *testing.T, ca bool) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aerolvm egress test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: ca,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func helperClient(r *rig) rootdpb.RootHelperClient { return rootdpb.NewRootHelperClient(r.conn) }

// statOf is a path's own stat, a link's included.
func statOf(t *testing.T, p string) *syscall.Stat_t {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t)
}

// wantFile checks a file the helper made: a plain file of this process's
// user (root's, in production), one link, the mode and content given.
func wantFile(t *testing.T, p string, mode fs.FileMode, body string) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != mode || st.Nlink != 1 || int(st.Uid) != os.Geteuid() {
		t.Fatalf("%s: mode %v, links %d, uid %d; want a plain %v file of uid %d", p, fi.Mode(), st.Nlink, st.Uid, mode, os.Geteuid())
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != body {
		t.Fatalf("%s holds %q (%v), want %q", p, got, err, body)
	}
}

// helperTree lists every name in the helper's folders, for a test to see
// that a refused call left nothing behind.
func helperTree(t *testing.T, cfg Config) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{cfg.Files.Hosts, cfg.Files.Ready, cfg.Files.Runsc, cfg.Policy.FIFODir} {
		err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			out = append(out, p)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestEnsureHostFiles(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	ca := testCert(t, true)
	req := &rootdpb.EnsureHostFilesRequest{
		ContainerId: testCID, Hostname: testCID, Hosts: localhostEntries(),
		Nameservers: []string{"10.0.0.2", "fd00::53"}, Search: []string{"svc.cluster.local", "ec2.internal"},
		DnsOptions: []string{"ndots:5", "edns0"}, EgressCaDer: ca.Raw,
	}
	resp, err := c.EnsureHostFiles(callCtx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.cfg.Files.Hosts, testCID)
	want := &rootdpb.EnsureHostFilesResponse{
		HostnamePath: filepath.Join(dir, "hostname"), HostsPath: filepath.Join(dir, "hosts"),
		ResolvConfPath: filepath.Join(dir, "resolv.conf"), EgressCaPath: filepath.Join(dir, "egress-ca.pem"),
	}
	if !proto.Equal(resp, want) {
		t.Fatalf("paths %v, want %v", resp, want)
	}
	wantFile(t, resp.GetHostnamePath(), 0o644, "sb-1\n")
	// The driver's own hosts file, byte for byte (hosts.go).
	wantFile(t, resp.GetHostsPath(), 0o644, "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n")
	wantFile(t, resp.GetResolvConfPath(), 0o644, "search svc.cluster.local ec2.internal\noptions ndots:5 edns0\nnameserver 10.0.0.2\nnameserver fd00::53\n")
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	wantFile(t, resp.GetEgressCaPath(), 0o644, caPEM)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("folder %s: %v %v", dir, fi.Mode(), err)
	}

	// The same request again changes nothing: the files keep their inodes,
	// so a running container's binds still see them.
	before := statOf(t, resp.GetResolvConfPath()).Ino
	if _, err := c.EnsureHostFiles(callCtx(t), req); err != nil {
		t.Fatal(err)
	}
	if statOf(t, resp.GetResolvConfPath()).Ino != before {
		t.Fatal("a repeated call rewrote an unchanged file")
	}

	// New values are written; a CA the request no longer has goes.
	req2 := proto.Clone(req).(*rootdpb.EnsureHostFilesRequest)
	req2.Nameservers, req2.EgressCaDer = []string{"10.9.9.9"}, nil
	resp2, err := c.EnsureHostFiles(callCtx(t), req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.GetEgressCaPath() != "" {
		t.Fatalf("egress CA path %q for a request without one", resp2.GetEgressCaPath())
	}
	wantFile(t, resp2.GetResolvConfPath(), 0o644, "search svc.cluster.local ec2.internal\noptions ndots:5 edns0\nnameserver 10.9.9.9\n")
	if _, err := os.Lstat(filepath.Join(dir, "egress-ca.pem")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the old egress CA is still there: %v", err)
	}
	// Without a CA again: nothing to drop, no error.
	if _, err := c.EnsureHostFiles(callCtx(t), req2); err != nil {
		t.Fatal(err)
	}
	if len(r.refused()) != 0 {
		t.Fatalf("refusals %v", r.refused())
	}
}

// TestHostFilesMatchResolvconf: what the agent reads from the host's
// resolv.conf (resolvconf.Parse), sent as typed values, comes back from
// the helper as the very file the driver writes today (Generate).
func TestHostFilesMatchResolvconf(t *testing.T) {
	r := newRig(t, nil)
	host := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(host, []byte("# host\nnameserver 127.0.0.53\nnameserver 10.0.0.2\nsearch a.example b.example\noptions ndots:2 timeout:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	parsed, err := resolvconf.Parse(host)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := helperClient(r).EnsureHostFiles(callCtx(t), &rootdpb.EnsureHostFilesRequest{
		ContainerId: testCID, Hostname: testCID, Hosts: localhostEntries(),
		Nameservers: parsed.Nameservers, Search: parsed.Search, DnsOptions: parsed.Options,
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := resolvconf.Generate(host)
	if err != nil {
		t.Fatal(err)
	}
	wantFile(t, resp.GetResolvConfPath(), 0o644, want)
}

// TestFileCallsRefuse: every value the helper checks, failing its check.
// Each is refused before anything is written, as a refusal the helper
// reports, and an ID shaped like a path never reaches one: the helper
// builds every path itself.
func TestFileCallsRefuse(t *testing.T) {
	notCA := testCert(t, false)
	good := func() *rootdpb.EnsureHostFilesRequest {
		return &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID, Hosts: localhostEntries(), Nameservers: []string{"10.0.0.2"}}
	}
	host := func(mut func(*rootdpb.EnsureHostFilesRequest)) func(rootdpb.RootHelperClient) error {
		return func(c rootdpb.RootHelperClient) error {
			req := good()
			mut(req)
			_, err := c.EnsureHostFiles(callCtx(t), req)
			return err
		}
	}
	many := func(n int, s string) []string { return slices.Repeat([]string{s}, n) }
	for _, tc := range []struct {
		name string
		call func(rootdpb.RootHelperClient) error
	}{
		{"no ID", host(func(r *rootdpb.EnsureHostFilesRequest) { r.ContainerId = "" })},
		{"an ID that climbs out", host(func(r *rootdpb.EnsureHostFilesRequest) { r.ContainerId = "../../etc" })},
		{"an ID that is a path", host(func(r *rootdpb.EnsureHostFilesRequest) { r.ContainerId = "/etc/cron.d" })},
		{"an ID with a slash", host(func(r *rootdpb.EnsureHostFilesRequest) { r.ContainerId = "a/b" })},
		{"an ID of dots", host(func(r *rootdpb.EnsureHostFilesRequest) { r.ContainerId = ".." })},
		{"no hostname", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hostname = "" })},
		{"a hostname with a newline", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hostname = "a\nnameserver 6.6.6.6" })},
		{"a hostname too long", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hostname = strings.Repeat("a", 254) })},
		{"a hosts address that is not one", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hosts[0].Address = "localhost" })},
		{"a hosts address with a zone", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hosts[1].Address = "fe80::1%eth0" })},
		{"a hosts entry with no name", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hosts[0].Names = nil })},
		{"a hosts name with a space", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hosts[0].Names = []string{"a b"} })},
		{"too many names on a line", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Hosts[0].Names = many(17, "x") })},
		{"too many hosts lines", host(func(r *rootdpb.EnsureHostFilesRequest) {
			r.Hosts = slices.Repeat([]*rootdpb.HostEntry{{Address: "10.0.0.1", Names: []string{"x"}}}, 65)
		})},
		{"a nameserver that is not an address", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Nameservers = []string{"10.0.0.2\noptions x"} })},
		{"too many nameservers", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Nameservers = many(17, "10.0.0.2") })},
		{"a search domain with a space", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Search = []string{"a b"} })},
		{"too many search domains", host(func(r *rootdpb.EnsureHostFilesRequest) { r.Search = many(33, "x") })},
		{"an empty option", host(func(r *rootdpb.EnsureHostFilesRequest) { r.DnsOptions = []string{""} })},
		{"an option with a newline", host(func(r *rootdpb.EnsureHostFilesRequest) { r.DnsOptions = []string{"ndots:1\nnameserver"} })},
		{"too many options", host(func(r *rootdpb.EnsureHostFilesRequest) { r.DnsOptions = many(33, "edns0") })},
		{"an egress CA that does not parse", host(func(r *rootdpb.EnsureHostFilesRequest) { r.EgressCaDer = []byte("-----BEGIN") })},
		{"an egress CA that is no CA", host(func(r *rootdpb.EnsureHostFilesRequest) { r.EgressCaDer = notCA.Raw })},
		{"an egress CA too big", host(func(r *rootdpb.EnsureHostFilesRequest) { r.EgressCaDer = make([]byte, 64<<10+1) })},
		{"FIFOs for a path", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureTaskFIFOs(callCtx(t), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: "../hosts/sb-1"})
			return err
		}},
		{"a runsc config the helper does not write", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureRunscConfig(callCtx(t), &rootdpb.EnsureRunscConfigRequest{})
			return err
		}},
		{"a runsc config from a newer agent", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureRunscConfig(callCtx(t), &rootdpb.EnsureRunscConfigRequest{Config: 99})
			return err
		}},
		{"a ready socket for a path", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: "../../run"})
			return err
		}},
		{"a ready nonce that climbs out", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "../x"})
			return err
		}},
		{"a ready nonce in capitals", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "AB12"})
			return err
		}},
		{"a ready nonce too long", func(c rootdpb.RootHelperClient) error {
			_, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: strings.Repeat("ab", 33)})
			return err
		}},
		{"a remove of a path", func(c rootdpb.RootHelperClient) error {
			_, err := c.RemoveContainerFiles(callCtx(t), &rootdpb.RemoveContainerFilesRequest{ContainerId: "../ready"})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			before := helperTree(t, r.cfg)
			err := tc.call(helperClient(r))
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err %v, want InvalidArgument", err)
			}
			if ref := r.refused(); len(ref) != 1 || ref[0].Reason != ReasonBadRequest || !strings.HasPrefix(ref[0].Method, rootdpb.ServicePrefix) {
				t.Fatalf("refusals %v, want one %s", ref, ReasonBadRequest)
			}
			if after := helperTree(t, r.cfg); !slices.Equal(before, after) {
				t.Fatalf("a refused call changed the helper's folders: %v -> %v", before, after)
			}
			// Nothing beside the helper's folders either.
			for _, p := range []string{filepath.Join(r.cfg.Files.Hosts, "..", "..", "etc"), filepath.Dir(r.cfg.Files.Hosts) + "/etc"} {
				if _, err := os.Lstat(p); err == nil {
					t.Fatalf("%s was made", p)
				}
			}
		})
	}
}

func TestEnsureTaskFIFOs(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	resp, err := c.EnsureTaskFIFOs(callCtx(t), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: testCID})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.cfg.Policy.FIFODir, testCID)
	if resp.GetStdoutPath() != filepath.Join(dir, "stdout") || resp.GetStderrPath() != filepath.Join(dir, "stderr") {
		t.Fatalf("paths %v", resp)
	}
	for _, p := range []string{resp.GetStdoutPath(), resp.GetStderrPath()} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if fi.Mode().Type() != fs.ModeNamedPipe || fi.Mode().Perm() != 0o640 || int(st.Uid) != os.Geteuid() || int(st.Gid) != r.cfg.SocketGID {
			t.Fatalf("%s: mode %v owner %d:%d; want a 0640 FIFO of %d:%d", p, fi.Mode(), st.Uid, st.Gid, os.Geteuid(), r.cfg.SocketGID)
		}
	}

	// The last task's reader keeps the last task's FIFO: the next task's
	// is a new one, which nothing reads yet.
	old, err := os.OpenFile(resp.GetStdoutPath(), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	oldIno := statOf(t, resp.GetStdoutPath()).Ino
	if _, err := c.EnsureTaskFIFOs(callCtx(t), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: testCID}); err != nil {
		t.Fatal(err)
	}
	if statOf(t, resp.GetStdoutPath()).Ino == oldIno {
		t.Fatal("the FIFO was kept, not made fresh")
	}
	if w, err := os.OpenFile(resp.GetStdoutPath(), os.O_WRONLY|syscall.O_NONBLOCK, 0); !errors.Is(err, syscall.ENXIO) {
		if w != nil {
			_ = w.Close()
		}
		t.Fatalf("the new FIFO has a reader (%v): the old one was reused", err)
	}
}

func TestEnsureRunscConfig(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	for _, tc := range []struct {
		config rootdpb.RunscConfig
		file   string
		body   string
	}{
		{rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT, "config.toml", runscHeader + "[runsc_config]\n  host-uds = \"open\"\n"},
		{rootdpb.RunscConfig_RUNSC_CONFIG_RESTORE, "restore.toml", runscHeader + "binary_name = \"/usr/local/bin/aerolvm-runsc\"\n[runsc_config]\n  host-uds = \"open\"\n"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			resp, err := c.EnsureRunscConfig(callCtx(t), &rootdpb.EnsureRunscConfigRequest{Config: tc.config})
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(r.cfg.Files.Runsc, tc.file)
			if resp.GetPath() != want || !slices.Contains(r.cfg.Policy.RunscConfigPaths, want) {
				t.Fatalf("path %q, want %q, one of the policy's %v", resp.GetPath(), want, r.cfg.Policy.RunscConfigPaths)
			}
			wantFile(t, want, 0o644, tc.body)
			ino := statOf(t, want).Ino
			if _, err := c.EnsureRunscConfig(callCtx(t), &rootdpb.EnsureRunscConfigRequest{Config: tc.config}); err != nil || statOf(t, want).Ino != ino {
				t.Fatalf("a repeated call rewrote the config (%v)", err)
			}
			// Anything else there is put right.
			if err := os.WriteFile(want, []byte("binary_name = \"/bin/sh\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := c.EnsureRunscConfig(callCtx(t), &rootdpb.EnsureRunscConfigRequest{Config: tc.config}); err != nil {
				t.Fatal(err)
			}
			wantFile(t, want, 0o644, tc.body)
		})
	}
}

// agentSocket binds a ready socket the way the agent does (pkg/docker),
// in the agent's ready folder.
func agentSocket(t testing.TB, cfg Config, id, nonce string) string {
	t.Helper()
	var path string
	var closer func() error
	if nonce == "" {
		pl, err := dockerpkg.NewParkedListener(cfg.Files.AgentReady, id, "token", "parknonce")
		if err != nil {
			t.Fatal(err)
		}
		path, closer = pl.HostSocketPath(), pl.Close
	} else {
		rl, err := dockerpkg.NewReadyListener(cfg.Files.AgentReady, id, "token", nonce)
		if err != nil {
			t.Fatal(err)
		}
		path, closer = rl.HostSocketPath(), rl.Close
	}
	t.Cleanup(func() { _ = closer() })
	return path
}

func TestEnsureReadySocket(t *testing.T) {
	for _, tc := range []struct {
		name, nonce, file string
	}{
		{"a create's socket", "0a1b", "0a1b.sock"},
		{"a warm-pool slot's park socket", "", "ready.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			c := helperClient(r)
			agentPath := agentSocket(t, r.cfg, testCID, tc.nonce)
			resp, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: tc.nonce})
			if err != nil {
				t.Fatal(err)
			}
			if want := filepath.Join(r.cfg.Files.Ready, testCID, tc.file); resp.GetPath() != want {
				t.Fatalf("path %q, want %q", resp.GetPath(), want)
			}
			// The helper's name is the agent's socket itself: a sandbox that
			// binds it reaches the listener the agent holds.
			if statOf(t, resp.GetPath()).Ino != statOf(t, agentPath).Ino {
				t.Fatal("the helper's name is not the agent's socket")
			}
			conn, err := net.Dial("unix", resp.GetPath())
			if err != nil {
				t.Fatalf("dial through the helper's name: %v", err)
			}
			_ = conn.Close()

			// Asked again for the same socket: the name stays, and nothing
			// else is left beside it (rename between two links to one
			// file does nothing, so the helper removes its temporary name).
			if _, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: tc.nonce}); err != nil {
				t.Fatal(err)
			}
			if names, _ := os.ReadDir(filepath.Dir(resp.GetPath())); len(names) != 1 || statOf(t, resp.GetPath()).Ino != statOf(t, agentPath).Ino {
				t.Fatalf("after a repeated call the ready folder holds %v", names)
			}

			// The agent binds its socket again (a restart): asking again
			// names the new one.
			if err := os.Remove(agentPath); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", agentPath)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			if _, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: tc.nonce}); err != nil {
				t.Fatal(err)
			}
			if statOf(t, resp.GetPath()).Ino != statOf(t, agentPath).Ino {
				t.Fatal("the helper still names the old socket")
			}
			if names, _ := os.ReadDir(filepath.Dir(resp.GetPath())); len(names) != 1 {
				t.Fatalf("the ready folder holds %v, want the one name", names)
			}
		})
	}
}

// TestReadySocketPlantsRefused: whatever the agent's folder holds under a
// container's name, the helper names only a socket the agent owns. A link
// (to a root file, a folder, anything) or a plain file is refused and
// leaves nothing in the helper's folder.
func TestReadySocketPlantsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, agentPath, target string)
	}{
		{"a link to a file", func(t *testing.T, agentPath, target string) {
			if err := os.Symlink(target, agentPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"a link to /", func(t *testing.T, agentPath, _ string) {
			if err := os.Symlink("/", agentPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"a plain file", func(t *testing.T, agentPath, _ string) {
			if err := os.WriteFile(agentPath, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"a folder", func(t *testing.T, agentPath, _ string) {
			if err := os.Mkdir(agentPath, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			if err := os.MkdirAll(r.cfg.Files.AgentReady, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(target, []byte("root's"), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.plant(t, filepath.Join(r.cfg.Files.AgentReady, testCID+".0a1b.sock"), target)
			_, err := helperClient(r).EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "0a1b"})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("err %v, want PermissionDenied", err)
			}
			if ref := r.refused(); len(ref) != 1 || ref[0].Reason != ReasonNotAgentSocket {
				t.Fatalf("refusals %v", ref)
			}
			names, _ := os.ReadDir(filepath.Join(r.cfg.Files.Ready, testCID))
			if len(names) != 0 {
				t.Fatalf("the helper's ready folder holds %v after a refusal", names)
			}
		})
	}
}

func TestEnsureReadySocketFails(t *testing.T) {
	t.Run("no socket yet", func(t *testing.T) {
		r := newRig(t, nil)
		if err := os.MkdirAll(r.cfg.Files.AgentReady, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := helperClient(r).EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID})
		if status.Code(err) != codes.NotFound || len(r.refused()) != 0 {
			t.Fatalf("err %v, refusals %v; want NotFound, no refusal (a bug, not an attack)", err, r.refused())
		}
	})
	t.Run("no agent ready folder", func(t *testing.T) {
		r := newRig(t, nil)
		_, err := helperClient(r).EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("err %v, want FailedPrecondition", err)
		}
		// Root makes nothing on the agent's side: a folder it made there
		// would be root's, and the agent could not bind its sockets in it.
		if _, err := os.Lstat(filepath.Dir(r.cfg.Files.AgentReady)); !os.IsNotExist(err) {
			t.Fatalf("the helper made the agent's folder: %v", err)
		}
	})
	t.Run("an agent ready folder through a link", func(t *testing.T) {
		r := newRig(t, nil)
		real := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.MkdirAll(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(r.cfg.Files.AgentReady), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, r.cfg.Files.AgentReady); err != nil {
			t.Fatal(err)
		}
		_, err := helperClient(r).EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("err %v, want FailedPrecondition", err)
		}
	})
}

func TestRemoveContainerFiles(t *testing.T) {
	r := newRig(t, nil)
	c := helperClient(r)
	agentSocket(t, r.cfg, testCID, "0a1b")
	if _, err := c.EnsureHostFiles(callCtx(t), &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID, EgressCaDer: testCert(t, true).Raw}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnsureTaskFIFOs(callCtx(t), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: testCID}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnsureReadySocket(callCtx(t), &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "0a1b"}); err != nil {
		t.Fatal(err)
	}
	// Another container's files stay.
	if _, err := c.EnsureTaskFIFOs(callCtx(t), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: "sb-2"}); err != nil {
		t.Fatal(err)
	}
	// A temporary name a crashed call left behind goes too.
	if err := os.WriteFile(filepath.Join(r.cfg.Files.Hosts, testCID, ".hosts.0011"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 { // the second time there is nothing left to remove
		if _, err := c.RemoveContainerFiles(callCtx(t), &rootdpb.RemoveContainerFilesRequest{ContainerId: testCID}); err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{r.cfg.Files.Hosts, r.cfg.Files.Ready, r.cfg.Policy.FIFODir} {
			if _, err := os.Lstat(filepath.Join(dir, testCID)); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("%s/%s is still there: %v", dir, testCID, err)
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(r.cfg.Policy.FIFODir, "sb-2", "stdout")); err != nil {
		t.Fatalf("another container's FIFO went: %v", err)
	}
	// A name that is not a folder (only root could have put it there)
	// goes as a name; a link is never followed.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(r.cfg.Files.Hosts, testCID)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.Files.Ready, testCID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RemoveContainerFiles(callCtx(t), &rootdpb.RemoveContainerFilesRequest{ContainerId: testCID}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "keep")); err != nil {
		t.Fatalf("the remove followed a link: %v", err)
	}
	for _, dir := range []string{r.cfg.Files.Hosts, r.cfg.Files.Ready} {
		if _, err := os.Lstat(filepath.Join(dir, testCID)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s/%s is still there: %v", dir, testCID, err)
		}
	}
}

// TestWritesNeverFollowALink: a link in a container's folder (only root
// could have left one) is replaced by the helper's file, never written
// through: the file it named is untouched.
func TestWritesNeverFollowALink(t *testing.T) {
	r := newRig(t, nil)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.cfg.Files.Hosts, testCID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "resolv.conf")); err != nil {
		t.Fatal(err)
	}
	resp, err := helperClient(r).EnsureHostFiles(callCtx(t), &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID, Nameservers: []string{"10.0.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	wantFile(t, resp.GetResolvConfPath(), 0o644, "nameserver 10.0.0.2\n")
	if got, _ := os.ReadFile(target); string(got) != "keep me" {
		t.Fatalf("the link's target was written: %q", got)
	}
}

// TestContainerFolderLinkRefused: a link where a container's folder goes
// is refused, not followed, so nothing lands where it points.
func TestContainerFolderLinkRefused(t *testing.T) {
	r := newRig(t, nil)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(r.cfg.Files.Hosts, testCID)); err != nil {
		t.Fatal(err)
	}
	_, err := helperClient(r).EnsureHostFiles(callCtx(t), &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err %v, want the helper's own failure", err)
	}
	if names, _ := os.ReadDir(outside); len(names) != 0 {
		t.Fatalf("files landed through the link: %v", names)
	}
}

// TestPinnedFoldersIgnoreSwaps: the helper's folders are opened once, at
// start, and every write goes through that open folder. A folder swapped
// for a link afterwards (on a host, only root could) does not move where
// root writes.
func TestPinnedFoldersIgnoreSwaps(t *testing.T) {
	r := newRig(t, nil)
	outside := t.TempDir()
	if err := os.Rename(r.cfg.Files.Hosts, r.cfg.Files.Hosts+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, r.cfg.Files.Hosts); err != nil {
		t.Fatal(err)
	}
	if _, err := helperClient(r).EnsureHostFiles(callCtx(t), &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID}); err != nil {
		t.Fatal(err)
	}
	if names, _ := os.ReadDir(outside); len(names) != 0 {
		t.Fatalf("root wrote through the swapped-in link: %v", names)
	}
	wantFile(t, filepath.Join(r.cfg.Files.Hosts+".old", testCID, "hostname"), 0o644, testCID+"\n")
}

// TestFileCallFailures: a failure that is the helper's own (here, its
// folders closed under it) is Internal, logged, and no refusal.
func TestFileCallFailures(t *testing.T) {
	var logs strings.Builder
	f := &files{hosts: -1, ready: -1, fifo: -1, runsc: -1, dirs: FileDirs{AgentReady: "/"}}
	h := helper{log: slog.New(slog.NewTextHandler(&logs, nil)), files: f,
		onRefusal: func(context.Context, Refusal) { t.Fatal("a failure of the helper's own is no refusal") }}
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"host files": func() error {
			_, err := h.EnsureHostFiles(ctx, &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: "x"})
			return err
		},
		"FIFOs": func() error {
			_, err := h.EnsureTaskFIFOs(ctx, &rootdpb.EnsureTaskFIFOsRequest{ContainerId: testCID})
			return err
		},
		"runsc": func() error {
			_, err := h.EnsureRunscConfig(ctx, &rootdpb.EnsureRunscConfigRequest{Config: rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT})
			return err
		},
		"ready socket": func() error {
			_, err := h.EnsureReadySocket(ctx, &rootdpb.EnsureReadySocketRequest{ContainerId: testCID})
			return err
		},
		"remove": func() error {
			_, err := h.RemoveContainerFiles(ctx, &rootdpb.RemoveContainerFilesRequest{ContainerId: testCID})
			return err
		},
	} {
		if err := call(); status.Code(err) != codes.Internal {
			t.Errorf("%s: %v, want Internal", name, err)
		}
	}
	if !strings.Contains(logs.String(), "call failed") {
		t.Fatalf("not logged: %s", logs.String())
	}
	// FIFOs in a folder that cannot take them: the half-made one goes.
	dir := shortDir(t)
	fd, err := openFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	f2 := &files{gid: -2}
	if err := f2.makeFIFO(fd, dir, "stdout"); err == nil && os.Geteuid() != 0 {
		t.Fatal("a FIFO for a group this user is not in was made")
	}
	if names, _ := os.ReadDir(dir); len(names) > 1 {
		t.Fatalf("leftovers %v", names)
	}
}

// The calls' cost on a create (CLAUDE.md, boot-path latency): each is one
// unary call over the helper's socket, against Version, the bare round
// trip. Run with -bench 'Version|Ensure' ./internal/rootd/.
func BenchmarkVersion(b *testing.B) {
	c := helperClient(newRig(b, nil))
	for b.Loop() {
		if _, err := c.Version(context.Background(), &rootdpb.VersionRequest{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnsureReadySocket(b *testing.B) {
	r := newRig(b, nil)
	agentSocket(b, r.cfg, testCID, "0a1b")
	c := helperClient(r)
	req := &rootdpb.EnsureReadySocketRequest{ContainerId: testCID, Nonce: "0a1b"}
	for b.Loop() {
		if _, err := c.EnsureReadySocket(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnsureHostFiles(b *testing.B) {
	c := helperClient(newRig(b, nil))
	req := &rootdpb.EnsureHostFilesRequest{ContainerId: testCID, Hostname: testCID, Hosts: localhostEntries(), Nameservers: []string{"10.0.0.2"}}
	for i := 0; b.Loop(); i++ {
		req.ContainerId = "sb-" + strconv.Itoa(i) // a new container each time, as on creates
		if _, err := c.EnsureHostFiles(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEnsureTaskFIFOs(b *testing.B) {
	c := helperClient(newRig(b, nil))
	for b.Loop() {
		if _, err := c.EnsureTaskFIFOs(context.Background(), &rootdpb.EnsureTaskFIFOsRequest{ContainerId: testCID}); err != nil {
			b.Fatal(err)
		}
	}
}
