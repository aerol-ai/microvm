package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// C4: a DNS name with a fixed port stays a name; everything else resolves
// as before, so an install that advertises an IP is unchanged.
func TestRaftAdvertiseAddr(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    string
		isName  bool
		wantErr string
	}{
		{in: "10.0.0.5:7000", want: "10.0.0.5:7000"},
		{in: "[::1]:7000", want: "[::1]:7000"},
		{in: "127.0.0.1:0", want: "127.0.0.1:0"},
		{in: "aerolvm-server-0.aerolvm-server.aerolvm.svc:7000", want: "aerolvm-server-0.aerolvm-server.aerolvm.svc:7000", isName: true},
		{in: "localhost:7000", want: "localhost:7000", isName: true},
		{in: "server-0.svc:0", wantErr: "a DNS name needs a fixed port"},
		{in: "invalid-addr:port:bad", wantErr: "address"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := raftAdvertiseAddr(tc.in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.String() != tc.want {
				t.Fatalf("= %v %v, want %s", got, err, tc.want)
			}
			if _, isName := got.(nameAddr); isName != tc.isName {
				t.Fatalf("kept as a name = %v, want %v", isName, tc.isName)
			}
			if _, isTCP := got.(*net.TCPAddr); isTCP == tc.isName {
				t.Fatalf("resolved to %T", got)
			}
		})
	}
	if (nameAddr("x:1")).Network() != "tcp" {
		t.Fatal("a name is not a tcp address")
	}
}

// raftNodeNamed starts a Raft node bound on loopback and advertised as
// localhost:<port>, a name, as a Kubernetes server pod would be.
func raftNodeNamed(t *testing.T, id string, bootstrap, withTLS bool) (*raftNode, string) {
	t.Helper()
	port := reserveTestPort(t, false)
	name := fmt.Sprintf("localhost:%d", port)
	cfg := raftSetupConfig{
		NodeID:           id,
		DataDir:          t.TempDir(),
		BindAddr:         fmt.Sprintf("127.0.0.1:%d", port),
		AdvertiseAddr:    name,
		BootstrapCluster: bootstrap,
	}
	if withTLS {
		ct, err := loadClusterTLS(writeTestClusterTLSDir(t, id))
		if err != nil {
			t.Fatal(err)
		}
		cfg.TLS = ct
	}
	rn, err := setupRaft(cfg, newPlacementFSM(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("setupRaft(%s): %v", name, err)
	}
	t.Cleanup(func() { _ = rn.Close() })
	return rn, name
}

// Two servers that know each other only by name: the configuration records
// the names, the follower hears from the leader (so the leader dialed the
// follower's name), and the follower names the leader by its name.
func TestRaftOverDNSNames(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft sockets")
	}
	for _, withTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", withTLS), func(t *testing.T) {
			a, aName := raftNodeNamed(t, "srv-a", true, withTLS)
			waitFor(t, 15*time.Second, "a leader", func() bool { return a.raft.State() == raft.Leader })
			if got := a.transport.LocalAddr(); string(got) != aName {
				t.Fatalf("transport advertises %q, want the name %q", got, aName)
			}
			b, bName := raftNodeNamed(t, "srv-b", false, withTLS)
			if err := a.raft.AddVoter("srv-b", raft.ServerAddress(bName), 0, 10*time.Second).Error(); err != nil {
				t.Fatalf("AddVoter by name: %v", err)
			}
			waitFor(t, 15*time.Second, "b to follow a by name", func() bool {
				addr, id := b.raft.LeaderWithID()
				return string(addr) == aName && id == "srv-a"
			})
			f := b.raft.GetConfiguration()
			if err := f.Error(); err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, s := range f.Configuration().Servers {
				got[string(s.ID)] = string(s.Address)
			}
			if got["srv-a"] != aName || got["srv-b"] != bName {
				t.Fatalf("configuration %v, want the names %s and %s", got, aName, bName)
			}
			// An entry the leader commits reaches the follower over the name.
			if err := a.raft.Barrier(5 * time.Second).Error(); err != nil {
				t.Fatal(err)
			}
			last := a.raft.LastIndex()
			waitFor(t, 15*time.Second, "b to apply a's log", func() bool { return b.raft.AppliedIndex() >= last })
		})
	}
}

// A name with no fixed port, and a bind that fails, are refused.
func TestSetupRaftNamedAdvertiseErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := setupRaft(raftSetupConfig{NodeID: "n", DataDir: t.TempDir(), BindAddr: "127.0.0.1:0", AdvertiseAddr: "server-0.svc:0"}, newPlacementFSM(), logger); err == nil || !strings.Contains(err.Error(), "fixed port") {
		t.Fatalf("err = %v, want the fixed-port refusal", err)
	}
	if _, err := setupRaft(raftSetupConfig{NodeID: "n", DataDir: t.TempDir(), BindAddr: "invalid-bind:xyz", AdvertiseAddr: "server-0.svc:7000"}, newPlacementFSM(), logger); err == nil || !strings.Contains(err.Error(), "tcp transport") {
		t.Fatalf("err = %v, want the bind failure", err)
	}
}
