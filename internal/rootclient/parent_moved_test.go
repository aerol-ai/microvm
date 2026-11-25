package rootclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// movedHook records what Config.OnCgroupParentMoved heard.
type movedHook struct {
	mu   sync.Mutex
	errs []error
}

func (h *movedHook) hear(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.errs = append(h.errs, err)
}

func (h *movedHook) heard() []error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]error(nil), h.errs...)
}

func parentClient(t *testing.T, sock, parent string, hook *movedHook) *Client {
	t.Helper()
	c := New(Config{Socket: sock, Timeout: 500 * time.Millisecond, AgentVersion: "agent-test", HelperUID: uint32(os.Getuid()),
		CgroupParent: parent, OnCgroupParentMoved: hook.hear})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestParentMovedAfterRestart ⭐: the runtime container starts again, and
// with it a helper whose sandboxes' cgroup parent is the new container's.
// The agent's containerd connection reconnects, shakes hands again first,
// and finds the parent moved: the dial fails as the helper being away
// does (ErrUnavailable, code Unavailable), so no container the agent sends
// reaches the gate to be refused; every typed call fails the same way, not
// tried again; and the agent hears it once, to start again.
func TestParentMovedAfterRestart(t *testing.T) {
	const before, after = "/kubepods/pod1/ctr-a/sandboxes", "/kubepods/pod1/ctr-b/sandboxes"
	sock := sockPath(t)
	first := realHelperWith(t, sock, func(c *rootd.Config) { c.Policy.CgroupParent = before }, nil)
	hook := &movedHook{}
	c := parentClient(t, sock, before, hook)
	ctr, err := cntr.New(c.Socket(), append(c.ContainerdOptions(), cntr.WithDefaultNamespace("aerolvm"))...)
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Close()
	if v, err := ctr.Version(ctxT(t)); err != nil || v.Version != "2.1.4" {
		t.Fatalf("containerd through the first helper = %v, %v", v, err)
	}
	if info, _ := c.Info(); info.CgroupParent != before {
		t.Fatalf("Info().CgroupParent = %q, want %q", info.CgroupParent, before)
	}

	// The runtime container started again: a new helper, a new parent.
	first.Shutdown(context.Background())
	realHelperWith(t, sock, func(c *rootd.Config) { c.Policy.CgroupParent = after }, nil)
	var pm *ParentMovedError
	eventually(t, func() error {
		_, err := ctr.Version(ctxT(t))
		if !errors.As(err, &pm) && !errors.Is(err, ErrUnavailable) {
			return errors.New("not refused yet")
		}
		if len(hook.heard()) == 0 {
			return errors.New("not heard yet")
		}
		return nil
	})
	if _, err := ctr.Version(ctxT(t)); !errors.Is(err, ErrUnavailable) || status.Code(err) != codes.Unavailable {
		t.Fatalf("containerd through a helper whose parent moved = %v, want ErrUnavailable with code Unavailable", err)
	}
	err = c.Ensure(ctxT(t))
	if !errors.As(err, &pm) || pm.Agent != before || pm.Helper != after || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Ensure = %v, want a ParentMovedError from %s to %s that matches ErrUnavailable", err, before, after)
	}
	start := time.Now()
	if _, err := c.EnsureHostFiles(ctxT(t), &rootdpb.EnsureHostFilesRequest{ContainerId: "sb-1"}); !errors.As(err, &pm) {
		t.Fatalf("a typed call = %v, want a ParentMovedError", err)
	}
	if d := time.Since(start); d > 300*time.Millisecond {
		t.Fatalf("a typed call took %v: a moved parent is not waited out", d)
	}
	time.Sleep(50 * time.Millisecond) // the hook runs in a goroutine of its own
	got := hook.heard()
	if len(got) != 1 || !errors.As(got[0], &pm) || pm.Helper != after {
		t.Fatalf("the agent heard %v, want the move once", got)
	}
}

// TestParentChecked: the handshake holds the helper's parent to the
// agent's, only when both say one.
func TestParentChecked(t *testing.T) {
	const mine = "/kubepods/pod1/ctr-a/sandboxes"
	for _, tc := range []struct {
		name   string
		agent  string
		helper *string
		moved  bool
	}{
		{"the same parent", mine, proto.String(mine), false},
		{"another parent", mine, proto.String("/kubepods/pod1/ctr-b/sandboxes"), true},
		{"containerd's own, on both sides", "/aerolvm", proto.String("/aerolvm"), false},
		{"a helper older than the field", mine, nil, false},
		{"an agent that checks none", "", proto.String("/elsewhere"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := sockPath(t)
			f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
			f.resp.CgroupParent = tc.helper
			serveFake(t, sock, f)
			hook := &movedHook{}
			c := parentClient(t, sock, tc.agent, hook)
			err := c.Ensure(ctxT(t))
			var pm *ParentMovedError
			if moved := errors.As(err, &pm); moved != tc.moved || (!tc.moved && err != nil) {
				t.Fatalf("Ensure = %v, want moved %v", err, tc.moved)
			}
			if tc.moved {
				// Not latched: each call asks again, and fails again.
				_ = c.Ensure(ctxT(t))
				if v, _ := f.counts(); v != 2 {
					t.Fatalf("%d handshakes after two Ensures, want 2", v)
				}
				eventually(t, func() error {
					if len(hook.heard()) != 1 {
						return errors.New("not heard once")
					}
					return nil
				})
				if pm.Error() == "" || !errors.Is(pm, ErrUnavailable) || errors.Is(pm, ErrUnsupported) {
					t.Fatalf("ParentMovedError %v", pm)
				}
			} else if len(hook.heard()) != 0 {
				t.Fatalf("heard %v", hook.heard())
			}
		})
	}
}

// TestContainerdRedialShakesHandsAgain: every containerd dial asks the
// helper again, the first one too, even when the client shook hands before
// it (a containerd client made after the helper changed). Calls on an open
// connection add none.
func TestContainerdRedialShakesHandsAgain(t *testing.T) {
	sock := sockPath(t)
	f := helperAt(rootdpb.APIVersion)
	serveFake(t, sock, f)
	c := newClient(t, sock)
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{2, 3, 4} {
		conn, err := c.DialContainerd(ctxT(t), "")
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if v, _ := f.counts(); v != want {
			t.Fatalf("dial %d: %d handshakes, want %d", i+1, v, want)
		}
	}
	// With no session, a recheck is a first handshake.
	_ = c.Close()
	c2 := newClient(t, sock)
	if err := c2.recheck(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if v, _ := f.counts(); v != 5 {
		t.Fatalf("%d handshakes, want 5", v)
	}
}

// TestParentMovedFirstContainerdClient: the client shook hands with the
// helper before it restarted, and a containerd client is made for the
// first time after (the event monitor's, or the driver's first use). Its
// first connection shakes hands first, finds the parent moved, and no
// containerd call reaches the new helper's gate.
func TestParentMovedFirstContainerdClient(t *testing.T) {
	const before, after = "/kubepods/pod1/ctr-a/sandboxes", "/kubepods/pod1/ctr-b/sandboxes"
	sock := sockPath(t)
	first := realHelperWith(t, sock, func(c *rootd.Config) { c.Policy.CgroupParent = before }, nil)
	hook := &movedHook{}
	c := parentClient(t, sock, before, hook)
	if err := c.Ensure(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	first.Shutdown(context.Background())
	var reached atomic.Int32
	realHelperWith(t, sock, func(c *rootd.Config) { c.Policy.CgroupParent = after }, func(o *rootd.Options) {
		o.Containerd = func(_ any, _ grpc.ServerStream) error {
			reached.Add(1)
			return status.Error(codes.PermissionDenied, "test gate: no call may reach it")
		}
	})
	ctr, err := cntr.New(c.Socket(), append(c.ContainerdOptions(), cntr.WithDefaultNamespace("aerolvm"))...)
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Close()
	var pm *ParentMovedError
	eventually(t, func() error {
		if _, err := ctr.Version(ctxT(t)); !errors.Is(err, ErrUnavailable) {
			return fmt.Errorf("containerd Version = %v, want ErrUnavailable", err)
		}
		if err := c.Ensure(ctxT(t)); !errors.As(err, &pm) {
			return fmt.Errorf("Ensure = %v, want a ParentMovedError", err)
		}
		return nil
	})
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d containerd calls reached the new helper's gate", n)
	}
	if got := hook.heard(); len(got) != 1 {
		t.Fatalf("the agent heard %v, want the move once", got)
	}
}
