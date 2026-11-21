package nsbuild

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/cni"
)

// recorder stands in for the namespace steps and records each one, so a
// test can check the order a build and a teardown run them in, and what a
// failure undoes.
type recorder struct {
	calls []string
	fail  map[string]error
	// ipv6 counts DisableIPv6 calls; failIPv6At fails that one (1-based).
	ipv6, failIPv6At int
}

func (r *recorder) step(name string) func(context.Context, string) error {
	return func(_ context.Context, ns string) error {
		r.calls = append(r.calls, name+" "+ns)
		return r.fail[name]
	}
}

func (r *recorder) steps(runner cni.Runner) Steps {
	return Steps{
		Runner: runner, Root: "/run/netns",
		Create: r.step("create"), LoopbackUp: r.step("lo"), Delete: r.step("delete"),
		DisableIPv6: func(path string) error {
			r.ipv6++
			r.calls = append(r.calls, "ipv6 "+path)
			if r.ipv6 == r.failIPv6At {
				return errors.New("sysctl refused")
			}
			return nil
		},
	}
}

func TestRealize(t *testing.T) {
	ctx := context.Background()
	t.Run("a build", func(t *testing.T) {
		r, runner := &recorder{}, cni.NewFakeRunner()
		path, ip, err := r.steps(runner).Realize(ctx, "sb-1")
		if err != nil || path != "/run/netns/sb-1" || ip == "" {
			t.Fatalf("Realize = %q %q %v", path, ip, err)
		}
		want := []string{"create sb-1", "lo sb-1", "ipv6 /run/netns/sb-1", "ipv6 /run/netns/sb-1"}
		if !slices.Equal(r.calls, want) {
			t.Fatalf("steps %v, want %v", r.calls, want)
		}
		if got, ok := runner.IPOf("sb-1"); !ok || got != ip {
			t.Fatalf("CNI gave %q (%v), Realize answered %q", got, ok, ip)
		}
	})
	for _, tc := range []struct {
		name   string
		fail   string
		ipv6At int
		add    bool
		want   []string
		errSub string
	}{
		{"create fails", "create", 0, false, []string{"create sb-1"}, "create netns sb-1"},
		{"loopback fails", "lo", 0, false, []string{"create sb-1", "lo sb-1", "delete sb-1"}, "loopback up sb-1"},
		{"IPv6 off fails before the ADD", "", 1, false, []string{"create sb-1", "lo sb-1", "ipv6 /run/netns/sb-1", "delete sb-1"}, "disable ipv6 in sb-1"},
		{"the ADD fails", "", 0, true, []string{"create sb-1", "lo sb-1", "ipv6 /run/netns/sb-1", "delete sb-1"}, "cni add"},
		{"IPv6 off fails after the ADD: all of it is undone", "", 2, false,
			[]string{"create sb-1", "lo sb-1", "ipv6 /run/netns/sb-1", "ipv6 /run/netns/sb-1", "delete sb-1"}, "after cni add"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{failIPv6At: tc.ipv6At, fail: map[string]error{}}
			if tc.fail != "" {
				r.fail[tc.fail] = errors.New("refused")
			}
			runner := cni.NewFakeRunner()
			if tc.add {
				runner.SetAddError(errors.New("bridge plugin failed"))
			}
			_, _, err := r.steps(runner).Realize(ctx, "sb-1")
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("Realize = %v, want an error with %q", err, tc.errSub)
			}
			if !slices.Equal(r.calls, tc.want) {
				t.Fatalf("steps %v, want %v", r.calls, tc.want)
			}
			if _, attached := runner.IPOf("sb-1"); attached {
				t.Fatal("a failed build left the sandbox attached")
			}
		})
	}
}

func TestRemove(t *testing.T) {
	ctx := context.Background()
	t.Run("everything goes, by the same name", func(t *testing.T) {
		r, runner := &recorder{}, cni.NewFakeRunner()
		path, ip, err := r.steps(runner).Realize(ctx, "aerol-netns-3")
		if err != nil {
			t.Fatal(err)
		}
		r.calls = nil
		if err := r.steps(runner).Remove(ctx, "aerol-netns-3", path, ip); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(r.calls, []string{"delete aerol-netns-3"}) {
			t.Fatalf("steps %v", r.calls)
		}
		dels := runner.Dels()
		if len(dels) != 1 {
			t.Fatalf("CNI DELs %v", dels)
		}
		if m := runner.MasqTeardowns(); len(m) != 1 || m[0].ContainerID != "aerol-netns-3" || m[0].ContainerIP != ip {
			t.Fatalf("NAT teardowns %+v", m)
		}
	})
	t.Run("errors are joined, and every step still runs", func(t *testing.T) {
		r := &recorder{fail: map[string]error{"delete": errors.New("busy")}}
		runner := cni.NewFakeRunner()
		runner.SetDelError(errors.New("plugin gone"))
		runner.SetMasqError(errors.New("no nat"))
		err := r.steps(runner).Remove(ctx, "sb-1", filepath.Join("/run/netns", "sb-1"), "10.88.0.9")
		for _, want := range []string{"busy", "plugin gone", "no nat"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Remove = %v, want %q in it", err, want)
			}
		}
		if !slices.Equal(r.calls, []string{"delete sb-1"}) {
			t.Fatalf("steps %v", r.calls)
		}
	})
	t.Run("a runner with no NAT teardown", func(t *testing.T) {
		r := &recorder{}
		if err := r.steps(delOnly{}).Remove(ctx, "sb-1", "/run/netns/sb-1", ""); err != nil {
			t.Fatal(err)
		}
	})
}

// TestRemoveForTheHelper (PR 4 review): the root helper's teardown flushes
// connection tracking through its own runner, with the call's context, and
// starts no step once that context has ended (a call its caller gave up
// on, or one cut by a helper swap): the retry, or the next build of the
// slot, does the rest.
func TestRemoveForTheHelper(t *testing.T) {
	t.Run("the flush is the helper's, with the call's context", func(t *testing.T) {
		r := &recorder{}
		st := r.steps(cni.NewFakeRunner())
		var flushed []string
		st.FlushConntrack = func(ctx context.Context, ip string) error {
			flushed = append(flushed, ip)
			return ctx.Err()
		}
		st.StopOnCancel = true
		if err := st.Remove(context.Background(), "sb-1", "/run/netns/sb-1", "10.88.0.9"); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(flushed, []string{"10.88.0.9"}) || !slices.Equal(r.calls, []string{"delete sb-1"}) {
			t.Fatalf("flushed %v, steps %v", flushed, r.calls)
		}
	})
	t.Run("a cancel during CNI DEL starts nothing after it", func(t *testing.T) {
		r := &recorder{}
		ctx, cancel := context.WithCancel(context.Background())
		runner := &cancellingDel{FakeRunner: cni.NewFakeRunner(), cancel: cancel}
		st := r.steps(runner)
		st.FlushConntrack = func(context.Context, string) error {
			t.Fatal("a flush ran after the cancel")
			return nil
		}
		st.StopOnCancel = true
		if err := st.Remove(ctx, "sb-1", "/run/netns/sb-1", "10.88.0.9"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Remove = %v", err)
		}
		if len(r.calls) != 0 || len(runner.MasqTeardowns()) != 0 {
			t.Fatalf("steps after the cancel: %v, NAT %v", r.calls, runner.MasqTeardowns())
		}
	})
	t.Run("a cancel during the NAT teardown starts no flush", func(t *testing.T) {
		r := &recorder{}
		ctx, cancel := context.WithCancel(context.Background())
		runner := &cancellingMasq{FakeRunner: cni.NewFakeRunner(), cancel: cancel}
		st := r.steps(runner)
		st.FlushConntrack = func(context.Context, string) error {
			t.Fatal("a flush ran after the cancel")
			return nil
		}
		st.StopOnCancel = true
		if err := st.Remove(ctx, "sb-1", "/run/netns/sb-1", "10.88.0.9"); !errors.Is(err, context.Canceled) {
			t.Fatalf("Remove = %v", err)
		}
		if len(r.calls) != 0 {
			t.Fatalf("steps after the cancel: %v", r.calls)
		}
	})
}

// cancellingDel ends the call's context while CNI DEL runs.
type cancellingDel struct {
	*cni.FakeRunner
	cancel context.CancelFunc
}

func (c *cancellingDel) Del(ctx context.Context, path, id string) error {
	c.cancel()
	return c.FakeRunner.Del(ctx, path, id)
}

// cancellingMasq ends it during the NAT teardown.
type cancellingMasq struct {
	*cni.FakeRunner
	cancel context.CancelFunc
}

func (c *cancellingMasq) TeardownIPMasq(ctx context.Context, id, ip string) error {
	c.cancel()
	return c.FakeRunner.TeardownIPMasq(ctx, id, ip)
}

// delOnly is a CNI runner without cni.IPMasqTeardown.
type delOnly struct{}

func (delOnly) Add(context.Context, string, string) (cni.Result, error) { return cni.Result{}, nil }
func (delOnly) Del(context.Context, string, string) error               { return nil }
