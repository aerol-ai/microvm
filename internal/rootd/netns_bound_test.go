package rootd

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// TestNetnsBound (PR 4 review, finding 5): the gate lets a container join
// a named namespace only when the helper made it and it is still a
// sandbox's, by the network calls' own reading of it.
func TestNetnsBound(t *testing.T) {
	fn := newFakeNet()
	r, c := netRig(t, fn)
	ctx := callCtx(t)
	if _, err := c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: "aerol-netns-0"}); err != nil {
		t.Fatal(err)
	}
	dir := r.cfg.Policy.NetnsDir
	fn.set(filepath.Join(dir, "operators"), NetnsState{Exists: true, Foreign: "a namespace without the helper's mark"})
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"aerol-netns-0", true},
		{"operators", false},
		{"never-made", false},
		{"../../proc/1/ns/net", false},
	} {
		got, err := r.srv.NetnsBound(ctx, tc.name, "sb-1")
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	fn.fail["inspect"] = errors.New("netlink: no buffer space")
	if _, err := r.srv.NetnsBound(ctx, "aerol-netns-0", "sb-1"); err == nil {
		t.Fatal("a failed read vouched for a namespace")
	}
	delete(fn.fail, "inspect")
	// It takes the namespace's lock: a build of it in flight is waited
	// for, for no longer than the gate's call.
	fn.hold = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = c.RealizeNetns(context.Background(), &rootdpb.RealizeNetnsRequest{NetnsName: "aerol-netns-1"})
	}()
	for fn.active.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	if _, err := r.srv.NetnsBound(short, "aerol-netns-1", "sb-2"); err == nil {
		t.Fatal("answered during the namespace's build")
	}
	close(fn.hold)
	wg.Wait()
	if ok, err := r.srv.NetnsBound(ctx, "aerol-netns-1", "sb-2"); err != nil || !ok {
		t.Fatalf("after the build: %v %v", ok, err)
	}
}

func TestNetnsBoundWithoutANetwork(t *testing.T) {
	r := newRig(t, nil)
	if _, err := r.srv.NetnsBound(callCtx(t), "aerol-netns-0", "sb-1"); err == nil {
		t.Fatal("a helper with no network vouched for a namespace")
	}
}

// TestNetworkCallsPastTheLimit (PR 4 review, finding 3): past its turns and
// its queue the helper answers a network call ResourceExhausted at once,
// with no refusal recorded (it is load, not a hostile call), and serves
// the next call once a turn is free.
func TestNetworkCallsPastTheLimit(t *testing.T) {
	fn := newFakeNet()
	fn.hold = make(chan struct{})
	r, c := netRig(t, fn)
	r.srv.net.limit = newCallLimit(2, 1)
	ctx := callCtx(t)
	var wg sync.WaitGroup
	for i := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: []string{"a", "b", "c"}[i]})
		}()
	}
	for fn.active.Load() != 2 || r.srv.net.limit.waiting.Load() != 1 {
		time.Sleep(time.Millisecond)
	}
	_, err := c.RemoveNetns(ctx, &rootdpb.RemoveNetnsRequest{NetnsName: "d"})
	wantCode(t, err, codes.ResourceExhausted)
	if _, refused := rootdpb.RefusalReason(err); refused || len(r.refused()) != 0 {
		t.Fatalf("a busy answer was a refusal: %v %v", err, r.refused())
	}
	close(fn.hold)
	wg.Wait()
	if _, err := c.RemoveNetns(ctx, &rootdpb.RemoveNetnsRequest{NetnsName: "d"}); err != nil {
		t.Fatal(err)
	}
	// A wait its caller gives up on ends with it.
	fn.hold = make(chan struct{})
	t.Cleanup(func() { close(fn.hold) })
	for _, n := range []string{"e", "f"} {
		go func() { _, _ = c.RealizeNetns(ctx, &rootdpb.RealizeNetnsRequest{NetnsName: n}) }()
	}
	for fn.active.Load() != 2 {
		time.Sleep(time.Millisecond)
	}
	short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	_, err = c.RealizeNetns(short, &rootdpb.RealizeNetnsRequest{NetnsName: "g"})
	wantCode(t, err, codes.DeadlineExceeded)
}

// TestAnswerAfterTheCallerLeft: a call that failed because its caller gave
// up is answered with the caller's own code, not as the helper's failure.
func TestAnswerAfterTheCallerLeft(t *testing.T) {
	h := helper{log: slog.New(slog.DiscardHandler), onRefusal: func(context.Context, Refusal) { t.Fatal("a cancel was a refusal") }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := answer(ctx, h, "m", (*rootdpb.RealizeNetnsResponse)(nil), errors.New("cni add: signal: killed"))
	wantCode(t, err, codes.Canceled)
	_, err = answer(context.Background(), h, "m", (*rootdpb.RealizeNetnsResponse)(nil), errors.New("cni add: exit status 1"))
	wantCode(t, err, codes.Internal)
}
