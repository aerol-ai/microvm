package service

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker/netstats"
	"github.com/aerol-ai/microvm/pkg/models"
)

// seenTestLookup is a PID lookup a test can switch off, so a poller it has
// cancelled (Poller has no join) cannot sample again behind the next one.
type seenTestLookup struct {
	mu   sync.Mutex
	pids map[string]int
}

func (l *seenTestLookup) ContainerPID(_ context.Context, ref string) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pids[ref], nil
}

func (l *seenTestLookup) off() {
	l.mu.Lock()
	l.pids = nil
	l.mu.Unlock()
}

func seenTestNetDev(in, out int64) fstest.MapFS {
	return fstest.MapFS{"4242/net/dev": &fstest.MapFile{Data: []byte(`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  eth0: ` + strconv.FormatInt(in, 10) + `       18    0    0    0     0          0         0 ` + strconv.FormatInt(out, 10) + `       11    0    0    0     0       0          0
`)}}
}

// waitNetOut polls the store (safe beside the poller goroutine) until the
// sandbox's sent-bytes counter reaches want.
func waitNetOut(t *testing.T, st *storepkg.Store, id string, want int64) *models.Sandbox {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sb, err := st.Get(context.Background(), id)
		if err != nil {
			t.Fatalf("store.Get: %v", err)
		}
		if sb.NetworkBytesOut == want {
			return sb
		}
		if sb.NetworkBytesOut > want || time.Now().After(deadline) {
			t.Fatalf("sent bytes = %d, want %d", sb.NetworkBytesOut, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestNetstatsCountsTheFirstWindowAndSurvivesARestart is issue #69 end to
// end, through the real store, lister, sink and poller: a new sandbox that
// sends past its cap before the first poll is counted and flagged on that
// poll, and a second poller (sandboxd restarted) carries on from the stored
// reading instead of counting the container's traffic again.
func TestNetstatsCountsTheFirstWindowAndSurvivesARestart(t *testing.T) {
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:                   "sb-burst",
		Image:                "alpine:3.20",
		Status:               models.SandboxStatusStarted,
		ContainerID:          "ctr-burst",
		ContainerIP:          "10.0.0.20",
		CPU:                  1,
		MemoryMB:             256,
		DiskGB:               5,
		OSUser:               "root",
		NetworkBytesOutLimit: 1000,
	})
	lister := netstatsServiceLister{svc: svc}
	if got := lister.NetstatsTargets(context.Background()); len(got) != 1 || got[0].Seen != (netstats.Seen{PID: netstats.SeenNew}) {
		t.Fatalf("targets = %+v, want the new sandbox marked SeenNew", got)
	}
	if storepkg.NetSeenNew != netstats.SeenNew || storepkg.NetSeenUnknown != netstats.SeenUnknown {
		t.Fatal("store and poller disagree on what a stored reading's PID means")
	}

	run := func(fsys fstest.MapFS) (*seenTestLookup, context.CancelFunc) {
		lookup := &seenTestLookup{pids: map[string]int{"ctr-burst": 4242}}
		ctx, cancel := context.WithCancel(context.Background())
		p := netstats.NewPoller(slog.Default(), netstats.NewReaderFS(fsys), lookup, lister, netstatsServiceSink{svc: svc}, 2*time.Millisecond)
		if err := p.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		return lookup, cancel
	}

	// The whole 5,000-byte burst before the first poll is counted, and the
	// 1,000-byte cap trips on that poll.
	lookup, cancel := run(seenTestNetDev(10, 5000))
	sb := waitNetOut(t, st, "sb-burst", 5000)
	// The sink commits the counters first and flags the quota right after,
	// in the same tick, so the flag can trail the counters by a moment.
	for deadline := time.Now().Add(5 * time.Second); !sb.NetworkQuotaExceeded && time.Now().Before(deadline); {
		time.Sleep(2 * time.Millisecond)
		sb = waitNetOut(t, st, "sb-burst", 5000)
	}
	cancel()
	lookup.off()
	if sb.NetworkBytesIn != 10 || !sb.NetworkQuotaExceeded {
		t.Fatalf("after the first poll: in=%d quota_exceeded=%v, want 10 and true", sb.NetworkBytesIn, sb.NetworkQuotaExceeded)
	}

	// sandboxd restarts while the container keeps running and sends 600
	// more: only those 600 are added, then nothing on later polls.
	lookup, cancel = run(seenTestNetDev(10, 5600))
	defer cancel()
	waitNetOut(t, st, "sb-burst", 5600)
	time.Sleep(20 * time.Millisecond) // several more polls
	cancel()
	lookup.off()
	waitNetOut(t, st, "sb-burst", 5600)

	// Rolled back: the previous release credits the next 400 bytes the way
	// it always did, with no reading. Rolled forward at 6,100 sent: only the
	// last 100 are new to this build.
	if _, err := st.ApplyNetCounterDeltas(context.Background(), []storepkg.NetCounterDelta{{SandboxID: "sb-burst", BytesOut: 400}}); err != nil {
		t.Fatalf("old build's credit: %v", err)
	}
	lookup, cancel = run(seenTestNetDev(10, 6100))
	defer cancel()
	waitNetOut(t, st, "sb-burst", 6100)
	time.Sleep(20 * time.Millisecond)
	cancel()
	lookup.off()
	waitNetOut(t, st, "sb-burst", 6100)
}

// TestNetstatsSinkStoresAReadingWithoutRecheckingQuota: a restarted container
// that has sent nothing yet still has its new reading stored, but its totals
// did not move, so the sink neither reports usage nor re-runs the quota
// block for it, even when the sandbox is already flagged over its cap.
func TestNetstatsSinkStoresAReadingWithoutRecheckingQuota(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	seedNetstatsSandbox(t, st, &models.Sandbox{
		ID:                   "sb-flagged",
		Image:                "alpine:3.20",
		Status:               models.SandboxStatusStarted,
		ContainerID:          "ctr-flagged",
		ContainerIP:          "10.0.0.21",
		CPU:                  1,
		MemoryMB:             256,
		DiskGB:               5,
		OSUser:               "root",
		NetworkBytesOutLimit: 100,
	})
	if _, err := st.ApplyNetCounterDeltas(ctx, []storepkg.NetCounterDelta{{SandboxID: "sb-flagged", BytesOut: 150}}); err != nil {
		t.Fatalf("seed counters: %v", err)
	}
	if err := st.MarkNetworkQuotaExceeded(ctx, "sb-flagged", time.Now().UTC()); err != nil {
		t.Fatalf("flag quota: %v", err)
	}

	netstatsServiceSink{svc: svc}.handleNetworkSamples(ctx, []netstats.Sample{{
		SandboxID: "sb-flagged", SampledAt: time.Now().UTC(), Seen: &netstats.Seen{PID: 77},
	}})

	got := netstatsServiceLister{svc: svc}.NetstatsTargets(ctx)
	if len(got) != 1 || got[0].Seen != (netstats.Seen{PID: 77}) {
		t.Fatalf("targets = %+v, want the new reading {77 0 0} stored", got)
	}
	sb, err := st.Get(ctx, "sb-flagged")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if sb.NetworkBytesOut != 150 || !sb.NetworkQuotaExceeded {
		t.Fatalf("out=%d flagged=%v, want 150 and still flagged", sb.NetworkBytesOut, sb.NetworkQuotaExceeded)
	}
	if len(rt.applyNetworkBlockAllCalls) != 0 {
		t.Fatalf("quota block re-applied %v for a sample with no bytes", rt.applyNetworkBlockAllCalls)
	}
}
