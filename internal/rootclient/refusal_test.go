package rootclient

import (
	"context"
	"errors"
	"expvar"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/observability"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// hookLog collects the refusals OnRefusal hears, with a value from each
// call's context, to show the hook runs with the caller's context.
type hookLog struct {
	mu   sync.Mutex
	seen []Refusal
	ctxs []any
}

type ctxKey struct{}

func (h *hookLog) hook(ctx context.Context, r Refusal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = append(h.seen, r)
	h.ctxs = append(h.ctxs, ctx.Value(ctxKey{}))
}

func (h *hookLog) refusals() []Refusal {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Refusal(nil), h.seen...)
}

func hookedClient(t *testing.T, sock string, h *hookLog) *Client {
	t.Helper()
	cfg := Config{Socket: sock, Timeout: 500 * time.Millisecond, HelperUID: uint32(os.Getuid())}
	if h != nil {
		cfg.OnRefusal = h.hook
	}
	c := New(cfg)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// refusalCount is aerolvm_rootd_refusals_total{key=call,key2=reason}.
func refusalCount(call, reason string) int64 {
	inner, ok := refusalsTotal.Get(call).(*expvar.Map)
	if !ok {
		return 0
	}
	n, ok := inner.Get(reason).(*expvar.Int)
	if !ok {
		return 0
	}
	return n.Value()
}

// TestTypedCallRefusedByTheRealHelper: a value the helper's own call
// refuses comes back as a RefusedError: ErrRefused, never ErrUnavailable
// or ErrUnsupported, still the helper's InvalidArgument underneath. It is
// counted, and the hook hears it once, with the call's own context.
func TestTypedCallRefusedByTheRealHelper(t *testing.T) {
	sock := sockPath(t)
	realHelper(t, sock, nil)
	h := &hookLog{}
	c := hookedClient(t, sock, h)
	const call, reason = "RootHelper.EnsureTaskFIFOs", "bad_request"
	before := refusalCount(call, reason)

	ctx := context.WithValue(ctxT(t), ctxKey{}, "create sb-1")
	_, err := c.EnsureTaskFIFOs(ctx, "../etc")
	var re *RefusedError
	if !errors.As(err, &re) || !errors.Is(err, ErrRefused) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnsupported) {
		t.Fatalf("a refused ID = %v (%T), want a RefusedError only", err, err)
	}
	if status.Code(err) != codes.InvalidArgument || re.Call != call || re.Reason != reason {
		t.Fatalf("RefusedError %+v, code %v", re, status.Code(err))
	}
	if msg := err.Error(); !strings.Contains(msg, call) || !strings.Contains(msg, reason) || !strings.Contains(msg, "../etc") {
		t.Fatalf("the error %q does not say which call, why and what", msg)
	}
	if got := h.refusals(); len(got) != 1 || got[0] != (Refusal{Call: call, Reason: reason}) || h.ctxs[0] != "create sb-1" {
		t.Fatalf("hook heard %+v with %v", got, h.ctxs)
	}
	if n := refusalCount(call, reason); n != before+1 {
		t.Fatalf("aerolvm_rootd_refusals_total{%s,%s} = %d, want %d", call, reason, n, before+1)
	}

	// A failure that is not a refusal (no agent ready folder yet, a bug
	// and not an attack) is neither counted nor heard.
	if _, err := c.EnsureReadySocket(ctx, "sb-1", ""); status.Code(err) != codes.FailedPrecondition || errors.Is(err, ErrRefused) {
		t.Fatalf("a missing ready folder = %v, want the helper's FailedPrecondition", err)
	}
	if got := h.refusals(); len(got) != 1 {
		t.Fatalf("hook heard %+v after a failure that is no refusal", got)
	}
}

// TestRefusalLabelsStayBounded: whatever reason a helper sends, the label
// is a plain code or "other", so a newer or broken helper cannot grow the
// series count; a newer helper's new plain code passes as it is.
func TestRefusalLabelsStayBounded(t *testing.T) {
	for _, tc := range []struct{ sent, want string }{
		{"mount", "mount"},
		{"a_newer_rule_2", "a_newer_rule_2"},
		{"", reasonOther},
		{"Bad Reason", reasonOther},
		{"bind /etc/shadow", reasonOther},
		{strings.Repeat("x", 65), reasonOther},
	} {
		t.Run(tc.want+"/"+tc.sent, func(t *testing.T) {
			sock := sockPath(t)
			f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
			f.ensureErr = rootdpb.Refused(codes.PermissionDenied, tc.sent, "refused")
			serveFake(t, sock, f)
			h := &hookLog{}
			err := hookedClient(t, sock, h).EnsureHost(ctxT(t))
			var re *RefusedError
			if !errors.As(err, &re) || re.Reason != tc.want || re.Call != "RootHelper.EnsureHost" {
				t.Fatalf("err %v (%+v), want reason %q", err, re, tc.want)
			}
			if got := h.refusals(); len(got) != 1 || got[0].Reason != tc.want {
				t.Fatalf("hook heard %+v", got)
			}
		})
	}
}

// TestRefusalWithoutAHook: with no OnRefusal the refusal is still counted
// and still ErrRefused: the alert does not hang on how the hook is wired.
func TestRefusalWithoutAHook(t *testing.T) {
	sock := sockPath(t)
	f := helperAt(rootdpb.APIVersion, rootdpb.FeatureEnsureHost)
	f.ensureErr = rootdpb.Refused(codes.PermissionDenied, "unhooked_reason", "refused")
	serveFake(t, sock, f)
	before := refusalCount("RootHelper.EnsureHost", "unhooked_reason")
	if err := hookedClient(t, sock, nil).EnsureHost(ctxT(t)); !errors.Is(err, ErrRefused) {
		t.Fatalf("err %v, want ErrRefused", err)
	}
	if n := refusalCount("RootHelper.EnsureHost", "unhooked_reason"); n != before+1 {
		t.Fatalf("count %d, want %d", n, before+1)
	}
}

// TestRefusalMetricExports: the counter reaches /v1/metrics and the OTEL
// exporter as aerolvm_rootd_refusals_total with the call as key and the
// reason as key2, the labels SandboxdRootHelperRefusal groups by.
func TestRefusalMetricExports(t *testing.T) {
	(&Client{}).refused(context.Background(), "/containerd.services.diff.v1.Diff/Apply", "snapshot_mount")
	for _, s := range observability.CollectAerolVMExpvars() {
		if s.Name != "aerolvm_rootd_refusals_total" || len(s.Labels) != 2 {
			continue
		}
		if s.Labels[0] == (observability.ExpvarLabel{Name: "key", Value: "Diff.Apply"}) &&
			s.Labels[1] == (observability.ExpvarLabel{Name: "key2", Value: "snapshot_mount"}) && s.Int64 != nil && *s.Int64 >= 1 {
			return
		}
	}
	t.Fatal("no aerolvm_rootd_refusals_total{key=Diff.Apply,key2=snapshot_mount} sample")
}

// TestConcurrentFirstRefusals: many first refusals of one call at once
// lose no count (the inner map is made once).
func TestConcurrentFirstRefusals(t *testing.T) {
	c := &Client{}
	const n = 64
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.refused(context.Background(), "/x.Concurrent/First", "race")
		}()
	}
	wg.Wait()
	if got := refusalCount("Concurrent.First", "race"); got != n {
		t.Fatalf("count %d, want %d", got, n)
	}
}

// failingStream is a client stream whose every receive and send fails
// with err, as gRPC answers every receive after a stream failed.
type failingStream struct {
	grpc.ClientStream
	ctx context.Context
	err error
}

func (s failingStream) RecvMsg(any) error        { return s.err }
func (s failingStream) SendMsg(any) error        { return s.err }
func (s failingStream) Context() context.Context { return s.ctx }
func (failingStream) Trailer() metadata.MD       { return metadata.Pairs(rootdpb.AnsweredTrailer, "1") }

// TestStreamRefusalRecordedOnce: a refused stream is one refusal however
// often its receives and sends fail, and each of them is ErrRefused. A
// stream that ends cleanly is not one.
func TestStreamRefusalRecordedOnce(t *testing.T) {
	h := &hookLog{}
	c := &Client{onRefusal: h.hook}
	refused := rootdpb.Refused(codes.PermissionDenied, "namespace", "aerolvm root gate refused")
	ctx := context.WithValue(context.Background(), ctxKey{}, "list")
	s := &markedStream{ClientStream: failingStream{ctx: ctx, err: refused}, c: c, method: "/containerd.services.containers.v1.Containers/ListStream"}
	for range 3 {
		if err := s.RecvMsg(nil); !errors.Is(err, ErrRefused) || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("RecvMsg = %v", err)
		}
	}
	if err := s.SendMsg(nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("SendMsg = %v", err)
	}
	if got := h.refusals(); len(got) != 1 || got[0] != (Refusal{Call: "Containers.ListStream", Reason: "namespace"}) || h.ctxs[0] != "list" {
		t.Fatalf("hook heard %+v with %v", got, h.ctxs)
	}
	done := &markedStream{ClientStream: failingStream{ctx: ctx, err: io.EOF}, c: c, method: "/x.Y/Z"}
	if err := done.RecvMsg(nil); err != io.EOF || len(h.refusals()) != 1 {
		t.Fatalf("a clean end = %v, refusals %v", err, h.refusals())
	}
}

// TestUnaryRefusalMarked: on containerd's unary path a refusal is marked
// ErrRefused, not unavailable, though the helper answered with a code
// (PermissionDenied) the API would otherwise call the caller's 400, and a
// mark that passes through again is not counted twice.
func TestUnaryRefusalMarked(t *testing.T) {
	h := &hookLog{}
	c := &Client{onRefusal: h.hook}
	const method = "/containerd.services.namespaces.v1.Namespaces/Create"
	err := c.markFailure(context.Background(), method, rootdpb.Refused(codes.PermissionDenied, "method_not_allowed", "no"), nil, nil)
	if !errors.Is(err, ErrRefused) || errors.Is(err, ErrUnavailable) || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("markFailure = %v", err)
	}
	if again := c.markFailure(context.Background(), method, err, nil, nil); again != err || len(h.refusals()) != 1 {
		t.Fatalf("a marked error marked again: %v, refusals %v", again, h.refusals())
	}
	if got := h.refusals(); got[0] != (Refusal{Call: "Namespaces.Create", Reason: "method_not_allowed"}) {
		t.Fatalf("hook heard %+v", got)
	}
}
