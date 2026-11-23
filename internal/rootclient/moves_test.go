package rootclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// moveHelper serves the move calls (M1 PR 13) and records them.
type moveHelper struct {
	rootdpb.UnimplementedRootHelperServer
	features []string

	mu        sync.Mutex
	seen      []string
	imported  []*rootdpb.ImportMoveRequest
	deadline  time.Duration
	importErr error
	// exported is what ExportMove sends, one chunk each.
	exported []string
	cut      chan error
	// first hears each import's first message.
	first chan struct{}
}

func (h *moveHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "n", Api: rootdpb.APIVersion, Features: h.features}, nil
}

func (h *moveHelper) note(ctx context.Context, s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = append(h.seen, s)
	if d, ok := ctx.Deadline(); ok {
		h.deadline = time.Until(d)
	}
}

func (h *moveHelper) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.seen)
}

func (h *moveHelper) CheckpointMove(ctx context.Context, req *rootdpb.CheckpointMoveRequest) (*rootdpb.CheckpointMoveResponse, error) {
	h.note(ctx, "checkpoint "+req.GetSandboxId())
	if req.GetSandboxId() == "refuse" {
		return nil, rootdpb.Refused(codes.InvalidArgument, "bad_request", "no")
	}
	return &rootdpb.CheckpointMoveResponse{}, nil
}

func (h *moveHelper) StagedMove(ctx context.Context, req *rootdpb.StagedMoveRequest) (*rootdpb.StagedMoveResponse, error) {
	h.note(ctx, "staged "+req.GetSandboxId())
	return &rootdpb.StagedMoveResponse{RestorePath: "/moves/in/" + req.GetSandboxId()}, nil
}

func (h *moveHelper) DropMove(ctx context.Context, req *rootdpb.DropMoveRequest) (*rootdpb.DropMoveResponse, error) {
	var sides []string
	for _, s := range req.GetSides() {
		sides = append(sides, s.String())
	}
	h.note(ctx, "drop "+req.GetSandboxId()+" "+strings.Join(sides, ","))
	return &rootdpb.DropMoveResponse{}, nil
}

func (h *moveHelper) ExportMove(req *rootdpb.ExportMoveRequest, s grpc.ServerStreamingServer[rootdpb.MoveChunk]) error {
	h.note(s.Context(), "export "+req.GetSandboxId())
	if req.GetSandboxId() == "refuse" {
		return rootdpb.Refused(codes.InvalidArgument, "bad_request", "no")
	}
	for _, c := range h.exported {
		if err := s.Send(&rootdpb.MoveChunk{Data: []byte(c)}); err != nil {
			return err
		}
	}
	return nil
}

func (h *moveHelper) ImportMove(s grpc.ClientStreamingServer[rootdpb.ImportMoveRequest, rootdpb.ImportMoveResponse]) error {
	h.note(s.Context(), "import")
	for {
		m, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if h.cut != nil {
				h.cut <- err
			}
			return err
		}
		h.mu.Lock()
		h.imported = append(h.imported, m)
		h.mu.Unlock()
		if h.first != nil && m.GetSandboxId() != "" {
			h.first <- struct{}{}
		}
		if h.importErr != nil {
			return h.importErr
		}
	}
	return s.SendAndClose(&rootdpb.ImportMoveResponse{RestorePath: "/moves/in/" + h.imported[0].GetSandboxId()})
}

func newMoveClient(t *testing.T, h *moveHelper) (*Client, *hookLog) {
	t.Helper()
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	log := &hookLog{}
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid()), OnRefusal: log.hook})
	t.Cleanup(func() { _ = c.Close() })
	return c, log
}

// TestMoveCalls: each move call reaches the helper as asked; the bundle's
// bytes pass through in chunks, the first naming the sandbox; a call whose
// caller set no deadline gets the move bound, not the client's short one.
func TestMoveCalls(t *testing.T) {
	h := &moveHelper{features: rootdpb.Features(), exported: []string{"tar ", "bytes"}}
	c, _ := newMoveClient(t, h)
	ctx := ctxT(t)
	if err := c.CheckpointMove(context.Background(), "sb-1"); err != nil {
		t.Fatal(err)
	}
	if h.deadline < DefaultMoveTimeout-time.Minute {
		t.Fatalf("a checkpoint with no deadline of its own was bound to %v", h.deadline)
	}
	if p, err := c.StagedMove(ctx, "sb-1"); err != nil || p != "/moves/in/sb-1" {
		t.Fatalf("StagedMove = %q, %v", p, err)
	}
	if err := c.DropMove(ctx, "sb-1", rootdpb.MoveSide_MOVE_SIDE_OUT, rootdpb.MoveSide_MOVE_SIDE_IN); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := c.ExportMove(ctx, "sb-1", &out); err != nil || out.String() != "tar bytes" {
		t.Fatalf("ExportMove = %q, %v", out.String(), err)
	}
	bundle := bytes.Repeat([]byte("b"), 2*moveChunk+5)
	p, err := c.ImportMove(ctx, "sb-2", bytes.NewReader(bundle))
	if err != nil || p != "/moves/in/sb-2" {
		t.Fatalf("ImportMove = %q, %v", p, err)
	}
	var got []byte
	for i, m := range h.imported {
		if (i == 0) != (m.GetSandboxId() == "sb-2") {
			t.Fatalf("message %d names %q", i, m.GetSandboxId())
		}
		if len(m.GetData()) > moveChunk {
			t.Fatalf("message %d holds %d bytes", i, len(m.GetData()))
		}
		got = append(got, m.GetData()...)
	}
	if !bytes.Equal(got, bundle) || len(h.imported) != 3 {
		t.Fatalf("the helper took %d bytes in %d messages", len(got), len(h.imported))
	}
	// An empty bundle is still one message, naming the sandbox.
	h.imported = nil
	if _, err := c.ImportMove(ctx, "sb-3", bytes.NewReader(nil)); err != nil || len(h.imported) != 1 {
		t.Fatalf("an empty import: %v, %d messages", err, len(h.imported))
	}
	want := []string{"checkpoint sb-1", "staged sb-1", "drop sb-1 MOVE_SIDE_OUT,MOVE_SIDE_IN", "export sb-1", "import", "import"}
	if got := h.calls(); !slices.Equal(got, want) {
		t.Fatalf("calls %v, want %v", got, want)
	}
}

// TestMoveCallFailures: a refusal is recorded; a writer's or a reader's
// failure ends the call without staging anything; a helper that lacks the
// calls gets none.
func TestMoveCallFailures(t *testing.T) {
	h := &moveHelper{features: rootdpb.Features(), exported: []string{"a", "b"}, cut: make(chan error, 1), first: make(chan struct{}, 8)}
	c, log := newMoveClient(t, h)
	ctx := ctxT(t)
	if err := c.CheckpointMove(ctx, "refuse"); !errors.Is(err, ErrRefused) {
		t.Fatalf("a refused checkpoint = %v", err)
	}
	if err := c.ExportMove(ctx, "refuse", io.Discard); !errors.Is(err, ErrRefused) {
		t.Fatalf("a refused export = %v", err)
	}
	if n := len(log.refusals()); n != 2 {
		t.Fatalf("refusals recorded %d, want 2", n)
	}
	if err := c.ExportMove(ctx, "sb-1", errWriter{}); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("an export into a failing writer = %v", err)
	}
	// The reader fails after the first chunk: the stream is cut, never
	// closed, so the helper takes no bundle.
	r := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("x"), moveChunk)), &afterFirst{h: h})
	if _, err := c.ImportMove(ctx, "sb-1", r); err == nil || !strings.Contains(err.Error(), "source gone") {
		t.Fatalf("an import from a failing reader = %v", err)
	}
	select {
	case err := <-h.cut:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("the helper saw %v, want the stream cancelled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the helper never saw the stream end")
	}
	// The helper ends an import early: its answer is the error.
	h.importErr = rootdpb.Refused(codes.InvalidArgument, "move_bundle", "not a bundle")
	if _, err := c.ImportMove(ctx, "sb-1", bytes.NewReader(bytes.Repeat([]byte("y"), 3*moveChunk))); !errors.Is(err, ErrRefused) {
		t.Fatalf("an import the helper refused = %v", err)
	}

	old := &moveHelper{features: []string{rootdpb.FeatureEnsureHostFiles}}
	c2, _ := newMoveClient(t, old)
	for name, err := range map[string]error{
		"checkpoint": c2.CheckpointMove(ctx, "sb-1"),
		"export":     c2.ExportMove(ctx, "sb-1", io.Discard),
		"drop":       c2.DropMove(ctx, "sb-1", rootdpb.MoveSide_MOVE_SIDE_IN),
	} {
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s on an older helper = %v", name, err)
		}
	}
	if _, err := c2.ImportMove(ctx, "sb-1", bytes.NewReader([]byte("x"))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("import on an older helper = %v", err)
	}
	if _, err := c2.StagedMove(ctx, "sb-1"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("staged on an older helper = %v", err)
	}
	if got := old.calls(); len(got) != 0 {
		t.Fatalf("calls sent to an older helper: %v", got)
	}
}

// afterFirst fails, as a source that went away, once the helper has the
// import's first message.
type afterFirst struct{ h *moveHelper }

func (a *afterFirst) Read([]byte) (int, error) {
	<-a.h.first
	return 0, errors.New("source gone")
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// TestMoveCallsOnAClosedClient: a closed client sends nothing.
func TestMoveCallsOnAClosedClient(t *testing.T) {
	h := &moveHelper{features: rootdpb.Features()}
	c, _ := newMoveClient(t, h)
	_ = c.Close()
	if err := c.ExportMove(ctxT(t), "sb-1", io.Discard); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("export = %v", err)
	}
	if _, err := c.ImportMove(ctxT(t), "sb-1", bytes.NewReader(nil)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("import = %v", err)
	}
}
