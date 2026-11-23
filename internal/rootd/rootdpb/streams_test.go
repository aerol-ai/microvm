package rootdpb

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// streamHelper serves the two streaming calls (M1 PR 13): an export of two
// chunks, and an import that answers what it took in.
type streamHelper struct{ UnimplementedRootHelperServer }

func (streamHelper) ExportMove(req *ExportMoveRequest, s grpc.ServerStreamingServer[MoveChunk]) error {
	for _, part := range []string{"bundle of ", req.GetSandboxId()} {
		if err := s.Send(&MoveChunk{Data: []byte(part)}); err != nil {
			return err
		}
	}
	return nil
}

func (streamHelper) ImportMove(s grpc.ClientStreamingServer[ImportMoveRequest, ImportMoveResponse]) error {
	var id string
	var got bytes.Buffer
	for {
		m, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return s.SendAndClose(&ImportMoveResponse{RestorePath: "/moves/in/" + id + ":" + got.String()})
		}
		if err != nil {
			return err
		}
		if id == "" {
			id = m.GetSandboxId()
		}
		got.Write(m.GetData())
	}
}

func dialStubs(t *testing.T, srv RootHelperServer) RootHelperClient {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	s := grpc.NewServer()
	RegisterRootHelperServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient("passthrough:///x", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return NewRootHelperClient(conn)
}

// TestStreamStubsRoundTrip runs the generated stream code both ways, and
// against a helper that has not built them.
func TestStreamStubsRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := dialStubs(t, streamHelper{})
	ex, err := c.ExportMove(ctx, &ExportMoveRequest{SandboxId: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for {
		m, err := ex.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got.Write(m.GetData())
	}
	if got.String() != "bundle of sb-1" {
		t.Fatalf("export %q", got.String())
	}
	im, err := c.ImportMove(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []*ImportMoveRequest{{SandboxId: "sb-2", Data: []byte("a")}, {Data: []byte("b")}} {
		if err := im.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := im.CloseAndRecv()
	if err != nil || resp.GetRestorePath() != "/moves/in/sb-2:ab" {
		t.Fatalf("import = %v, %v", resp, err)
	}

	old := dialStubs(t, fakeHelper{})
	ex, err = old.ExportMove(ctx, &ExportMoveRequest{SandboxId: "sb-1"})
	if err == nil {
		_, err = ex.Recv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("export on an older helper = %v", err)
	}
	im, err = old.ImportMove(ctx)
	if err == nil {
		_, err = im.CloseAndRecv()
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("import on an older helper = %v", err)
	}
	for _, v := range []MoveSide{MoveSide_MOVE_SIDE_OUT, MoveSide_MOVE_SIDE_IN} {
		if v.Enum() == nil || v.String() == "" || v.Descriptor().FullName() != "aerolvm.rootd.v1.MoveSide" || v.Type() == nil || v.Number() != 1 && v.Number() != 2 {
			t.Fatalf("enum %v methods", v)
		}
		if _, idx := v.EnumDescriptor(); len(idx) != 1 {
			t.Fatalf("enum descriptor index %v", idx)
		}
	}
}
