package gate

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	contentapi "github.com/containerd/containerd/api/services/content/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

// TestContainerdDown: with containerd unreachable the agent gets
// Unavailable, which is not a refusal.
func TestContainerdDown(t *testing.T) {
	lis := bufconn.Listen(1 << 10)
	_ = lis.Close()
	up, err := grpc.NewClient("passthrough:///down", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	var refusals atomic.Int32
	g, err := New(Config{Policy: testPolicy(), Upstream: up, OnRefusal: func(context.Context, Refusal) { refusals.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	_, dial := bufServer(t, g.ServerOptions()...)
	r := &rig{t: t, fake: &fakeContainerd{}, gate: g, conn: bufConn(t, dial), dial: dial}
	_, err = r.invoke(nsCtx(), "/containerd.services.containers.v1.Containers/Get", &containersapi.GetContainerRequest{ID: testID})
	if status.Code(err) != codes.Unavailable || refusals.Load() != 0 {
		t.Fatalf("err %v, refusals %d", err, refusals.Load())
	}
}

// TestAgentHangsUpMidStream: when the agent goes away mid-write, the
// gate's call to containerd ends too.
func TestAgentHangsUpMidStream(t *testing.T) {
	r := newRig(t, testPolicy())
	const write = "/containerd.services.content.v1.Content/Write"
	ended := make(chan struct{})
	r.fake.on(write, func(ctx context.Context, _ proto.Message) ([]proto.Message, error) {
		go func() { <-ctx.Done(); close(ended) }()
		return []proto.Message{&contentapi.WriteContentResponse{Action: contentapi.WriteAction_STAT}}, nil
	})
	ctx, cancel := context.WithCancel(nsCtx())
	defer cancel()
	cs, err := r.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, write)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SendMsg(&contentapi.WriteContentRequest{Action: contentapi.WriteAction_STAT, Ref: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := cs.RecvMsg(&contentapi.WriteContentResponse{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("containerd's side of the call outlived the agent's")
	}
}
