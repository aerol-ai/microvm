package gate

import (
	"bytes"
	"context"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	contentapi "github.com/containerd/containerd/api/services/content/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/status"
	protobuf "google.golang.org/protobuf/proto"
)

// TestOnlyUncheckedReadsPassThrough: the gate forwards a request unread
// only for a read with no check. Every write, and every method with a
// check, is decoded, walked and checked.
func TestOnlyUncheckedReadsPassThrough(t *testing.T) {
	var unread int
	for _, m := range allowlist {
		_, isFrame := m.request().(*frame)
		if isFrame != m.passThrough() {
			t.Fatalf("%s: request is a frame %v, pass-through %v", m.name, isFrame, m.passThrough())
		}
		if !m.passThrough() {
			continue
		}
		unread++
		if m.write || m.check != nil {
			t.Fatalf("%s passes through unread, but it is a write or has a check", m.name)
		}
		// The walk's table covers write messages only; none passes through.
		if _, ok := fieldDecisions[m.newReq().ProtoReflect().Descriptor().FullName()]; ok {
			t.Fatalf("%s passes through, but its request is one the walk reads", m.name)
		}
	}
	if unread == 0 {
		t.Fatal("no method passes through; the test no longer tests anything")
	}
}

// TestCheckedMessageArrivingAsFrameFailsClosed: a method with a check
// never runs it on bytes it has not decoded.
func TestCheckedMessageArrivingAsFrameFailsClosed(t *testing.T) {
	g, err := New(Config{Policy: testPolicy(), Upstream: &grpc.ClientConn{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"/containerd.services.namespaces.v1.Namespaces/Get",
		"/containerd.services.containers.v1.Containers/Create",
	} {
		if err := g.check(context.Background(), methods[name], &frame{b: []byte{1}}); status.Code(err) != codes.Internal {
			t.Fatalf("%s: err %v, want Internal", name, err)
		}
	}
}

// TestReadsAndAnswersArriveAsSent: a pass-through read reaches containerd
// as the agent sent it, and containerd's answer reaches the agent as
// containerd sent it, unknown fields included.
func TestReadsAndAnswersArriveAsSent(t *testing.T) {
	r := newRig(t, testPolicy())
	const get = "/containerd.services.containers.v1.Containers/Get"
	answer := withUnknownField(&containersapi.GetContainerResponse{Container: goodContainer(t)})
	r.fake.on(get, func(context.Context, protobuf.Message) ([]protobuf.Message, error) {
		return []protobuf.Message{answer}, nil
	})
	req := withUnknownField(&containersapi.GetContainerRequest{ID: testID})
	got, err := r.invoke(nsCtx(), get, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !protobuf.Equal(got[0], answer) {
		t.Fatalf("answer %v, want %v", got, answer)
	}
	seen := r.fake.seen()
	if len(seen) != 1 || !protobuf.Equal(seen[0].req, req) {
		t.Fatalf("containerd saw %+v", seen)
	}
	// A server stream's answers too.
	const read = "/containerd.services.content.v1.Content/Read"
	chunks := []protobuf.Message{&contentapi.ReadContentResponse{Offset: 0, Data: []byte("ab")}, &contentapi.ReadContentResponse{Offset: 2, Data: []byte("c")}}
	r.fake.on(read, func(context.Context, protobuf.Message) ([]protobuf.Message, error) { return chunks, nil })
	got, err = r.invoke(nsCtx(), read, &contentapi.ReadContentRequest{Digest: "sha256:00"})
	if err != nil || len(got) != 2 || !protobuf.Equal(got[0], chunks[0]) || !protobuf.Equal(got[1], chunks[1]) {
		t.Fatalf("stream answers %v, %v", got, err)
	}
	// A checked read is still checked: another namespace's name is refused.
	const nsGet = "/containerd.services.namespaces.v1.Namespaces/Get"
	_, err = r.invoke(nsCtx(), nsGet, &namespacesapi.GetNamespaceRequest{Name: "k8s.io"})
	r.wantRefused(err, nsGet, ReasonNamespace)
}

func TestFrameCodec(t *testing.T) {
	c := frameCodec{}
	if c.Name() != proto.Name {
		t.Fatalf("name %q", c.Name())
	}
	// Frames go as their bytes, and come back as a copy.
	out, err := c.Marshal(&frame{b: []byte("raw")})
	if err != nil || !bytes.Equal(out.Materialize(), []byte("raw")) {
		t.Fatalf("marshal %q, %v", out.Materialize(), err)
	}
	buf := []byte("wire")
	var f frame
	if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer(buf)}, &f); err != nil {
		t.Fatal(err)
	}
	buf[0] = 'X'
	if string(f.b) != "wire" {
		t.Fatalf("the frame shares gRPC's buffer: %q", f.b)
	}
	// Anything else is proto's.
	msg := &containersapi.GetContainerRequest{ID: testID}
	enc, err := c.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	var back containersapi.GetContainerRequest
	if err := c.Unmarshal(enc, &back); err != nil || back.GetID() != testID {
		t.Fatalf("proto round trip %v, %v", &back, err)
	}
	if _, err := c.Marshal("not a message"); err == nil {
		t.Fatal("a value that is neither a frame nor a message was encoded")
	}
}
