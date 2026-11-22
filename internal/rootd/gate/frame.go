package gate

import (
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
)

// frame is a message the gate forwards as the bytes it arrived as, without
// decoding it. Two kinds of message travel this way:
//
//   - every answer from containerd: the gate never reads one, so decoding
//     it to encode it again changed nothing but the CPU it cost;
//   - the request of a read the gate passes without reading it (a method
//     that is not a write and has no check, passThrough). Its namespace
//     is in the call's metadata, which the gate checks as before.
//
// A write, and a read with a check (Namespaces.Get), is still decoded,
// walked field by field and checked, and containerd gets the message the
// gate encodes from what it checked, never the agent's bytes.
type frame struct{ b []byte }

// frameCodec is the proto codec that also carries frames. It replaces the
// codec on the helper's whole server, so the helper's own typed calls go
// through it too; for them, and for every other message, it is proto's.
type frameCodec struct{}

var protoCodec = encoding.GetCodecV2(proto.Name)

func (frameCodec) Marshal(v any) (mem.BufferSlice, error) {
	if f, ok := v.(*frame); ok {
		return mem.BufferSlice{mem.SliceBuffer(f.b)}, nil
	}
	return protoCodec.Marshal(v)
}

// Unmarshal copies a frame's bytes out of gRPC's buffers, which it reuses
// once this returns.
func (frameCodec) Unmarshal(data mem.BufferSlice, v any) error {
	if f, ok := v.(*frame); ok {
		f.b = data.Materialize()
		return nil
	}
	return protoCodec.Unmarshal(data, v)
}

func (frameCodec) Name() string { return proto.Name }

// request is a new message for one of m's requests: a frame when m passes
// through, else the decoded type the walk and the check read.
func (m *method) request() any {
	if m.passThrough() {
		return &frame{}
	}
	return m.newReq()
}

// passThrough says whether the gate forwards m's requests unread: a read
// with no check. Its only rule, the namespace, is in the call's metadata.
func (m *method) passThrough() bool { return !m.write && m.check == nil }
