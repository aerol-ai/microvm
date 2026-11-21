package rootdpb

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// TestGeneratedCodeIsCurrent: gen.sh records a checksum of rootd.proto and
// the two files it generates. An edit to the proto without regenerating, or
// a hand edit to generated code, changes a checksum and fails here, so
// make test catches it without needing protoc. `make rootd-proto-check`
// regenerates and diffs, for a machine that has protoc.
func TestGeneratedCodeIsCurrent(t *testing.T) {
	f, err := os.Open("rootd.sum")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		want, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok {
			t.Fatalf("rootd.sum line %q", sc.Text())
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("%s changed since gen.sh last ran: run `make rootd-proto`", name)
		}
		names = append(names, name)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if want := []string{"rootd.pb.go", "rootd.proto", "rootd_grpc.pb.go"}; !slices.Equal(names, want) {
		t.Fatalf("rootd.sum covers %v, want %v", names, want)
	}
}

// TestAPIConstants pins the rules the constants promise: every feature
// names a real call, every call sits under ServicePrefix (so an unknown one
// never reaches the gate), and the helper one release back is accepted.
func TestAPIConstants(t *testing.T) {
	var calls []string
	for _, m := range RootHelper_ServiceDesc.Methods {
		calls = append(calls, m.MethodName)
	}
	for _, f := range []string{FeatureEnsureHost} {
		if !slices.Contains(calls, f) {
			t.Errorf("feature %q is not a RootHelper call (%v)", f, calls)
		}
	}
	for _, full := range []string{RootHelper_Version_FullMethodName, RootHelper_EnsureHost_FullMethodName} {
		if !strings.HasPrefix(full, ServicePrefix) {
			t.Errorf("%s is not under %s", full, ServicePrefix)
		}
	}
	if len(RootHelper_ServiceDesc.Streams) != 0 {
		t.Error("a streaming call needs its own entry in the checks above")
	}
	if MinHelperAPI < 1 || MinHelperAPI > APIVersion || APIVersion-MinHelperAPI > 1 {
		t.Fatalf("MinHelperAPI %d, APIVersion %d: the agent must accept exactly one release back", MinHelperAPI, APIVersion)
	}
}

// TestWireIsAppendOnly pins every message's fields by name, number and
// kind. Agent N talks to helper N-1 (eng review D5), so a field may be
// added but never renumbered, retyped or dropped: a change to a row here
// is a wire break, and a new field fails until its row is added.
func TestWireIsAppendOnly(t *testing.T) {
	want := map[protoreflect.FullName][]string{
		"aerolvm.rootd.v1.VersionRequest":     {"agent_version=1:string", "agent_api=2:uint32"},
		"aerolvm.rootd.v1.VersionResponse":    {"helper_version=1:string", "api=2:uint32", "features=3:repeated string"},
		"aerolvm.rootd.v1.EnsureHostRequest":  nil,
		"aerolvm.rootd.v1.EnsureHostResponse": nil,
		"aerolvm.rootd.v1.HelperUnavailable":  nil,
		"aerolvm.rootd.v1.HelperUnsupported":  {"reason=1:string"},
	}
	msgs := File_rootd_proto.Messages()
	if msgs.Len() != len(want) {
		t.Fatalf("rootd.proto has %d messages, the table %d", msgs.Len(), len(want))
	}
	for i := range msgs.Len() {
		m := msgs.Get(i)
		var got []string
		for j := range m.Fields().Len() {
			f := m.Fields().Get(j)
			kind := f.Kind().String()
			if f.IsList() {
				kind = "repeated " + kind
			}
			got = append(got, fmt.Sprintf("%s=%d:%s", f.Name(), f.Number(), kind))
		}
		w, ok := want[m.FullName()]
		if !ok || !slices.Equal(got, w) {
			t.Errorf("%s fields %v, pinned %v", m.FullName(), got, w)
		}
	}
}

// fakeHelper serves only Version; EnsureHost falls to the generated
// default, which every helper that has not built a call answers with.
type fakeHelper struct{ UnimplementedRootHelperServer }

func (fakeHelper) Version(_ context.Context, r *VersionRequest) (*VersionResponse, error) {
	return &VersionResponse{HelperVersion: "v-" + r.GetAgentVersion(), Api: r.GetAgentApi(), Features: []string{FeatureEnsureHost}}, nil
}

// TestStubsRoundTrip runs the generated client and server against each
// other, with and without an interceptor, and checks a message survives
// the wire.
func TestStubsRoundTrip(t *testing.T) {
	for _, intercept := range []bool{false, true} {
		t.Run(fmt.Sprint("interceptor=", intercept), func(t *testing.T) {
			lis := bufconn.Listen(1 << 16)
			var opts []grpc.ServerOption
			var seen []string
			if intercept {
				opts = append(opts, grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
					seen = append(seen, info.FullMethod)
					return h(ctx, req)
				}))
			}
			srv := grpc.NewServer(opts...)
			RegisterRootHelperServer(srv, fakeHelper{})
			go func() { _ = srv.Serve(lis) }()
			defer srv.Stop()
			conn, err := grpc.NewClient("passthrough:///x", grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			c := NewRootHelperClient(conn)
			v, err := c.Version(context.Background(), &VersionRequest{AgentVersion: "a", AgentApi: APIVersion})
			if err != nil || v.GetHelperVersion() != "v-a" || v.GetApi() != APIVersion || !slices.Equal(v.GetFeatures(), []string{FeatureEnsureHost}) {
				t.Fatalf("Version = %v, %v", v, err)
			}
			if _, err := c.EnsureHost(context.Background(), &EnsureHostRequest{}); status.Code(err) != codes.Unimplemented {
				t.Fatalf("EnsureHost = %v, want Unimplemented", err)
			}
			if intercept && !slices.Equal(seen, []string{RootHelper_Version_FullMethodName, RootHelper_EnsureHost_FullMethodName}) {
				t.Fatalf("interceptor saw %v", seen)
			}
		})
	}

	// Each message's generated methods, and a nil message's getters,
	// which a decoder can hand back.
	for _, m := range []interface {
		proto.Message
		Reset()
		String() string
		ProtoMessage()
		Descriptor() ([]byte, []int)
	}{
		&VersionRequest{AgentVersion: "a", AgentApi: 1},
		&VersionResponse{HelperVersion: "h", Api: 1, Features: []string{"x"}},
		&EnsureHostRequest{},
		&EnsureHostResponse{},
		&HelperUnavailable{},
		&HelperUnsupported{Reason: "upgrade the helper"},
	} {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		back := m.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(b, back); err != nil || !proto.Equal(m, back) {
			t.Fatalf("%T round trip: %v", m, err)
		}
		m.ProtoMessage()
		if _, idx := m.Descriptor(); len(idx) != 1 {
			t.Fatalf("%T descriptor index %v", m, idx)
		}
		_ = m.String()
		m.Reset()
	}
	var vr *VersionRequest
	var vs *VersionResponse
	if vr.GetAgentVersion() != "" || vr.GetAgentApi() != 0 || vs.GetHelperVersion() != "" || vs.GetApi() != 0 || vs.GetFeatures() != nil {
		t.Fatal("a nil message's getters return zero values")
	}
	var u UnimplementedRootHelperServer
	if _, err := u.Version(context.Background(), nil); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Unimplemented Version = %v", err)
	}
}

// TestHelperUnavailableIsTheError: the detail the agent's client adds is an
// error matching ErrHelperUnavailable, and stays one after a trip through
// a gRPC status's details, which is how containerd's client hands it back.
func TestHelperUnavailableIsTheError(t *testing.T) {
	var d error = &HelperUnavailable{}
	if !errors.Is(d, ErrHelperUnavailable) || d.Error() != ErrHelperUnavailable.Error() || errors.Is(d, errors.New("x")) {
		t.Fatalf("detail %v does not match ErrHelperUnavailable", d)
	}
	st, err := status.New(codes.Unavailable, "down").WithDetails(&HelperUnavailable{})
	if err != nil {
		t.Fatal(err)
	}
	back := status.Convert(st.Err()).Details()
	if len(back) != 1 {
		t.Fatalf("details %v", back)
	}
	if e, ok := back[0].(error); !ok || !errors.Is(e, ErrHelperUnavailable) {
		t.Fatalf("detail after the trip: %T %v", back[0], back[0])
	}
}

func TestHelperUnsupportedIsTheError(t *testing.T) {
	var d error = &HelperUnsupported{Reason: "root helper v1 speaks API 0: upgrade the helper"}
	if !errors.Is(d, ErrHelperUnsupported) || errors.Is(d, ErrHelperUnavailable) || d.Error() != "root helper v1 speaks API 0: upgrade the helper" {
		t.Fatalf("detail %v", d)
	}
	if (&HelperUnsupported{}).Error() != ErrHelperUnsupported.Error() {
		t.Fatal("an empty reason says what the error is")
	}
	var nilDetail *HelperUnsupported
	if nilDetail.GetReason() != "" {
		t.Fatal("nil getter")
	}
}
