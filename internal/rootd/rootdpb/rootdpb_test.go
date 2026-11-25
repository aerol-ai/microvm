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
	"reflect"
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
	"google.golang.org/protobuf/reflect/protoregistry"
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
	for _, s := range RootHelper_ServiceDesc.Streams {
		calls = append(calls, s.StreamName)
	}
	features := Features()
	for _, f := range features {
		if !slices.Contains(calls, f) {
			t.Errorf("feature %q is not a RootHelper call (%v)", f, calls)
		}
	}
	// Every call but Version is a feature, so the agent can ask about it.
	for _, c := range calls {
		if c != "Version" && !slices.Contains(features, c) {
			t.Errorf("call %s has no feature name", c)
		}
	}
	for _, full := range []string{RootHelper_Version_FullMethodName, RootHelper_EnsureHost_FullMethodName,
		RootHelper_EnsureHostFiles_FullMethodName, RootHelper_EnsureTaskFIFOs_FullMethodName,
		RootHelper_EnsureRunscConfig_FullMethodName, RootHelper_EnsureReadySocket_FullMethodName,
		RootHelper_RemoveContainerFiles_FullMethodName, RootHelper_EnsureHostNetwork_FullMethodName,
		RootHelper_RealizeNetns_FullMethodName, RootHelper_RemoveNetns_FullMethodName,
		RootHelper_DisableNetnsIPv6_FullMethodName, RootHelper_NetnsAddrs_FullMethodName,
		RootHelper_SetNodeGuard_FullMethodName, RootHelper_SetEgressFloor_FullMethodName, RootHelper_SandboxRules_FullMethodName,
		RootHelper_PrepareSandbox_FullMethodName, RootHelper_ReleaseSandbox_FullMethodName} {
		if !strings.HasPrefix(full, ServicePrefix) {
			t.Errorf("%s is not under %s", full, ServicePrefix)
		}
	}
	// The two streams (M1 PR 13): an export the helper sends, an import
	// the agent sends. A new one needs its own entry here and in
	// TestStreamStubsRoundTrip.
	var streams []string
	for _, s := range RootHelper_ServiceDesc.Streams {
		streams = append(streams, fmt.Sprintf("%s server=%v client=%v", s.StreamName, s.ServerStreams, s.ClientStreams))
	}
	if want := []string{"ExportMove server=true client=false", "ImportMove server=false client=true"}; !slices.Equal(streams, want) {
		t.Errorf("streams %v, want %v", streams, want)
	}
	for _, full := range []string{RootHelper_ExportMove_FullMethodName, RootHelper_ImportMove_FullMethodName} {
		if !strings.HasPrefix(full, ServicePrefix) {
			t.Errorf("%s is not under %s", full, ServicePrefix)
		}
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
		"aerolvm.rootd.v1.VersionRequest": {"agent_version=1:string", "agent_api=2:uint32"},
		"aerolvm.rootd.v1.VersionResponse": {"helper_version=1:string", "api=2:uint32", "features=3:repeated string", "parts=4:repeated string",
			"hosts=5:repeated string", "cgroup_parent=6:string"},
		"aerolvm.rootd.v1.EnsureHostRequest":  nil,
		"aerolvm.rootd.v1.EnsureHostResponse": {"ipv6_fence_error=1:string", "fences_firecracker=2:bool", "firecracker_ipv6_fence_error=3:string"},
		"aerolvm.rootd.v1.HelperUnavailable":  nil,
		"aerolvm.rootd.v1.HelperUnsupported":  {"reason=1:string"},
		"aerolvm.rootd.v1.HelperRefused":      {"reason=1:string"},
		"aerolvm.rootd.v1.HostEntry":          {"address=1:string", "names=2:repeated string"},
		"aerolvm.rootd.v1.EnsureHostFilesRequest": {"container_id=1:string", "hostname=2:string", "hosts=3:repeated message",
			"nameservers=4:repeated string", "search=5:repeated string", "dns_options=6:repeated string", "egress_ca_der=7:bytes"},
		"aerolvm.rootd.v1.EnsureHostFilesResponse":      {"hostname_path=1:string", "hosts_path=2:string", "resolv_conf_path=3:string", "egress_ca_path=4:string"},
		"aerolvm.rootd.v1.EnsureTaskFIFOsRequest":       {"container_id=1:string"},
		"aerolvm.rootd.v1.EnsureTaskFIFOsResponse":      {"stdout_path=1:string", "stderr_path=2:string"},
		"aerolvm.rootd.v1.EnsureRunscConfigRequest":     {"config=1:enum"},
		"aerolvm.rootd.v1.EnsureRunscConfigResponse":    {"path=1:string"},
		"aerolvm.rootd.v1.EnsureReadySocketRequest":     {"container_id=1:string", "nonce=2:string"},
		"aerolvm.rootd.v1.EnsureReadySocketResponse":    {"path=1:string"},
		"aerolvm.rootd.v1.RemoveContainerFilesRequest":  {"container_id=1:string"},
		"aerolvm.rootd.v1.RemoveContainerFilesResponse": nil,
		"aerolvm.rootd.v1.EnsureHostNetworkRequest":     nil,
		"aerolvm.rootd.v1.EnsureHostNetworkResponse":    {"subnet=1:string"},
		"aerolvm.rootd.v1.RealizeNetnsRequest":          {"netns_name=1:string"},
		"aerolvm.rootd.v1.RealizeNetnsResponse":         {"netns_path=1:string", "container_ip=2:string"},
		"aerolvm.rootd.v1.RemoveNetnsRequest":           {"netns_name=1:string", "container_ip=2:string"},
		"aerolvm.rootd.v1.RemoveNetnsResponse":          nil,
		"aerolvm.rootd.v1.DisableNetnsIPv6Request":      {"netns_name=1:string"},
		"aerolvm.rootd.v1.DisableNetnsIPv6Response":     nil,
		"aerolvm.rootd.v1.NetnsAddrsRequest":            {"netns_name=1:string"},
		"aerolvm.rootd.v1.NetnsAddrsResponse":           {"exists=1:bool", "ipv4=2:repeated string"},
		"aerolvm.rootd.v1.NodePort":                     {"proto=1:string", "port=2:uint32", "dst=3:string"},
		"aerolvm.rootd.v1.SetNodeGuardRequest":          {"allow=1:repeated message"},
		"aerolvm.rootd.v1.SetNodeGuardResponse":         {"repaired=1:bool"},
		"aerolvm.rootd.v1.SetEgressFloorRequest":        {"cidrs=1:repeated string"},
		"aerolvm.rootd.v1.SetEgressFloorResponse":       {"repaired=1:bool"},
		"aerolvm.rootd.v1.SandboxRulesRequest":          {"container_ip=1:string", "op=2:enum", "allow_cidrs=3:repeated string", "deny_cidrs=4:repeated string"},
		"aerolvm.rootd.v1.SandboxRulesResponse":         {"inserted=1:bool"},
		"aerolvm.rootd.v1.SandboxFirewall":              {"block_all_egress=1:bool", "allow_cidrs=2:repeated string", "deny_cidrs=3:repeated string"},
		"aerolvm.rootd.v1.SandboxCgroup":                {"container_id=1:string"},
		"aerolvm.rootd.v1.HostNaming": {"hostname=1:string", "hosts=2:repeated message", "nameservers=3:repeated string",
			"search=4:repeated string", "dns_options=5:repeated string"},
		"aerolvm.rootd.v1.ContainerSetup": {"naming=1:message", "task_fifos=2:bool", "ready_nonce=3:string", "runsc_config=4:enum", "toolbox=5:bool"},
		"aerolvm.rootd.v1.SandboxFilePaths": {"hostname_path=1:string", "hosts_path=2:string", "resolv_conf_path=3:string",
			"stdout_path=4:string", "stderr_path=5:string", "ready_socket_path=6:string", "runsc_config_path=7:string", "toolbox_path=8:string"},
		"aerolvm.rootd.v1.ImageUser":       {"user=1:string"},
		"aerolvm.rootd.v1.ImageUserAnswer": {"uid=1:uint32", "gid=2:uint32", "additional_gids=3:repeated uint32"},
		"aerolvm.rootd.v1.DiskQuota":       {"bytes=1:uint64"},
		"aerolvm.rootd.v1.PrepareSandboxRequest": {"netns_name=1:string", "parts=2:repeated string", "container_ip=3:string", "firewall=4:message", "cgroup=5:message",
			"container_id=6:string", "setup=7:message", "image_user=8:message", "disk_quota=9:message"},
		"aerolvm.rootd.v1.PrepareSandboxResponse": {"netns_path=1:string", "container_ip=2:string", "block_inserted=3:bool", "files=4:message", "image_user=5:message"},
		"aerolvm.rootd.v1.ReleaseSandboxRequest":  {"netns_name=1:string", "container_ip=2:string", "parts=3:repeated string", "container_id=4:string"},
		"aerolvm.rootd.v1.ReleaseSandboxResponse": nil,
		"aerolvm.rootd.v1.BridgeProbeRequest":     {"op=1:enum", "slot=2:uint32"},
		"aerolvm.rootd.v1.BridgeProbeResponse":    {"bridge_absent=1:bool", "not_ready=2:string", "send_error=3:string"},
		"aerolvm.rootd.v1.MatchProcessRequest":    {"pid=1:uint32", "local=2:string", "remote=3:string", "paths=4:repeated string"},
		"aerolvm.rootd.v1.MatchProcessResponse":   {"matched=1:repeated string", "not_found=2:bool"},
		"aerolvm.rootd.v1.HostPortForward":        {"host_port=1:uint32", "kind=2:enum", "address=3:string", "port=4:uint32"},
		"aerolvm.rootd.v1.HostPortRequest":        {"op=1:enum", "forwards=2:repeated message", "host_port=3:uint32"},
		"aerolvm.rootd.v1.HostPortResponse":       {"skipped=1:repeated uint32"},
		"aerolvm.rootd.v1.ExternalMount": {"type=1:string", "target=2:string", "source=3:string", "options=4:map",
			"read_only=5:bool", "credentials=6:map"},
		"aerolvm.rootd.v1.MountExternalRequest":        {"sandbox_id=1:string", "mode=2:enum", "mounts=3:repeated message"},
		"aerolvm.rootd.v1.MountBind":                   {"host_path=1:string", "target=2:string", "read_only=3:bool"},
		"aerolvm.rootd.v1.MountExternalResponse":       {"binds=1:repeated message", "kept=2:repeated uint32", "gone=3:repeated uint32", "already=4:bool"},
		"aerolvm.rootd.v1.UnmountExternalRequest":      {"sandbox_id=1:string", "discard=2:bool"},
		"aerolvm.rootd.v1.UnmountExternalResponse":     {"had=1:bool"},
		"aerolvm.rootd.v1.SweepExternalMountsRequest":  {"keep=1:repeated string"},
		"aerolvm.rootd.v1.SweepExternalMountsResponse": nil,
		"aerolvm.rootd.v1.ReclaimVolumeRequest":        {"source=1:string"},
		"aerolvm.rootd.v1.ReclaimVolumeResponse":       nil,
		"aerolvm.rootd.v1.HostLimits":                  {"cpu_millis=1:uint32", "memory_mb=2:uint64", "pids=3:uint32"},
		"aerolvm.rootd.v1.PrepareHostRequest":          {"kind=1:enum", "id=2:string", "firecracker=3:message"},
		"aerolvm.rootd.v1.PrepareHostResponse":         {"run_dir=1:string", "stage_dir=2:string"},
		"aerolvm.rootd.v1.FirecrackerHostSpec":         {"stage=1:repeated string"},
		"aerolvm.rootd.v1.EnsureTapRequest":            {"name=1:string", "guest_cid=2:uint32"},
		"aerolvm.rootd.v1.EnsureTapResponse":           {"cidr=1:string", "host_ip=2:string", "guest_ip=3:string", "vsock_cid=4:uint32"},
		"aerolvm.rootd.v1.RemoveTapRequest":            {"name=1:string"},
		"aerolvm.rootd.v1.RemoveTapResponse":           nil,
		"aerolvm.rootd.v1.MakeFilesystemRequest":       {"id=1:string", "name=2:string", "source=3:string", "size_mib=4:uint64"},
		"aerolvm.rootd.v1.MakeFilesystemResponse":      nil,
		"aerolvm.rootd.v1.WasmHostSpec":                {"cache=1:string", "env=2:repeated string"},
		"aerolvm.rootd.v1.SpawnHostRequest":            {"kind=1:enum", "id=2:string", "limits=3:message", "wasm=4:message"},
		"aerolvm.rootd.v1.SpawnHostResponse":           {"pid=1:uint32", "start_ticks=2:uint64", "already=3:bool", "socket=4:string"},
		"aerolvm.rootd.v1.StopHostRequest":             {"kind=1:enum", "id=2:string"},
		"aerolvm.rootd.v1.StopHostResponse":            {"had=1:bool"},
		"aerolvm.rootd.v1.ListHostsRequest":            {"kind=1:enum"},
		"aerolvm.rootd.v1.RunningHost":                 {"kind=1:enum", "id=2:string", "pid=3:uint32", "start_ticks=4:uint64"},
		"aerolvm.rootd.v1.ListHostsResponse":           {"hosts=1:repeated message"},
		"aerolvm.rootd.v1.SetHostLimitsRequest":        {"kind=1:enum", "id=2:string", "limits=3:message"},
		"aerolvm.rootd.v1.SetHostLimitsResponse":       nil,
		"aerolvm.rootd.v1.EnsureGuestFirewallRequest":  nil,
		"aerolvm.rootd.v1.EnsureGuestFirewallResponse": nil,
		"aerolvm.rootd.v1.GuestRulesRequest":           {"guest_ip=1:string", "op=2:enum", "allow_cidrs=3:repeated string", "deny_cidrs=4:repeated string"},
		"aerolvm.rootd.v1.GuestRulesResponse":          {"inserted=1:bool"},
		"aerolvm.rootd.v1.FirecrackerFilesRequest":     {"id=1:string", "names=2:repeated string"},
		"aerolvm.rootd.v1.FirecrackerFilesResponse":    nil,
		"aerolvm.rootd.v1.GrantWasmMountsRequest":      {"sandbox_id=1:string", "kind=2:enum", "host_id=3:string"},
		"aerolvm.rootd.v1.GrantWasmMountsResponse":     {"granted=1:uint32"},
		"aerolvm.rootd.v1.CheckpointMoveRequest":       {"sandbox_id=1:string"},
		"aerolvm.rootd.v1.CheckpointMoveResponse":      nil,
		"aerolvm.rootd.v1.ExportMoveRequest":           {"sandbox_id=1:string"},
		"aerolvm.rootd.v1.MoveChunk":                   {"data=1:bytes"},
		"aerolvm.rootd.v1.ImportMoveRequest":           {"sandbox_id=1:string", "data=2:bytes"},
		"aerolvm.rootd.v1.ImportMoveResponse":          {"restore_path=1:string"},
		"aerolvm.rootd.v1.StagedMoveRequest":           {"sandbox_id=1:string"},
		"aerolvm.rootd.v1.StagedMoveResponse":          {"restore_path=1:string"},
		"aerolvm.rootd.v1.DropMoveRequest":             {"sandbox_id=1:string", "sides=2:repeated enum"},
		"aerolvm.rootd.v1.DropMoveResponse":            nil,
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
			switch {
			case f.IsMap():
				kind = "map"
			case f.IsList():
				kind = "repeated " + kind
			}
			got = append(got, fmt.Sprintf("%s=%d:%s", f.Name(), f.Number(), kind))
		}
		w, ok := want[m.FullName()]
		if !ok || !slices.Equal(got, w) {
			t.Errorf("%s fields %v, pinned %v", m.FullName(), got, w)
		}
	}

	// Enum values are wire numbers too.
	wantEnums := map[protoreflect.FullName][]string{
		"aerolvm.rootd.v1.RunscConfig": {"RUNSC_CONFIG_UNSPECIFIED=0", "RUNSC_CONFIG_DEFAULT=1", "RUNSC_CONFIG_RESTORE=2"},
		"aerolvm.rootd.v1.SandboxRulesOp": {"SANDBOX_RULES_OP_UNSPECIFIED=0", "SANDBOX_RULES_OP_BLOCK_EGRESS=1", "SANDBOX_RULES_OP_LIFT_BLOCK_EGRESS=2",
			"SANDBOX_RULES_OP_CLEAR_BLOCK_EGRESS=3", "SANDBOX_RULES_OP_BLOCK_INGRESS=4", "SANDBOX_RULES_OP_CLEAR_BLOCK_INGRESS=5",
			"SANDBOX_RULES_OP_APPLY_EGRESS_POLICY=6", "SANDBOX_RULES_OP_CLEAR_EGRESS_POLICY=7", "SANDBOX_RULES_OP_HOLD_EGRESS=8",
			"SANDBOX_RULES_OP_CLEAR_HOLD_EGRESS=9"},
		"aerolvm.rootd.v1.BridgeProbeOp": {"BRIDGE_PROBE_OP_UNSPECIFIED=0", "BRIDGE_PROBE_OP_SETUP=1", "BRIDGE_PROBE_OP_SEND=2",
			"BRIDGE_PROBE_OP_CLOSE=3"},
		"aerolvm.rootd.v1.HostPortOp": {"HOST_PORT_OP_UNSPECIFIED=0", "HOST_PORT_OP_SET=1", "HOST_PORT_OP_REMOVE=2",
			"HOST_PORT_OP_RECONCILE=3"},
		"aerolvm.rootd.v1.HostPortKind": {"HOST_PORT_KIND_UNSPECIFIED=0", "HOST_PORT_KIND_SANDBOX=1", "HOST_PORT_KIND_PEER=2",
			"HOST_PORT_KIND_REDIRECT=3"},
		"aerolvm.rootd.v1.MountExternalMode": {"MOUNT_EXTERNAL_MODE_UNSPECIFIED=0", "MOUNT_EXTERNAL_MODE_CREATE=1",
			"MOUNT_EXTERNAL_MODE_REESTABLISH=2", "MOUNT_EXTERNAL_MODE_KEEP_LIVE=3"},
		"aerolvm.rootd.v1.HostKind": {"HOST_KIND_UNSPECIFIED=0", "HOST_KIND_WORKERD=1", "HOST_KIND_WASM_WORKER=2",
			"HOST_KIND_WASM_RESIDENT=3", "HOST_KIND_FIRECRACKER=4"},
		"aerolvm.rootd.v1.MoveSide": {"MOVE_SIDE_UNSPECIFIED=0", "MOVE_SIDE_OUT=1", "MOVE_SIDE_IN=2"},
	}
	enums := File_rootd_proto.Enums()
	if enums.Len() != len(wantEnums) {
		t.Fatalf("rootd.proto has %d enums, the table %d", enums.Len(), len(wantEnums))
	}
	for i := range enums.Len() {
		e := enums.Get(i)
		var got []string
		for j := range e.Values().Len() {
			v := e.Values().Get(j)
			got = append(got, fmt.Sprintf("%s=%d", v.Name(), v.Number()))
		}
		if w, ok := wantEnums[e.FullName()]; !ok || !slices.Equal(got, w) {
			t.Errorf("%s values %v, pinned %v", e.FullName(), got, w)
		}
	}
}

// fakeHelper serves only Version; every other call falls to the generated
// default, which every helper that has not built a call answers with.
type fakeHelper struct{ UnimplementedRootHelperServer }

func (fakeHelper) Version(_ context.Context, r *VersionRequest) (*VersionResponse, error) {
	return &VersionResponse{HelperVersion: "v-" + r.GetAgentVersion(), Api: r.GetAgentApi(), Features: []string{FeatureEnsureHost}}, nil
}

// TestStubsRoundTrip runs the generated client and server against each
// other, with and without an interceptor, for every call, and checks a
// message survives the wire.
func TestStubsRoundTrip(t *testing.T) {
	var calls []string
	for _, m := range RootHelper_ServiceDesc.Methods {
		calls = append(calls, m.MethodName)
	}
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
			want := []string{RootHelper_Version_FullMethodName}
			for _, name := range calls[1:] {
				m := reflect.ValueOf(c).MethodByName(name)
				req := reflect.New(m.Type().In(1).Elem())
				out := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), req})
				if err, _ := out[1].Interface().(error); status.Code(err) != codes.Unimplemented {
					t.Fatalf("%s = %v, want Unimplemented", name, err)
				}
				want = append(want, "/aerolvm.rootd.v1.RootHelper/"+name)
			}
			if intercept && !slices.Equal(seen, want) {
				t.Fatalf("interceptor saw %v, want %v", seen, want)
			}
		})
	}

	// Each message's generated methods and getters, set and nil: a decoder
	// can hand back a nil message.
	msgs := File_rootd_proto.Messages()
	for i := range msgs.Len() {
		mt, err := protoregistry.GlobalTypes.FindMessageByName(msgs.Get(i).FullName())
		if err != nil {
			t.Fatal(err)
		}
		m := mt.New()
		fillMessage(m)
		b, err := proto.Marshal(m.Interface())
		if err != nil {
			t.Fatal(err)
		}
		back := mt.New().Interface()
		if err := proto.Unmarshal(b, back); err != nil || !proto.Equal(m.Interface(), back) {
			t.Fatalf("%s round trip: %v", mt.Descriptor().FullName(), err)
		}
		g := m.Interface().(interface {
			Reset()
			String() string
			ProtoMessage()
			Descriptor() ([]byte, []int)
		})
		g.ProtoMessage()
		if _, idx := g.Descriptor(); len(idx) != 1 {
			t.Fatalf("%T descriptor index %v", g, idx)
		}
		_ = g.String()
		rv := reflect.ValueOf(g)
		for j := range rv.NumMethod() {
			name := rv.Type().Method(j).Name
			if !strings.HasPrefix(name, "Get") || rv.Method(j).Type().NumIn() != 0 {
				continue
			}
			if rv.Method(j).Call(nil)[0].IsZero() {
				t.Errorf("%T.%s of a filled message is zero", g, name)
			}
			nilMsg := reflect.Zero(rv.Type())
			if !nilMsg.MethodByName(name).Call(nil)[0].IsZero() {
				t.Errorf("a nil %T's %s is not zero", g, name)
			}
		}
		g.Reset()
	}
	for _, v := range []RunscConfig{RunscConfig_RUNSC_CONFIG_DEFAULT, RunscConfig_RUNSC_CONFIG_RESTORE} {
		if v.Enum() == nil || *v.Enum() != v || v.String() == "" || v.Number() != protoreflect.EnumNumber(v) ||
			v.Descriptor().FullName() != "aerolvm.rootd.v1.RunscConfig" || v.Type() == nil {
			t.Fatalf("enum %v methods", v)
		}
		if _, idx := v.EnumDescriptor(); len(idx) != 1 {
			t.Fatalf("enum descriptor index %v", idx)
		}
	}
	var u UnimplementedRootHelperServer
	ru := reflect.ValueOf(u)
	for _, name := range calls {
		m := ru.MethodByName(name)
		out := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.Zero(m.Type().In(1))})
		if err, _ := out[1].Interface().(error); status.Code(err) != codes.Unimplemented {
			t.Fatalf("Unimplemented %s = %v", name, err)
		}
	}
}

// fillMessage sets every field of m to something other than its zero.
func fillMessage(m protoreflect.Message) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if fd.IsMap() { // the mount calls' options and credentials
			m.Mutable(fd).Map().Set(protoreflect.ValueOfString("x").MapKey(), protoreflect.ValueOfString("x"))
			continue
		}
		var v protoreflect.Value
		switch fd.Kind() {
		case protoreflect.StringKind:
			v = protoreflect.ValueOfString("x")
		case protoreflect.BytesKind:
			v = protoreflect.ValueOfBytes([]byte{1})
		case protoreflect.Uint32Kind:
			v = protoreflect.ValueOfUint32(1)
		case protoreflect.Uint64Kind:
			v = protoreflect.ValueOfUint64(1)
		case protoreflect.BoolKind:
			v = protoreflect.ValueOfBool(true)
		case protoreflect.EnumKind:
			v = protoreflect.ValueOfEnum(1)
		case protoreflect.MessageKind:
			sub := m.NewField(fd)
			if fd.IsList() {
				sub = protoreflect.ValueOfMessage(m.NewField(fd).List().NewElement().Message())
			}
			fillMessage(sub.Message())
			v = sub
		default:
			panic("fillMessage: add kind " + fd.Kind().String())
		}
		if fd.IsList() {
			l := m.Mutable(fd).List()
			l.Append(v)
			continue
		}
		m.Set(fd, v)
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

// TestHelperRefusedIsTheError: the helper's refusal detail is an error
// matching ErrHelperRefused and nothing else, so containerd's client keeps
// it when it rebuilds an error from the status, and it is never read as
// the helper being down or too old.
func TestHelperRefusedIsTheError(t *testing.T) {
	var d error = &HelperRefused{Reason: "mount"}
	if !errors.Is(d, ErrHelperRefused) || errors.Is(d, ErrHelperUnavailable) || errors.Is(d, ErrHelperUnsupported) {
		t.Fatalf("detail %v does not match ErrHelperRefused alone", d)
	}
	if d.Error() != "root helper refused the call (mount)" || (&HelperRefused{}).Error() != ErrHelperRefused.Error() {
		t.Fatalf("Error() = %q", d.Error())
	}
}

// TestRefusedCarriesTheReason: Refused keeps the code and the message, and
// its reason comes back out after the status crosses a connection; a
// status without the detail, or an error that is no status, is no refusal.
func TestRefusedCarriesTheReason(t *testing.T) {
	err := Refused(codes.InvalidArgument, "bad_request", "root helper: hostname too long")
	// What the agent's side gets: the status rebuilt from its wire form.
	back := status.ErrorProto(status.Convert(err).Proto())
	if status.Code(back) != codes.InvalidArgument || status.Convert(back).Message() != "root helper: hostname too long" {
		t.Fatalf("status = %v", back)
	}
	for _, tc := range []struct {
		name   string
		err    error
		reason string
		ok     bool
	}{
		{"refused", back, "bad_request", true},
		{"wrapped", fmt.Errorf("ensure host files: %w", back), "bad_request", true},
		{"a refusal with no reason", Refused(codes.PermissionDenied, "", "x"), "", true},
		{"a plain status", status.Error(codes.PermissionDenied, "aerolvm root gate refused"), "", false},
		{"helper unavailable", mustDetail(t, codes.Unavailable, &HelperUnavailable{}), "", false},
		{"not a status", errors.New("refused"), "", false},
		{"nil", nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := RefusalReason(tc.err)
			if reason != tc.reason || ok != tc.ok {
				t.Fatalf("RefusalReason = %q, %v; want %q, %v", reason, ok, tc.reason, tc.ok)
			}
		})
	}
}

func mustDetail(t *testing.T, code codes.Code, d *HelperUnavailable) error {
	t.Helper()
	st, err := status.New(code, "down").WithDetails(d)
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

// TestCallName: the short name is Service.Method for every call the agent
// makes, and anything that is not a plain gRPC method name is "other", so
// the metric label stays a fixed set whatever arrives.
func TestCallName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/containerd.services.tasks.v1.Tasks/Create", "Tasks.Create"},
		{"/containerd.services.diff.v1.Diff/Apply", "Diff.Apply"},
		{RootHelper_EnsureHostFiles_FullMethodName, "RootHelper.EnsureHostFiles"},
		{"/grpc.health.v1.Health/Check", "Health.Check"},
		{"/Tasks/Create", "Tasks.Create"},
		{"connect", "connect"},
		{"peer_not_allowed", "peer_not_allowed"},
		{"", CallOther},
		{"Tasks/Create", CallOther},
		{"/containerd.services.tasks.v1.Tasks", CallOther},
		{"/a.B/C/D", CallOther},
		{"/a.B/", CallOther},
		{"/a.B/C D", CallOther},
		{"/a.B/" + strings.Repeat("x", 65), CallOther},
		{"/a.9B/C", CallOther},
		{"Connect", CallOther},
	} {
		if got := CallName(tc.in); got != tc.want {
			t.Errorf("CallName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRequestsNameNoPaths: no request the agent sends names a path, a
// folder or a file, or carries bytes for root to write, beyond the egress
// CA's DER, which the helper parses as a certificate and writes itself.
// The helper builds every path from IDs it checks (plans/security-gaps
// §3: the agent sends typed values, never a path for root to trust). A
// field that breaks this must be argued for here, not slipped in.
func TestRequestsNameNoPaths(t *testing.T) {
	msgs := File_rootd_proto.Messages()
	// An import's data is a move bundle's bytes (M1 PR 13). The helper
	// writes them only as that format lets it (movebundle.ReadDir: a
	// manifest for this sandbox, then exactly the regular files it names,
	// each once, by flat names), bounded in size, in a folder of its own
	// that only root can open. They are a sandbox's checkpoint, which runsc
	// reads; the agent could already reach the sandbox it holds (eng
	// review R9), and a file it could still change after the helper's
	// check is what the copy avoids.
	bytesOK := map[protoreflect.FullName]bool{"aerolvm.rootd.v1.EnsureHostFilesRequest.egress_ca_der": true,
		"aerolvm.rootd.v1.ImportMoveRequest.data": true}
	// MatchProcess's paths are executables a sandbox's own rules list. The
	// helper never opens one on the host's tree: each is resolved inside
	// the sandbox's root (openat2 RESOLVE_IN_ROOT under /proc/<pid>/root)
	// and only compared, by file identity, with what the sandbox's
	// processes run (internal/egress/procid).
	pathOK := map[protoreflect.FullName]bool{"aerolvm.rootd.v1.MatchProcessRequest.paths": true}
	var check func(m protoreflect.MessageDescriptor)
	check = func(m protoreflect.MessageDescriptor) {
		for i := range m.Fields().Len() {
			f := m.Fields().Get(i)
			name := strings.ToLower(string(f.Name()))
			for _, bad := range []string{"path", "dir", "file", "folder", "content", "toml", "body"} {
				if strings.Contains(name, bad) && !pathOK[f.FullName()] {
					t.Errorf("%s: a request field named like a path or a file's content", f.FullName())
				}
			}
			if f.Kind() == protoreflect.BytesKind && !bytesOK[f.FullName()] {
				t.Errorf("%s: raw bytes in a request", f.FullName())
			}
			if f.Kind() == protoreflect.MessageKind {
				check(f.Message())
			}
		}
	}
	for i := range msgs.Len() {
		if m := msgs.Get(i); strings.HasSuffix(string(m.Name()), "Request") {
			check(m)
		}
	}
}
