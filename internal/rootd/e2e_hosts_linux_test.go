//go:build linux

package rootd

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestE2EBrokenAgentHosts sends a broken agent's host-process asks (M1 PR
// 9) to a live helper, over its socket, as the agent's own uid (the PR 9
// box, AEROL_E2E_HELPER_SOCKET). Each is refused, and none starts,
// prepares or stops anything: the box checks the helper's folders and the
// processes after.
func TestE2EBrokenAgentHosts(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	const (
		v8   = rootdpb.HostKind_HOST_KIND_WORKERD
		wasm = rootdpb.HostKind_HOST_KIND_WASM_WORKER
		res  = rootdpb.HostKind_HOST_KIND_WASM_RESIDENT
	)
	spawn := func(kind rootdpb.HostKind, id string, l *rootdpb.HostLimits, w *rootdpb.WasmHostSpec) func(context.Context) error {
		return func(ctx context.Context) error {
			_, err := c.SpawnHost(ctx, &rootdpb.SpawnHostRequest{Kind: kind, Id: id, Limits: l, Wasm: w})
			return err
		}
	}
	for _, tc := range []struct {
		name   string
		call   func(context.Context) error
		code   codes.Code
		reason string
	}{
		{"no kind", spawn(0, "g", nil, nil), codes.InvalidArgument, ReasonHostKind},
		{"a V8 group up the tree", spawn(v8, "../../etc", nil, nil), codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"the jails' base tree", spawn(v8, ".base", nil, nil), codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a V8 group as an option", spawn(v8, "-rf", nil, nil), codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a V8 group with the node's memory and more", spawn(v8, "e2e-big", &rootdpb.HostLimits{MemoryMb: 1 << 40}, nil),
			codes.InvalidArgument, string(rootpolicy.RuleHostLimits)},
		{"a V8 group with more pids than a sandbox", spawn(v8, "e2e-pids", &rootdpb.HostLimits{Pids: 1 << 30}, nil),
			codes.InvalidArgument, string(rootpolicy.RuleHostLimits)},
		{"a WASM spec on a V8 group", spawn(v8, "e2e-x", nil, &rootdpb.WasmHostSpec{}), codes.InvalidArgument, ReasonBadRequest},
		{"a WASM worker named by a path", spawn(wasm, "../w", nil, &rootdpb.WasmHostSpec{}), codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a WASM worker in the machinery's group", spawn(wasm, "_runtime", nil, &rootdpb.WasmHostSpec{}), codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a WASM cache out of the cache root", spawn(wasm, "e2e-w", nil, &rootdpb.WasmHostSpec{Cache: "../../../root"}),
			codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a WASM worker library path", spawn(wasm, "e2e-w", nil, &rootdpb.WasmHostSpec{Env: []string{"LD_PRELOAD=/tmp/x.so"}}),
			codes.InvalidArgument, ReasonBadRequest},
		{"a WASM worker operator file", spawn(wasm, "e2e-w", nil, &rootdpb.WasmHostSpec{Env: []string{"SB_EGRESS_OPERATOR_FILE=/etc/shadow"}}),
			codes.InvalidArgument, ReasonBadRequest},
		{"a WASM worker that is not dropped", spawn(wasm, "e2e-w", nil, &rootdpb.WasmHostSpec{Env: []string{"AEROL_WASM_WORKER_CONFINE=0:0"}}),
			codes.InvalidArgument, ReasonBadRequest},
		{"a WASM cache by its folder", spawn(res, "e2e-r", nil, &rootdpb.WasmHostSpec{Env: []string{"AEROL_WASM_WORKER_CACHE_DIR=/"}}),
			codes.InvalidArgument, ReasonBadRequest},
		{"WASM limits", spawn(wasm, "e2e-w", &rootdpb.HostLimits{Pids: 1}, &rootdpb.WasmHostSpec{}), codes.InvalidArgument, ReasonBadRequest},
		{"a V8 jail prepared up the tree", func(ctx context.Context) error {
			_, err := c.PrepareHost(ctx, &rootdpb.PrepareHostRequest{Kind: v8, Id: "a/../../b"})
			return err
		}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a stop up the tree", func(ctx context.Context) error {
			_, err := c.StopHost(ctx, &rootdpb.StopHostRequest{Kind: v8, Id: ".."})
			return err
		}, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"limits past the node", func(ctx context.Context) error {
			_, err := c.SetHostLimits(ctx, &rootdpb.SetHostLimitsRequest{Kind: v8, Id: "g", Limits: &rootdpb.HostLimits{CpuMillis: 1 << 31}})
			return err
		}, codes.InvalidArgument, string(rootpolicy.RuleHostLimits)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			err := tc.call(ctx)
			if status.Code(err) != tc.code {
				t.Fatalf("got %v, want %v", err, tc.code)
			}
			if reason, refused := rootdpb.RefusalReason(err); !refused || reason != tc.reason {
				t.Fatalf("refusal %q (%v), want %q: %v", reason, refused, tc.reason, err)
			}
		})
	}
}
