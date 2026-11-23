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

// TestE2EBrokenAgentWasmMounts sends a broken agent's mount loans (M1 PR
// 15) to a live helper, over its socket, as the agent's own uid (the PR 15
// box, AEROL_E2E_HELPER_SOCKET). AEROL_E2E_LEND_SANDBOX names a sandbox
// with mounts, and AEROL_E2E_LEND_OTHER another sandbox's running WASM
// worker: lending the first's mounts to the second is refused as another
// tenant's host, and every malformed loan is refused before the helper
// opens anything.
func TestE2EBrokenAgentWasmMounts(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	owner, other := os.Getenv("AEROL_E2E_LEND_SANDBOX"), os.Getenv("AEROL_E2E_LEND_OTHER")
	if sock == "" || owner == "" || other == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET, AEROL_E2E_LEND_SANDBOX and AEROL_E2E_LEND_OTHER")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	const (
		wasm = rootdpb.HostKind_HOST_KIND_WASM_WORKER
		res  = rootdpb.HostKind_HOST_KIND_WASM_RESIDENT
	)
	for _, tc := range []struct {
		name   string
		id     string
		kind   rootdpb.HostKind
		host   string
		code   codes.Code
		reason string
	}{
		{"a sandbox id with ../", "../" + owner, wasm, other, codes.InvalidArgument, string(rootpolicy.RuleExternalMount)},
		{"a sandbox id that is a path", "/etc", wasm, other, codes.InvalidArgument, string(rootpolicy.RuleExternalMount)},
		{"a V8 group as the host", owner, rootdpb.HostKind_HOST_KIND_WORKERD, "g", codes.InvalidArgument, ReasonHostKind},
		{"a Firecracker VM as the host", owner, rootdpb.HostKind_HOST_KIND_FIRECRACKER, owner, codes.InvalidArgument, ReasonHostKind},
		{"a host id with ../", owner, wasm, "../" + other, codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"a resident host id that is a path", owner, res, "a/b", codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"the machinery's group", owner, wasm, "aerolvm-mounts", codes.InvalidArgument, string(rootpolicy.RuleHost)},
		{"another tenant's worker", owner, wasm, other, codes.PermissionDenied, ReasonWasmMountHost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err := c.GrantWasmMounts(ctx, &rootdpb.GrantWasmMountsRequest{SandboxId: tc.id, Kind: tc.kind, HostId: tc.host})
			if status.Code(err) != tc.code {
				t.Fatalf("got %v, want %v", err, tc.code)
			}
			if reason, refused := rootdpb.RefusalReason(err); !refused || reason != tc.reason {
				t.Fatalf("refusal %q (%v), want %q: %v", reason, refused, tc.reason, err)
			}
		})
	}
	// A host that does not run is the agent's race, answered, not reported.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := c.GrantWasmMounts(ctx, &rootdpb.GrantWasmMountsRequest{SandboxId: owner, Kind: wasm, HostId: "e2e-no-such-host"})
	if _, refused := rootdpb.RefusalReason(err); status.Code(err) != codes.NotFound || refused {
		t.Fatalf("a host that does not run: %v", err)
	}
}
