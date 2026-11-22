//go:build linux

package rootd

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestE2EBrokenAgent sends a broken agent's asks to a live helper, over
// its socket, as the agent's own uid, with real containerd behind it (the
// PR 7 end-to-end box, AEROL_E2E_HELPER_SOCKET). The box prepares the
// snapshots it names: one in another namespace, one under another
// snapshotter, an image's committed layer, and active snapshots over
// layers whose /etc/passwd is a FIFO, a link out of the image, or too big.
func TestE2EBrokenAgent(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	key := func(name string) string { return os.Getenv("AEROL_E2E_" + name) }
	user := func(id string) *rootdpb.PrepareSandboxRequest {
		return &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartImageUser}, ContainerId: id, ImageUser: &rootdpb.ImageUser{User: "appuser"}}
	}
	for _, tc := range []struct {
		name   string
		req    *rootdpb.PrepareSandboxRequest
		code   codes.Code
		reason string // "" when the call fails without a refusal
		text   string
	}{
		{"a snapshot of another namespace", user(key("OTHER_NS")), codes.NotFound, string(rootpolicy.RuleSnapshot), ""},
		{"a snapshot of another snapshotter", user(key("NATIVE")), codes.NotFound, string(rootpolicy.RuleSnapshot), ""},
		{"an image's committed layer", user(key("COMMITTED")), codes.InvalidArgument, string(rootpolicy.RuleSnapshot), ""},
		{"a FIFO passwd", user(key("FIFO")), codes.FailedPrecondition, "", "not a regular file"},
		{"a passwd that links out of the image", user(key("LINK")), codes.FailedPrecondition, "", "no such file"},
		{"a huge passwd", user(key("HUGE")), codes.FailedPrecondition, "", "not a regular file"},
		{"a zero quota", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartDiskQuota}, ContainerId: key("FIFO"),
			DiskQuota: &rootdpb.DiskQuota{}}, codes.InvalidArgument, string(rootpolicy.RuleDiskQuota), ""},
		{"files for a path", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "../../etc",
			Setup: &rootdpb.ContainerSetup{TaskFifos: true}}, codes.InvalidArgument, ReasonBadRequest, ""},
		{"a newer agent's part", &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles, "files-v2"}, ContainerId: "sb-x",
			Setup: &rootdpb.ContainerSetup{TaskFifos: true}}, codes.Unimplemented, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.req.GetContainerId() == "" {
				t.Skip("the box made no such snapshot")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			start := time.Now()
			_, err := c.PrepareSandbox(ctx, tc.req)
			reason, refused := rootdpb.RefusalReason(err)
			t.Logf("%s after %v: %v", tc.name, time.Since(start).Round(time.Microsecond), err)
			if status.Code(err) != tc.code || refused != (tc.reason != "") || reason != tc.reason || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("err %v (refused %v %q), want %v %q %q", err, refused, reason, tc.code, tc.reason, tc.text)
			}
		})
	}
}
