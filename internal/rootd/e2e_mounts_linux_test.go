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
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestE2EBrokenAgentMounts sends a broken agent's mount asks to a live
// helper, over its socket, as the agent's own uid (the PR 8 end-to-end box,
// AEROL_E2E_HELPER_SOCKET). AEROL_E2E_LINKED_ID names a sandbox whose
// folder the box planted as a link out of the mounts folder. The box
// checks afterwards that nothing was mounted and no secret reached the
// helper's log.
func TestE2EBrokenAgentMounts(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	const secret = "e2e-s3cr3t-in-the-wrong-place"
	create := rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE
	nfs := func(opts string) *rootdpb.ExternalMount {
		return &rootdpb.ExternalMount{Type: "nfs", Target: "/share", Source: "127.0.0.1:/", Options: map[string]string{"opts": opts}}
	}
	s3 := func(extra string, creds map[string]string) *rootdpb.ExternalMount {
		return &rootdpb.ExternalMount{Type: "s3", Target: "/data", Source: "bkt",
			Options: map[string]string{"endpoint": "http://127.0.0.1:9000", "extra_args": extra}, Credentials: creds}
	}
	req := func(id string, ms ...*rootdpb.ExternalMount) *rootdpb.MountExternalRequest {
		return &rootdpb.MountExternalRequest{SandboxId: id, Mode: create, Mounts: ms}
	}
	unknown := req("sb-e2e-unknown", nfs("vers=4.2"))
	unknown.Mounts[0].ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 77, protowire.VarintType), 1))
	extMount := string(rootpolicy.RuleExternalMount)
	for _, tc := range []struct {
		name   string
		req    *rootdpb.MountExternalRequest
		code   codes.Code
		reason string
	}{
		{"a sandbox ID out of the mounts folder", req("../../etc", nfs("vers=4.2")), codes.InvalidArgument, extMount},
		{"a sandbox ID that is another's path", req("sb-a/../sb-b", nfs("vers=4.2")), codes.InvalidArgument, extMount},
		{"an NFS option off the list", req("sb-e2e", nfs("vers=4.2,helper=/tmp/x")), codes.InvalidArgument, extMount},
		{"NFS suid and dev", req("sb-e2e", nfs("suid,dev")), codes.InvalidArgument, extMount},
		{"an extra_arg off the list", req("sb-e2e", s3("--log-directory=/etc", nil)), codes.InvalidArgument, extMount},
		{"a cache folder of the caller's choosing", req("sb-e2e", s3("--cache /etc", nil)), codes.InvalidArgument, extMount},
		{"a credential in the arguments", req("sb-e2e", s3("--secret-access-key="+secret, nil)), codes.InvalidArgument, extMount},
		{"a credential no tool reads", req("sb-e2e", s3("", map[string]string{"access_key_id": "k", "secret_access_key": "s", "web_identity_token": secret})),
			codes.InvalidArgument, extMount},
		{"an s3 mount with no keys (the node's own role)", req("sb-e2e", s3("--force-path-style", nil)), codes.InvalidArgument, extMount},
		{"rclone env_auth (the node's own role)", req("sb-e2e", &rootdpb.ExternalMount{Type: "rclone", Target: "/rc", Source: ":s3,provider=AWS,env_auth=true:bkt"}),
			codes.InvalidArgument, extMount},
		{"rclone_conf use_msi", req("sb-e2e", &rootdpb.ExternalMount{Type: "rclone", Target: "/rc", Source: "a:c",
			Credentials: map[string]string{"rclone_conf": "[a]\ntype = azureblob\naccount = x\nuse_msi = true\n"}}), codes.InvalidArgument, extMount},
		{"rclone's local backend", req("sb-e2e", &rootdpb.ExternalMount{Type: "rclone", Target: "/rc", Source: ":local:/etc",
			Credentials: map[string]string{"rclone_conf": "[x]\ntype = s3\n"}}), codes.InvalidArgument, extMount},
		{"a mode the helper does not know", &rootdpb.MountExternalRequest{SandboxId: "sb-e2e", Mode: 42, Mounts: []*rootdpb.ExternalMount{nfs("vers=4.2")}},
			codes.InvalidArgument, ReasonBadRequest},
		{"a field the helper does not know", unknown, codes.Unimplemented, ""},
		{"a sandbox folder planted as a link", req(os.Getenv("AEROL_E2E_LINKED_ID"), nfs("vers=4.2,soft,timeo=10,retrans=1")),
			codes.PermissionDenied, ReasonMountFolder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.req.GetSandboxId() == "" {
				t.Skip("the box planted no link")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			start := time.Now()
			_, err := c.MountExternal(ctx, tc.req)
			reason, refused := rootdpb.RefusalReason(err)
			t.Logf("%s after %v: %v", tc.name, time.Since(start).Round(time.Microsecond), err)
			if status.Code(err) != tc.code || refused != (tc.reason != "") || reason != tc.reason {
				t.Fatalf("err %v (refused %v %q), want %v %q", err, refused, reason, tc.code, tc.reason)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the answer carries the credential: %v", err)
			}
		})
	}
	t.Run("a part no helper serves", func(t *testing.T) {
		_, err := c.PrepareSandbox(context.Background(), &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles, "mounts"},
			ContainerId: "sb-e2e", Setup: &rootdpb.ContainerSetup{TaskFifos: true}})
		if status.Code(err) != codes.Unimplemented {
			t.Fatalf("%v", err)
		}
	})
	t.Run("an unmount and a sweep under a path", func(t *testing.T) {
		_, err := c.UnmountExternal(context.Background(), &rootdpb.UnmountExternalRequest{SandboxId: "../.."})
		if r, ok := rootdpb.RefusalReason(err); !ok || r != extMount {
			t.Fatalf("unmount: %v", err)
		}
		_, err = c.SweepExternalMounts(context.Background(), &rootdpb.SweepExternalMountsRequest{Keep: []string{"/etc"}})
		if r, ok := rootdpb.RefusalReason(err); !ok || r != extMount {
			t.Fatalf("sweep: %v", err)
		}
	})
}

// TestE2EReclaimVolume asks a live helper whose own settings put platform
// volumes on the box's NFS export to reclaim one volume's folder
// (AEROL_E2E_RECLAIM_SOURCE), then to reclaim folders that are not one
// volume's. The box checks the folder is empty, its link's target and its
// neighbour untouched.
func TestE2EReclaimVolume(t *testing.T) {
	sock, src := os.Getenv("AEROL_E2E_HELPER_SOCKET"), os.Getenv("AEROL_E2E_RECLAIM_SOURCE")
	if sock == "" || src == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_RECLAIM_SOURCE")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := c.ReclaimVolume(ctx, &rootdpb.ReclaimVolumeRequest{Source: src}); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	server, dir, _ := strings.Cut(src, ":")
	for _, bad := range []string{server + ":/", server + ":" + dir[:strings.LastIndex(dir, "/")], src + "/../../..", "10.66.6.6:" + dir} {
		_, err := c.ReclaimVolume(ctx, &rootdpb.ReclaimVolumeRequest{Source: bad})
		if r, ok := rootdpb.RefusalReason(err); !ok || r != string(rootpolicy.RuleReclaim) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
