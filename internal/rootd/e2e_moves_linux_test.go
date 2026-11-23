//go:build linux

package rootd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runscwrap"
	"github.com/aerol-ai/microvm/internal/runtime/movebundle"
)

// TestE2EBrokenAgentMoves sends a broken agent's move asks (M1 PR 13) to a
// live helper over its socket, as the agent's own uid
// (AEROL_E2E_HELPER_SOCKET), with gVisor checkpoint moves on in the
// helper's settings and SB_ROOTD_MOVE_MAX_BYTES at AEROL_E2E_MOVE_MAX.
// Each must be refused, and the box checks nothing was written outside
// the moves folder.
func TestE2EBrokenAgentMoves(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" {
		t.Skip("a live run: set AEROL_E2E_HELPER_SOCKET")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	bundle := func(id string, entries ...*tar.Header) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		var names []string
		for _, h := range entries {
			names = append(names, h.Name)
		}
		raw, _ := json.Marshal(movebundle.Manifest{Version: 1, SandboxID: id, Files: names})
		_ = tw.WriteHeader(&tar.Header{Name: movebundle.ManifestName, Mode: 0o600, Size: int64(len(raw)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(raw)
		for _, h := range entries {
			_ = tw.WriteHeader(h)
			if h.Typeflag == tar.TypeReg {
				_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
			}
		}
		_ = tw.Close()
		return buf.Bytes()
	}
	reg := func(name string, size int64) *tar.Header {
		return &tar.Header{Name: name, Mode: 0o600, Size: size, Typeflag: tar.TypeReg}
	}
	big := int64(1 << 20)
	if v := os.Getenv("AEROL_E2E_MOVE_MAX"); v != "" {
		var n int64
		if err := json.Unmarshal([]byte(v), &n); err == nil {
			big = n + 1
		}
	}
	for _, tc := range []struct {
		name   string
		id     string
		data   []byte
		reason string
	}{
		{"a sandbox ID with ../", "../../etc", bundle("x", reg(runscwrap.CheckpointFile, 1)), ReasonBadRequest},
		{"a manifest for another sandbox", "sb-e2e", bundle("sb-other", reg(runscwrap.CheckpointFile, 1)), string(rootpolicy.RuleMoveBundle)},
		{"a file that climbs out", "sb-e2e", bundle("sb-e2e", reg("../../../../etc/cron.d/x", 1)), string(rootpolicy.RuleMoveBundle)},
		{"a link to the host", "sb-e2e", bundle("sb-e2e", &tar.Header{Name: runscwrap.CheckpointFile, Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}),
			string(rootpolicy.RuleMoveBundle)},
		{"a bundle past the bound", "sb-e2e", bundle("sb-e2e", reg(runscwrap.CheckpointFile, big)), string(rootpolicy.RuleMoveBundle)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			s, err := c.ImportMove(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = s.Send(&rootdpb.ImportMoveRequest{SandboxId: tc.id})
			for b := tc.data; len(b) > 0; {
				k := min(len(b), 1<<20)
				if s.Send(&rootdpb.ImportMoveRequest{Data: b[:k]}) != nil {
					break
				}
				b = b[k:]
			}
			_, err = s.CloseAndRecv()
			reason, refused := rootdpb.RefusalReason(err)
			t.Logf("%s: %v", tc.name, err)
			if !refused || reason != tc.reason {
				t.Fatalf("err %v, want a refusal %q", err, tc.reason)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "../../etc"})
	if reason, refused := rootdpb.RefusalReason(err); !refused || reason != ReasonBadRequest {
		t.Fatalf("a checkpoint of a path: %v", err)
	}
	_, err = c.DropMove(ctx, &rootdpb.DropMoveRequest{SandboxId: "sb-e2e", Sides: []rootdpb.MoveSide{rootdpb.MoveSide(7)}})
	if reason, refused := rootdpb.RefusalReason(err); !refused || reason != ReasonBadRequest {
		t.Fatalf("a drop of no side: %v", err)
	}
	// runsc has no such sandbox: an error, never a checkpoint.
	_, err = c.CheckpointMove(ctx, &rootdpb.CheckpointMoveRequest{SandboxId: "sb-nope"})
	if _, refused := rootdpb.RefusalReason(err); err == nil || refused || !strings.Contains(err.Error(), "runsc checkpoint") {
		t.Fatalf("a checkpoint of no sandbox: %v", err)
	}
	t.Logf("checkpoint of no sandbox: %v", err)
}

// TestE2EMovesWrongCaller: a process that is not the agent (another uid,
// AEROL_E2E_WRONG_CALLER) gets no move call through: the helper's peer
// check closes its connection before any call.
func TestE2EMovesWrongCaller(t *testing.T) {
	sock := os.Getenv("AEROL_E2E_HELPER_SOCKET")
	if sock == "" || os.Getenv("AEROL_E2E_WRONG_CALLER") == "" {
		t.Skip("a live run as another uid: set AEROL_E2E_HELPER_SOCKET and AEROL_E2E_WRONG_CALLER")
	}
	c := rootdpb.NewRootHelperClient(dialSocket(t, sock))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.StagedMove(ctx, &rootdpb.StagedMoveRequest{SandboxId: "sb-e2e"})
	t.Logf("staged as the wrong caller: %v", err)
	if err == nil || status.Code(err) == codes.OK {
		t.Fatal("the wrong caller was answered")
	}
	s, err := c.ImportMove(ctx)
	if err == nil {
		_ = s.Send(&rootdpb.ImportMoveRequest{SandboxId: "sb-e2e"})
		_, err = s.CloseAndRecv()
	}
	t.Logf("import as the wrong caller: %v", err)
	if err == nil {
		t.Fatal("the wrong caller's import was taken")
	}
}
