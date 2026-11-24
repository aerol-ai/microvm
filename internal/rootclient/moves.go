package rootclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// The gVisor checkpoint move calls (M1 PR 13): in privilege mode split the
// helper runs runsc checkpoint on a sandbox moving away and keeps its
// checkpoint, and takes in and stages the bundle of one moving here, in
// its own moves folder (internal/rootd moves.go). The agent names a
// sandbox by its ID; the bundle's bytes pass through the agent on their
// way from or to the other worker, which seals them (pkg/secrets).

// DefaultMoveTimeout bounds a checkpoint, an export or an import whose
// context has no deadline: a checkpoint saves a sandbox's whole memory,
// and a bundle carries it.
const DefaultMoveTimeout = 10 * time.Minute

// moveChunk is the size of one message of a bundle's bytes, as the
// helper's own.
const moveChunk = 1 << 20

// moveCalls are the calls bounded by DefaultMoveTimeout.
var moveCalls = map[string]bool{
	rootdpb.FeatureCheckpointMove: true,
	rootdpb.FeatureExportMove:     true,
	rootdpb.FeatureImportMove:     true,
}

// CheckpointMove has the helper save a running gVisor sandbox for a move,
// with runsc checkpoint, which ends the sandbox once it is saved.
func (c *Client) CheckpointMove(ctx context.Context, sandboxID string) error {
	_, err := call(ctx, c, rootdpb.FeatureCheckpointMove, &rootdpb.CheckpointMoveRequest{SandboxId: sandboxID}, rootdpb.RootHelperClient.CheckpointMove)
	return err
}

// StagedMove answers the folder of the checkpoint staged for a sandbox's
// restore, "" when none is.
func (c *Client) StagedMove(ctx context.Context, sandboxID string) (string, error) {
	resp, err := call(ctx, c, rootdpb.FeatureStagedMove, &rootdpb.StagedMoveRequest{SandboxId: sandboxID}, rootdpb.RootHelperClient.StagedMove)
	return resp.GetRestorePath(), err
}

// DropMove has the helper make sure a sandbox's checkpoints on sides are
// gone.
func (c *Client) DropMove(ctx context.Context, sandboxID string, sides ...rootdpb.MoveSide) error {
	_, err := call(ctx, c, rootdpb.FeatureDropMove, &rootdpb.DropMoveRequest{SandboxId: sandboxID, Sides: sides}, rootdpb.RootHelperClient.DropMove)
	return err
}

// ExportMove writes the checkpoint the helper saved for a sandbox to w, as
// a move bundle. A dropped stream is not sent again: part of it may be in w
// already.
func (c *Client) ExportMove(ctx context.Context, sandboxID string, w io.Writer) error {
	const feature = rootdpb.FeatureExportMove
	s, err := c.require(ctx, feature)
	if err != nil {
		return err
	}
	cctx, cancel := c.callContext(ctx, feature)
	defer cancel()
	stream, err := s.rpc.ExportMove(cctx, &rootdpb.ExportMoveRequest{SandboxId: sandboxID})
	if err != nil {
		return c.callErr(ctx, s, feature, err)
	}
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return c.callErr(ctx, s, feature, err)
		}
		if _, err := w.Write(msg.GetData()); err != nil {
			return fmt.Errorf("export %s: %w", sandboxID, err)
		}
	}
}

// ImportMove sends the move bundle r holds for a sandbox to the helper,
// which stages it for the sandbox's restore, and answers the staged
// checkpoint's folder. When r fails, the stream is cut rather than
// closed, so the helper stages nothing of a bundle that is not whole.
func (c *Client) ImportMove(ctx context.Context, sandboxID string, r io.Reader) (string, error) {
	const feature = rootdpb.FeatureImportMove
	s, err := c.require(ctx, feature)
	if err != nil {
		return "", err
	}
	cctx, cancel := c.callContext(ctx, feature)
	defer cancel()
	// A cancel of its own: callContext hands back the caller's context as
	// it is when it has a deadline, and the stream must end at once when
	// the reader fails.
	cctx, cut := context.WithCancel(cctx)
	defer cut()
	stream, err := s.rpc.ImportMove(cctx)
	if err != nil {
		return "", c.callErr(ctx, s, feature, err)
	}
	buf := make([]byte, moveChunk)
	for first := true; ; first = false {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 || first {
			// A copy: a sent message must not change after it is sent.
			msg := &rootdpb.ImportMoveRequest{Data: bytes.Clone(buf[:n])}
			if first {
				msg.SandboxId = sandboxID
			}
			if err := stream.Send(msg); err != nil {
				// The helper ended the call: its answer says why.
				if errors.Is(err, io.EOF) {
					break
				}
				return "", c.callErr(ctx, s, feature, err)
			}
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			// The deferred cut ends the stream, never closed.
			return "", fmt.Errorf("import %s: read the bundle: %w", sandboxID, rerr)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return "", c.callErr(ctx, s, feature, err)
	}
	return resp.GetRestorePath(), nil
}
