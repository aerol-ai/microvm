package rootclient

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// External storage mounts (M1 PR 8, internal/rootd mounts.go).

// MountExternal asks the helper to make sure a sandbox's mounts serve.
func (c *Client) MountExternal(ctx context.Context, req *rootdpb.MountExternalRequest) (*rootdpb.MountExternalResponse, error) {
	return call(ctx, c, rootdpb.FeatureMountExternal, req, rootdpb.RootHelperClient.MountExternal)
}

// UnmountExternal asks the helper to make sure a sandbox's mounts are gone.
// With discard it leaves a set another call is making alone, and answers
// whether there was anything to tear down.
func (c *Client) UnmountExternal(ctx context.Context, sandboxID string, discard bool) (bool, error) {
	resp, err := call(ctx, c, rootdpb.FeatureUnmountExternal,
		&rootdpb.UnmountExternalRequest{SandboxId: sandboxID, Discard: discard}, rootdpb.RootHelperClient.UnmountExternal)
	return resp.GetHad(), err
}

// SweepExternalMounts asks the helper to remove every sandbox's mounts but
// keep's.
func (c *Client) SweepExternalMounts(ctx context.Context, keep []string) error {
	_, err := call(ctx, c, rootdpb.FeatureSweepExternalMounts,
		&rootdpb.SweepExternalMountsRequest{Keep: keep}, rootdpb.RootHelperClient.SweepExternalMounts)
	return err
}

// Mounts is the agent's side of the mount calls: pkg/mounts' Remote, which
// the Manager of privilege mode split runs every call through. Client, a
// function so the daemon can set it once the client exists, is the helper.
type Mounts struct {
	Client func() *Client
}

var _ mounts.Remote = Mounts{}

var errNoClient = fmt.Errorf("%w: no root helper client yet", ErrUnavailable)

func (m Mounts) client() *Client {
	if m.Client == nil {
		return nil
	}
	return m.Client()
}

// Ready says why the helper cannot mount: one whose handshake lists no
// mount call (no mount user on the node, or a helper older than this
// agent). Before any handshake it says nothing, and the call will.
func (m Mounts) Ready() error {
	c := m.client()
	if c == nil {
		return nil
	}
	info, ok := c.Info()
	if !ok || info.Has(rootdpb.FeatureMountExternal) {
		return nil
	}
	return fmt.Errorf("the root helper %s serves no external storage mounts (its node has no mount user, SB_ROOTD_MOUNT_USER, or the helper is older than this agent)", info.HelperVersion)
}

// Mount checks specs with the helper's own rules before it sends them
// (rootpolicy.CheckExternalMounts): what this agent would send and the
// helper refuse is the caller's error, answered as one, never sent to
// count as a broken agent. It sends each mount only the credentials its
// tool reads.
func (m Mounts) Mount(ctx context.Context, sandboxID string, mode mounts.RemoteMode, specs []models.MountSpec) (mounts.RemoteResult, error) {
	c := m.client()
	if c == nil {
		return mounts.RemoteResult{}, errNoClient
	}
	var wireMode rootdpb.MountExternalMode
	switch mode {
	case mounts.RemoteCreate:
		wireMode = rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_CREATE
	case mounts.RemoteReestablish:
		wireMode = rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_REESTABLISH
	case mounts.RemoteKeepLive:
		wireMode = rootdpb.MountExternalMode_MOUNT_EXTERNAL_MODE_KEEP_LIVE
	default:
		return mounts.RemoteResult{}, fmt.Errorf("mount: unknown mode %d", mode)
	}
	sent := make([]models.MountSpec, len(specs))
	wire := make([]*rootdpb.ExternalMount, len(specs))
	for i, s := range specs {
		s.Credentials = onlyReadCredentials(s.Type, s.Credentials)
		sent[i] = s
		wire[i] = &rootdpb.ExternalMount{Type: string(s.Type), Target: s.Target, Source: s.Source,
			Options: s.Options, ReadOnly: s.ReadOnly, Credentials: s.Credentials}
	}
	if err := rootpolicy.CheckExternalMounts(sent, mode == mounts.RemoteKeepLive); err != nil {
		return mounts.RemoteResult{}, fmt.Errorf("mount: %w", err)
	}
	resp, err := c.MountExternal(ctx, &rootdpb.MountExternalRequest{SandboxId: sandboxID, Mode: wireMode, Mounts: wire})
	if err != nil {
		return mounts.RemoteResult{}, mountErr(err)
	}
	res := mounts.RemoteResult{Report: mounts.KeepReport{Already: resp.GetAlready()}}
	for _, b := range resp.GetBinds() {
		res.Binds = append(res.Binds, mounts.ContainerBind{HostPath: b.GetHostPath(), ContainerPath: b.GetTarget(), ReadOnly: b.GetReadOnly()})
	}
	for _, i := range resp.GetKept() {
		res.Report.Kept = append(res.Report.Kept, int(i))
	}
	for _, i := range resp.GetGone() {
		res.Report.Gone = append(res.Report.Gone, int(i))
	}
	return res, nil
}

// Unmount is UnmountExternal.
func (m Mounts) Unmount(ctx context.Context, sandboxID string, discard bool) (bool, error) {
	c := m.client()
	if c == nil {
		return false, errNoClient
	}
	had, err := c.UnmountExternal(ctx, sandboxID, discard)
	return had, mountErr(err)
}

// Sweep is SweepExternalMounts.
func (m Mounts) Sweep(ctx context.Context, keep []string) error {
	c := m.client()
	if c == nil {
		return errNoClient
	}
	return mountErr(c.SweepExternalMounts(ctx, keep))
}

// onlyReadCredentials keeps the credentials a type's tool reads: the rest
// has no reason to reach root, and single mode ignores it too.
func onlyReadCredentials(t models.MountType, in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, k := range adapters.CredentialKeys(t) {
		if v, ok := in[k]; ok {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mountErr turns the helper's answer to a failed mount call back into
// single mode's errors, so the API answers as it does there: a sandbox
// whose mounts serve (ErrMountsEstablished), a tool the node lacks
// (ErrMountToolUnavailable, 501), and the storage's own answer, as plain
// text (400). The client's own errors (the helper down, too old, busy, or
// a refusal) are kept as they are.
func mountErr(err error) error {
	if err == nil {
		return nil
	}
	var refused *RefusedError
	if errors.As(err, &refused) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrUnsupported) || errors.Is(err, ErrBusy) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.AlreadyExists:
		return fmt.Errorf("%w (%s)", mounts.ErrMountsEstablished, st.Message())
	case codes.FailedPrecondition:
		return fmt.Errorf("%w (%s)", mounts.ErrMountToolUnavailable, st.Message())
	case codes.Unknown:
		return errors.New(st.Message())
	}
	return err
}
