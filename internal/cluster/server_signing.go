package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// Routes for signing that only servers do (least privilege): the feed of
// public keys every node verifies sandbox tokens with, and the two calls a
// sandbox's owner makes to have a server sign for it.
const (
	PublicInternalSigningKeysPath       = "/v1/cluster/internal/signing-keys"
	PublicInternalSandboxTokenSignPath  = "/v1/cluster/internal/sandbox-tokens/sign"
	PublicInternalIdentityTokenSignPath = "/v1/cluster/internal/identity/sign"
)

// SigningKeys is the feed: when the server keys took over, and the public
// sandbox token keys by id. Since is 0 while there is no server signing
// record: every node still signs and verifies with the server key ring.
type SigningKeys struct {
	SinceUnixNano int64             `json:"since_unix_nano"`
	TokenKeys     map[uint32][]byte `json:"token_keys,omitempty"`
}

// SandboxTokenSignRequest is a token's claims, as the sandbox's owner made
// them, for a server to check and sign. Claims is pkg/sandboxtoken.Claims
// in its JSON form.
type SandboxTokenSignRequest struct {
	Claims json.RawMessage `json:"claims"`
}

// SandboxTokenSignResponse is the signed token.
type SandboxTokenSignResponse struct {
	Token string `json:"token"`
	KeyID uint32 `json:"key_id"`
}

// IdentityTokenSignRequest names the sandbox a cloud-identity token is for.
// A server builds every claim itself from the sandbox's placement.
type IdentityTokenSignRequest struct {
	SandboxID     string `json:"sandbox_id"`
	IncarnationID string `json:"incarnation_id,omitempty"`
}

// IdentityTokenSignResponse is the signed token and its claims, which the
// owner records in its audit log.
type IdentityTokenSignResponse struct {
	Token  string               `json:"token"`
	KeyID  string               `json:"key_id"`
	Claims cloudidentity.Claims `json:"claims"`
}

// ServerSigningRecord is this server's copy of the record (fsm_server_signing.go).
func (c *Cluster) ServerSigningRecord() (ServerSigning, bool) {
	if c == nil || c.fsm == nil {
		return ServerSigning{}, false
	}
	return c.fsm.serverSigningRecord()
}

// ServerSigningAllowed reports whether the record may be written: the
// active cluster version says every member runs a build that verifies what
// servers sign.
func (c *Cluster) ServerSigningAllowed() bool {
	return c != nil && c.fsm != nil && c.fsm.activeFVValue() >= serverSigningFSMOpsVersion
}

// WriteServerSigning proposes a write of the record on this leader: the
// first write, or a reseal. Only the leader writes it; another server
// answers ErrNotLeader and the caller retries on its next pass.
func (c *Cluster) WriteServerSigning(ctx context.Context, w ServerSigningWrite) (ServerSigning, error) {
	if !c.IsLeader() {
		return ServerSigning{}, ErrNotLeader
	}
	if len(w.Expect) == 0 && !c.ServerSigningAllowed() {
		return ServerSigning{}, fmt.Errorf("%w: the active cluster version is below %d", ErrClusterVersion, serverSigningFSMOpsVersion)
	}
	payload, err := encodeCommand(command{Op: opPutServerSigning, StampUnixNano: time.Now().UnixNano(), ServerSigning: &w})
	if err != nil {
		return ServerSigning{}, err
	}
	res, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return ServerSigning{}, err
	}
	out, _ := res.(serverSigningApplyResult)
	return out.Record, nil
}

// FetchSigningKeys asks the server tier for the feed. A server tier from
// before it answers 404: no record anywhere, the ring signs.
func (a *Agent) FetchSigningKeys(ctx context.Context) (SigningKeys, error) {
	var out SigningKeys
	err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalSigningKeysPath, PublicInternalSigningKeysPath, nil, &out)
	if isStatus(err, http.StatusNotFound) {
		return SigningKeys{}, nil
	}
	return out, err
}

// SignSandboxToken has a server sign claims for a sandbox this node owns.
func (a *Agent) SignSandboxToken(ctx context.Context, req SandboxTokenSignRequest) (SandboxTokenSignResponse, error) {
	var out SandboxTokenSignResponse
	err := a.doControlPlaneJSON(ctx, http.MethodPost, PublicInternalSandboxTokenSignPath, PublicInternalSandboxTokenSignPath, req, &out)
	return out, err
}

// ErrIdentityRoleGone is a server's refusal to sign for a role tag no
// longer on the owner's allow list (410).
var ErrIdentityRoleGone = errors.New("cluster: the role tag is no longer allowed")

// SignIdentityToken has a server sign a cloud-identity token for a sandbox
// this node owns.
func (a *Agent) SignIdentityToken(ctx context.Context, req IdentityTokenSignRequest) (IdentityTokenSignResponse, error) {
	var out IdentityTokenSignResponse
	req.SandboxID = strings.TrimSpace(req.SandboxID)
	err := a.doControlPlaneJSON(ctx, http.MethodPost, PublicInternalIdentityTokenSignPath, PublicInternalIdentityTokenSignPath, req, &out)
	if isStatus(err, http.StatusGone) {
		return out, fmt.Errorf("%w: %v", ErrIdentityRoleGone, err)
	}
	return out, err
}
