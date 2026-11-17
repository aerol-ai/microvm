package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
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
	// OldTokensEndUnixNano is the record's (ServerSigning): once set, no
	// token signed the old way counts.
	OldTokensEndUnixNano int64 `json:"old_tokens_end_unix_nano,omitempty"`
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

// ServerSigningGate is whether the leader may write the record, and why
// not; once it may, Waiting is for the operator to see.
type ServerSigningGate struct {
	// ActiveFV is the active cluster version's fv (0: never written).
	ActiveFV int
	// FirstWrite: the active version is its first write, which counted
	// only the servers (active_version.go).
	FirstWrite bool
	// Waiting names the live members that report a version below the one
	// servers sign from, or none at all (0: their meta is not seen).
	Waiting []string
	// RolesInCertificates is whether this server's certificate names its
	// role: in a cluster signed before roles, no peer can prove it is a
	// server, so servers never take over.
	RolesInCertificates bool
	// ServersAtVersion: every Raft server runs a build at the version
	// servers sign from, so each one applies the record. RolloutInFlight:
	// a rollout is under way, whose finalize moves the active version.
	ServersAtVersion bool
	RolloutInFlight  bool
	// Allowed and, when not, Reason.
	Allowed bool
	Reason  string
}

// Held reports whether the record waits on something only the operator
// can resolve: the active version allows it, or every server runs the
// build with no rollout to move the active version, and still the gate
// is shut (the gauge aerolvm_server_signing_held, its alert, and the
// leader's log).
func (g ServerSigningGate) Held() bool {
	return !g.Allowed && (g.ActiveFV >= serverSigningFSMOpsVersion || g.ServersAtVersion && !g.RolloutInFlight)
}

// ServerSigningGate reads the gate. The record is written once the active
// cluster version reaches serverSigningFSMOpsVersion: Raft-backed and
// forward-only, it moves there only when a rollout that brought every
// member is finalized, or once every live member reports it (no rollout),
// so every member verifies what servers sign. Gossip, each member's own
// word, does not hold it then; its laggards are listed (Waiting) and
// alerted on (membersBelowActive). The one exception is the active
// version's first write, which counts only the servers: then every live
// member must report the version too, or the operator starts it anyway
// (force; aerolvm upgrade signing start).
//
// Below the version, an upgrade with no rollout (install.sh, sandboxd
// upgrade node) moves the active version only once every live member
// reports the new build, so one member on an older build, or one that
// reports none, keeps it there. Once every Raft server runs the build,
// each applies the record, so the operator may start it anyway then too.
func (c *Cluster) ServerSigningGate(force bool) ServerSigningGate {
	g := ServerSigningGate{RolesInCertificates: c.certNamesServerRole()}
	if c == nil || c.fsm == nil {
		g.Reason = "no cluster"
		return g
	}
	g.ActiveFV = c.fsm.activeFVValue()
	if av, ok := c.fsm.activeVersionView(); ok {
		g.FirstWrite = av.FromFV == 0 && strings.TrimSpace(av.RolloutID) == ""
	}
	g.Waiting = c.membersBelow(serverSigningFSMOpsVersion)
	if g.ActiveFV < serverSigningFSMOpsVersion {
		g.ServersAtVersion = c.raftServersRunAtLeast(serverSigningFSMOpsVersion, "server signing") == nil
		r, _ := c.fsm.rolloutView()
		g.RolloutInFlight = !rolloutTerminal(r)
	}
	switch {
	case g.ActiveFV < serverSigningFSMOpsVersion && !g.ServersAtVersion:
		g.Reason = fmt.Sprintf("the active cluster version is %d and servers sign from %d: upgrade every server first", g.ActiveFV, serverSigningFSMOpsVersion)
	case g.ActiveFV < serverSigningFSMOpsVersion && g.RolloutInFlight && !force:
		g.Reason = fmt.Sprintf("the active cluster version is %d and servers sign from %d: finish the upgrade (aerolvm upgrade finalize)", g.ActiveFV, serverSigningFSMOpsVersion)
	case g.ActiveFV < serverSigningFSMOpsVersion && !force:
		g.Reason = fmt.Sprintf("the active cluster version is %d and servers sign from %d: it moves there once every live member runs the new build, and these report an older version, or none: %s; upgrade them, or start server signing anyway (aerolvm upgrade signing start)",
			g.ActiveFV, serverSigningFSMOpsVersion, strings.Join(g.Waiting, ", "))
	case !g.RolesInCertificates:
		g.Reason = "this cluster's certificates name no role, so no node can prove a server is one: tokens are signed as before"
	case g.FirstWrite && len(g.Waiting) > 0 && !force:
		g.Reason = fmt.Sprintf("these members report a version below %d, or none: %s; upgrade them, or start server signing anyway (aerolvm upgrade signing start)",
			serverSigningFSMOpsVersion, strings.Join(g.Waiting, ", "))
	default:
		g.Allowed = true
	}
	return g
}

// ServerSigningAllowed reports whether the record may be written now.
func (c *Cluster) ServerSigningAllowed() bool {
	return c.ServerSigningGate(false).Allowed
}

// certNamesServerRole reports whether this node's certificate names the
// server role. A cluster with no TLS (tests) counts as one that does.
func (c *Cluster) certNamesServerRole() bool {
	if c == nil {
		return false
	}
	if c.selfCertRole != nil {
		return c.selfCertRole() == JoinRoleServer
	}
	return c.tls == nil || c.tls.SelfRole() == JoinRoleServer
}

// membersBelow names the live members that report an fv below v, or none
// (0), sorted.
func (c *Cluster) membersBelow(v int) []string {
	if c == nil || c.gossip == nil {
		return nil
	}
	var out []string
	for _, m := range c.gossip.members() {
		if m.Alive && m.NodeID != c.nodeID && m.FSMOpsVersion < v {
			out = append(out, m.NodeID)
		}
	}
	sort.Strings(out)
	return out
}

// WriteServerSigning proposes a write of the record on this leader: the
// first write, or a reseal. Only the leader writes it; another server
// answers ErrNotLeader and the caller retries on its next pass.
func (c *Cluster) WriteServerSigning(ctx context.Context, w ServerSigningWrite, force bool) (ServerSigning, error) {
	if !c.IsLeader() {
		return ServerSigning{}, ErrNotLeader
	}
	if len(w.Expect) == 0 && !w.EndOldTokens {
		if g := c.ServerSigningGate(force); !g.Allowed {
			return ServerSigning{}, fmt.Errorf("%w: %s", ErrClusterVersion, g.Reason)
		}
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

// The feed and the two sign calls go only to a peer whose certificate
// names the server role (ServerClientForPeer): the feed says which keys
// this node takes tokens signed with, so it is never read from a member
// that only says it is a server in gossip. In a cluster whose servers'
// certificates name no role (signed by cluster-sign-node.sh), no server
// proves it, and no server can sign either: the leader writes the record
// only with a certificate that names its role (Cluster.ServerSigningGate).
// So when every server answers with a certificate that names no role at
// all, the feed's answer is that there is no record, as on a server tier
// from before the feed, and tokens are signed as before. This node's own
// certificate does not decide it: a node joined with a role, in a cluster
// whose servers still hold certificates from before roles, reads the
// same, and one from before roles, among servers that prove theirs,
// follows them.

// doServerJSON is doControlPlaneJSON to the server-role members that prove
// it. A peer that does not, or cannot be reached, is skipped for the next:
// the handshake fails before the request is sent.
func (a *Agent) doServerJSON(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	members := a.controlPlaneMembers()
	if len(members) == 0 {
		a.logNoControlPlaneMembers(method, path, path)
		return errors.New("cluster agent: no live server-role control-plane members")
	}
	var firstErr error
	roleLess := true
	for _, m := range members {
		err := a.tryServerMember(ctx, m, method, path, body, out)
		if err == nil {
			a.contact.record(time.Now())
			return nil
		}
		roleLess = roleLess && errors.Is(err, ErrPeerCertNamesNoRole)
		if firstErr == nil || errors.Is(firstErr, ErrPeerCertNotServer) {
			firstErr = err
		}
		if errors.Is(err, ErrPeerCertNotServer) || isStatus(err, http.StatusServiceUnavailable) || errors.Is(err, ErrNotLeader) || neverReachedPeer(err) {
			continue
		}
		return err
	}
	if roleLess {
		return fmt.Errorf("%w: %v", ErrServersNameNoRole, firstErr)
	}
	return firstErr
}

// ErrServersNameNoRole is a server-only call no server could take because
// every one answered with a certificate that names no role (doServerJSON).
var ErrServersNameNoRole = errors.New("cluster agent: every server's certificate names no role")

func (a *Agent) tryServerMember(ctx context.Context, m Member, method, path string, body []byte, out any) error {
	if a.internalClient == nil || strings.TrimSpace(m.InternalURL) == "" {
		return ErrPeerInternalURLRequired
	}
	client := a.serverClients.getWith(a.internalClient, m.NodeID, ServerClientForPeer)
	if client == nil || client == a.internalClient {
		return fmt.Errorf("%w: no pinned client for node:%s", ErrPeerCertNotServer, m.NodeID)
	}
	return a.doHTTPRequest(ctx, client, strings.TrimRight(m.InternalURL, "/")+path, method, body, out)
}

// FetchSigningKeys asks the server tier for the feed. A server tier from
// before it answers 404, and one whose certificates name no role cannot
// sign (see above): no record anywhere, the ring signs.
func (a *Agent) FetchSigningKeys(ctx context.Context) (SigningKeys, error) {
	var out SigningKeys
	err := a.doServerJSON(ctx, http.MethodGet, PublicInternalSigningKeysPath, nil, &out)
	if isStatus(err, http.StatusNotFound) || errors.Is(err, ErrServersNameNoRole) {
		return SigningKeys{}, nil
	}
	return out, err
}

// SignSandboxToken has a server sign claims for a sandbox this node owns.
func (a *Agent) SignSandboxToken(ctx context.Context, req SandboxTokenSignRequest) (SandboxTokenSignResponse, error) {
	var out SandboxTokenSignResponse
	err := a.doServerJSON(ctx, http.MethodPost, PublicInternalSandboxTokenSignPath, req, &out)
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
	err := a.doServerJSON(ctx, http.MethodPost, PublicInternalIdentityTokenSignPath, req, &out)
	if isStatus(err, http.StatusGone) {
		return out, fmt.Errorf("%w: %v", ErrIdentityRoleGone, err)
	}
	return out, err
}
