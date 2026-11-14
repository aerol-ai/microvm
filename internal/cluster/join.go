package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// The cluster side of one-line joins (plans/kubectl-style-cluster-ops.md
// §4, D3-D6, eng D3/D5, Codex CEO 5/6, Codex eng 1).
//
//	operator ─► POST /v1/cluster/join-tokens (fleet.admin) ─► leader: opPutJoinToken
//	new node ─► server:7003 GET  /v1/join/cluster-info  ─► ca.crt + HMAC(discovery key)
//	         ─► server:7003 POST /v1/join               ─► check token, version, CSR
//	                                                    ─► dial back the caller's source IP
//	                                                    ─► leader: opAdmitNode (one winner per ID)
//	                                                    ─► sign; answer cert, gossip key, peers,
//	                                                       credentials, CA key (servers only)
//	node     ─► :7002 POST /v1/cluster/internal/renew-cert (mTLS, admitted key) ─► sign
//	seed     ─► POST /v1/cluster/adopt (fleet.admin) ─► import ca.key, opAdoptNodes
//
// Writes go through one internal route (PublicInternalJoinWritePath) that
// only a Raft server may call, so a worker can never propose a join op, and
// the generic apply forward refuses them (errJoinOpNotForwardable).

// Public and internal paths of the join service.
const (
	// The three join paths, served only on the join listener (:7003).
	JoinClusterInfoPath = "/v1/join/cluster-info"
	JoinPath            = "/v1/join"
	JoinPreflightPath   = "/v1/join/preflight"
	// JoinByCertPath is a join by certificate (external-CA mode, C23): the
	// join port verifies the client certificate against the bank's CA.
	JoinByCertPath = "/v1/join/by-certificate"
	// Operator routes on the public API (fleet.admin).
	PublicJoinTokensPath = "/v1/cluster/join-tokens"
	PublicAdoptPath      = "/v1/cluster/adopt"
	// Internal routes over 7002 mTLS.
	PublicInternalJoinWritePath = "/v1/cluster/internal/join/write"
	PublicInternalRenewCertPath = "/v1/cluster/internal/renew-cert"
	PublicInternalCAKeyPath     = "/v1/cluster/internal/ca-key"
)

// Token TTL rules (D3, CEO D13, eng D5).
const (
	DefaultJoinTokenTTL = 2 * time.Hour
	MaxServerJoinTTL    = 24 * time.Hour
)

// Default ports a joining node must answer on, dialled back on the caller's
// source IP (§4.3). Servers need Raft too; others run no Raft listener.
const (
	DefaultRaftPort     = 7000
	DefaultGossipPort   = 7001
	DefaultInternalPort = 7002
	DefaultJoinPort     = 7003
)

// joinDialTimeout bounds each dial-back port (eng Section 4: 3 s).
var joinDialTimeout = 3 * time.Second

var (
	// ErrJoinTTLInvalid is a TTL outside the role's rule.
	ErrJoinTTLInvalid = errors.New("cluster: invalid join token TTL")
	// ErrJoinTTLNeedsWrappedCustody is a never-expiring token in enterprise
	// mode with plain credential custody (eng D5).
	ErrJoinTTLNeedsWrappedCustody = errors.New("cluster: SB_ENTERPRISE_MODE refuses never-expiring join tokens unless credential custody is wrapped (sandboxd key wrap)")
	// ErrJoinVersion is a joiner on a build that may not join.
	ErrJoinVersion = errors.New("cluster: this build may not join the cluster")
	// ErrJoinDialBack is a join or preflight whose dial-back failed.
	ErrJoinDialBack = errors.New("cluster: the join server could not reach this node back")
	// ErrJoinBadRequest is a malformed join body.
	ErrJoinBadRequest = errors.New("cluster: bad join request")
	// ErrPeerNotServer is a server-only internal call from a peer whose
	// admitted role, or Raft membership, is not a server's.
	ErrPeerNotServer = errors.New("cluster: only server nodes may call this")
)

// JoinTokenCreateRequest makes a join token. TTL is a Go duration ("2h");
// empty means DefaultJoinTokenTTL and "0" means never (worker and ingress
// only).
type JoinTokenCreateRequest struct {
	Role      string `json:"role"`
	TTL       string `json:"ttl,omitempty"`
	Reusable  bool   `json:"reusable,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	// Token registers a token the caller made (`sandboxd init --token`,
	// Terraform's random_password) instead of a random one. Registering the
	// same token again answers the stored row, so a re-run of init is safe.
	Token string `json:"token,omitempty"`
}

// JoinTokenCreated is the answer: the only time the secret is shown.
type JoinTokenCreated struct {
	Token      string     `json:"token"`
	ID         string     `json:"id"`
	Role       string     `json:"role"`
	Reusable   bool       `json:"reusable"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	CACertHash string     `json:"ca_cert_hash"`
	JoinURLs   []string   `json:"join_urls"`
	// Warning is set for a never-expiring token outside enterprise mode.
	Warning string `json:"warning,omitempty"`
	// Domain, IngressAdvertiseHost and TLSIssuer are the answering node's
	// public setup, which the printed join command repeats so a new node
	// serves the same addresses: SB_DOMAIN, SB_INGRESS_ADVERTISE_HOST when
	// it is not the domain, and SB_TLS_ISSUER when it is "internal". The API
	// handler fills them (the cluster package does not hold that config);
	// none is a secret.
	Domain               string `json:"domain,omitempty"`
	IngressAdvertiseHost string `json:"ingress_advertise_host,omitempty"`
	TLSIssuer            string `json:"tls_issuer,omitempty"`
}

// JoinTokenInfo is one token in a list. Never the secret or its hash.
type JoinTokenInfo struct {
	ID        string         `json:"id"`
	Role      string         `json:"role"`
	CreatedBy string         `json:"created_by,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Reusable  bool           `json:"reusable"`
	Expired   bool           `json:"expired"`
	UsedBy    []JoinTokenUse `json:"used_by"`
}

// JoinTokenList answers GET /v1/cluster/join-tokens.
type JoinTokenList struct {
	Tokens []JoinTokenInfo `json:"tokens"`
}

// ClusterInfo answers GET /v1/join/cluster-info?token_id=. MAC is
// HMAC-SHA256(discovery key, ca_cert) (D4); InfoMAC also covers the version
// and URLs, so a man in the middle can't steer an installer to another
// build. Both are base64 (standard encoding).
type ClusterInfo struct {
	CACert    string   `json:"ca_cert"`
	MAC       string   `json:"mac"`
	InfoMAC   string   `json:"info_mac"`
	ClusterID string   `json:"cluster_id"`
	Version   string   `json:"version"`
	JoinURLs  []string `json:"join_urls"`
}

// ClusterInfoSigningBytes is what InfoMAC covers.
func ClusterInfoSigningBytes(info ClusterInfo) []byte {
	return []byte(strings.Join([]string{"aerolvm-cluster-info-v1", info.CACert, info.ClusterID, info.Version, strings.Join(info.JoinURLs, ",")}, "\n"))
}

// VerifyClusterInfo is the new machine's whole check of a cluster-info
// answer against its token.
func VerifyClusterInfo(token string, info ClusterInfo) bool {
	key, err := JoinDiscoveryKey(token)
	if err != nil {
		return false
	}
	mac, err1 := base64.StdEncoding.DecodeString(info.MAC)
	infoMAC, err2 := base64.StdEncoding.DecodeString(info.InfoMAC)
	if err1 != nil || err2 != nil {
		return false
	}
	return constantTimeEqual(JoinDiscoveryMAC(key, []byte(info.CACert)), mac) &&
		constantTimeEqual(JoinDiscoveryMAC(key, ClusterInfoSigningBytes(info)), infoMAC)
}

// JoinPorts are the TCP ports the joiner listens on for the dial-back, on
// its source IP. Zero means the default.
type JoinPorts struct {
	Raft     int `json:"raft,omitempty"`
	Gossip   int `json:"gossip,omitempty"`
	Internal int `json:"internal,omitempty"`
}

// JoinRequest is POST /v1/join.
type JoinRequest struct {
	Token  string `json:"token"`
	NodeID string `json:"node_id"`
	// Role defaults to the token's role; anything else is refused.
	Role string `json:"role,omitempty"`
	// CSR is a PEM certificate request. Its names are ignored.
	CSR string `json:"csr"`
	// Version is the joiner's sandboxd build.
	Version string     `json:"version"`
	Ports   *JoinPorts `json:"ports,omitempty"`
	// FSMOpsVersion is the joiner's FSM op set (FSMOpsVersion()), so the
	// server can tell whether its build supports the active cluster
	// version. Optional: an older joiner sends none and is judged by its
	// build version.
	FSMOpsVersion int `json:"fv,omitempty"`
}

// JoinCredentials is the credential bundle: what cluster-init.sh's
// aerolvm-cred-bundle.tar.gz carries. With wrapped custody only the wrapped
// blob travels (the node unwraps it with its own key access); file custody
// sends the key file and its ring. Values are the files' bytes, base64.
type JoinCredentials struct {
	Custody string `json:"custody"`
	Key     string `json:"key,omitempty"`
	KeyRing string `json:"key_ring,omitempty"`
	Wrapped string `json:"wrapped,omitempty"`
}

// JoinResponse is a successful join.
type JoinResponse struct {
	NodeID         string           `json:"node_id"`
	Role           string           `json:"role"`
	ClusterID      string           `json:"cluster_id"`
	NodeCert       string           `json:"node_cert"`
	CACert         string           `json:"ca_cert"`
	CAKey          string           `json:"ca_key,omitempty"`
	GossipKey      string           `json:"gossip_key,omitempty"`
	BootstrapPeers []string         `json:"bootstrap_peers"`
	JoinURLs       []string         `json:"join_urls"`
	Credentials    JoinCredentials  `json:"credentials"`
	NotAfter       time.Time        `json:"not_after"`
	Version        string           `json:"version"`
	Replay         bool             `json:"replay,omitempty"`
	DialBack       []DialBackResult `json:"dial_back,omitempty"`
	// PATToken is the operator PAT (SB_PAT_TOKEN). A server gets it: it
	// already gets the CA key, and the operator's tools on it use the PAT.
	// A worker or ingress node gets it only from a cluster where some
	// member still needs it on peer calls (PATFreeJoin); otherwise it gets
	// PATSHA256 instead, so a leaked worker or ingress token never yields
	// an admin credential that also works from outside.
	PATToken string `json:"pat_token,omitempty"`
	// PATSHA256 lists the hex SHA-256 of each operator PAT the cluster
	// accepts, current first, for a node joined without the PAT: it checks
	// the PAT operators send it against these (SB_PAT_TOKEN_SHA256).
	PATSHA256 []string `json:"pat_sha256,omitempty"`
	// OperatorVolumeScope is the cluster's operator volume scope, sent with
	// PATSHA256: the scope is a hash of the PAT unless pinned, and a node
	// without the PAT must still put operator volumes where the others do.
	OperatorVolumeScope string `json:"operator_volume_scope,omitempty"`
}

// DialBackResult is one port the join server dialled on the caller.
type DialBackResult struct {
	Name  string `json:"name"`
	Port  int    `json:"port"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// PreflightRequest is POST /v1/join/preflight: token-authenticated, signs
// nothing, uses nothing up.
type PreflightRequest struct {
	Token string     `json:"token"`
	Role  string     `json:"role,omitempty"`
	Ports *JoinPorts `json:"ports,omitempty"`
	// NodeID asks whether the ID is free (§4.3's node ID check). KeyHash
	// is the caller's node key when it already has one: an ID admitted for
	// that very key is a re-run, not a clash.
	NodeID  string `json:"node_id,omitempty"`
	KeyHash string `json:"key_hash,omitempty"`
}

// PreflightResponse reports the dial-back and the server's clock.
type PreflightResponse struct {
	OK         bool             `json:"ok"`
	Role       string           `json:"role"`
	DialBack   []DialBackResult `json:"dial_back"`
	ServerTime time.Time        `json:"server_time"`
	Version    string           `json:"version"`
	// NodeIDInUse: a live member, or another admitted key, holds NodeID.
	NodeIDInUse bool `json:"node_id_in_use,omitempty"`
}

// JoinDialBackError carries the per-port results of a failed dial-back.
type JoinDialBackError struct {
	Results []DialBackResult
}

func (e *JoinDialBackError) Error() string {
	var failed []string
	for _, r := range e.Results {
		if !r.OK {
			failed = append(failed, fmt.Sprintf("%s %d", r.Name, r.Port))
		}
	}
	return ErrJoinDialBack.Error() + " on TCP " + strings.Join(failed, ", ")
}

func (e *JoinDialBackError) Unwrap() error { return ErrJoinDialBack }

// JoinWriteRequest is one join-state write, proposed by the leader.
type JoinWriteRequest struct {
	Kind    string            `json:"kind"`
	Token   *JoinTokenRecord  `json:"token,omitempty"`
	TokenID string            `json:"token_id,omitempty"`
	Admit   *JoinAdmitCommand `json:"admit,omitempty"`
	Adopt   *JoinAdoptCommand `json:"adopt,omitempty"`
	Rekey   *JoinRekeyCommand `json:"rekey,omitempty"`
}

// Join write kinds.
const (
	joinWritePutToken    = "put_token"
	joinWriteDeleteToken = "delete_token"
	joinWriteAdmit       = "admit"
	joinWriteAdopt       = "adopt"
	joinWriteRekey       = "rekey"
	// joinWriteAdmitByCert admits a node by its certificate (external-CA
	// mode, opAdmitNodeByCert): Admit without a token.
	joinWriteAdmitByCert = "admit_by_cert"
)

// JoinWriteResponse is the outcome. Code carries a refusal's sentinel so it
// survives forwarding hops, like the API token write.
type JoinWriteResponse struct {
	Code    string           `json:"code,omitempty"`
	Message string           `json:"message,omitempty"`
	Token   *JoinTokenRecord `json:"token,omitempty"`
	Admit   *JoinAdmitResult `json:"admit,omitempty"`
	Adopt   *JoinAdoptResult `json:"adopt,omitempty"`
	Node    *AdmittedNode    `json:"node,omitempty"`
}

// joinWriteCodes are the refusals a join write can carry, by code.
var joinWriteCodes = []struct {
	code string
	err  error
}{
	{"token_invalid", ErrJoinTokenInvalid},
	{"token_expired", ErrJoinTokenExpired},
	{"token_used", ErrJoinTokenUsed},
	{"role_mismatch", ErrJoinRoleMismatch},
	{"node_id_in_use", ErrNodeIDInUse},
	{"key_revoked", ErrJoinKeyRevoked},
	{"key_in_use", ErrJoinKeyInUse},
	{"token_id_taken", ErrJoinTokenIDTaken},
	{"not_admitted", ErrNotAdmitted},
	{"rekey_conflict", ErrRekeyConflict},
	{"cluster_version", ErrClusterVersion},
	{"bad_request", ErrJoinBadRequest},
}

// JoinWriteOutcome turns a write error into the body a peer gets.
func JoinWriteOutcome(err error) JoinWriteResponse {
	if err == nil {
		return JoinWriteResponse{}
	}
	for _, c := range joinWriteCodes {
		if errors.Is(err, c.err) {
			return JoinWriteResponse{Code: c.code, Message: err.Error()}
		}
	}
	return JoinWriteResponse{}
}

func (r JoinWriteResponse) err() error {
	if r.Code == "" {
		return nil
	}
	for _, c := range joinWriteCodes {
		if c.code == r.Code {
			return fmt.Errorf("%w (%s)", c.err, r.Message)
		}
	}
	return fmt.Errorf("cluster: join write: %s: %s", r.Code, r.Message)
}

// JoinReason is the short reason label for metrics and audit.
func JoinReason(err error) string {
	if err == nil {
		return "ok"
	}
	if out := JoinWriteOutcome(err); out.Code != "" {
		return out.Code
	}
	switch {
	case errors.Is(err, ErrJoinTokenFormat):
		return "token_invalid"
	case errors.Is(err, ErrJoinVersion):
		return "version"
	case errors.Is(err, ErrJoinDialBack):
		return "dial_back"
	case errors.Is(err, ErrNoCASigner):
		return "no_ca_signer"
	case errors.Is(err, ErrJoinNodeIDInvalid):
		return "bad_request"
	case errors.Is(err, ErrNotLeader):
		return "not_leader"
	case errors.Is(err, ErrExternalCAMode), errors.Is(err, ErrJoinByCertOff):
		return "ca_mode"
	case errors.Is(err, ErrJoinCertRequired):
		return "no_client_cert"
	}
	return "error"
}

// WriteJoin proposes one join-state write on the leader; a follower
// forwards it one hop. The leader checks the upgrade gate first and, for an
// admit, that no live member holds the ID under another key: gossip is not
// replicated, so that check is the proposer's, before the entry exists.
func (c *Cluster) WriteJoin(ctx context.Context, req JoinWriteRequest) (JoinWriteResponse, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return JoinWriteResponse{}, errors.New("cluster: node holds no placement state")
	}
	if c.raft.raft.State() != raft.Leader {
		var out JoinWriteResponse
		if err := c.forwardToLeaderJSON(ctx, "join write", PublicInternalJoinWritePath, req, &out); err != nil {
			return JoinWriteResponse{}, err
		}
		return out, out.err()
	}
	if err := c.raftServersSupport(joinFSMOpsVersion, "join tokens"); err != nil {
		return JoinWriteResponse{}, err
	}
	cmd := command{StampUnixNano: time.Now().UnixNano()}
	switch req.Kind {
	case joinWritePutToken:
		cmd.Op, cmd.JoinToken = opPutJoinToken, req.Token
	case joinWriteDeleteToken:
		cmd.Op, cmd.JoinTokenID = opDeleteJoinToken, req.TokenID
	case joinWriteAdmit:
		if req.Admit == nil {
			return JoinWriteResponse{}, fmt.Errorf("%w: admit without a node", ErrJoinBadRequest)
		}
		if err := c.liveMemberHoldsID(req.Admit.NodeID, req.Admit.KeyHash); err != nil {
			return JoinWriteResponse{}, err
		}
		cmd.Op, cmd.JoinAdmit = opAdmitNode, req.Admit
	case joinWriteAdmitByCert:
		if req.Admit == nil {
			return JoinWriteResponse{}, fmt.Errorf("%w: admit without a node", ErrJoinBadRequest)
		}
		// A newer op than the join set: every server must apply it alike.
		if err := c.raftServersSupport(externalCAFSMOpsVersion, "joins by certificate"); err != nil {
			return JoinWriteResponse{}, err
		}
		if err := c.liveMemberHoldsID(req.Admit.NodeID, req.Admit.KeyHash); err != nil {
			return JoinWriteResponse{}, err
		}
		cmd.Op, cmd.JoinAdmit = opAdmitNodeByCert, req.Admit
	case joinWriteAdopt:
		cmd.Op, cmd.JoinAdopt = opAdoptNodes, req.Adopt
	case joinWriteRekey:
		cmd.Op, cmd.JoinRekey = opRekeyNode, req.Rekey
	default:
		return JoinWriteResponse{}, fmt.Errorf("%w: unknown join write %q", ErrJoinBadRequest, req.Kind)
	}
	payload, err := encodeCommand(cmd)
	if err != nil {
		return JoinWriteResponse{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return JoinWriteResponse{}, err
	}
	var out JoinWriteResponse
	switch r := result.(type) {
	case JoinTokenRecord:
		out.Token = &r
	case JoinAdmitResult:
		out.Admit = &r
	case JoinAdoptResult:
		out.Adopt = &r
	case AdmittedNode:
		out.Node = &r
	}
	return out, nil
}

// liveMemberHoldsID refuses a join for an ID a live member holds, unless
// that member is this very key retrying (its admitted record is the key).
func (c *Cluster) liveMemberHoldsID(nodeID, keyHash string) error {
	if c.gossip == nil {
		return nil
	}
	m, ok := c.gossip.lookupMember(nodeID)
	if !ok || !m.Alive {
		return nil
	}
	if rec, ok := c.fsm.admittedNode(nodeID); ok && rec.KeyHash == keyHash {
		return nil
	}
	// The live member is this very server, admitting the key it serves
	// with (external-CA mode: the seed admits itself by its certificate).
	if nodeID == c.nodeID && keyHash != "" && keyHash == c.selfKeyHash() {
		return nil
	}
	return fmt.Errorf("%w: %s is a live member", ErrNodeIDInUse, nodeID)
}

// IsJoinWritePeer reports whether peerID may call the join write route: a
// configured Raft server whose admitted role (when it has one) is server.
// Workers never propose join state.
func (c *Cluster) IsJoinWritePeer(peerID string) bool {
	return c.peerIsServer(peerID)
}

// peerIsServer is the role binding for server-only operations (Codex eng
// finding 1): the admitted role when an admitted record exists, and Raft
// membership always. A node with no record (a scripted cluster before
// adopt) passes on Raft membership alone, which is today's trust.
func (c *Cluster) peerIsServer(peerID string) bool {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return false
	}
	if rec, ok := c.fsm.admittedNode(peerID); ok && !rec.IsServer() {
		return false
	}
	_, ok := c.configuredServer(peerID)
	return ok
}

// validateJoinTokenTTL applies the TTL rules: default 2h; servers 0 < TTL
// ≤ 24h; worker and ingress any TTL, 0 meaning never, except in enterprise
// mode with plain credential custody (eng D5). Returns the TTL and a
// warning for a never-expiring token.
func (c *Cluster) validateJoinTokenTTL(role, raw string) (time.Duration, string, error) {
	ttl := DefaultJoinTokenTTL
	if s := strings.TrimSpace(raw); s != "" {
		if s == "0" {
			ttl = 0
		} else {
			d, err := time.ParseDuration(s)
			if err != nil {
				return 0, "", fmt.Errorf("%w: %v", ErrJoinTTLInvalid, err)
			}
			ttl = d
		}
	}
	switch {
	case ttl < 0:
		return 0, "", fmt.Errorf("%w: negative", ErrJoinTTLInvalid)
	case role == JoinRoleServer && ttl == 0:
		return 0, "", fmt.Errorf("%w: server tokens must expire (at most %s)", ErrJoinTTLInvalid, MaxServerJoinTTL)
	case role == JoinRoleServer && ttl > MaxServerJoinTTL:
		return 0, "", fmt.Errorf("%w: server tokens last at most %s", ErrJoinTTLInvalid, MaxServerJoinTTL)
	case ttl > 0 && ttl < time.Minute:
		return 0, "", fmt.Errorf("%w: at least 1m", ErrJoinTTLInvalid)
	}
	if ttl != 0 {
		return ttl, "", nil
	}
	if c.cfg.EnterpriseMode && c.cfg.CredentialKeyCustody != secrets.CustodyWrapped {
		return 0, "", ErrJoinTTLNeedsWrappedCustody
	}
	return 0, "this token never expires: anyone who gets it can join a " + role + " and receive the gossip key and the credential bundle until you revoke it", nil
}

// CreateJoinToken mints a join token, stores its hash and discovery key in
// Raft and returns the token once.
func (c *Cluster) CreateJoinToken(ctx context.Context, req JoinTokenCreateRequest) (JoinTokenCreated, error) {
	if err := c.refuseInExternalCAMode(); err != nil {
		return JoinTokenCreated{}, err
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = JoinRoleWorker
	}
	if !ValidJoinRole(role) {
		return JoinTokenCreated{}, fmt.Errorf("%w: role must be server, worker or ingress", ErrJoinBadRequest)
	}
	ttl, warning, err := c.validateJoinTokenTTL(role, req.TTL)
	if err != nil {
		return JoinTokenCreated{}, err
	}
	given := strings.TrimSpace(req.Token)
	if given != "" {
		if _, _, err := ParseJoinToken(given); err != nil {
			return JoinTokenCreated{}, fmt.Errorf("%w: %v", ErrJoinBadRequest, err)
		}
	}
	// A random id colliding is ~2^-31 per pair; retry a couple of times
	// rather than surface it. A given token is never retried: its id is the
	// caller's.
	for attempt := 0; ; attempt++ {
		token := given
		if token == "" {
			if token, err = GenerateJoinToken(); err != nil {
				return JoinTokenCreated{}, err
			}
		}
		id, secret, _ := ParseJoinToken(token)
		disc, err := joinDiscoveryKey(id, secret)
		if err != nil {
			return JoinTokenCreated{}, err
		}
		now := time.Now()
		rec := JoinTokenRecord{
			ID: id, Role: role, SecretHash: joinTokenSecretHash(id, secret), DiscoveryKey: disc,
			CreatedBy: strings.TrimSpace(req.CreatedBy), CreatedUnixNano: now.UnixNano(), Reusable: req.Reusable,
		}
		if ttl > 0 {
			rec.ExpiresUnixNano = now.Add(ttl).UnixNano()
		}
		written, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWritePutToken, Token: &rec})
		if errors.Is(err, ErrJoinTokenIDTaken) && given == "" && attempt < 3 {
			continue
		}
		if err != nil {
			return JoinTokenCreated{}, err
		}
		// The FSM answers the stored row: on a repeat of a given token that
		// is the first registration, whose role and expiry stand.
		if stored := written.Token; stored != nil {
			if stored.Role != role || stored.Reusable != req.Reusable {
				return JoinTokenCreated{}, fmt.Errorf("%w: %s is already registered as a %s token (reusable %t)", ErrJoinTokenIDTaken, id, stored.Role, stored.Reusable)
			}
			rec = *stored
		}
		out := JoinTokenCreated{
			Token: token, ID: id, Role: role, Reusable: req.Reusable,
			CACertHash: c.clusterID(), JoinURLs: c.joinURLs(), Warning: warning,
		}
		if rec.ExpiresUnixNano != 0 {
			exp := time.Unix(0, rec.ExpiresUnixNano).UTC()
			out.ExpiresAt = &exp
		}
		if c.logger != nil {
			c.logger.Info("cluster: join token created", "token_id", id, "role", role, "ttl", ttl.String(), "reusable", req.Reusable, "caller", rec.CreatedBy)
		}
		return out, nil
	}
}

// ListJoinTokens lists every token from this server's FSM.
func (c *Cluster) ListJoinTokens(context.Context) (JoinTokenList, error) {
	tokens, _, _ := c.fsm.joinStateView()
	now := time.Now().UnixNano()
	out := JoinTokenList{Tokens: make([]JoinTokenInfo, 0, len(tokens))}
	for _, t := range tokens {
		out.Tokens = append(out.Tokens, joinTokenInfo(t, now))
	}
	return out, nil
}

func joinTokenInfo(t JoinTokenRecord, now int64) JoinTokenInfo {
	info := JoinTokenInfo{
		ID: t.ID, Role: t.Role, CreatedBy: t.CreatedBy, CreatedAt: time.Unix(0, t.CreatedUnixNano).UTC(),
		Reusable: t.Reusable, Expired: t.expiredAt(now), UsedBy: t.UsedBy,
	}
	if info.UsedBy == nil {
		info.UsedBy = []JoinTokenUse{}
	}
	if t.ExpiresUnixNano != 0 {
		exp := time.Unix(0, t.ExpiresUnixNano).UTC()
		info.ExpiresAt = &exp
	}
	return info
}

// RevokeJoinToken deletes a token. Idempotent.
func (c *Cluster) RevokeJoinToken(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if !ValidJoinTokenID(id) {
		return fmt.Errorf("%w: token id %q", ErrJoinBadRequest, id)
	}
	if _, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteDeleteToken, TokenID: id}); err != nil {
		return err
	}
	if c.logger != nil {
		c.logger.Info("cluster: join token revoked", "token_id", id)
	}
	return nil
}

// clusterCACert returns the cluster CA this node trusts (its TLS ca.crt,
// read at boot) and its PEM.
func (c *Cluster) clusterCACert() (*x509.Certificate, []byte, error) {
	if c == nil || c.tls == nil || len(c.tls.caPEM) == 0 {
		return nil, nil, errors.New("cluster: no cluster TLS material")
	}
	cert, err := firstPEMCertificate(c.tls.caPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster: parse ca.crt: %w", err)
	}
	return cert, c.tls.caPEM, nil
}

// clusterID is the CA pin, or "" before TLS is loaded.
func (c *Cluster) clusterID() string {
	cert, _, err := c.clusterCACert()
	if err != nil {
		return ""
	}
	return CACertHash(cert)
}

// joinVersion is the build a new node should install (§6.5): a running
// rollout's target (the version it moves nodes to, so a rollback's is the
// previous one), else this server's build. So a long-lived token (CEO
// D13) never installs a build the cluster is moving away from.
func (c *Cluster) joinVersion() string {
	if c != nil && c.fsm != nil {
		if r, _ := c.fsm.rolloutView(); r != nil && !rolloutTerminal(r) {
			return targetOf(r)
		}
	}
	return version.Version
}

// joinVersionAllowed reports whether a joiner on build v, applying FSM ops
// of version fv (0 when an older joiner did not say), may join (§6.5):
//
//   - while a rollout is not finalized or rolled back, only on its target
//     or its previous version (the rollout adds the node: done on the
//     version it moves to, else pending and caught up); a finalizing
//     rollout takes only its target;
//   - otherwise only a build that supports the active cluster version:
//     fv >= the active fv when the joiner says its fv, else the active
//     release itself;
//   - before the active version was ever written, this server's build or
//     one some live member runs (a cluster mid-upgrade runs two).
func (c *Cluster) joinVersionAllowed(v string, fv int) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if c.fsm != nil {
		r, active := c.fsm.rolloutView()
		if r != nil && !rolloutTerminal(r) {
			if v == r.TargetVersion {
				return true
			}
			return v == r.PreviousVersion && r.State != upgradewire.StateFinalizing
		}
		if active.FV > 0 {
			if fv > 0 {
				return fv >= active.FV
			}
			if active.Release != "" && v == active.Release {
				return true
			}
		}
	}
	if v == c.joinVersion() {
		return true
	}
	if c.gossip == nil {
		return false
	}
	for _, m := range c.gossip.members() {
		if m.Alive && m.Version == v {
			return true
		}
	}
	return false
}

// joinURLs lists https://<host>:<join port> for every live server member.
// The host is the member's internal URL host; the port is this server's
// join port, which every server shares by convention.
func (c *Cluster) joinURLs() []string {
	port := c.joinAdvertisePort
	if port == 0 {
		port = DefaultJoinPort
	}
	seen := map[string]bool{}
	var out []string
	add := func(internalURL string) {
		u, err := url.Parse(internalURL)
		if err != nil || u.Hostname() == "" {
			return
		}
		joinURL := "https://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
		if !seen[joinURL] {
			seen[joinURL] = true
			out = append(out, joinURL)
		}
	}
	add(c.internalURL)
	if c.gossip != nil {
		for _, m := range c.gossip.members() {
			if m.Alive && !isForcedNonVoterRole(m.Role) && m.InternalURL != "" {
				add(m.InternalURL)
			}
		}
	}
	sort.Strings(out)
	if out == nil {
		out = []string{}
	}
	return out
}

// ClusterInfo answers the discovery call for tokenID: the CA, its MACs
// under that token's discovery key, the version to install and the join
// URLs. An unknown or expired token gets ErrJoinTokenInvalid and no MAC.
func (c *Cluster) ClusterInfo(tokenID string) (ClusterInfo, error) {
	tok, ok := c.fsm.joinToken(strings.TrimSpace(tokenID))
	if !ok || tok.expiredAt(time.Now().UnixNano()) {
		return ClusterInfo{}, ErrJoinTokenInvalid
	}
	caCert, caPEM, err := c.clusterCACert()
	if err != nil {
		return ClusterInfo{}, err
	}
	info := ClusterInfo{
		CACert: string(caPEM), ClusterID: CACertHash(caCert), Version: c.joinVersion(), JoinURLs: c.joinURLs(),
	}
	info.MAC = base64.StdEncoding.EncodeToString(JoinDiscoveryMAC(tok.DiscoveryKey, caPEM))
	info.InfoMAC = base64.StdEncoding.EncodeToString(JoinDiscoveryMAC(tok.DiscoveryKey, ClusterInfoSigningBytes(info)))
	return info, nil
}

// checkJoinToken verifies token against Raft in constant time and returns
// its record. Unknown and wrong-secret tokens are one answer.
func (c *Cluster) checkJoinToken(token string) (JoinTokenRecord, error) {
	id, secret, err := ParseJoinToken(token)
	if err != nil {
		return JoinTokenRecord{}, ErrJoinTokenInvalid
	}
	tok, ok := c.fsm.joinToken(id)
	if !ok || !constantTimeEqual(tok.SecretHash, joinTokenSecretHash(id, secret)) {
		return JoinTokenRecord{}, ErrJoinTokenInvalid
	}
	return tok, nil
}

// joinRole resolves the role a join asks for against its token.
func joinRole(asked string, tok JoinTokenRecord) (string, error) {
	role := strings.ToLower(strings.TrimSpace(asked))
	if role == "" {
		role = tok.Role
	}
	if role != tok.Role {
		return "", fmt.Errorf("%w: token admits %s", ErrJoinRoleMismatch, tok.Role)
	}
	return role, nil
}

// dialBackPorts lists the ports role needs, with the caller's overrides.
func dialBackPorts(role string, p *JoinPorts) ([]DialBackResult, error) {
	ports := JoinPorts{Raft: DefaultRaftPort, Gossip: DefaultGossipPort, Internal: DefaultInternalPort}
	if p != nil {
		for _, set := range []struct {
			v   int
			dst *int
		}{{p.Raft, &ports.Raft}, {p.Gossip, &ports.Gossip}, {p.Internal, &ports.Internal}} {
			if set.v < 0 || set.v > 65535 {
				return nil, fmt.Errorf("%w: port %d", ErrJoinBadRequest, set.v)
			}
			if set.v != 0 {
				*set.dst = set.v
			}
		}
	}
	var out []DialBackResult
	if role == JoinRoleServer {
		out = append(out, DialBackResult{Name: "raft", Port: ports.Raft})
	}
	return append(out, DialBackResult{Name: "gossip", Port: ports.Gossip}, DialBackResult{Name: "internal", Port: ports.Internal}), nil
}

// dialFunc dials one address; tests swap it.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dialBack dials source on every port in parallel, joinDialTimeout each. It
// dials only the call's source IP, never an address from the body, so a
// token holder can't aim the server at another host (§8).
func dialBack(ctx context.Context, dial dialFunc, source netip.Addr, ports []DialBackResult) ([]DialBackResult, bool) {
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	out := append([]DialBackResult(nil), ports...)
	done := make(chan struct{}, len(out))
	for i := range out {
		go func(r *DialBackResult) {
			defer func() { done <- struct{}{} }()
			dctx, cancel := context.WithTimeout(ctx, joinDialTimeout)
			defer cancel()
			conn, err := dial(dctx, "tcp", net.JoinHostPort(source.Unmap().String(), strconv.Itoa(r.Port)))
			if err != nil {
				r.Error = err.Error()
				return
			}
			_ = conn.Close()
			r.OK = true
		}(&out[i])
	}
	for range out {
		<-done
	}
	ok := true
	for _, r := range out {
		ok = ok && r.OK
	}
	return out, ok
}

// JoinPreflight checks a token (without using it) and dials the caller
// back. It signs nothing.
func (c *Cluster) JoinPreflight(ctx context.Context, req PreflightRequest, source netip.Addr) (PreflightResponse, error) {
	tok, err := c.checkJoinToken(req.Token)
	if err != nil {
		return PreflightResponse{}, err
	}
	if tok.expiredAt(time.Now().UnixNano()) {
		return PreflightResponse{}, ErrJoinTokenExpired
	}
	role, err := joinRole(req.Role, tok)
	if err != nil {
		return PreflightResponse{}, err
	}
	ports, err := dialBackPorts(role, req.Ports)
	if err != nil {
		return PreflightResponse{}, err
	}
	results, ok := dialBack(ctx, c.joinDial, source, ports)
	inUse := c.nodeIDTaken(strings.TrimSpace(req.NodeID), strings.TrimSpace(req.KeyHash))
	return PreflightResponse{
		OK: ok && !inUse, Role: role, DialBack: results, ServerTime: time.Now().UTC(), Version: c.joinVersion(), NodeIDInUse: inUse,
	}, nil
}

// nodeIDTaken is preflight's node ID check: a join for nodeID would be
// refused because another key is admitted for it, or a live member holds
// it with no admitted record (a scripted node). keyHash's own record is a
// re-run, not a clash.
func (c *Cluster) nodeIDTaken(nodeID, keyHash string) bool {
	if nodeID == "" {
		return false
	}
	if rec, ok := c.fsm.admittedNode(nodeID); ok {
		return rec.KeyHash != keyHash
	}
	return c.liveMemberHoldsID(nodeID, keyHash) != nil
}

// Join admits one node: checks, dial-back, one Raft op, then the signature
// (§4). A retry with the same key and node ID gets the same answer.
func (c *Cluster) Join(ctx context.Context, req JoinRequest, source netip.Addr) (JoinResponse, error) {
	if err := c.refuseInExternalCAMode(); err != nil {
		return JoinResponse{}, err
	}
	tok, err := c.checkJoinToken(req.Token)
	if err != nil {
		return JoinResponse{}, err
	}
	role, err := joinRole(req.Role, tok)
	if err != nil {
		return JoinResponse{}, err
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if !ValidJoinNodeID(nodeID) {
		return JoinResponse{}, fmt.Errorf("%w: %q", ErrJoinNodeIDInvalid, req.NodeID)
	}
	if !c.joinVersionAllowed(req.Version, req.FSMOpsVersion) {
		return JoinResponse{}, fmt.Errorf("%w: %q (cluster runs %s)", ErrJoinVersion, req.Version, c.joinVersion())
	}
	csr, err := ParseCertificateRequestPEM([]byte(req.CSR))
	if err != nil {
		return JoinResponse{}, fmt.Errorf("%w: %v", ErrJoinBadRequest, err)
	}
	keyHash, err := PublicKeyHash(csr.PublicKey)
	if err != nil {
		return JoinResponse{}, fmt.Errorf("%w: %v", ErrJoinBadRequest, err)
	}
	// Fail before using the token up when this server can't sign.
	signer := c.ca.get()
	if signer == nil {
		return JoinResponse{}, ErrNoCASigner
	}
	ports, err := dialBackPorts(role, req.Ports)
	if err != nil {
		return JoinResponse{}, err
	}
	results, ok := dialBack(ctx, c.joinDial, source, ports)
	if !ok {
		return JoinResponse{}, &JoinDialBackError{Results: results}
	}
	lifetime := c.nodeCertTTL()
	now := time.Now()
	written, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdmit, Admit: &JoinAdmitCommand{
		TokenID: tok.ID, NodeID: nodeID, Role: role, KeyHash: keyHash, NotAfterUnixNano: now.Add(lifetime).UnixNano(),
	}})
	if err != nil {
		return JoinResponse{}, err
	}
	admitted := JoinAdmitResult{Node: AdmittedNode{NodeID: nodeID, Role: role}}
	if written.Admit != nil {
		admitted = *written.Admit
	}
	certPEM, leaf, err := signer.SignNodeCert(NodeCertRequest{PublicKey: csr.PublicKey, NodeID: nodeID, Role: admitted.Node.Role, Lifetime: lifetime, Now: now})
	if err != nil {
		return JoinResponse{}, err
	}
	out := JoinResponse{
		NodeID: nodeID, Role: admitted.Node.Role, ClusterID: CACertHash(signer.Certificate()),
		NodeCert: string(certPEM), CACert: string(signer.CertPEM()),
		GossipKey: c.cfg.ClusterGossipSecretKey, BootstrapPeers: c.bootstrapPeers(), JoinURLs: c.joinURLs(),
		Credentials: c.credentialBundle(), NotAfter: leaf.NotAfter.UTC(), Version: c.joinVersion(),
		Replay: admitted.Replay, DialBack: results,
	}
	// The CA key goes to servers only (D5), by the token's role.
	if admitted.Node.IsServer() {
		out.CAKey = string(signer.KeyPEM())
	}
	c.addJoinPAT(&out, admitted.Node.IsServer())
	if c.logger != nil {
		c.logger.Info("cluster: node joined", "node_id", nodeID, "role", out.Role, "token_id", tok.ID,
			"source", source.String(), "replay", admitted.Replay, "replaced_deny", admitted.ReplacedDeny)
	}
	return out, nil
}

// nodeCertTTL is the life of certs this server signs.
func (c *Cluster) nodeCertTTL() time.Duration {
	if ttl := c.cfg.ClusterNodeCertTTL; ttl > 0 && ttl <= NodeCertLifetime {
		return ttl
	}
	return NodeCertLifetime
}

// bootstrapPeers lists the gossip addresses of live control-plane members,
// this server included.
func (c *Cluster) bootstrapPeers() []string {
	if c.gossip == nil {
		return []string{}
	}
	peers := normalizeGossipPeers(liveControlPlanePeerAddrs(c.gossip.memberlistNodes(), ""))
	if peers == nil {
		return []string{}
	}
	return peers
}

// credentialBundle reads the server key the way cluster-init.sh bundles
// it. Wrapped custody sends only the wrapped blob; file custody sends the
// key and its ring when there is one. A missing file is left out: the node
// then boots without it exactly as a hand join without --cred-bundle would.
func (c *Cluster) credentialBundle() JoinCredentials {
	read := func(path string) string {
		if strings.TrimSpace(path) == "" {
			return ""
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	if c.cfg.CredentialKeyCustody == secrets.CustodyWrapped {
		return JoinCredentials{Custody: secrets.CustodyWrapped, Wrapped: read(c.cfg.CredentialKeyWrappedPath)}
	}
	return JoinCredentials{Custody: secrets.CustodyFile, Key: read(c.cfg.CredentialEncryptionKeyPath), KeyRing: read(c.cfg.KeyRingPath())}
}

// RenewCertRequest is the renewal body: a CSR for the node's current key or
// a new one.
type RenewCertRequest struct {
	CSR string `json:"csr"`
}

// RenewCertResponse is the renewed cert.
type RenewCertResponse struct {
	NodeCert string    `json:"node_cert"`
	CACert   string    `json:"ca_cert"`
	NotAfter time.Time `json:"not_after"`
	Rekeyed  bool      `json:"rekeyed,omitempty"`
}

// RenewNodeCert signs a fresh cert for an authenticated peer (§4.2). The
// peer must have an admitted record and present its admitted key (the
// internal listener already checked); a new key in the CSR moves the record
// first (opRekeyNode). The cert's role is the admitted one.
func (c *Cluster) RenewNodeCert(ctx context.Context, peerID string, leaf *x509.Certificate, csrPEM []byte) (RenewCertResponse, error) {
	signer := c.ca.get()
	if signer == nil {
		return RenewCertResponse{}, ErrNoCASigner
	}
	rec, ok := c.fsm.admittedNode(peerID)
	if !ok {
		return RenewCertResponse{}, ErrNotAdmitted
	}
	if err := c.fsm.peerTrustSnapshot().checkPeerCert(peerID, leaf, time.Now().UnixNano()); err != nil {
		return RenewCertResponse{}, err
	}
	csr, err := ParseCertificateRequestPEM(csrPEM)
	if err != nil {
		return RenewCertResponse{}, fmt.Errorf("%w: %v", ErrJoinBadRequest, err)
	}
	newKey, err := PublicKeyHash(csr.PublicKey)
	if err != nil {
		return RenewCertResponse{}, fmt.Errorf("%w: %v", ErrJoinBadRequest, err)
	}
	if c.fsm.peerTrustSnapshot().revokedKey(newKey, time.Now().UnixNano()) {
		return RenewCertResponse{}, ErrJoinKeyRevoked
	}
	lifetime := c.nodeCertTTL()
	now := time.Now()
	rekeyed := false
	if newKey != rec.KeyHash {
		if _, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteRekey, Rekey: &JoinRekeyCommand{
			NodeID: peerID, OldKeyHash: rec.KeyHash, NewKeyHash: newKey, NotAfterUnixNano: now.Add(lifetime).UnixNano(),
		}}); err != nil {
			return RenewCertResponse{}, err
		}
		rekeyed = true
	}
	certPEM, signed, err := signer.SignNodeCert(NodeCertRequest{PublicKey: csr.PublicKey, NodeID: peerID, Role: rec.Role, Lifetime: lifetime, Now: now})
	if err != nil {
		return RenewCertResponse{}, err
	}
	return RenewCertResponse{NodeCert: string(certPEM), CACert: string(signer.CertPEM()), NotAfter: signed.NotAfter.UTC(), Rekeyed: rekeyed}, nil
}

// CAKeyResponse is the CA key an adopting server fetches (§4.4 step 2).
type CAKeyResponse struct {
	CAKey string `json:"ca_key"`
}

// CAKeyForPeer hands this server's CA key to another server: only a Raft
// server whose admitted role (if any) is server (Codex eng finding 1).
func (c *Cluster) CAKeyForPeer(peerID string) (CAKeyResponse, error) {
	if !c.peerIsServer(peerID) {
		return CAKeyResponse{}, ErrPeerNotServer
	}
	signer := c.ca.get()
	if signer == nil {
		return CAKeyResponse{}, ErrNoCASigner
	}
	if c.logger != nil {
		c.logger.Info("cluster: CA key handed to an adopting server", "peer", peerID)
	}
	return CAKeyResponse{CAKey: string(signer.KeyPEM())}, nil
}

// AdoptRequest is POST /v1/cluster/adopt. CAKey is optional: the seed's
// `sandboxd adopt` may pass /etc/sandboxd/cluster-ca/ca.key, otherwise the
// server reads its CA store, then asks another server.
type AdoptRequest struct {
	CAKey string `json:"ca_key,omitempty"`
}

// AdoptResponse says what adopt did.
type AdoptResponse struct {
	ClusterID  string            `json:"cluster_id"`
	CAImported bool              `json:"ca_imported"`
	CASource   string            `json:"ca_source"`
	Admitted   []string          `json:"admitted"`
	Already    []string          `json:"already"`
	Skipped    map[string]string `json:"skipped,omitempty"`
}

// Adopt brings a cluster built with today's scripts onto the join service
// (§4.4): it makes sure this server holds the CA key (from the request, the
// CA store, or another server over mTLS), then records every live member's
// node ID, current cert key and role as admitted, in one Raft op. Running
// it again changes nothing.
func (c *Cluster) Adopt(ctx context.Context, req AdoptRequest) (AdoptResponse, error) {
	if c.cfg.ClusterExternalCA {
		return c.adoptSelfByCert(ctx)
	}
	caCert, caPEM, err := c.clusterCACert()
	if err != nil {
		return AdoptResponse{}, err
	}
	out := AdoptResponse{ClusterID: CACertHash(caCert), Admitted: []string{}, Already: []string{}, Skipped: map[string]string{}}
	src, imported, err := c.ensureCAKey(ctx, caPEM, req.CAKey)
	if err != nil {
		return out, err
	}
	out.CASource, out.CAImported = src, imported
	nodes, unreachable := c.collectMemberKeys(ctx)
	for id, why := range unreachable {
		out.Skipped[id] = why
	}
	if len(nodes) > 0 {
		written, err := c.WriteJoin(ctx, JoinWriteRequest{Kind: joinWriteAdopt, Adopt: &JoinAdoptCommand{Nodes: nodes}})
		if err != nil {
			return out, err
		}
		if res := written.Adopt; res != nil {
			out.Admitted, out.Already = res.Admitted, res.Already
			for id, why := range res.Skipped {
				out.Skipped[id] = why
			}
		}
	}
	if c.logger != nil {
		c.logger.Info("cluster: adopted", "ca_source", out.CASource, "admitted", out.Admitted, "already", len(out.Already), "skipped", out.Skipped)
	}
	return out, nil
}

// ensureCAKey installs the CA signer: a key in the request, the CA store,
// or another server's copy. The key must match this node's ca.crt.
func (c *Cluster) ensureCAKey(ctx context.Context, caPEM []byte, keyPEM string) (string, bool, error) {
	install := func(raw []byte, source string) (string, bool, error) {
		ca, err := ParseClusterCA(caPEM, raw)
		if err != nil {
			return "", false, err
		}
		if err := SaveClusterCA(c.cfg.ClusterCADir, ca); err != nil {
			return "", false, err
		}
		c.ca.set(ca)
		return source, true, nil
	}
	if strings.TrimSpace(keyPEM) != "" {
		return install([]byte(keyPEM), "request")
	}
	if c.ca.get() != nil {
		return "ca_store", false, nil
	}
	if ca, err := LoadClusterCA(c.cfg.ClusterCADir); err != nil {
		return "", false, err
	} else if ca != nil {
		if CACertHash(ca.Certificate()) != c.clusterID() {
			return "", false, errors.New("cluster: the CA store's ca.crt is not this cluster's CA")
		}
		c.ca.set(ca)
		return "ca_store", false, nil
	}
	var resp CAKeyResponse
	if err := c.postToServerPeers(ctx, PublicInternalCAKeyPath, struct{}{}, &resp); err != nil {
		return "", false, fmt.Errorf("cluster: no CA key here and none from another server (keep ca.key from the seed, or run adopt on the seed first): %w", err)
	}
	return install([]byte(resp.CAKey), "peer")
}

// collectMemberKeys reads every live member's current cert key: its own
// from memory, the rest from a TLS handshake with their internal listener
// (the cert must name the member's node ID).
func (c *Cluster) collectMemberKeys(ctx context.Context) ([]AdmittedNode, map[string]string) {
	unreachable := map[string]string{}
	var nodes []AdmittedNode
	if c.gossip == nil {
		return nil, unreachable
	}
	for _, m := range c.gossip.members() {
		if !m.Alive {
			continue
		}
		var leaf *x509.Certificate
		var err error
		if m.NodeID == c.nodeID {
			leaf, err = c.currentLeaf()
		} else {
			leaf, err = c.peerLeaf(ctx, m)
		}
		if err != nil {
			unreachable[m.NodeID] = "unreachable: " + err.Error()
			continue
		}
		nodes = append(nodes, AdmittedNode{
			NodeID: m.NodeID, Role: joinRoleForNodeRole(m.Role), KeyHash: CertKeyHash(leaf),
			NotAfterUnixNano: leaf.NotAfter.UnixNano(),
		})
	}
	return nodes, unreachable
}

// currentLeaf is this node's cert as served.
func (c *Cluster) currentLeaf() (*x509.Certificate, error) {
	if c.tls == nil {
		return nil, errors.New("no cluster TLS")
	}
	cert, err := c.tls.certificateForHandshake()
	if err != nil {
		return nil, err
	}
	return leafCertificate(cert)
}

// peerLeaf handshakes with m's internal listener and returns its leaf.
func (c *Cluster) peerLeaf(ctx context.Context, m Member) (*x509.Certificate, error) {
	if c.tls == nil || m.InternalURL == "" {
		return nil, errors.New("no internal URL")
	}
	u, err := url.Parse(m.InternalURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad internal URL %q", m.InternalURL)
	}
	dctx, cancel := context.WithTimeout(ctx, joinDialTimeout)
	defer cancel()
	d := &tls.Dialer{Config: c.tls.clientConfig()}
	conn, err := d.DialContext(dctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// The handshake verified the chain against the cluster CA, so there is
	// always a leaf here.
	leaf := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	if ExtractPeerNodeID(leaf) != m.NodeID {
		return nil, fmt.Errorf("cert names %q", ExtractPeerNodeID(leaf))
	}
	return leaf, nil
}

// postToServerPeers posts in to path on live server members, the leader
// first, until one answers 200. A 503 (this server can't serve it, or is not
// ready) moves on to the next.
func (c *Cluster) postToServerPeers(ctx context.Context, path string, in, out any) error {
	if c.gossip == nil || c.currentInternalClient() == nil {
		return ErrPeerInternalURLRequired
	}
	leader := c.Leader()
	var peers []Member
	for _, m := range c.gossip.members() {
		if m.Alive && m.NodeID != c.nodeID && m.InternalURL != "" && c.peerIsServer(m.NodeID) {
			peers = append(peers, m)
		}
	}
	sort.SliceStable(peers, func(i, j int) bool { return peers[i].NodeID == leader && peers[j].NodeID != leader })
	if len(peers) == 0 {
		return errors.New("cluster: no other live server")
	}
	var firstErr error
	for _, m := range peers {
		err := c.doNodeLifecycleJSONBody(ctx, c.ClientForPeer(m.NodeID), strings.TrimRight(m.InternalURL, "/")+path, in, out)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// doNodeLifecycleJSONBody is doNodeLifecycleJSON with a JSON body (POST).
func (c *Cluster) doNodeLifecycleJSONBody(ctx context.Context, client *http.Client, endpoint string, in, out any) error {
	return postPeerJSON(ctx, client, endpoint, c.nodeID, c.patToken, in, out)
}
