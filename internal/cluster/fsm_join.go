package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// Join tokens, admitted keys and revoked-key tombstones in the Raft FSM
// (plans/kubectl-style-cluster-ops.md D3, §4, §5; Codex CEO finding 6,
// Codex eng finding 1).
//
//	opPutJoinToken    ─► joinTokens[id]            (hash + discovery key, never the secret)
//	opDeleteJoinToken ─► revoke                    (idempotent)
//	opAdmitNode       ─► one join, atomically:     use the token for this key,
//	                                               reserve the node ID for this key,
//	                                               replace a deny record, write admitted[id]
//	opAdoptNodes      ─► admitted[id] for every live member of a scripted cluster (§4.4)
//	opRekeyNode       ─► a renewal that moved the node to a new key (§4.2)
//	opDenyNode (42)   ─► also moves the admitted key to the tombstones (§5)
//
// Why not the API token table (D3 asked us to check first): its records
// carry a controlplane role, a required expiry and a team, and every worker
// mirrors them as API credentials. A join token needs a node role, may never
// expire, is single-use with a used-by list, and carries a discovery key; it
// must never authenticate an API call. So it gets its own ops, behind
// joinFSMOpsVersion.
//
// Every decision reads only the entry and FSM state: "now" is the proposer's
// StampUnixNano, so every replica expires the same tokens and tombstones at
// the same entry. The gossip-liveness check (a live member keeps its ID) is
// the proposer's, before the entry exists, because gossip is not replicated.
//
// Rolling upgrade: an older build fails these ops, so the leader proposes
// them only once every Raft server reports joinFSMOpsVersion
// (raftServersSupport). An older snapshot has none of the three tables and
// restores as "no tokens, nothing admitted, nothing revoked", which is
// today's behaviour; an older build ignores the fields in a newer snapshot,
// which is safe because nothing is written until every server runs this
// build.
const (
	opPutJoinToken    opCode = 43 // store one join token (hash + discovery key)
	opDeleteJoinToken opCode = 44 // revoke one join token (idempotent)
	opAdmitNode       opCode = 45 // one join: use the token, reserve the ID, admit the key
	opAdoptNodes      opCode = 46 // admit the current members of a scripted cluster
	opRekeyNode       opCode = 47 // move an admitted node to a new key (renewal)
)

// joinFSMOpsVersion: opPutJoinToken through opRekeyNode, and opDenyNode
// tombstoning an admitted key.
const joinFSMOpsVersion = 13

// Bounds on the replicated join state.
const (
	// maxJoinTokenUses caps a reusable token's used-by list; the oldest
	// uses drop first. Autoscaling with a never-expiring worker token would
	// otherwise grow one record forever. Audit keeps every use.
	maxJoinTokenUses = 256
	// joinTokenListRetention keeps an expired token listable for a day
	// (`aerolvm get join-tokens` shows it as expired), then a later join
	// write drops it.
	joinTokenListRetention = 24 * time.Hour
	// revokedKeySkew pads a tombstone past the last moment its key's cert
	// could still verify, for clock skew between signer and checker.
	revokedKeySkew = time.Hour
	// rekeyGrace keeps a renewing node's previous key accepted while its
	// pooled connections still present the old cert.
	rekeyGrace = 15 * time.Minute
	// adoptTokenID marks an admitted record written by adopt, not a token.
	adoptTokenID = "adopt"
)

var (
	// ErrJoinTokenInvalid is an unknown, revoked or wrong-secret token. The
	// three are one answer so a caller can't probe which ids exist.
	ErrJoinTokenInvalid = errors.New("cluster: join token is not valid")
	// ErrJoinTokenExpired is a token past its TTL.
	ErrJoinTokenExpired = errors.New("cluster: join token has expired")
	// ErrJoinTokenUsed is a single-use token another node or key used.
	ErrJoinTokenUsed = errors.New("cluster: join token was already used by another node")
	// ErrJoinRoleMismatch is a join asking for a role its token does not carry.
	ErrJoinRoleMismatch = errors.New("cluster: join role does not match the token's role")
	// ErrNodeIDInUse is a join for an ID a live member or another key holds.
	ErrNodeIDInUse = errors.New("cluster: node ID in use")
	// ErrJoinKeyRevoked is a key on the tombstone list: a deleted node's.
	ErrJoinKeyRevoked = errors.New("cluster: this key was revoked (its node was deleted); make a new key")
	// ErrJoinKeyInUse is a key already admitted under another node ID.
	ErrJoinKeyInUse = errors.New("cluster: this key is admitted for another node ID")
	// ErrJoinTokenIDTaken is a create whose random id collides.
	ErrJoinTokenIDTaken = errors.New("cluster: join token id already exists")
	// ErrJoinNodeIDInvalid is a node ID no cert, gossip name or Raft ID takes.
	ErrJoinNodeIDInvalid = errors.New("cluster: node ID must be 1-63 letters, digits, '.', '_' or '-'")
	// ErrNotAdmitted is a renewal or rekey for a node with no admitted record
	// (a scripted cluster that has not run `sandboxd adopt`).
	ErrNotAdmitted = errors.New("cluster: node has no admitted key; run `sandboxd adopt` on the seed first")
	// ErrRekeyConflict is a rekey whose old key is no longer the admitted one.
	ErrRekeyConflict = errors.New("cluster: node's admitted key changed; retry the renewal")
	// ErrNoCASigner is a signing request on a server that holds no CA key.
	ErrNoCASigner = errors.New("cluster: this server holds no cluster CA key (run `sandboxd adopt`)")
	// ErrPeerKeyRevoked is an internal call with a deleted node's cert key.
	ErrPeerKeyRevoked = errors.New("cluster peer cert key was revoked (its node was deleted); it needs a fresh join")
	// ErrPeerKeyNotAdmitted is an internal call whose cert key is not the
	// one admitted for its node ID (an old cert of a reused ID).
	ErrPeerKeyNotAdmitted = errors.New("cluster peer cert key is not the one admitted for its node ID")
)

// JoinTokenRecord is one join token. The secret is never stored.
type JoinTokenRecord struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	// SecretHash checks a join; DiscoveryKey signs cluster-info (D4).
	SecretHash   []byte `json:"secret_hash"`
	DiscoveryKey []byte `json:"discovery_key"`
	CreatedBy    string `json:"created_by,omitempty"`
	// Times come from the proposer, never the applier's clock.
	CreatedUnixNano int64 `json:"created_unix_nano"`
	// ExpiresUnixNano is 0 for a token that never expires (worker and
	// ingress only, CEO D13).
	ExpiresUnixNano int64          `json:"expires_unix_nano,omitempty"`
	Reusable        bool           `json:"reusable,omitempty"`
	UsedBy          []JoinTokenUse `json:"used_by,omitempty"`
}

// JoinTokenUse is one node that joined with a token.
type JoinTokenUse struct {
	NodeID   string `json:"node_id"`
	KeyHash  string `json:"key_hash"`
	UnixNano int64  `json:"unix_nano"`
}

func (r JoinTokenRecord) clone() JoinTokenRecord {
	r.SecretHash = append([]byte(nil), r.SecretHash...)
	r.DiscoveryKey = append([]byte(nil), r.DiscoveryKey...)
	r.UsedBy = append([]JoinTokenUse(nil), r.UsedBy...)
	return r
}

// expiredAt reports whether the token is past its TTL at nano.
func (r JoinTokenRecord) expiredAt(nano int64) bool {
	return r.ExpiresUnixNano != 0 && nano >= r.ExpiresUnixNano
}

func (r JoinTokenRecord) usedBy(nodeID, keyHash string) bool {
	for _, u := range r.UsedBy {
		if u.NodeID == nodeID && u.KeyHash == keyHash {
			return true
		}
	}
	return false
}

func (r JoinTokenRecord) validate() error {
	switch {
	case !ValidJoinTokenID(r.ID):
		return fmt.Errorf("join token id %q", r.ID)
	case !ValidJoinRole(r.Role):
		return fmt.Errorf("join token role %q", r.Role)
	case len(r.SecretHash) != 32 || len(r.DiscoveryKey) != 32:
		return errors.New("join token hash and discovery key must be 32 bytes")
	case r.ExpiresUnixNano == 0 && r.Role == JoinRoleServer:
		return errors.New("a server join token must expire")
	}
	return nil
}

// AdmittedNode is the one key a node ID may present (§5). Every
// authenticated internal call and renewal from that ID must use it.
type AdmittedNode struct {
	NodeID string `json:"node_id"`
	// Role is the admitted join role (server, worker or ingress). Voter
	// auto-join and every server-only operation read this, never the
	// gossiped role (Codex eng finding 1).
	Role    string `json:"role"`
	KeyHash string `json:"key_hash"`
	// NotAfterUnixNano is the newest cert this record saw for KeyHash; a
	// tombstone outlives it.
	NotAfterUnixNano int64 `json:"not_after_unix_nano,omitempty"`
	AdmittedUnixNano int64 `json:"admitted_unix_nano"`
	// TokenID is the token that admitted it, or "adopt".
	TokenID string `json:"token_id,omitempty"`
	// PrevKeyHash stays accepted until PrevUntilUnixNano after a rekey.
	PrevKeyHash       string `json:"prev_key_hash,omitempty"`
	PrevUntilUnixNano int64  `json:"prev_until_unix_nano,omitempty"`
}

// IsServer reports whether the admitted role may hold Raft and the CA key.
func (a AdmittedNode) IsServer() bool { return a.Role == JoinRoleServer }

// RevokedKey is a tombstone: a deleted node's cert key, refused on every
// internal call until any cert for it would have expired, even after its
// node ID is reused (Codex CEO finding 6).
type RevokedKey struct {
	KeyHash         string `json:"key_hash"`
	NodeID          string `json:"node_id"`
	RevokedUnixNano int64  `json:"revoked_unix_nano"`
	ExpiresUnixNano int64  `json:"expires_unix_nano"`
}

// JoinAdmitCommand is opAdmitNode's payload.
type JoinAdmitCommand struct {
	TokenID          string `json:"token_id"`
	NodeID           string `json:"node_id"`
	Role             string `json:"role"`
	KeyHash          string `json:"key_hash"`
	NotAfterUnixNano int64  `json:"not_after_unix_nano"`
}

// JoinAdmitResult is the leader FSM's answer to opAdmitNode.
type JoinAdmitResult struct {
	Node AdmittedNode `json:"node"`
	// Replay: this token already admitted this key for this ID, so the
	// retry gets the same answer and nothing changed.
	Replay bool `json:"replay,omitempty"`
	// ReplacedDeny: the ID had a deny record this join removed.
	ReplacedDeny bool `json:"replaced_deny,omitempty"`
}

// JoinAdoptCommand is opAdoptNodes' payload: the live members to admit.
type JoinAdoptCommand struct {
	Nodes []AdmittedNode `json:"nodes"`
}

// JoinAdoptResult says what adopt did with each member.
type JoinAdoptResult struct {
	Admitted []string          `json:"admitted"`
	Already  []string          `json:"already"`
	Skipped  map[string]string `json:"skipped,omitempty"`
}

// JoinRekeyCommand is opRekeyNode's payload.
type JoinRekeyCommand struct {
	NodeID           string `json:"node_id"`
	OldKeyHash       string `json:"old_key_hash"`
	NewKeyHash       string `json:"new_key_hash"`
	NotAfterUnixNano int64  `json:"not_after_unix_nano"`
}

// peerTrustView is the published copy of the admitted keys and tombstones
// for the per-request peer check, read without the FSM lock like the deny
// set (isNodeDenied).
type peerTrustView struct {
	admitted map[string]AdmittedNode
	revoked  map[string]int64 // key hash -> expires (unix nano)
}

func (f *placementFSM) joinStateInitLocked() {
	if f.joinTokens == nil {
		f.joinTokens = make(map[string]*JoinTokenRecord)
	}
	if f.admitted == nil {
		f.admitted = make(map[string]AdmittedNode)
	}
	if f.admittedByKey == nil {
		f.admittedByKey = make(map[string]string)
	}
	if f.revokedKeys == nil {
		f.revokedKeys = make(map[string]RevokedKey)
	}
}

func joinStamp(cmd command) (int64, error) {
	if cmd.StampUnixNano <= 0 {
		return 0, errors.New("placementFSM: join ops need the proposer's stamp")
	}
	return cmd.StampUnixNano, nil
}

func (f *placementFSM) applyPutJoinTokenLocked(cmd command) (any, error) {
	in := cmd.JoinToken
	if in == nil {
		return nil, errors.New("placementFSM: opPutJoinToken requires a token")
	}
	stamp, err := joinStamp(cmd)
	if err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, fmt.Errorf("placementFSM: opPutJoinToken: %w", err)
	}
	f.joinStateInitLocked()
	f.pruneJoinTokensLocked(stamp)
	if old, ok := f.joinTokens[in.ID]; ok {
		// A retried proposal of the same create gets the row it made; a
		// different token on the same id never overwrites one.
		if constantTimeEqual(old.SecretHash, in.SecretHash) {
			return old.clone(), nil
		}
		return nil, fmt.Errorf("%w: %s", ErrJoinTokenIDTaken, in.ID)
	}
	rec := in.clone()
	rec.UsedBy = nil
	f.joinTokens[rec.ID] = &rec
	return rec.clone(), nil
}

func (f *placementFSM) applyDeleteJoinTokenLocked(cmd command) error {
	id := strings.TrimSpace(cmd.JoinTokenID)
	if id == "" {
		return errors.New("placementFSM: opDeleteJoinToken requires a token id")
	}
	if f.joinTokens != nil {
		delete(f.joinTokens, id)
	}
	return nil
}

// pruneJoinTokensLocked drops tokens expired for longer than the list
// retention, at the entry's stamp.
func (f *placementFSM) pruneJoinTokensLocked(stamp int64) {
	cutoff := stamp - int64(joinTokenListRetention)
	for id, rec := range f.joinTokens {
		if rec.ExpiresUnixNano != 0 && rec.ExpiresUnixNano < cutoff {
			delete(f.joinTokens, id)
		}
	}
}

// pruneRevokedKeysLocked drops tombstones whose certs have all expired.
// Reports whether any went.
func (f *placementFSM) pruneRevokedKeysLocked(stamp int64) bool {
	changed := false
	for k, rec := range f.revokedKeys {
		if rec.ExpiresUnixNano <= stamp {
			delete(f.revokedKeys, k)
			changed = true
		}
	}
	return changed
}

func (f *placementFSM) applyAdmitNodeLocked(cmd command, index uint64) (any, error) {
	in := cmd.JoinAdmit
	if in == nil {
		return nil, errors.New("placementFSM: opAdmitNode requires a join")
	}
	stamp, err := joinStamp(cmd)
	if err != nil {
		return nil, err
	}
	nodeID := strings.TrimSpace(in.NodeID)
	switch {
	case !ValidJoinNodeID(nodeID):
		return nil, fmt.Errorf("%w: %q", ErrJoinNodeIDInvalid, in.NodeID)
	case !validKeyHash(in.KeyHash):
		return nil, errors.New("placementFSM: opAdmitNode requires a key hash")
	}
	f.joinStateInitLocked()
	trustChanged := f.pruneRevokedKeysLocked(stamp)
	defer func() {
		if trustChanged {
			f.deniedNodesVersion = index
			f.publishDeniedLocked()
			f.publishPeerTrustLocked()
		}
	}()
	tok, ok := f.joinTokens[strings.TrimSpace(in.TokenID)]
	if !ok {
		return nil, ErrJoinTokenInvalid
	}
	// A retry of a join that already landed: same token, same ID, same key.
	// It gets the same answer even past the token's TTL, so a join that
	// crashed after its Raft write can simply run again.
	if cur, ok := f.admitted[nodeID]; ok && cur.KeyHash == in.KeyHash && tok.usedBy(nodeID, in.KeyHash) {
		return JoinAdmitResult{Node: cur, Replay: true}, nil
	}
	switch {
	case tok.expiredAt(stamp):
		return nil, ErrJoinTokenExpired
	case tok.Role != in.Role:
		return nil, fmt.Errorf("%w: token admits %s, join asked for %s", ErrJoinRoleMismatch, tok.Role, in.Role)
	case !tok.Reusable && len(tok.UsedBy) > 0:
		return nil, ErrJoinTokenUsed
	}
	if _, revoked := f.revokedKeys[in.KeyHash]; revoked {
		return nil, ErrJoinKeyRevoked
	}
	if holder, ok := f.admittedByKey[in.KeyHash]; ok && holder != nodeID {
		return nil, fmt.Errorf("%w: %s", ErrJoinKeyInUse, holder)
	}
	if cur, ok := f.admitted[nodeID]; ok && cur.KeyHash != in.KeyHash {
		// One admitted key per ID: the old one must be deleted first
		// (`aerolvm delete node` tombstones it), so a stolen token can't
		// take over a running node's identity.
		return nil, fmt.Errorf("%w: %s is admitted with another key; delete the node first", ErrNodeIDInUse, nodeID)
	}
	rec := AdmittedNode{
		NodeID: nodeID, Role: in.Role, KeyHash: in.KeyHash,
		NotAfterUnixNano: in.NotAfterUnixNano, AdmittedUnixNano: stamp, TokenID: tok.ID,
	}
	f.admitted[nodeID] = rec
	f.admittedByKey[in.KeyHash] = nodeID
	tok.UsedBy = append(tok.UsedBy, JoinTokenUse{NodeID: nodeID, KeyHash: in.KeyHash, UnixNano: stamp})
	if n := len(tok.UsedBy); n > maxJoinTokenUses {
		tok.UsedBy = append([]JoinTokenUse(nil), tok.UsedBy[n-maxJoinTokenUses:]...)
	}
	f.pruneJoinTokensLocked(stamp)
	res := JoinAdmitResult{Node: rec}
	if _, denied := f.deniedNodes[nodeID]; denied {
		// A fresh join (new token, new key: the revoked check above refused
		// the old one) replaces the deny record (§5).
		delete(f.deniedNodes, nodeID)
		res.ReplacedDeny = true
	}
	trustChanged = trustChanged || res.ReplacedDeny
	f.publishPeerTrustLocked()
	return res, nil
}

func (f *placementFSM) applyAdoptNodesLocked(cmd command) (any, error) {
	in := cmd.JoinAdopt
	if in == nil {
		return nil, errors.New("placementFSM: opAdoptNodes requires members")
	}
	stamp, err := joinStamp(cmd)
	if err != nil {
		return nil, err
	}
	f.joinStateInitLocked()
	nodes := append([]AdmittedNode(nil), in.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	res := JoinAdoptResult{Admitted: []string{}, Already: []string{}, Skipped: map[string]string{}}
	for _, n := range nodes {
		id := strings.TrimSpace(n.NodeID)
		reason := ""
		switch cur, admitted := f.admitted[id]; {
		case !ValidJoinNodeID(id) || !validKeyHash(n.KeyHash) || !ValidJoinRole(n.Role):
			reason = "invalid record"
		case admitted && cur.KeyHash == n.KeyHash:
			res.Already = append(res.Already, id)
			continue
		case admitted:
			reason = "admitted with another key"
		case f.deniedNodes[id].NodeID != "":
			reason = "node was deleted"
		case f.revokedKeys[n.KeyHash].KeyHash != "":
			reason = "key was revoked"
		case f.admittedByKey[n.KeyHash] != "":
			reason = "key is admitted for " + f.admittedByKey[n.KeyHash]
		}
		if reason != "" {
			res.Skipped[id] = reason
			continue
		}
		f.admitted[id] = AdmittedNode{
			NodeID: id, Role: n.Role, KeyHash: n.KeyHash, NotAfterUnixNano: n.NotAfterUnixNano,
			AdmittedUnixNano: stamp, TokenID: adoptTokenID,
		}
		f.admittedByKey[n.KeyHash] = id
		res.Admitted = append(res.Admitted, id)
	}
	if len(res.Admitted) > 0 {
		f.publishPeerTrustLocked()
	}
	return res, nil
}

func (f *placementFSM) applyRekeyNodeLocked(cmd command) (any, error) {
	in := cmd.JoinRekey
	if in == nil {
		return nil, errors.New("placementFSM: opRekeyNode requires a rekey")
	}
	stamp, err := joinStamp(cmd)
	if err != nil {
		return nil, err
	}
	if !validKeyHash(in.OldKeyHash) || !validKeyHash(in.NewKeyHash) {
		return nil, errors.New("placementFSM: opRekeyNode requires both key hashes")
	}
	f.joinStateInitLocked()
	id := strings.TrimSpace(in.NodeID)
	cur, ok := f.admitted[id]
	if !ok {
		return nil, ErrNotAdmitted
	}
	if cur.KeyHash == in.NewKeyHash {
		return cur, nil // a retried rekey
	}
	if cur.KeyHash != in.OldKeyHash {
		return nil, ErrRekeyConflict
	}
	if _, revoked := f.revokedKeys[in.NewKeyHash]; revoked {
		return nil, ErrJoinKeyRevoked
	}
	if holder, ok := f.admittedByKey[in.NewKeyHash]; ok && holder != id {
		return nil, fmt.Errorf("%w: %s", ErrJoinKeyInUse, holder)
	}
	delete(f.admittedByKey, cur.KeyHash)
	if cur.PrevKeyHash != "" && f.admittedByKey[cur.PrevKeyHash] == id {
		delete(f.admittedByKey, cur.PrevKeyHash)
	}
	cur.PrevKeyHash, cur.PrevUntilUnixNano = cur.KeyHash, stamp+int64(rekeyGrace)
	cur.KeyHash, cur.NotAfterUnixNano = in.NewKeyHash, in.NotAfterUnixNano
	f.admitted[id] = cur
	f.admittedByKey[cur.KeyHash] = id
	f.publishPeerTrustLocked()
	return cur, nil
}

// tombstoneAdmittedLocked is opDenyNode's addition: the deleted node's
// admitted key (and a previous key still in its grace) joins the
// tombstones until every cert for it would have expired, and the ID is
// freed for a fresh join. The bound is the later of the cert this record
// saw and the deny stamp plus a full cert life, because a same-key renewal
// does not write Raft. Returns whether the tombstones changed.
func (f *placementFSM) tombstoneAdmittedLocked(nodeID string, stamp int64) bool {
	cur, ok := f.admitted[nodeID]
	if !ok {
		return false
	}
	f.joinStateInitLocked()
	expires := max(cur.NotAfterUnixNano, stamp+int64(NodeCertLifetime)) + int64(revokedKeySkew)
	f.revokedKeys[cur.KeyHash] = RevokedKey{KeyHash: cur.KeyHash, NodeID: nodeID, RevokedUnixNano: stamp, ExpiresUnixNano: expires}
	if cur.PrevKeyHash != "" && cur.PrevUntilUnixNano > stamp {
		f.revokedKeys[cur.PrevKeyHash] = RevokedKey{KeyHash: cur.PrevKeyHash, NodeID: nodeID, RevokedUnixNano: stamp, ExpiresUnixNano: expires}
	}
	delete(f.admitted, nodeID)
	if f.admittedByKey[cur.KeyHash] == nodeID {
		delete(f.admittedByKey, cur.KeyHash)
	}
	f.publishPeerTrustLocked()
	return true
}

// publishPeerTrustLocked swaps in a fresh copy of the admitted keys and
// tombstones for lock-free readers. Caller holds f.mu. Copy-on-write is
// cheap: these change on a join, an adopt, a rekey or a delete.
func (f *placementFSM) publishPeerTrustLocked() {
	view := &peerTrustView{
		admitted: make(map[string]AdmittedNode, len(f.admitted)),
		revoked:  make(map[string]int64, len(f.revokedKeys)),
	}
	for id, rec := range f.admitted {
		view.admitted[id] = rec
	}
	for k, rec := range f.revokedKeys {
		view.revoked[k] = rec.ExpiresUnixNano
	}
	f.peerTrust.Store(view)
}

func (f *placementFSM) peerTrustSnapshot() *peerTrustView {
	if f == nil {
		return nil
	}
	return f.peerTrust.Load()
}

// admittedNode returns nodeID's admitted record, lock-free.
func (f *placementFSM) admittedNode(nodeID string) (AdmittedNode, bool) {
	view := f.peerTrustSnapshot()
	if view == nil {
		return AdmittedNode{}, false
	}
	rec, ok := view.admitted[nodeID]
	return rec, ok
}

// checkPeerKey is the per-request rule (§5): a tombstoned key is refused;
// a node with an admitted record must present its admitted key (or its
// previous key inside the rekey grace); a node with no record (a scripted
// cluster before adopt) keeps today's behaviour. now is the checker's
// clock: it only ever retires a tombstone or a grace, never grants.
func (v *peerTrustView) checkPeerKey(nodeID, keyHash string, now int64) error {
	if v == nil || keyHash == "" {
		return nil
	}
	if exp, ok := v.revoked[keyHash]; ok && now < exp {
		return ErrPeerKeyRevoked
	}
	rec, ok := v.admitted[nodeID]
	if !ok {
		return nil
	}
	if keyHash == rec.KeyHash || (keyHash == rec.PrevKeyHash && now < rec.PrevUntilUnixNano) {
		return nil
	}
	return ErrPeerKeyNotAdmitted
}

func (v *peerTrustView) revokedKey(keyHash string, now int64) bool {
	if v == nil {
		return false
	}
	exp, ok := v.revoked[keyHash]
	return ok && now < exp
}

// joinTokenView returns one token, copied.
func (f *placementFSM) joinToken(id string) (JoinTokenRecord, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rec, ok := f.joinTokens[id]
	if !ok {
		return JoinTokenRecord{}, false
	}
	return rec.clone(), true
}

func (f *placementFSM) joinTokensSnapshotLocked() []JoinTokenRecord {
	out := make([]JoinTokenRecord, 0, len(f.joinTokens))
	for _, rec := range f.joinTokens {
		out = append(out, rec.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (f *placementFSM) admittedSnapshotLocked() []AdmittedNode {
	out := make([]AdmittedNode, 0, len(f.admitted))
	for _, rec := range f.admitted {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func (f *placementFSM) revokedSnapshotLocked() []RevokedKey {
	out := make([]RevokedKey, 0, len(f.revokedKeys))
	for _, rec := range f.revokedKeys {
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyHash < out[j].KeyHash })
	return out
}

// joinStateView returns every table, sorted, under the read lock.
func (f *placementFSM) joinStateView() ([]JoinTokenRecord, []AdmittedNode, []RevokedKey) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.joinTokensSnapshotLocked(), f.admittedSnapshotLocked(), f.revokedSnapshotLocked()
}

// restoreJoinStateLocked loads the snapshot's tables; an older snapshot has
// none, which reads as nothing issued, admitted or revoked.
func (f *placementFSM) restoreJoinStateLocked(tokens []JoinTokenRecord, admitted []AdmittedNode, revoked []RevokedKey) {
	f.joinTokens = make(map[string]*JoinTokenRecord, len(tokens))
	f.admitted = make(map[string]AdmittedNode, len(admitted))
	f.admittedByKey = make(map[string]string, len(admitted))
	f.revokedKeys = make(map[string]RevokedKey, len(revoked))
	for _, t := range tokens {
		if t.ID == "" {
			continue
		}
		rec := t.clone()
		f.joinTokens[rec.ID] = &rec
	}
	for _, a := range admitted {
		if a.NodeID == "" || a.KeyHash == "" {
			continue
		}
		f.admitted[a.NodeID] = a
		f.admittedByKey[a.KeyHash] = a.NodeID
	}
	for _, r := range revoked {
		if r.KeyHash != "" {
			f.revokedKeys[r.KeyHash] = r
		}
	}
	f.publishPeerTrustLocked()
}

// joinRoleForNodeRole maps a gossiped SB_NODE_ROLE to the join role adopt
// records: any role set with server (or the mixed shorthand) is a server.
func joinRoleForNodeRole(role string) string {
	role = strings.TrimSpace(role)
	if role == "" || !isForcedNonVoterRole(role) {
		return JoinRoleServer
	}
	for raw := range strings.SplitSeq(role, ",") {
		if strings.EqualFold(strings.TrimSpace(raw), config.NodeRoleWorker) {
			return JoinRoleWorker
		}
	}
	return JoinRoleIngress
}

// errJoinOpNotForwardable refuses join ops on the generic leader-forward
// apply path: only the join write route (raft servers only) proposes them.
var errJoinOpNotForwardable = errors.New("cluster: join state is written only through the join write route")

// isJoinOp reports whether op belongs to this file.
func isJoinOp(op opCode) bool {
	switch op {
	case opPutJoinToken, opDeleteJoinToken, opAdmitNode, opAdoptNodes, opRekeyNode:
		return true
	}
	return false
}
