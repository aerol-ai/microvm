package cluster

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The cluster's server signing seed (least privilege): 32 random bytes only
// Raft servers hold, from which they derive the keys sandbox tokens are
// signed with and the key that seals the cloud-identity signing keys
// (internal/service/server_signing.go). Workers and gateways hold the
// server key ring, which seals what they must open themselves; they never
// hold this. It lives in the FSM, which only Raft servers replicate, sealed
// with the server key ring so a copy of the Raft data alone does not open
// it, and no route serves it.
//
//	leader, once every member runs a build that knows it (the active
//	cluster version reaches serverSigningFSMOpsVersion)
//	  ─► opPutServerSigning{sealed seed, since = now + serverSigningLead}
//	every server ─► opens it with its ring ─► derives the signing keys
//	workers, gateways ─► the public keys only (signing-keys feed)
//	ring rotation ─► the leader reseals it (compare-and-set on the sealed bytes)
//
// Since is when the derived keys take over: a sandbox token signed with a
// key derived from the server key ring and issued at or after it is
// refused. It is set a little after the record is written, so every node
// has seen the record, and signs with the servers, before such tokens stop
// counting. One issued before Since counts until it expires (at most the
// token max TTL after Since), or until the operator ends them all
// (OldTokensEndUnixNano: aerolvm upgrade signing end-old-tokens).
const opPutServerSigning opCode = 55

// Bounds on Since against the leader's clock when the record is first
// written (the command's stamp): the leader sets it a short lead ahead.
const (
	serverSigningMaxLead = 10 * time.Minute
	serverSigningMaxSkew = time.Minute
)

// serverSigningFSMOpsVersion: opPutServerSigning, the keys derived from it,
// and the routes that serve them. Nothing derived from it is used until the
// active cluster version reaches it, so every member verifies what servers
// sign.
const serverSigningFSMOpsVersion = 22

// ServerSigningFSMOpsVersion is serverSigningFSMOpsVersion for other packages.
const ServerSigningFSMOpsVersion = serverSigningFSMOpsVersion

// ServerSigning is the record.
type ServerSigning struct {
	// Sealed is the seed, sealed with the server key ring.
	Sealed []byte `json:"sealed"`
	// SinceUnixNano is when the derived keys took over (see above).
	SinceUnixNano int64 `json:"since_unix_nano"`
	// OldTokensEndUnixNano, once set, is when tokens signed with a server
	// key ring key stopped counting at all, whenever they were issued.
	OldTokensEndUnixNano int64 `json:"old_tokens_end_unix_nano,omitempty"`
}

// ServerSigningWrite is opPutServerSigning's payload: the record, and for a
// reseal the sealed bytes it replaces. EndOldTokens instead sets the
// record's OldTokensEndUnixNano to the leader's clock (the command's
// stamp), or Since if that is later; once set it does not move.
type ServerSigningWrite struct {
	Signing      ServerSigning `json:"signing"`
	Expect       []byte        `json:"expect,omitempty"`
	EndOldTokens bool          `json:"end_old_tokens,omitempty"`
}

var (
	// ErrServerSigningInvalid is a write with no sealed seed or no since.
	ErrServerSigningInvalid = errors.New("cluster: server signing record refused")
	// ErrServerSigningConflict is a reseal of a record that changed since
	// it was read; read again.
	ErrServerSigningConflict = errors.New("cluster: the server signing record changed")
)

type serverSigningApplyResult struct {
	Record  ServerSigning
	Changed bool
}

// applyPutServerSigningLocked writes the record once, and reseals it under
// compare-and-set. A first write when one exists changes nothing and
// answers the one that stands, so two leaders racing at the first write
// agree on one seed.
func (f *placementFSM) applyPutServerSigningLocked(cmd command) (any, error) {
	w := cmd.ServerSigning
	if w != nil && w.EndOldTokens {
		return f.endOldTokensLocked(cmd.StampUnixNano)
	}
	if w == nil || len(w.Signing.Sealed) == 0 || w.Signing.SinceUnixNano <= 0 {
		return nil, ErrServerSigningInvalid
	}
	cur := f.serverSigning
	switch {
	case cur == nil && len(w.Expect) == 0:
		if !sinceNearStamp(w.Signing.SinceUnixNano, cmd.StampUnixNano) {
			return nil, fmt.Errorf("%w: since is not a short lead after the leader's clock", ErrServerSigningInvalid)
		}
		rec := ServerSigning{Sealed: bytes.Clone(w.Signing.Sealed), SinceUnixNano: w.Signing.SinceUnixNano}
		f.serverSigning = &rec
		return serverSigningApplyResult{Record: rec, Changed: true}, nil
	case cur == nil:
		return nil, fmt.Errorf("%w: no record to reseal", ErrServerSigningConflict)
	case len(w.Expect) == 0:
		return serverSigningApplyResult{Record: cur.clone()}, nil
	case !bytes.Equal(w.Expect, cur.Sealed) || w.Signing.SinceUnixNano != cur.SinceUnixNano:
		return nil, ErrServerSigningConflict
	}
	cur.Sealed = bytes.Clone(w.Signing.Sealed)
	return serverSigningApplyResult{Record: cur.clone(), Changed: true}, nil
}

// sinceNearStamp reports whether since is within the lead the leader sets,
// against its clock when it proposed the write. A command with no stamp
// (none is written without one) passes.
func sinceNearStamp(since, stamp int64) bool {
	if stamp <= 0 {
		return true
	}
	return since >= stamp-int64(serverSigningMaxSkew) && since <= stamp+int64(serverSigningMaxLead+serverSigningMaxSkew)
}

// endOldTokensLocked sets OldTokensEndUnixNano once.
func (f *placementFSM) endOldTokensLocked(stamp int64) (any, error) {
	cur := f.serverSigning
	if cur == nil {
		return nil, fmt.Errorf("%w: servers do not sign yet", ErrServerSigningConflict)
	}
	if cur.OldTokensEndUnixNano > 0 {
		return serverSigningApplyResult{Record: cur.clone()}, nil
	}
	if stamp <= 0 {
		return nil, fmt.Errorf("%w: no clock on the write", ErrServerSigningInvalid)
	}
	cur.OldTokensEndUnixNano = max(stamp, cur.SinceUnixNano)
	return serverSigningApplyResult{Record: cur.clone(), Changed: true}, nil
}

func (r *ServerSigning) clone() ServerSigning {
	return ServerSigning{Sealed: bytes.Clone(r.Sealed), SinceUnixNano: r.SinceUnixNano, OldTokensEndUnixNano: r.OldTokensEndUnixNano}
}

func (f *placementFSM) serverSigningRecord() (ServerSigning, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.serverSigning == nil {
		return ServerSigning{}, false
	}
	return f.serverSigning.clone(), true
}

func (f *placementFSM) serverSigningSnapshotLocked() *ServerSigning {
	if f.serverSigning == nil {
		return nil
	}
	rec := f.serverSigning.clone()
	return &rec
}

// restoreServerSigningLocked loads a snapshot's record; a snapshot from
// before it has none, and a malformed one is dropped like a missing one
// (the leader writes a new record, so this cannot strand the cluster).
func (f *placementFSM) restoreServerSigningLocked(rec *ServerSigning) {
	f.serverSigning = nil
	if rec != nil && len(rec.Sealed) > 0 && rec.SinceUnixNano > 0 {
		restored := rec.clone()
		f.serverSigning = &restored
	}
}

// specKeepingIdentityLocked is spec with the cloud identity cur carries,
// when spec carries none: only a server sets a placement's identity
// (peer_proposals.go identityKeptBy), and an owner that sends its
// sandbox's spec again (an ownership replay, an orphan claim, a spec
// write) rebuilds it from its own row, which does not keep it, so the
// sandbox would stop getting its tokens. From the active version that
// brought server signing on, so every replica applies an entry alike.
func (f *placementFSM) specKeepingIdentityLocked(spec, cur *models.CreateSandboxRequest) *models.CreateSandboxRequest {
	if spec == nil || spec.Identity != nil || cur == nil || cur.Identity == nil || f.activeFVValue() < serverSigningFSMOpsVersion {
		return spec
	}
	out := *spec
	idn := *cur.Identity
	out.Identity = &idn
	return &out
}
