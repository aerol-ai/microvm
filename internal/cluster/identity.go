package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
)

// Cloud identity over the cluster (plans/sandbox-cloud-identity.md D1.3,
// D1.5). Writes go through a dedicated internal endpoint, like egress
// profiles, so the caller gets the stored state back and only a leader that
// checked every Raft server's build applies them. Reads answer from a
// server's FSM; a worker (no FSM) reads through the server tier.
const (
	PublicInternalIdentityWritePath = "/v1/cluster/internal/identity/write"
	PublicInternalIdentityReadPath  = "/v1/cluster/internal/identity/read"
)

// Outcome codes of an identity write, carried in a 200 body so the sentinel
// survives any number of forwarding hops.
const (
	identityCodeKeysConflict   = "keys_conflict"
	identityCodeInvalid        = "invalid"
	identityCodeClusterVersion = "cluster_version"
)

// IdentityWriteRequest is one identity write: a key-set replace, or a role
// put (DeleteRole false) or delete.
type IdentityWriteRequest struct {
	Keys       *IdentityKeysWrite  `json:"keys,omitempty"`
	Role       *IdentityRoleRecord `json:"role,omitempty"`
	DeleteRole bool                `json:"delete_role,omitempty"`
}

// IdentityWriteResponse is the outcome. Code is set when the FSM refused.
type IdentityWriteResponse struct {
	Keys    *cloudidentity.KeySet `json:"keys,omitempty"`
	Role    *IdentityRoleRecord   `json:"role,omitempty"`
	Changed bool                  `json:"changed,omitempty"`
	Code    string                `json:"code,omitempty"`
	Message string                `json:"message,omitempty"`
}

// IdentityReadRequest reads the key set (Keys) and/or an owner's roles: the
// named tags, or a page by tag when Tags is empty and RolePage is set.
type IdentityReadRequest struct {
	Keys     bool     `json:"keys,omitempty"`
	Owner    string   `json:"owner,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	RolePage bool     `json:"role_page,omitempty"`
	After    string   `json:"after,omitempty"`
	Limit    int      `json:"limit,omitempty"`
}

// IdentityReadResponse answers a read from a server's FSM. A tag with no
// role is simply absent.
type IdentityReadResponse struct {
	Keys          *cloudidentity.KeySet `json:"keys,omitempty"`
	Roles         []IdentityRoleRecord  `json:"roles"`
	Authoritative bool                  `json:"authoritative"`
}

// IdentityWriteOutcome turns a write error into the body a peer gets.
func IdentityWriteOutcome(err error) IdentityWriteResponse {
	switch {
	case errors.Is(err, ErrIdentityKeysConflict):
		return IdentityWriteResponse{Code: identityCodeKeysConflict, Message: err.Error()}
	case errors.Is(err, ErrIdentityInvalid):
		return IdentityWriteResponse{Code: identityCodeInvalid, Message: err.Error()}
	case errors.Is(err, ErrClusterVersion):
		return IdentityWriteResponse{Code: identityCodeClusterVersion, Message: err.Error()}
	}
	return IdentityWriteResponse{}
}

func (r IdentityWriteResponse) err() error {
	var sentinel error
	switch r.Code {
	case "":
		return nil
	case identityCodeKeysConflict:
		sentinel = ErrIdentityKeysConflict
	case identityCodeInvalid:
		sentinel = ErrIdentityInvalid
	case identityCodeClusterVersion:
		sentinel = ErrClusterVersion
	default:
		return fmt.Errorf("cluster: identity write: %s: %s", r.Code, r.Message)
	}
	return fmt.Errorf("%w (%s)", sentinel, r.Message)
}

// IdentityGate is implemented by cluster clients that can tell whether
// every live member runs a build with cloud identity. The service asserts
// it, so the single-node Noop (which does not implement it) and a cluster
// service that has not attached its client yet both stay closed.
type IdentityGate interface {
	IdentityAllowed() bool
}

// IdentityAllowed reports whether every live member, workers and ingress
// included, understands cloud identity: the create option (an older worker
// would drop it and run the sandbox with no identity), the token push, and
// the audit field (an older reader would not verify the record's hash).
func (c *Cluster) IdentityAllowed() bool {
	if c == nil {
		return false
	}
	return c.gossip.liveMembersAtLeast(identityFSMOpsVersion)
}

// IdentityAllowed is the same gate on a worker or ingress node.
func (a *Agent) IdentityAllowed() bool {
	if a == nil {
		return false
	}
	return a.gossip.liveMembersAtLeast(identityFSMOpsVersion)
}

// WriteIdentity applies an identity write on the leader after the upgrade
// gate; a follower forwards one hop to the leader.
func (c *Cluster) WriteIdentity(ctx context.Context, req IdentityWriteRequest) (IdentityWriteResponse, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return IdentityWriteResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	cmd, err := identityCommand(req)
	if err != nil {
		return IdentityWriteResponse{}, err
	}
	if c.raft.raft.State() != raft.Leader {
		var out IdentityWriteResponse
		if err := c.forwardToLeaderJSON(ctx, "identity write", PublicInternalIdentityWritePath, req, &out); err != nil {
			return IdentityWriteResponse{}, err
		}
		return out, out.err()
	}
	if err := c.raftServersSupport(identityFSMOpsVersion, "cloud identity writes"); err != nil {
		return IdentityWriteResponse{}, err
	}
	cmd.StampUnixNano = time.Now().UnixNano()
	payload, err := encodeCommand(cmd)
	if err != nil {
		return IdentityWriteResponse{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return IdentityWriteResponse{}, err
	}
	switch applied := result.(type) {
	case identityKeysApplyResult:
		return IdentityWriteResponse{Keys: &applied.Keys, Changed: true}, nil
	case identityRoleApplyResult:
		role := applied.Role
		return IdentityWriteResponse{Role: &role, Changed: applied.Changed}, nil
	}
	return IdentityWriteResponse{Changed: true}, nil
}

// identityCommand builds the FSM command of a write, refusing one that names
// nothing or two things.
func identityCommand(req IdentityWriteRequest) (command, error) {
	switch {
	case req.Keys != nil && req.Role == nil && !req.DeleteRole:
		keys := *req.Keys
		return command{Op: opPutIdentityKeys, IdentityKeys: &keys}, nil
	case req.Role != nil && req.Keys == nil:
		role := *req.Role
		op := opPutIdentityRole
		if req.DeleteRole {
			op = opDeleteIdentityRole
		}
		return command{Op: op, IdentityRole: &role}, nil
	}
	return command{}, fmt.Errorf("%w: a write names a key set or one role", ErrIdentityInvalid)
}

// ReadIdentity answers from this server's FSM.
func (c *Cluster) ReadIdentity(_ context.Context, req IdentityReadRequest) (IdentityReadResponse, error) {
	if c == nil || c.fsm == nil {
		return IdentityReadResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.readIdentity(req), nil
}

func (f *placementFSM) readIdentity(req IdentityReadRequest) IdentityReadResponse {
	out := IdentityReadResponse{Roles: []IdentityRoleRecord{}, Authoritative: true}
	if req.Keys {
		keys := f.identityKeys()
		out.Keys = &keys
	}
	if len(req.Tags) > 0 || req.RolePage {
		out.Roles = f.identityRoles(req.Owner, req.Tags, req.After, req.Limit)
	}
	return out
}

// WriteIdentity sends an identity write to the server tier; any server
// takes it and forwards it to the leader.
func (a *Agent) WriteIdentity(ctx context.Context, req IdentityWriteRequest) (IdentityWriteResponse, error) {
	if a == nil {
		return IdentityWriteResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out IdentityWriteResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalIdentityWritePath, PublicInternalIdentityWritePath, req, &out); err != nil {
		return IdentityWriteResponse{}, fmt.Errorf("cluster: identity write: %w", err)
	}
	if req.Role != nil {
		a.identityRoles.forget(req.Role.key())
	}
	return out, out.err()
}

// ReadIdentity reads from the server tier. Point reads of roles (the create
// check and the refresher) go through a cache refreshed every
// identityRoleCacheTTL, like egress profiles: a tag an admin removed stops
// new creates and refreshes on a worker within that TTL. Past
// identityRoleCacheMaxStale with the server tier unreachable, the read
// fails and the caller fails closed. Key reads are not cached here: the
// service caches the parsed signer.
func (a *Agent) ReadIdentity(ctx context.Context, req IdentityReadRequest) (IdentityReadResponse, error) {
	if a == nil {
		return IdentityReadResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	if !req.Keys && !req.RolePage && len(req.Tags) > 0 {
		return a.identityRoles.read(ctx, req, a.readIdentityRemote)
	}
	return a.readIdentityRemote(ctx, req)
}

func (a *Agent) readIdentityRemote(ctx context.Context, req IdentityReadRequest) (IdentityReadResponse, error) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out IdentityReadResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalIdentityReadPath, PublicInternalIdentityReadPath, req, &out); err != nil {
		return IdentityReadResponse{}, fmt.Errorf("cluster: identity read: %w", err)
	}
	if !out.Authoritative {
		return IdentityReadResponse{}, fmt.Errorf("cluster: identity read was not authoritative")
	}
	return out, nil
}

const (
	identityRoleCacheTTL      = 10 * time.Second
	identityRoleCacheMaxStale = 30 * time.Second
	// identityRoleCacheMax caps the entries. Any caller who can create a
	// sandbox picks the tags asked about, refused ones included, so
	// without a cap a worker's cache grows by one entry per made-up tag.
	// Past it a tag is still answered, just fetched again next time.
	identityRoleCacheMax = 4096
)

// identityRoleCache is a worker's view of the role tags its creates and
// refreshes ask about.
type identityRoleCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[IdentityRoleKey]identityRoleCacheEntry
}

type identityRoleCacheEntry struct {
	rec   IdentityRoleRecord
	found bool
	at    time.Time
}

func (c *identityRoleCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *identityRoleCache) forget(k IdentityRoleKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, k)
}

func (c *identityRoleCache) read(ctx context.Context, req IdentityReadRequest, fetch func(context.Context, IdentityReadRequest) (IdentityReadResponse, error)) (IdentityReadResponse, error) {
	now := c.clock()
	out := IdentityReadResponse{Roles: []IdentityRoleRecord{}, Authoritative: true}
	var missing []string
	c.mu.Lock()
	for _, tag := range req.Tags {
		e, ok := c.entries[IdentityRoleKey{req.Owner, tag}]
		if ok && now.Sub(e.at) < identityRoleCacheTTL {
			if e.found {
				out.Roles = append(out.Roles, e.rec)
			}
			continue
		}
		missing = append(missing, tag)
	}
	c.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	fetched, err := fetch(ctx, IdentityReadRequest{Owner: req.Owner, Tags: missing})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[IdentityRoleKey]identityRoleCacheEntry)
	}
	if err != nil {
		for _, tag := range missing {
			e, ok := c.entries[IdentityRoleKey{req.Owner, tag}]
			if !ok || now.Sub(e.at) >= identityRoleCacheMaxStale {
				return IdentityReadResponse{}, err
			}
			if e.found {
				out.Roles = append(out.Roles, e.rec)
			}
		}
		return out, nil
	}
	got := make(map[string]IdentityRoleRecord, len(fetched.Roles))
	for _, rec := range fetched.Roles {
		got[rec.Tag] = rec
	}
	if len(c.entries)+len(missing) > identityRoleCacheMax {
		// An entry past the stale window is never read again (a fresh
		// hit needs < TTL, the outage fallback < MaxStale), so dropping
		// it changes no answer.
		for k, e := range c.entries {
			if now.Sub(e.at) >= identityRoleCacheMaxStale {
				delete(c.entries, k)
			}
		}
	}
	for _, tag := range missing {
		rec, found := got[tag]
		k := IdentityRoleKey{req.Owner, tag}
		if _, held := c.entries[k]; held || len(c.entries) < identityRoleCacheMax {
			c.entries[k] = identityRoleCacheEntry{rec: rec, found: found, at: now}
		}
		if found {
			out.Roles = append(out.Roles, rec)
		}
	}
	return out, nil
}
