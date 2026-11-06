package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Cloud identity per sandbox (plans/sandbox-cloud-identity.md): sandboxd is
// an OIDC issuer. This file holds the issuer half every node runs (the
// signing keys and their lazy bootstrap, the public documents, the role-tag
// allow lists) and the create-path checks. identity_push.go delivers tokens
// to sandboxes and keeps them fresh.
//
// Security review answers this code carries (section 7 of the design):
//
//  1. The signing key exists in the clear only in this process's memory
//     (identitySigner); at rest it is sealed under the server key (store,
//     FSM). No API returns it and nothing here logs it, or a token.
//  3. The subject is built from the sandbox's owner ref, which create takes
//     from the caller's credential (ownerRefForCreateOrRecreate), and a role
//     tag checked against that owner's allow list and the caller's role.
//     Nothing in the request names the team.

var (
	// ErrIdentityDisabled is an identity create on a deployment that is not
	// an issuer (400, D1.1 failure handling).
	ErrIdentityDisabled = errors.New("identity needs SB_IDENTITY_ISSUER_URL")
	// ErrIdentityInvalid is a malformed identity option or role (400).
	ErrIdentityInvalid = cloudidentity.ErrInvalid
	// ErrIdentityRuntime is identity on a runtime with no file a cloud SDK
	// could read (400, D1.9).
	ErrIdentityRuntime = errors.New("identity is not supported on the wasm and isolate runtimes")
	// ErrIdentityRoleNotFound is a tag not on the owner's allow list: 404 on
	// the roles API.
	ErrIdentityRoleNotFound = store.ErrIdentityRoleNotFound
	// ErrIdentityRoleDenied is a create asking for a tag not on the allow
	// list, or by a caller below its minimum role, or a roles call for a team
	// the caller is not bound to (403, D1.5).
	ErrIdentityRoleDenied = errors.New("identity role tag not allowed")
	// ErrIdentityUnavailable means the keys or the allow list could not be
	// read or written right now, or a cluster member still runs a build
	// without identity (503, retry).
	ErrIdentityUnavailable = errors.New("cloud identity is unavailable")
	// ErrIdentityKeysConflict is a key-set write another writer beat; the
	// service re-reads and decides again, so callers only see it wrapped in
	// ErrIdentityUnavailable after repeated losses.
	ErrIdentityKeysConflict = store.ErrIdentityKeysConflict
)

const (
	// identitySignerTTL is how often a node re-reads the key set while it
	// signs: a rotation on another node reaches it within this long. The
	// old key stays in the JWKS for two hours, so tokens signed in the gap
	// still verify.
	identitySignerTTL = 30 * time.Second
	// identitySignerMaxStale is how long a node keeps signing with the key
	// set it last read when it cannot read a new one. Far under the two-hour
	// JWKS window, so a node cut off from the server tier never signs with a
	// key the JWKS has stopped listing.
	identitySignerMaxStale = 30 * time.Minute
	// identityKeyWriteAttempts bounds the read-decide-CAS loop of a key-set
	// write; each loss means another node just wrote.
	identityKeyWriteAttempts = 4
	// Role list paging, like the other list APIs.
	defaultIdentityRoleListLimit = 100
	maxIdentityRoleListLimit     = 500
)

// identityBackend stores the signing key set and the role allow lists: the
// store on a single node, the Raft FSM in a cluster.
type identityBackend interface {
	ReadIdentityKeys(ctx context.Context) (cloudidentity.KeySet, error)
	WriteIdentityKeys(ctx context.Context, expected int64, keys []cloudidentity.KeyRecord) (cloudidentity.KeySet, error)
	PutIdentityRole(ctx context.Context, owner, tag, minRole string, now time.Time) (models.IdentityRole, bool, error)
	GetIdentityRole(ctx context.Context, owner, tag string) (models.IdentityRole, error)
	ListIdentityRoles(ctx context.Context, owner, after string, limit int) ([]models.IdentityRole, error)
	DeleteIdentityRole(ctx context.Context, owner, tag string) error
}

// identityState is the Service's cloud-identity state.
type identityState struct {
	// keysReady latches the lazy bootstrap of the first signing key
	// (CLAUDE.md rule 3, EnsureLayer4Ready's shape): a single atomic load
	// once a key exists, keysMu single-flights the bootstrap, and a failure
	// leaves the latch unset for the next caller.
	keysMu    sync.Mutex
	keysReady atomic.Bool
	// signer is the parsed key set this node signs and publishes with;
	// refreshMu single-flights its refresh.
	signer    atomic.Pointer[identitySigner]
	refreshMu sync.Mutex
	// inflight holds the sandboxes a push is running for, so the first push,
	// a start's push and the refresher never deliver twice at once.
	inflight sync.Map
	// Seams; nil in production.
	backend identityBackend
	now     func() time.Time
	rand    io.Reader
	deliver func(ctx context.Context, sb *models.Sandbox, token string) error
}

// identitySigner is one read of the key set: the set (sealed) for the JWKS
// and, once this node signs with it, the active key opened. A node that only
// serves the JWKS (an ingress or server node) never opens a private key.
type identitySigner struct {
	set      cloudidentity.KeySet
	signer   cloudidentity.Signer
	loadedAt time.Time
}

// IdentityEnabled reports whether this deployment is an OIDC issuer.
func (s *Service) IdentityEnabled() bool {
	return s != nil && s.cfg.IdentityIssuerURL != ""
}

// IdentityIssuer is the issuer URL, or "" when off.
func (s *Service) IdentityIssuer() string {
	if s == nil {
		return ""
	}
	return s.cfg.IdentityIssuerURL
}

func (s *Service) identityNow() time.Time {
	if s.identity.now != nil {
		return s.identity.now()
	}
	return time.Now()
}

func (s *Service) identityRand() io.Reader {
	if s.identity.rand != nil {
		return s.identity.rand
	}
	return rand.Reader
}

func (s *Service) identityBackend() identityBackend {
	if s.identity.backend != nil {
		return s.identity.backend
	}
	if s.ClusterEnabled() {
		if c, ok := s.Cluster().(identityCluster); ok {
			return clusterIdentity{c}
		}
		// A node's own store would give each node its own keys, and tokens
		// one node signed would not verify with another node's JWKS.
		return noClusterIdentity{}
	}
	return s.store
}

// identityAllowed is the rolling-upgrade gate (cluster.IdentityGate): a
// single node always may; a cluster only once every live member runs a build
// with identity, and never through a client that cannot say.
func (s *Service) identityAllowed() bool {
	if !s.cfg.EnableCluster {
		return true
	}
	gate, ok := s.Cluster().(cluster.IdentityGate)
	return ok && gate.IdentityAllowed()
}

// EnsureIdentityKeysReady makes sure a signing key exists: the deployment's
// first key is made by whichever node gets here first (the daemon start, or
// the first JWKS fetch or token after a start that could not reach the
// store or the leader). Concurrent nodes race through the key set's
// generation CAS, so exactly one key is made.
func (s *Service) EnsureIdentityKeysReady(ctx context.Context) error {
	if !s.IdentityEnabled() {
		return ErrIdentityDisabled
	}
	if s.identity.keysReady.Load() {
		return nil
	}
	s.identity.keysMu.Lock()
	defer s.identity.keysMu.Unlock()
	if s.identity.keysReady.Load() {
		return nil
	}
	if _, err := s.loadIdentitySigner(ctx, true); err != nil {
		return err
	}
	s.identity.keysReady.Store(true)
	return nil
}

// currentIdentitySigner returns the key set with its active key opened, to
// sign with. The key is opened once per read of the set, on the first
// token a node signs.
func (s *Service) currentIdentitySigner(ctx context.Context) (*identitySigner, error) {
	cur, err := s.currentIdentityKeys(ctx)
	if err != nil {
		return nil, err
	}
	if cur.signer.Key != nil {
		return cur, nil
	}
	active, ok := cur.set.Active()
	if !ok {
		return nil, fmt.Errorf("%w: the key set has no active key", ErrIdentityUnavailable)
	}
	key, err := s.openIdentityKey(active)
	if err != nil {
		return nil, err
	}
	opened := &identitySigner{set: cur.set, signer: cloudidentity.Signer{KeyID: active.ID, Key: key}, loadedAt: cur.loadedAt}
	// A refresh that landed meanwhile wins; this opened copy is still a
	// correct signer for the set it was read from.
	s.identity.signer.CompareAndSwap(cur, opened)
	return opened, nil
}

// currentIdentityKeys returns the key set to sign and publish with, re-read
// every identitySignerTTL. A failed re-read keeps the last set for up to
// identitySignerMaxStale; refreshes are single-flight, and a caller that
// finds one running uses the set it has while it is still usable.
func (s *Service) currentIdentityKeys(ctx context.Context) (*identitySigner, error) {
	if err := s.EnsureIdentityKeysReady(ctx); err != nil {
		return nil, err
	}
	now := s.identityNow()
	cur := s.identity.signer.Load()
	if cur != nil && now.Sub(cur.loadedAt) < identitySignerTTL {
		return cur, nil
	}
	usable := cur != nil && now.Sub(cur.loadedAt) < identitySignerMaxStale
	if usable && !s.identity.refreshMu.TryLock() {
		return cur, nil
	}
	if !usable {
		s.identity.refreshMu.Lock()
	}
	defer s.identity.refreshMu.Unlock()
	if again := s.identity.signer.Load(); again != nil && s.identityNow().Sub(again.loadedAt) < identitySignerTTL {
		return again, nil
	}
	next, err := s.loadIdentitySigner(ctx, false)
	if err != nil {
		if usable {
			s.logger.Warn("identity: re-reading the signing keys failed; signing with the keys read before", "error", err)
			return cur, nil
		}
		return nil, err
	}
	return next, nil
}

// loadIdentitySigner reads the key set, makes the first key when create is
// set and there is none, and stores the result. It opens no private key.
func (s *Service) loadIdentitySigner(ctx context.Context, create bool) (*identitySigner, error) {
	backend := s.identityBackend()
	set, err := backend.ReadIdentityKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: read signing keys: %v", ErrIdentityUnavailable, err)
	}
	if _, ok := set.Active(); !ok {
		if !create {
			return nil, fmt.Errorf("%w: no signing key yet", ErrIdentityUnavailable)
		}
		if set, err = s.writeIdentityKeys(ctx, func(cur cloudidentity.KeySet) (cloudidentity.KeySet, bool, error) {
			if _, ok := cur.Active(); ok {
				return cur, false, nil
			}
			rec, err := s.newIdentityKeyRecord()
			if err != nil {
				return cur, false, err
			}
			return cloudidentity.KeySet{Generation: cur.Generation, Keys: []cloudidentity.KeyRecord{rec}}, true, nil
		}, set); err != nil {
			return nil, err
		}
	}
	active, ok := set.Active()
	if !ok {
		return nil, fmt.Errorf("%w: the key set has no active key", ErrIdentityUnavailable)
	}
	signer := &identitySigner{set: set, signer: cloudidentity.Signer{KeyID: active.ID}, loadedAt: s.identityNow()}
	s.identity.signer.Store(signer)
	return signer, nil
}

// writeIdentityKeys runs a read-decide-CAS loop: decide returns the next set
// and whether to write it. A lost CAS re-reads and decides again, so the
// decision is always made on the current set (two first keys, two
// rotations and a reseal cannot clobber one another).
func (s *Service) writeIdentityKeys(ctx context.Context, decide func(cloudidentity.KeySet) (cloudidentity.KeySet, bool, error), cur cloudidentity.KeySet) (cloudidentity.KeySet, error) {
	backend := s.identityBackend()
	for attempt := 0; ; attempt++ {
		next, write, err := decide(cur)
		if err != nil || !write {
			return next, err
		}
		stored, err := backend.WriteIdentityKeys(ctx, cur.Generation, next.Keys)
		if err == nil {
			s.identity.signer.Store(nil)
			return stored, nil
		}
		if !errors.Is(err, ErrIdentityKeysConflict) {
			if errors.Is(err, cloudidentity.ErrKeySetInvalid) {
				return cloudidentity.KeySet{}, err
			}
			return cloudidentity.KeySet{}, fmt.Errorf("%w: write signing keys: %v", ErrIdentityUnavailable, err)
		}
		if attempt+1 >= identityKeyWriteAttempts {
			return cloudidentity.KeySet{}, fmt.Errorf("%w: signing keys kept changing under this write", ErrIdentityUnavailable)
		}
		if cur, err = backend.ReadIdentityKeys(ctx); err != nil {
			return cloudidentity.KeySet{}, fmt.Errorf("%w: read signing keys: %v", ErrIdentityUnavailable, err)
		}
	}
}

func (s *Service) newIdentityKeyRecord() (cloudidentity.KeyRecord, error) {
	if s.cipher == nil {
		return cloudidentity.KeyRecord{}, fmt.Errorf("%w: no server key to seal the signing key with", ErrIdentityUnavailable)
	}
	key, err := cloudidentity.GenerateKey(s.identityRand())
	if err != nil {
		return cloudidentity.KeyRecord{}, err
	}
	return cloudidentity.NewKeyRecord(key, s.identityNow(), s.cipher.EncryptWithAAD)
}

func (s *Service) openIdentityKey(rec cloudidentity.KeyRecord) (*rsa.PrivateKey, error) {
	if s.cipher == nil {
		return nil, fmt.Errorf("%w: no server key to open the signing key with", ErrIdentityUnavailable)
	}
	der, err := s.cipher.DecryptWithAAD(rec.SealedPrivate, cloudidentity.SealAAD(rec.ID))
	if err != nil {
		// Never the bytes: only which key could not be opened.
		return nil, fmt.Errorf("%w: open signing key %s: %v", ErrIdentityUnavailable, rec.ID, err)
	}
	defer clear(der)
	return cloudidentity.ParsePrivateKey(der)
}

// IdentityDiscovery is the OIDC discovery document.
func (s *Service) IdentityDiscovery() ([]byte, error) {
	if !s.IdentityEnabled() {
		return nil, ErrIdentityDisabled
	}
	return cloudidentity.Discovery(s.cfg.IdentityIssuerURL)
}

// IdentityJWKS is the public key set: the active key and every key rotated
// out less than two hours ago (D1.3). It holds public keys only.
func (s *Service) IdentityJWKS(ctx context.Context) ([]byte, error) {
	signer, err := s.currentIdentityKeys(ctx)
	if err != nil {
		return nil, err
	}
	return cloudidentity.JWKS(signer.set.Published(s.identityNow()))
}

// RotateIdentityKey makes a new active signing key; the old one stays in the
// JWKS for two hours (section 4). ifActive, when set, makes the call
// idempotent under retries: it rotates only while that key is still the
// active one, and otherwise answers with the current state.
func (s *Service) RotateIdentityKey(ctx context.Context, ifActive string) (*models.IdentityKeyRotation, error) {
	if !s.IdentityEnabled() {
		return nil, ErrIdentityDisabled
	}
	if err := s.EnsureIdentityKeysReady(ctx); err != nil {
		return nil, err
	}
	backend := s.identityBackend()
	cur, err := backend.ReadIdentityKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: read signing keys: %v", ErrIdentityUnavailable, err)
	}
	// The rotation replaces the key that is active now (or the one the
	// caller named). A lost CAS re-reads: if that key is no longer active,
	// another writer rotated in between and that rotation is this one; if it
	// is (a reseal won the race), the rotation is decided again on the new
	// set. Either way one call rotates at most once.
	want := strings.TrimSpace(ifActive)
	if want == "" {
		active, _ := cur.Active()
		want = active.ID
	}
	set, err := s.writeIdentityKeys(ctx, func(cur cloudidentity.KeySet) (cloudidentity.KeySet, bool, error) {
		if active, ok := cur.Active(); ok && active.ID != want {
			return cur, false, nil
		}
		rec, err := s.newIdentityKeyRecord()
		if err != nil {
			return cur, false, err
		}
		next, err := cur.Rotate(rec, s.identityNow())
		if err != nil {
			return cur, false, fmt.Errorf("%w: %w", ErrIdentityInvalid, err)
		}
		return next, true, nil
	}, cur)
	if err != nil {
		return nil, err
	}
	active, _ := set.Active()
	out := &models.IdentityKeyRotation{ActiveKeyID: active.ID, PublishedKeyID: []string{}}
	for _, k := range set.Published(s.identityNow()) {
		out.PublishedKeyID = append(out.PublishedKeyID, k.ID)
	}
	s.logger.Info("identity: signing key rotated", "active_key_id", active.ID, "published_key_ids", out.PublishedKeyID)
	return out, nil
}

// identityRoleOwner resolves the owner a roles call acts on, from the
// caller's credential: a team-bound caller acts on its own team and may
// name no other; a fleet caller names a team, or none for the operator
// namespace (sandboxes the operator token or a fleet credential creates).
func identityRoleOwner(ctx context.Context, team string) (owner, teamName string, err error) {
	team = strings.TrimSpace(team)
	if own, scoped := ownerScope(ctx); scoped {
		name, isTeam := strings.CutPrefix(own, controlplane.TeamOwnerPrefix)
		if team != "" && (!isTeam || team != name) {
			return "", "", fmt.Errorf("%w: this credential is not bound to team %q", ErrIdentityRoleDenied, team)
		}
		if !isTeam {
			name = ""
		}
		return own, name, nil
	}
	if team == "" {
		return "", "", nil
	}
	if !identitywire.ValidTeamName(team) {
		return "", "", fmt.Errorf("%w: team %q: want 1 to 63 characters of a-z, 0-9 and -", ErrIdentityInvalid, team)
	}
	return controlplane.TeamOwnerRef(team), team, nil
}

// PutIdentityRole puts a role tag on a team's allow list, or changes its
// minimum role. The same body twice is a no-op (idempotent PUT).
func (s *Service) PutIdentityRole(ctx context.Context, team, tag string, req models.IdentityRoleRequest) (*models.IdentityRole, error) {
	if !s.IdentityEnabled() {
		return nil, ErrIdentityDisabled
	}
	tag = strings.TrimSpace(tag)
	if err := cloudidentity.ValidateRoleTag(tag); err != nil {
		return nil, err
	}
	minRole := strings.TrimSpace(req.MinRole)
	if !cloudidentity.ValidMinRole(minRole) {
		return nil, fmt.Errorf("%w: min_role %q: want runner or admin", ErrIdentityInvalid, req.MinRole)
	}
	owner, teamName, err := identityRoleOwner(ctx, team)
	if err != nil {
		return nil, err
	}
	role, changed, err := s.identityBackend().PutIdentityRole(ctx, owner, tag, minRole, s.identityNow())
	if err != nil {
		return nil, identityBackendError(err)
	}
	if changed {
		s.logger.Info("identity: role tag put", "owner_ref", owner, "tag", tag, "min_role", minRole)
	}
	role.Team = teamName
	return &role, nil
}

// ListIdentityRoles pages a team's allow list by tag.
func (s *Service) ListIdentityRoles(ctx context.Context, team, after string, limit int) (*models.IdentityRoleList, error) {
	if !s.IdentityEnabled() {
		return nil, ErrIdentityDisabled
	}
	owner, teamName, err := identityRoleOwner(ctx, team)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = defaultIdentityRoleListLimit
	}
	if limit > maxIdentityRoleListLimit {
		limit = maxIdentityRoleListLimit
	}
	roles, err := s.identityBackend().ListIdentityRoles(ctx, owner, strings.TrimSpace(after), limit+1)
	if err != nil {
		return nil, identityBackendError(err)
	}
	out := &models.IdentityRoleList{Roles: []models.IdentityRole{}}
	if len(roles) > limit {
		roles = roles[:limit]
		out.NextCursor = roles[limit-1].Tag
	}
	for _, r := range roles {
		r.Team = teamName
		out.Roles = append(out.Roles, r)
	}
	return out, nil
}

// DeleteIdentityRole takes a tag off a team's allow list. Deleting a tag
// already gone succeeds. Sandboxes created with it keep their current token
// until it expires (at most one hour) and get no new one.
func (s *Service) DeleteIdentityRole(ctx context.Context, team, tag string) error {
	if !s.IdentityEnabled() {
		return ErrIdentityDisabled
	}
	tag = strings.TrimSpace(tag)
	if err := cloudidentity.ValidateRoleTag(tag); err != nil {
		return err
	}
	owner, _, err := identityRoleOwner(ctx, team)
	if err != nil {
		return err
	}
	if err := s.identityBackend().DeleteIdentityRole(ctx, owner, tag); err != nil {
		return identityBackendError(err)
	}
	s.logger.Info("identity: role tag deleted", "owner_ref", owner, "tag", tag)
	return nil
}

func identityBackendError(err error) error {
	switch {
	case errors.Is(err, ErrIdentityRoleNotFound), errors.Is(err, ErrIdentityInvalid), errors.Is(err, ErrIdentityUnavailable):
		return err
	}
	return fmt.Errorf("%w: %v", ErrIdentityUnavailable, err)
}

// roleRank orders the roles that can create a sandbox; a role that cannot
// create one ranks below both.
func roleRank(r controlplane.Role) int {
	switch r {
	case controlplane.RoleRunner:
		return 1
	case controlplane.RoleAdmin:
		return 2
	}
	return 0
}

// prepareCreateIdentity checks a create's identity option and gives the
// request the environment the cloud SDKs read (D1.6). It runs before any
// runtime is touched, so a refusal costs nothing. On a stored-spec replay
// (failover recreate) the allow-list check is skipped: the spec was admitted
// when it was created, and the refresher stops refreshing a tag that has
// since been removed.
//
// Boot-path cost when identity is set: one allow-list read (an SQLite point
// read on a single node, an FSM map read on a server, a cached server-tier
// read on a worker) and a few map writes. Unset, it is one nil check.
func (s *Service) prepareCreateIdentity(ctx context.Context, req *models.CreateSandboxRequest, ownerRef, runtimeName string) error {
	if req.Identity == nil {
		return nil
	}
	if !s.IdentityEnabled() {
		return fmt.Errorf("%w: %w", ErrIdentityInvalid, ErrIdentityDisabled)
	}
	if runtimeName == models.RuntimeWasm || runtimeName == models.RuntimeIsolate {
		return fmt.Errorf("%w: %w (runtime %q)", ErrIdentityInvalid, ErrIdentityRuntime, runtimeName)
	}
	idr := cloudidentity.Request(*req.Identity).Normalize()
	if err := idr.Validate(); err != nil {
		return err
	}
	normalized := models.IdentityRequest(idr)
	req.Identity = &normalized
	if !s.identityAllowed() {
		return fmt.Errorf("%w: not every cluster node runs a build with cloud identity yet; finish the upgrade and retry", ErrIdentityUnavailable)
	}
	if !isStoredSpecReplay(ctx) {
		if err := s.checkIdentityRoleTag(ctx, ownerRef, idr.RoleTag); err != nil {
			return err
		}
	}
	env := idr.Env()
	if req.Env == nil {
		req.Env = make(map[string]string, len(env))
	}
	for k, v := range env {
		if have, ok := req.Env[k]; ok && have != v {
			return fmt.Errorf("%w: env %s is set by identity; remove it from env", ErrIdentityInvalid, k)
		}
		req.Env[k] = v
	}
	return nil
}

// checkIdentityRoleTag is the D1.5 check: the tag must be on the owner's
// allow list and the caller must hold its minimum role. A call with no
// Access (an internal create) passes the role check but still needs the tag
// on the list.
func (s *Service) checkIdentityRoleTag(ctx context.Context, ownerRef, tag string) error {
	role, err := s.identityBackend().GetIdentityRole(ctx, ownerRef, tag)
	if errors.Is(err, ErrIdentityRoleNotFound) {
		return fmt.Errorf("%w: role tag %q is not on this team's identity allow list", ErrIdentityRoleDenied, tag)
	}
	if err != nil {
		return identityBackendError(err)
	}
	if access, ok := controlplane.AccessFromContext(ctx); ok {
		if have := access.EffectiveRole(); roleRank(have) < roleRank(controlplane.Role(role.MinRole)) {
			return fmt.Errorf("%w: role tag %q needs role %s or higher", ErrIdentityRoleDenied, tag, role.MinRole)
		}
	}
	return nil
}

// recordCreateIdentity stores a new sandbox's identity and starts its first
// token push off the create response path (D1.8). If the row cannot be
// written the create is undone, the same rule as the egress profile state:
// a sandbox whose identity was accepted but never recorded would carry the
// environment with no token ever arriving.
func (s *Service) recordCreateIdentity(ctx context.Context, sb *models.Sandbox, idr *models.IdentityRequest) error {
	if sb == nil || idr == nil {
		return nil
	}
	row := store.SandboxIdentity{
		SandboxID: sb.ID, OwnerRef: sb.OwnerRef, RoleTag: idr.RoleTag, Audience: idr.Audience,
		AWSRoleARN: idr.AWSRoleARN, AzureClientID: idr.AzureClientID, AzureTenantID: idr.AzureTenantID,
	}
	if err := s.store.PutSandboxIdentity(ctx, row); err != nil {
		if derr := s.DestroySandbox(context.WithoutCancel(ctx), sb.ID); derr != nil {
			s.logger.Warn("identity: undo create after the identity write failed", "sandbox_id", sb.ID, "error", derr)
		}
		return fmt.Errorf("record sandbox identity: %w", err)
	}
	sb.Identity = row.View()
	s.pushIdentityTokenSoon(sb.ID, identityPushFirst)
	return nil
}
