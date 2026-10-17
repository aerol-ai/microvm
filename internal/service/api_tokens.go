package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/identity"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/identitywire"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Scoped API tokens (plans/identity-and-access.md §5.4): create, list and
// revoke, behind one backend that is SQLite on a single node and the Raft
// FSM in a cluster (the egress-profile pattern), plus the token index the
// request path reads: identity.TokenSet on a single node, the FSM on a Raft
// server, and identity.TokenMirror on every other cluster node.
//
// The secret is minted on the node that received the create, and only its
// hash is written or proposed. The plaintext is returned once, after the
// write succeeded, and is never stored, logged or replicated.

var (
	// ErrAPITokenInvalid is a create request that fails validation (400);
	// the message names the field.
	ErrAPITokenInvalid = errors.New("invalid token request")
	// ErrAPITokenNameTaken is a create whose name another token in the team
	// already holds (409). Two live tokens never share a name.
	ErrAPITokenNameTaken = errors.New("token name already used in this team")
	// ErrAPITokenClusterVersion is a token write before every Raft server
	// runs a build that applies token ops (409).
	ErrAPITokenClusterVersion = errors.New("not every server supports API tokens yet: upgrade every server first")
	// ErrAPITokensUnavailable is a token write whose outcome is unknown or
	// that could not reach the leader (503). After a create, the token may
	// exist without its secret: list tokens, find it by name, revoke it by
	// id, then create it again.
	ErrAPITokensUnavailable = errors.New("API token store unavailable")
)

// apiTokenRetentionAfterExpiry is how long an expired token stays listed
// (flagged expired) before the sweep deletes it, so an access review still
// sees recently expired tokens (§5.4).
const apiTokenRetentionAfterExpiry = 30 * 24 * time.Hour

// apiTokenSweepInterval is how often the expiry sweep looks. The sweep is
// a scan of an in-memory map (or one indexed SQLite delete), so hourly is
// free, and a leader change can never postpone it by a whole day.
const apiTokenSweepInterval = time.Hour

// apiTokenIDAttempts bounds re-minting after a 71-bit id collision.
const apiTokenIDAttempts = 3

// apiTokenBackend stores tokens. Lookups never go through it: the request
// path reads APITokenLookup.
type apiTokenBackend interface {
	put(ctx context.Context, rec identity.TokenRecord) (identity.TokenRecord, error)
	list(ctx context.Context) ([]identity.TokenRecord, error)
	remove(ctx context.Context, id string) error
}

// apiTokenCluster is the replicated store: the Raft FSM on a server
// (cluster.Cluster), the server tier on any other node (cluster.Agent). The
// single-node Noop doesn't implement it.
type apiTokenCluster interface {
	WriteAPIToken(context.Context, cluster.APITokenWriteRequest) (cluster.APITokenWriteResponse, error)
	ListAPITokens(context.Context) ([]identity.TokenRecord, error)
}

func (s *Service) apiTokenBackend() apiTokenBackend {
	if s.ClusterEnabled() {
		if c, ok := s.Cluster().(apiTokenCluster); ok {
			return clusterAPITokens{c}
		}
		// A node's own SQLite would give each node its own tokens.
		return noClusterAPITokens{}
	}
	return localAPITokens{store: s.store, set: &s.apiTokenSet}
}

func (s *Service) apiTokenNow() time.Time {
	if s.apiTokenClock != nil {
		return s.apiTokenClock()
	}
	return time.Now()
}

// CreateAPIToken mints a token. Only an admin reaches it (token.write).
// Names are unique per team: a retry or a concurrent duplicate gets
// ErrAPITokenNameTaken, so the secret of the first create was shown once
// and is never shown again.
func (s *Service) CreateAPIToken(ctx context.Context, req models.CreateAPITokenRequest) (models.CreatedAPIToken, error) {
	rec, err := s.apiTokenRecordFor(ctx, req)
	if err != nil {
		return models.CreatedAPIToken{}, err
	}
	backend := s.apiTokenBackend()
	for attempt := 0; ; attempt++ {
		tok, err := identitywire.NewAPIToken(s.apiTokenEntropy)
		if err != nil {
			return models.CreatedAPIToken{}, fmt.Errorf("mint API token: %w", err)
		}
		hash := tok.SecretHash()
		rec.ID, rec.SecretHash = tok.ID, hash[:]
		stored, err := backend.put(ctx, rec)
		if errors.Is(err, errAPITokenIDCollision) {
			if attempt+1 < apiTokenIDAttempts {
				continue
			}
			// Three 71-bit collisions in a row is not chance: something is
			// wrong with the entropy source. Write nothing.
			return models.CreatedAPIToken{}, fmt.Errorf("%w: token ids keep colliding", ErrAPITokensUnavailable)
		}
		if err != nil {
			return models.CreatedAPIToken{}, err
		}
		if s.logger != nil {
			s.logger.Info("API token created", "token_id", stored.ID, "role", stored.Role, "team", stored.Team(),
				"expires_at", stored.ExpiresAt, "actor", stored.CreatedBy)
		}
		return models.CreatedAPIToken{APIToken: apiTokenView(stored, s.apiTokenNow()), Token: tok.Plaintext()}, nil
	}
}

// apiTokenRecordFor validates a create and builds its record (no id or
// hash yet). Every failure names the field (§5.4, finding 3.6).
func (s *Service) apiTokenRecordFor(ctx context.Context, req models.CreateAPITokenRequest) (identity.TokenRecord, error) {
	name := strings.TrimSpace(req.Name)
	if !identitywire.ValidTokenName(name) {
		return identity.TokenRecord{}, fmt.Errorf("%w: name must be 1 to 64 characters of A-Z, a-z, 0-9, '.', '_' and '-'", ErrAPITokenInvalid)
	}
	role := controlplane.Role(strings.TrimSpace(req.Role))
	if !role.Valid() {
		return identity.TokenRecord{}, fmt.Errorf("%w: role must be viewer, runner, auditor or admin", ErrAPITokenInvalid)
	}
	team := strings.TrimSpace(req.Team)
	switch {
	case team == "":
		return identity.TokenRecord{}, fmt.Errorf("%w: team is required: a team name, or \"*\" for every team", ErrAPITokenInvalid)
	case team != controlplane.FleetTeam && !identitywire.ValidTeamName(team):
		return identity.TokenRecord{}, fmt.Errorf("%w: team must be \"*\" or 1 to 63 characters of a-z, 0-9 and '-'", ErrAPITokenInvalid)
	case role.RequiresFleet() && team != controlplane.FleetTeam:
		// An auditor or admin sees the whole fleet by definition: bound to
		// one team, it would be a misbinding Access.Can refuses anyway.
		return identity.TokenRecord{}, fmt.Errorf("%w: role %s must be bound to every team (team \"*\")", ErrAPITokenInvalid, role)
	}
	if strings.TrimSpace(req.ExpiresIn) == "" {
		return identity.TokenRecord{}, fmt.Errorf("%w: expires_in is required: every token expires (for example 90d)", ErrAPITokenInvalid)
	}
	ttl, err := identitywire.ParseTokenTTL(req.ExpiresIn)
	if err != nil {
		return identity.TokenRecord{}, fmt.Errorf("%w: expires_in must be a positive lifetime such as 90d or 720h", ErrAPITokenInvalid)
	}
	if max := s.tokenMaxTTL(); ttl > max {
		return identity.TokenRecord{}, fmt.Errorf("%w: expires_in is longer than this server's maximum of %s (SB_TOKEN_MAX_TTL)", ErrAPITokenInvalid, max)
	}
	now := s.apiTokenNow().UTC().Truncate(time.Second)
	return identity.TokenRecord{
		Name:      name,
		Role:      role,
		OwnerRef:  identity.OwnerRefForTeam(team),
		CreatedBy: apiTokenCreator(ctx),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}, nil
}

func (s *Service) tokenMaxTTL() time.Duration {
	if s.cfg.TokenMaxTTL > 0 {
		return s.cfg.TokenMaxTTL
	}
	return 365 * 24 * time.Hour
}

// apiTokenCreator is the principal id of the caller minting a token, so
// "who minted this admin token" has an answer in the list itself.
func apiTokenCreator(ctx context.Context) string {
	if access, ok := controlplane.AccessFromContext(ctx); ok && access.Principal.ID != "" {
		return access.Principal.ID
	}
	if caller, ok := controlplane.SystemCallerFromContext(ctx); ok {
		return caller.ID
	}
	return controlplane.SystemPrincipal("").ID
}

// ListAPITokens returns every token, sorted by team and name, expired ones
// flagged. Never a secret or a hash.
func (s *Service) ListAPITokens(ctx context.Context) (models.APITokenList, error) {
	recs, err := s.apiTokenBackend().list(ctx)
	if err != nil {
		return models.APITokenList{}, err
	}
	now := s.apiTokenNow()
	out := models.APITokenList{Tokens: make([]models.APIToken, 0, len(recs))}
	for _, rec := range recs {
		out.Tokens = append(out.Tokens, apiTokenView(rec, now))
	}
	return out, nil
}

// RevokeAPIToken deletes a token at once. A token already gone is not an
// error: revoke is idempotent, so a retried or repeated revoke is a 204.
// The evidence of who revoked it is the api record of the call (T5).
func (s *Service) RevokeAPIToken(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if !identitywire.ValidAPITokenID(id) {
		return fmt.Errorf("%w: a token id looks like tok_ followed by 12 letters or digits", ErrAPITokenInvalid)
	}
	if err := s.apiTokenBackend().remove(ctx, id); err != nil {
		return err
	}
	if s.logger != nil {
		s.logger.Info("API token revoked", "token_id", id, "actor", apiTokenCreator(ctx))
	}
	return nil
}

func apiTokenView(rec identity.TokenRecord, now time.Time) models.APIToken {
	return models.APIToken{
		ID:        rec.ID,
		Name:      rec.Name,
		Role:      string(rec.Role),
		Team:      rec.Team(),
		CreatedBy: rec.CreatedBy,
		CreatedAt: rec.CreatedAt.UTC(),
		ExpiresAt: rec.ExpiresAt.UTC(),
		Expired:   rec.Expired(now),
	}
}

// APITokenLookup is the token index the apiToken authenticator reads: the
// single-node set, this server's FSM, or this node's mirror. A cluster node
// with neither is never fresh, so every token is refused with 503 rather
// than checked against a node-local list.
func (s *Service) APITokenLookup() identity.TokenLookup {
	if !s.ClusterEnabled() {
		return &s.apiTokenSet
	}
	if s.apiTokenMirror != nil {
		return s.apiTokenMirror
	}
	if lookup, ok := s.Cluster().(identity.TokenLookup); ok {
		return lookup
	}
	return unavailableTokens{}
}

// unavailableTokens answers every lookup "not fresh".
type unavailableTokens struct{}

func (unavailableTokens) LookupToken(string) (identity.TokenRecord, bool, bool) {
	return identity.TokenRecord{}, false, false
}

// StartAPITokens readies the token index when identity is on: it loads a
// single node's tokens into memory, or starts the mirror on a cluster node
// that holds no Raft state, and starts the expiry sweep. With identity off
// it does nothing: no load, no mirror, no polls (L8). Call it after
// AttachCluster and before the API server is built.
//
// Boot cost: one SELECT of api_tokens on a single node; nothing on a Raft
// server; one background goroutine on any other cluster node. Nothing runs
// on CreateSandbox.
func (s *Service) StartAPITokens(ctx context.Context) error {
	if !s.cfg.IdentityEnabled {
		return nil
	}
	if !s.ClusterEnabled() {
		recs, err := s.store.ListAPITokens(ctx)
		if err != nil {
			return fmt.Errorf("load API tokens: %w", err)
		}
		s.apiTokenSet.Replace(recs)
	} else if feed, ok := s.Cluster().(identity.TokenFeed); ok {
		if _, server := s.Cluster().(identity.TokenLookup); !server {
			m := identity.NewTokenMirror(feed, identity.MirrorConfig{
				SyncInterval: s.cfg.IdentitySyncInterval,
				MaxStale:     s.cfg.IdentityMaxStale,
				Logger:       s.logger,
			})
			s.apiTokenMirror = m
			go m.Run(ctx)
		}
	}
	// The sweep runs where it can delete: a single node, or a Raft server
	// (which acts only while it leads). A worker has nothing to sweep.
	if _, sweeper := s.Cluster().(apiTokenSweeper); sweeper || !s.ClusterEnabled() {
		go s.runAPITokenSweep(ctx, apiTokenSweepInterval)
	}
	return nil
}

// apiTokenSweeper is a cluster client that can delete expired tokens; only
// the Raft leader's sweep does anything.
type apiTokenSweeper interface {
	SweepExpiredAPITokens(ctx context.Context, cutoff time.Time) (int, error)
}

func (s *Service) runAPITokenSweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.SweepExpiredAPITokens(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SweepExpiredAPITokens deletes tokens that expired more than 30 days ago:
// on a single node from SQLite and memory, in a cluster through Raft from
// the leader only. It returns how many went.
func (s *Service) SweepExpiredAPITokens(ctx context.Context) int {
	cutoff := s.apiTokenNow().Add(-apiTokenRetentionAfterExpiry)
	var (
		n   int
		err error
	)
	if s.ClusterEnabled() {
		if sweeper, ok := s.Cluster().(apiTokenSweeper); ok {
			n, err = sweeper.SweepExpiredAPITokens(ctx, cutoff)
		}
	} else {
		var ids []string
		ids, err = s.store.DeleteAPITokensExpiredBefore(ctx, cutoff)
		for _, id := range ids {
			s.apiTokenSet.Delete(id)
		}
		n = len(ids)
	}
	if err != nil && s.logger != nil {
		s.logger.Warn("API token expiry sweep failed; next sweep retries", "err", err, "swept", n)
	} else if n > 0 && s.logger != nil {
		s.logger.Info("API token expiry sweep deleted tokens expired over 30 days", "count", n)
	}
	return n
}

// errAPITokenIDCollision asks CreateAPIToken to mint a new id.
var errAPITokenIDCollision = errors.New("API token id collision")

// localAPITokens is the single-node backend: SQLite, mirrored into the
// in-memory set after each write commits.
type localAPITokens struct {
	store *store.Store
	set   *identity.TokenSet
}

func (b localAPITokens) put(ctx context.Context, rec identity.TokenRecord) (identity.TokenRecord, error) {
	err := b.store.InsertAPIToken(ctx, rec)
	switch {
	case errors.Is(err, store.ErrAPITokenIDTaken):
		return identity.TokenRecord{}, errAPITokenIDCollision
	case errors.Is(err, store.ErrAPITokenNameTaken):
		return identity.TokenRecord{}, fmt.Errorf("%w: %q", ErrAPITokenNameTaken, rec.Name)
	case err != nil:
		return identity.TokenRecord{}, err
	}
	b.set.Put(rec)
	return rec, nil
}

func (b localAPITokens) list(ctx context.Context) ([]identity.TokenRecord, error) {
	return b.store.ListAPITokens(ctx)
}

func (b localAPITokens) remove(ctx context.Context, id string) error {
	if _, err := b.store.DeleteAPIToken(ctx, id); err != nil {
		return err
	}
	b.set.Delete(id)
	return nil
}

// clusterAPITokens adapts the replicated store to apiTokenBackend.
type clusterAPITokens struct{ c apiTokenCluster }

func (b clusterAPITokens) put(ctx context.Context, rec identity.TokenRecord) (identity.TokenRecord, error) {
	resp, err := b.c.WriteAPIToken(ctx, cluster.APITokenWriteRequest{Token: rec})
	if err != nil {
		return identity.TokenRecord{}, clusterAPITokenError(err)
	}
	return resp.Token, nil
}

func (b clusterAPITokens) list(ctx context.Context) ([]identity.TokenRecord, error) {
	recs, err := b.c.ListAPITokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAPITokensUnavailable, err)
	}
	return recs, nil
}

func (b clusterAPITokens) remove(ctx context.Context, id string) error {
	if _, err := b.c.WriteAPIToken(ctx, cluster.APITokenWriteRequest{Delete: true, ID: id}); err != nil {
		return clusterAPITokenError(err)
	}
	return nil
}

// clusterAPITokenError maps the cluster's verdicts onto the service's: the
// FSM's refusals keep their meaning, an unfinished rolling upgrade is a
// 409, and everything else (no leader, a lost or timed-out apply, an
// unreachable server tier) is a retryable 503 whose outcome is unknown.
func clusterAPITokenError(err error) error {
	switch {
	case errors.Is(err, cluster.ErrAPITokenNameTaken):
		return fmt.Errorf("%w: %v", ErrAPITokenNameTaken, err)
	case errors.Is(err, cluster.ErrAPITokenIDTaken):
		return errAPITokenIDCollision
	case errors.Is(err, cluster.ErrClusterVersion):
		return fmt.Errorf("%w: %v", ErrAPITokenClusterVersion, err)
	case errors.Is(err, identity.ErrInvalidTokenRecord):
		return fmt.Errorf("%w: %v", ErrAPITokenInvalid, err)
	}
	return fmt.Errorf("%w: %v", ErrAPITokensUnavailable, err)
}

// noClusterAPITokens answers every write on a cluster that has no
// replicated token store wired.
type noClusterAPITokens struct{}

var errNoClusterAPITokens = fmt.Errorf("%w: this cluster node has no replicated token store", ErrAPITokensUnavailable)

func (noClusterAPITokens) put(context.Context, identity.TokenRecord) (identity.TokenRecord, error) {
	return identity.TokenRecord{}, errNoClusterAPITokens
}

func (noClusterAPITokens) list(context.Context) ([]identity.TokenRecord, error) {
	return nil, errNoClusterAPITokens
}

func (noClusterAPITokens) remove(context.Context, string) error { return errNoClusterAPITokens }
