package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Cloud identity once servers sign (server_signing.go). The signing keys are
// sealed with the servers' own key (secrets.ServerSealer), so only a server
// opens one, and a sandbox's owner has a server sign its tokens:
//
//	leader upkeep    makes the first key, sealed for servers; rotates a key
//	                 sealed with the ring out (it stays in the JWKS for its
//	                 two hours, then is gone)
//	worker push      POST /v1/cluster/internal/identity/sign {sandbox}
//	server           checks the sender owns the sandbox; builds every claim
//	                 from the sandbox's placement (its owner and its
//	                 spec's identity), the role allow list and its issuer;
//	                 signs
//	identity read    a worker or gateway gets the public keys only
//
// A placement's spec carries an identity only when a server put it there
// (peer_proposals.go): a create with an identity goes to a server.

// identityServerSealer is the sealer for identity keys on a server that
// holds the signing record, and nil anywhere else.
func (s *Service) identityServerSealer() (*secrets.ServerSealer, error) {
	k, err := s.openServerKeys()
	if err != nil || k == nil {
		return nil, err
	}
	st := &s.serverSigning
	st.mu.Lock()
	defer st.mu.Unlock()
	if k.identity == nil {
		sealer, err := secrets.NewServerIdentitySealer(k.seed)
		if err != nil {
			return nil, err
		}
		k.identity = sealer
	}
	return k.identity, nil
}

// mayMakeIdentityKeys reports whether this node makes and keeps the
// signing keys: any node until servers sign, then servers only.
func (s *Service) mayMakeIdentityKeys() bool {
	if _, isServer := s.Cluster().(serverSigningCluster); isServer {
		return true
	}
	return !s.currentSigningMode().on
}

// ServerSigningOn reports whether this cluster's servers sign.
func (s *Service) ServerSigningOn() bool {
	return s != nil && s.currentSigningMode().on
}

// UpkeepServerIdentityKeys is the leader's identity upkeep once servers
// sign: the first key, sealed for servers, and the move of a key sealed
// with the ring out of the active slot. Nothing else does it.
func (s *Service) UpkeepServerIdentityKeys(ctx context.Context) error {
	c, ok := s.Cluster().(serverSigningCluster)
	if !ok || !c.IsLeader() || !s.IdentityEnabled() {
		return nil
	}
	if _, on := c.ServerSigningRecord(); !on {
		return nil
	}
	set, err := s.identityBackend().ReadIdentityKeys(ctx)
	if err != nil {
		return err
	}
	active, ok := set.Active()
	switch {
	case !ok:
		_, err = s.loadIdentitySigner(ctx, true)
		return err
	case active.Seal != cloudidentity.SealServer:
		_, err = s.RotateIdentityKey(ctx, active.ID)
		if err == nil && s.logger != nil {
			s.logger.Info("identity: the signing key is now one only servers hold; the previous key stays in the JWKS for its two hours", "previous_key_id", active.ID)
		}
		return err
	}
	return nil
}

// ErrIdentityNotOnSandbox is a sign request for a sandbox with no identity.
var ErrIdentityNotOnSandbox = errors.New("the sandbox has no cloud identity")

// SignIdentityTokenFor signs a cloud-identity token for a sandbox, on a
// server (POST /v1/cluster/internal/identity/sign), for the node that owns
// it (a server may ask for any). Every claim comes from this server: the
// sandbox's owner and the identity in its placement's spec, which only a
// server can put there, checked against the owner's role allow list.
func (s *Service) SignIdentityTokenFor(ctx context.Context, peerID string, peerIsServer bool, req cluster.IdentityTokenSignRequest) (cluster.IdentityTokenSignResponse, error) {
	if !s.IdentityEnabled() {
		return cluster.IdentityTokenSignResponse{}, ErrIdentityDisabled
	}
	c := s.Cluster()
	if c == nil {
		return cluster.IdentityTokenSignResponse{}, ErrServerSigningOff
	}
	p, ok := c.PlacementOf(strings.TrimSpace(req.SandboxID))
	if !ok || p.IsDeleting() {
		return cluster.IdentityTokenSignResponse{}, fmt.Errorf("%w: sandbox %s", store.ErrNotFound, req.SandboxID)
	}
	if !peerIsServer && (strings.TrimSpace(peerID) == "" || strings.TrimSpace(p.OwnerNodeID) != strings.TrimSpace(peerID)) {
		return cluster.IdentityTokenSignResponse{}, ErrSignNotOwner
	}
	if inc := strings.TrimSpace(req.IncarnationID); inc != "" && inc != strings.TrimSpace(p.IncarnationID) {
		return cluster.IdentityTokenSignResponse{}, fmt.Errorf("%w: sandbox %s is another lifetime now", store.ErrNotFound, req.SandboxID)
	}
	if p.Spec == nil || p.Spec.Identity == nil {
		return cluster.IdentityTokenSignResponse{}, fmt.Errorf("%w: %s", ErrIdentityNotOnSandbox, req.SandboxID)
	}
	idn := cloudidentity.Request(*p.Spec.Identity).Normalize()
	if err := s.identityRoleStillAllowed(ctx, p.OwnerRef, idn.RoleTag); err != nil {
		return cluster.IdentityTokenSignResponse{}, err
	}
	signer, err := s.currentIdentitySigner(ctx)
	if err != nil {
		return cluster.IdentityTokenSignResponse{}, fmt.Errorf("%w: %v", errIdentitySign, err)
	}
	tok, err := signer.signer.Issue(cloudidentity.IssueRequest{
		Issuer: s.cfg.IdentityIssuerURL, OwnerRef: p.OwnerRef, SandboxID: p.SandboxID,
		RoleTag: idn.RoleTag, Audience: idn.Audience, Now: s.identityNow(), Rand: s.identity.rand,
	})
	if err != nil {
		return cluster.IdentityTokenSignResponse{}, fmt.Errorf("%w: %v", errIdentitySign, err)
	}
	return cluster.IdentityTokenSignResponse{Token: tok.Raw, KeyID: tok.KeyID, Claims: tok.Claims}, nil
}
