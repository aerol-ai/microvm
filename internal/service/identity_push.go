package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cloudidentity"
	"github.com/aerol-ai/microvm/internal/scaleobs"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
	"github.com/aerol-ai/microvm/pkg/toolboxhttp"
)

// Token delivery (plans/sandbox-cloud-identity.md D1.7, D1.8). toolboxd
// cannot call sandboxd, so sandboxd pushes each token to the sandbox's
// toolboxd, which writes it to the token file. Three things push:
//
//   - the create, once the sandbox's toolbox answers, off the response path;
//   - a start (and a serverless wake), at once, like the first token;
//   - the refresher, owner-local, every five minutes, for every running
//     sandbox whose token has less than thirty minutes left. 100k sandboxes
//     refreshing every half hour is ~55 pushes a second across the fleet,
//     each on the node that runs the sandbox: no cross-node traffic.
//
// A push that fails is retried by the next pass; a token that expires
// before one succeeds is logged and counted. Security point 5: the push
// carries the sandbox's toolbox token, which only sandboxd holds, and goes
// to an /admin path every tenant-facing toolbox proxy refuses
// (refuseToolboxAdminPath), so neither a forged push nor a push through the
// API is possible.

const (
	// identityRefreshInterval and identityRefreshWindow are D1.7's numbers.
	identityRefreshInterval = 5 * time.Minute
	identityRefreshWindow   = 30 * time.Minute
	// identityRefreshPage bounds one store read of due rows; a pass reads
	// pages until a short one or identityRefreshMaxPerPass rows.
	identityRefreshPage       = 500
	identityRefreshMaxPerPass = 5000
	// identityRefreshWorkers bounds the pushes one pass runs at once.
	identityRefreshWorkers = 8
	// identityPushWindow is how long a first or post-start push keeps
	// retrying while the toolbox comes up; past it the refresher owns it.
	identityPushWindow = 60 * time.Second
	// identityPushTimeout bounds one PUT to toolboxd.
	identityPushTimeout = 10 * time.Second
	// identityTokenPath is toolboxd's push route.
	identityTokenPath = "/admin/identity/token"
)

// Why a push ran: the first token, a start, or the refresher.
const (
	identityPushFirst   = "first"
	identityPushStart   = "start"
	identityPushRefresh = "refresh"
)

// KindIdentityTokenIssued is the audit record of one token delivered to a
// sandbox (D1.10): sandbox, owner (the team), and in Reason the role tag,
// key id, token id, expiry and audience. Never the token. A new Kind and no
// new field, like the key-rotation records, so every build verifies it.
const KindIdentityTokenIssued = "identity.token_issued"

// auditSubsystemIdentity names the token records' caller: system:identity.
const auditSubsystemIdentity = "identity"

var (
	// identityTokensIssued counts tokens delivered, by why the push ran.
	identityTokensIssued = expvar.NewMap("aerolvm_identity_tokens_issued_total")
	// identityRefreshFailures counts pushes that failed, by reason
	// (section 4: aerolvm_identity_refresh_failures_total).
	identityRefreshFailures = expvar.NewMap("aerolvm_identity_refresh_failures_total")
	// identityFirstTokenLatency is the gap between a create returning and
	// its first token landing (D1.8): the number that decides whether the
	// first push moves onto the create path.
	identityFirstTokenLatency = scaleobs.NewDurationBuckets("aerolvm_identity_first_token_seconds_bucket",
		10*time.Millisecond, 50*time.Millisecond, 100*time.Millisecond, 250*time.Millisecond, 500*time.Millisecond,
		time.Second, 2*time.Second, 5*time.Second, 10*time.Second, 30*time.Second, 60*time.Second)
)

// Failure reasons on aerolvm_identity_refresh_failures_total.
const (
	identityFailSign        = "sign"
	identityFailPush        = "push"
	identityFailOldToolbox  = "toolbox_too_old"
	identityFailRoleRemoved = "role_removed"
	identityFailRoleCheck   = "role_unavailable"
	identityFailExpired     = "expired_unrefreshed"
)

// errIdentityToolboxTooOld is a toolboxd with no push route: a Firecracker
// template or a long-running container built before identity.
var errIdentityToolboxTooOld = errors.New("this sandbox's toolboxd is too old to receive identity tokens; re-create the template or the sandbox")

// errIdentityRoleRemoved is a sandbox whose role tag was taken off its
// owner's allow list after it was created: it gets no new token.
var errIdentityRoleRemoved = errors.New("the role tag was removed from the allow list; no new token")

// pushIdentityTokenSoon delivers a token to one sandbox in the background,
// retrying while its toolbox comes up (the first token after a create, and
// a start's). A push already running for the sandbox makes this a no-op.
func (s *Service) pushIdentityTokenSoon(id, why string) {
	if !s.IdentityEnabled() || id == "" {
		return
	}
	if _, busy := s.identity.inflight.LoadOrStore(id, struct{}{}); busy {
		return
	}
	go func() {
		defer s.identity.inflight.Delete(id)
		started := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), identityPushWindow)
		defer cancel()
		backoff := 100 * time.Millisecond
		for {
			done, err := s.pushIdentityTokenByID(ctx, id, why)
			if done {
				if err == nil && why == identityPushFirst {
					identityFirstTokenLatency.Observe(time.Since(started))
				}
				return
			}
			select {
			case <-ctx.Done():
				s.logger.Warn("identity: token not delivered yet; the refresher will retry", "sandbox_id", id, "why", why, "error", err)
				return
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}()
}

// kickIdentityPush is the start hook: a started sandbox gets a token at
// once. It is a no-op for a sandbox with no identity (the push finds no
// row) and when the deployment is not an issuer.
func (s *Service) kickIdentityPush(id string) {
	s.pushIdentityTokenSoon(id, identityPushStart)
}

// pushIdentityTokenByID pushes once. done reports whether to stop retrying:
// the push landed, or retrying within the window cannot help (no identity,
// sandbox gone or stopped, an old toolboxd, a removed role tag).
func (s *Service) pushIdentityTokenByID(ctx context.Context, id, why string) (done bool, err error) {
	row, err := s.store.GetSandboxIdentity(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	sb, err := s.store.Get(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if sb.Status != models.SandboxStatusStarted || sb.ContainerIP == "" {
		// Not up yet right after a create (wait for it), or stopped (the
		// next start pushes).
		return sb.Status != models.SandboxStatusStarted && sb.Status != models.SandboxStatusCreating, nil
	}
	err = s.pushIdentityToken(ctx, sb, row, why)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, errIdentityToolboxTooOld), errors.Is(err, errIdentityRoleRemoved):
		return true, err
	}
	return false, err
}

// pushIdentityToken signs one token for sb and delivers it. It refuses to
// sign for a tag no longer on the owner's allow list, records the outcome on
// the row, and writes the audit record only once the token is in the
// sandbox.
func (s *Service) pushIdentityToken(ctx context.Context, sb *models.Sandbox, row store.SandboxIdentity, why string) (err error) {
	defer func() {
		if err == nil {
			return
		}
		reason := identityFailPush
		switch {
		case errors.Is(err, errIdentityToolboxTooOld):
			reason = identityFailOldToolbox
		case errors.Is(err, errIdentityRoleRemoved):
			reason = identityFailRoleRemoved
		case errors.Is(err, errIdentityRoleUnavailable):
			reason = identityFailRoleCheck
		case errors.Is(err, errIdentitySign):
			reason = identityFailSign
		}
		identityRefreshFailures.Add(reason, 1)
		if row.TokenExpiresUnix > 0 && !time.Unix(row.TokenExpiresUnix, 0).After(s.identityNow()) {
			identityRefreshFailures.Add(identityFailExpired, 1)
			s.logger.Warn("identity: a sandbox's token expired before a new one could be delivered",
				"sandbox_id", sb.ID, "role_tag", row.RoleTag, "error", err)
		}
		if rerr := s.store.RecordIdentityTokenFailed(context.WithoutCancel(ctx), sb.ID, err.Error()); rerr != nil && !errors.Is(rerr, store.ErrNotFound) {
			s.logger.Warn("identity: record a failed push", "sandbox_id", sb.ID, "error", rerr)
		}
	}()
	// The sandbox's own owner ref, taken from the caller's credential at
	// create: the team in the subject never comes from anywhere else.
	if err := s.identityRoleStillAllowed(ctx, sb.OwnerRef, row.RoleTag); err != nil {
		return err
	}
	signer, err := s.currentIdentitySigner(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", errIdentitySign, err)
	}
	tok, err := signer.signer.Issue(cloudidentity.IssueRequest{
		Issuer: s.cfg.IdentityIssuerURL, OwnerRef: sb.OwnerRef, SandboxID: sb.ID,
		RoleTag: row.RoleTag, Audience: row.Audience, Now: s.identityNow(), Rand: s.identity.rand,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", errIdentitySign, err)
	}
	if err := s.deliverIdentityToken(ctx, sb, tok.Raw); err != nil {
		return err
	}
	if err := s.store.RecordIdentityTokenPushed(context.WithoutCancel(ctx), sb.ID, tok.KeyID, tok.Expires()); err != nil && !errors.Is(err, store.ErrNotFound) {
		// The token is in the sandbox; the next pass may push again early.
		s.logger.Warn("identity: record a delivered token", "sandbox_id", sb.ID, "error", err)
	}
	identityTokensIssued.Add(why, 1)
	s.recordIdentityTokenIssued(sb, row.RoleTag, tok)
	return nil
}

var (
	errIdentitySign            = errors.New("identity: sign token")
	errIdentityRoleUnavailable = errors.New("identity: the role allow list could not be read; retrying next pass")
)

// identityRoleStillAllowed fails closed: a tag taken off the list stops
// refresh, and an allow list that cannot be read skips this push (the token
// in the sandbox is good for at least another twenty-five minutes, so a
// short outage costs nothing).
func (s *Service) identityRoleStillAllowed(ctx context.Context, ownerRef, tag string) error {
	_, err := s.identityBackend().GetIdentityRole(ctx, ownerRef, tag)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrIdentityRoleNotFound):
		return errIdentityRoleRemoved
	}
	return fmt.Errorf("%w: %v", errIdentityRoleUnavailable, err)
}

// identityPushClient sends pushes; its transport is the toolbox one, so
// pushes share the proxy's connection limits.
var identityPushClient = &http.Client{Transport: toolboxhttp.Transport, Timeout: identityPushTimeout}

// deliverIdentityToken PUTs the token to toolboxd. The sandbox's state was
// read by the caller and is not touched (a push must not keep a serverless
// sandbox awake or wake a stopped one).
func (s *Service) deliverIdentityToken(ctx context.Context, sb *models.Sandbox, token string) error {
	if s.identity.deliver != nil {
		return s.identity.deliver(ctx, sb, token)
	}
	endpoint, err := s.toolboxEndpointForSandbox(ctx, sb)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"token": token})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, identityPushTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPut, strings.TrimRight(endpoint.URL, "/")+identityTokenPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	resp, err := identityPushClient.Do(req)
	if err != nil {
		return fmt.Errorf("push identity token: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return nil
	case resp.StatusCode == http.StatusNotFound && resp.Header.Get("X-Toolbox-Route") == "none":
		return errIdentityToolboxTooOld
	}
	return fmt.Errorf("push identity token: toolboxd answered %d", resp.StatusCode)
}

// recordIdentityTokenIssued writes the D1.10 audit record.
func (s *Service) recordIdentityTokenIssued(sb *models.Sandbox, roleTag string, tok cloudidentity.Token) {
	sink := s.secretAuditSink()
	if sink == nil {
		return
	}
	actor := s.auditActor()
	incarnationID, _ := s.auditIdentityFor(sb.ID)
	ev := SecretAuditEvent{
		Time:          time.Now().UTC(),
		Actor:         actor,
		NodeID:        actor,
		SandboxID:     sb.ID,
		Result:        secretAuditResultSuccess,
		Reason:        fmt.Sprintf("role_tag=%s kid=%s jti=%s exp=%d aud=%s", roleTag, tok.KeyID, tok.Claims.ID, tok.Claims.Expiry, tok.Claims.Audience),
		Kind:          KindIdentityTokenIssued,
		IncarnationID: incarnationID,
		OwnerRef:      sb.OwnerRef,
		Caller:        s.auditCaller(controlplane.ContextWithSystemCaller(context.Background(), auditSubsystemIdentity)),
	}
	ensureSecretAuditEventID(&ev)
	sink.Emit(ev)
}

// SuperviseIdentityTokens is the refresher (D1.7): every five minutes it
// re-pushes the token of every running sandbox on this node with less than
// thirty minutes left. Each node refreshes only its own sandboxes.
func (s *Service) SuperviseIdentityTokens(ctx context.Context) {
	if !s.IdentityEnabled() {
		return
	}
	t := time.NewTicker(identityRefreshInterval)
	defer t.Stop()
	for {
		s.refreshIdentityTokens(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// refreshIdentityTokens is one pass: due rows, soonest expiry first, pushed
// by a few workers. A push already running for a sandbox (a create's or a
// start's) is skipped.
func (s *Service) refreshIdentityTokens(ctx context.Context) int {
	cutoff := s.identityNow().Add(identityRefreshWindow)
	var rows []store.SandboxIdentity
	cursor := store.IdentityDueCursor{}
	for len(rows) < identityRefreshMaxPerPass {
		page, err := s.store.SandboxIdentitiesDue(ctx, cutoff, cursor, identityRefreshPage)
		if err != nil {
			s.logger.Warn("identity: list tokens due for refresh", "error", err)
			break
		}
		rows = append(rows, page...)
		if len(page) < identityRefreshPage {
			break
		}
		cursor = cursor.Next(page)
	}
	work := make(chan store.SandboxIdentity)
	var wg sync.WaitGroup
	var mu sync.Mutex
	pushed := 0
	for i := 0; i < identityRefreshWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for row := range work {
				if s.refreshOne(ctx, row) {
					mu.Lock()
					pushed++
					mu.Unlock()
				}
			}
		}()
	}
	for _, r := range rows {
		select {
		case work <- r:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(work)
	wg.Wait()
	return pushed
}

func (s *Service) refreshOne(ctx context.Context, row store.SandboxIdentity) bool {
	if _, busy := s.identity.inflight.LoadOrStore(row.SandboxID, struct{}{}); busy {
		return false
	}
	defer s.identity.inflight.Delete(row.SandboxID)
	sb, err := s.store.Get(ctx, row.SandboxID)
	if err != nil || sb.Status != models.SandboxStatusStarted {
		return false
	}
	if err := s.pushIdentityToken(ctx, sb, row, identityPushRefresh); err != nil {
		if !errors.Is(err, errIdentityRoleRemoved) {
			s.logger.Warn("identity: token refresh failed; retrying next pass", "sandbox_id", row.SandboxID, "error", err)
		}
		return false
	}
	return true
}

// resealIdentityKeys moves the sealed signing keys onto the current server
// key during a server-key rotation (key_rotation.go), so retiring the old
// server key never strands them. It runs whether or not this node is an
// issuer now: keys made while it was must stay openable. A lost CAS counts
// the keys under their old server key until the next pass.
func (s *Service) resealIdentityKeys(ctx context.Context, count func(uint32, bool), unopenable func()) error {
	if s.identity.backend == nil && !s.ClusterEnabled() && s.store == nil {
		return nil
	}
	backend := s.identityBackend()
	set, err := backend.ReadIdentityKeys(ctx)
	if err != nil {
		if !s.IdentityEnabled() {
			// Not an issuer, and the replicated set cannot be read: there
			// is nothing this node made or signs with to move.
			return nil
		}
		// An issuer that cannot say leaves the pass unfinished, so a
		// retire keeps waiting rather than stranding the keys.
		return err
	}
	if len(set.Keys) == 0 {
		return nil
	}
	next := set.Clone()
	var moved []uint32
	for i, k := range next.Keys {
		out, from, changed, err := s.cipher.Reseal(k.SealedPrivate, cloudidentity.SealAAD(k.ID))
		switch {
		case errors.Is(err, secrets.ErrKeyRevoked):
			return err
		case err != nil:
			unopenable()
		case !changed:
			count(from, false)
		default:
			next.Keys[i].SealedPrivate = out
			moved = append(moved, from)
		}
	}
	if len(moved) == 0 {
		return nil
	}
	if _, err := backend.WriteIdentityKeys(ctx, set.Generation, next.Keys); err != nil {
		for _, from := range moved {
			count(from, false)
		}
		if errors.Is(err, ErrIdentityKeysConflict) {
			return nil
		}
		return err
	}
	s.identity.signer.Store(nil)
	for _, from := range moved {
		count(from, true)
	}
	return nil
}
