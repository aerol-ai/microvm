package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// inlineRecoveryMaxBytes bounds the recovery payload a raft command may carry.
// Recovery payloads ride inline in the log entry — there is no other delivery
// path — so the cap is a hard validation limit, not a routing decision: an
// oversized spec is rejected at create (see ValidateRecoveryPayloadSize),
// never silently re-routed. Typical redacted specs encode to ~0.5–1KiB, so
// 4KiB gives the normal create 4–8× headroom while keeping log entries and
// per-placement snapshot growth bounded. A const, not config — the limit is a
// wire-format property and must be identical on every node.
const inlineRecoveryMaxBytes = 4096

// ErrRecoveryPayloadTooLarge is returned when a redacted spec + secret handle
// encodes past inlineRecoveryMaxBytes. It surfaces at create validation (the
// user-facing 400) and again defensively at command encode time — hitting the
// latter without the former means a service-side mutation grew the spec after
// validation, which is a bug, not a routing case.
var ErrRecoveryPayloadTooLarge = errors.New("cluster: recovery payload exceeds inline size limit")

// ValidateRecoveryPayloadSize reports whether the recovery record for
// (sandboxID, spec, secrets) fits in a raft log entry. Exported so the
// service layer can reject oversized specs with a clean validation error
// before any admission/container work happens. Encodes the exact bytes the
// FSM's recovery store persists, so validation and apply cannot disagree.
func ValidateRecoveryPayloadSize(sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	rec := placementRecovery{
		Spec:          spec,
		SecretRef:     secrets.Ref,
		SecretVersion: secrets.Version,
	}
	_, payload, err := encodePlacementRecoveryRecord(placementRecoveryStoreRecord{SandboxID: sandboxID, Recovery: rec})
	if err != nil {
		return err
	}
	if len(payload) > inlineRecoveryMaxBytes {
		return fmt.Errorf("%w: sandbox %s encodes to %d bytes (limit %d)", ErrRecoveryPayloadTooLarge, sandboxID, len(payload), inlineRecoveryMaxBytes)
	}
	return nil
}

// validateCommandRecoverySize is the defensive half of the size cap, run on
// every command before it is encoded into the raft log (leader-forwarded
// commands re-run it on the leader). It must stay cheap: one JSON encode +
// SHA-256 of a ≤4KiB payload (~µs) on the create path.
func validateCommandRecoverySize(cmd command) error {
	switch cmd.Op {
	case opPlace, opClaimOrphan, opUpsertSpec, opReserve:
		if !commandCarriesRecoveryPayload(cmd.Spec, cmd.SecretRef, cmd.SecretVersion) {
			return nil
		}
		return ValidateRecoveryPayloadSize(cmd.SandboxID, cmd.Spec, cmd.placementSecrets())
	case opReserveBatch:
		for _, r := range cmd.Reservations {
			if !commandCarriesRecoveryPayload(r.Spec, r.SecretRef, r.SecretVersion) {
				continue
			}
			if err := ValidateRecoveryPayloadSize(r.SandboxID, r.Spec, PlacementSecrets{Ref: r.SecretRef, Version: r.SecretVersion}); err != nil {
				return err
			}
		}
	}
	return nil
}

func commandCarriesRecoveryPayload(spec *models.CreateSandboxRequest, secretRef string, secretVersion int) bool {
	return spec != nil || secretRef != "" || secretVersion != 0
}

func (c *Cluster) RecoveryBlob(ctx context.Context, ref string) (RecoveryBlob, bool, error) {
	_ = ctx
	if c.fsm == nil || c.fsm.recoveryStore == nil {
		return RecoveryBlob{}, false, nil
	}
	record, ok, err := c.fsm.recoveryStore.GetRecord(ref)
	if err != nil || !ok {
		return RecoveryBlob{}, ok, err
	}
	return recoveryBlobFromRecord(ref, record), true, nil
}

func (c *Cluster) fetchRecoveryBlob(ctx context.Context, ref string) (RecoveryBlob, bool, error) {
	for _, m := range c.recoveryServerMembers() {
		if m.NodeID == "" || m.NodeID == c.nodeID {
			continue
		}
		blob, ok, err := c.getRecoveryBlobFromMember(ctx, m, ref)
		if err == nil && ok {
			return blob, true, nil
		}
		if err != nil && !isStatus(err, http.StatusNotFound) {
			continue
		}
	}
	return RecoveryBlob{}, false, nil
}

func (c *Cluster) recoveryServerMembers() []Member {
	if c.gossip == nil {
		return nil
	}
	members := c.gossip.members()
	out := make([]Member, 0, len(members))
	for _, m := range members {
		if m.NodeID == "" || !m.Alive || !CanServeControlPlaneRole(m.Role) {
			continue
		}
		if m.NodeID != c.nodeID && m.APIURL == "" && m.InternalURL == "" {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (c *Cluster) getRecoveryBlobFromMember(ctx context.Context, m Member, ref string) (RecoveryBlob, bool, error) {
	var out RecoveryBlob
	path := recoveryBlobPath(ref)
	client, base, err := PeerDial(m, c.httpClient, c.currentInternalClient())
	if err != nil {
		return RecoveryBlob{}, false, err
	}
	err = doRecoveryHTTPRequest(ctx, client, strings.TrimRight(base, "/")+path, http.MethodGet, c.patToken, nil, &out)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return RecoveryBlob{}, false, nil
		}
		return RecoveryBlob{}, false, err
	}
	return out, true, nil
}

func recoveryBlobPath(ref string) string {
	return PublicInternalRecoveryPath + url.PathEscape(ref)
}

func doRecoveryHTTPRequest(ctx context.Context, client *http.Client, endpoint, method, pat string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if pat != "" {
		req.Header.Set("Authorization", "Bearer "+pat)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return statusError{status: resp.StatusCode, message: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
