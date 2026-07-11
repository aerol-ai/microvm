package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/models"
)

func (c *Cluster) externalizeCommandRecovery(ctx context.Context, cmd command) (command, error) {
	return externalizeCommandRecovery(ctx, cmd, c.storeAndReplicateRecoveryBlob)
}

func (a *Agent) externalizeCommandRecovery(ctx context.Context, cmd command) (command, error) {
	return externalizeCommandRecovery(ctx, cmd, a.replicateRecoveryBlob)
}

func externalizeCommandRecovery(ctx context.Context, cmd command, put func(context.Context, RecoveryBlob) error) (command, error) {
	switch cmd.Op {
	case opPlace, opClaimOrphan, opUpsertSpec, opReserve:
		return externalizeSingleCommandRecovery(ctx, cmd, put)
	case opReserveBatch:
		for i := range cmd.Reservations {
			r, err := externalizeReservationRecovery(ctx, cmd.Reservations[i], put)
			if err != nil {
				return command{}, err
			}
			cmd.Reservations[i] = r
		}
	}
	return cmd, nil
}

// inlineRecoveryMaxBytes bounds the recovery payload a command may carry
// inline in the raft log instead of pre-replicating it as a blob. The value
// keeps log entries and FSM snapshots small: typical redacted specs encode to
// ~0.5–1KiB, so 4KiB covers the normal create with headroom while capping
// worst-case snapshot growth at ~4KiB per placement. A const, not config —
// an env knob would make what the emitter sends diverge per node for no
// benefit (any mix of inline and ref commands is valid either way).
const inlineRecoveryMaxBytes = 4096

// inlineRecoveryEligible reports whether a recovery payload may stay inline
// in the raft command, skipping the blob store + synchronous replication to
// every control-plane member. Two conditions, both load-bearing:
//
//   - Sealed secret bytes must NEVER enter the raft log: the log and FSM
//     snapshots are not erasable per-sandbox, while blob files are deleted on
//     destroy. The modern path's SecretRef is a provider handle, not secret
//     material, so it may ride the log.
//   - The encoded payload (the exact bytes the blob store would persist) must
//     fit inlineRecoveryMaxBytes so log/snapshot growth stays bounded.
//
// Inline commands are the original wire shape: hydrateCommandRecovery is a
// no-op for RecoveryRef == "", and at apply time storePlacementLocked splits
// the payload into each voter's local recovery store under the same
// content-addressed ref this encoding produces — so failover recreate and
// destroy-time blob deletion behave exactly as on the blob path, minus the
// pre-apply HTTP fan-out.
func inlineRecoveryEligible(sandboxID string, rec placementRecovery) (bool, error) {
	if len(rec.SealedSecrets) > 0 {
		return false, nil
	}
	_, payload, err := encodePlacementRecoveryRecord(placementRecoveryStoreRecord{SandboxID: sandboxID, Recovery: rec})
	if err != nil {
		return false, err
	}
	return len(payload) <= inlineRecoveryMaxBytes, nil
}

func externalizeSingleCommandRecovery(ctx context.Context, cmd command, put func(context.Context, RecoveryBlob) error) (command, error) {
	if !commandCarriesRecoveryPayload(cmd.Spec, cmd.SecretRef, cmd.SecretVersion, cmd.SealedSecrets) {
		return cmd, nil
	}
	rec := placementRecovery{
		Spec:          cmd.Spec,
		SecretRef:     cmd.SecretRef,
		SecretVersion: cmd.SecretVersion,
		SealedSecrets: cloneBytes(cmd.SealedSecrets),
	}
	inline, err := inlineRecoveryEligible(cmd.SandboxID, rec)
	if err != nil {
		return command{}, err
	}
	if inline {
		recordRecoveryExternalize(recoveryExternalizeModeInline)
		return cmd, nil
	}
	recordRecoveryExternalize(recoveryExternalizeModeBlob)
	blob, err := newRecoveryBlob(cmd.SandboxID, rec)
	if err != nil {
		return command{}, err
	}
	if err := put(ctx, blob); err != nil {
		return command{}, err
	}
	cmd.Name = commandName(cmd)
	cmd.RecoveryRef = blob.Ref
	cmd.Spec = nil
	cmd.SecretRef = ""
	cmd.SecretVersion = 0
	cmd.SealedSecrets = nil
	return cmd, nil
}

func externalizeReservationRecovery(ctx context.Context, r reservationCommand, put func(context.Context, RecoveryBlob) error) (reservationCommand, error) {
	if !commandCarriesRecoveryPayload(r.Spec, r.SecretRef, r.SecretVersion, r.SealedSecrets) {
		return r, nil
	}
	rec := placementRecovery{
		Spec:          r.Spec,
		SecretRef:     r.SecretRef,
		SecretVersion: r.SecretVersion,
		SealedSecrets: cloneBytes(r.SealedSecrets),
	}
	inline, err := inlineRecoveryEligible(r.SandboxID, rec)
	if err != nil {
		return reservationCommand{}, err
	}
	if inline {
		recordRecoveryExternalize(recoveryExternalizeModeInline)
		return r, nil
	}
	recordRecoveryExternalize(recoveryExternalizeModeBlob)
	blob, err := newRecoveryBlob(r.SandboxID, rec)
	if err != nil {
		return reservationCommand{}, err
	}
	if err := put(ctx, blob); err != nil {
		return reservationCommand{}, err
	}
	r.Name = reservationName(r)
	r.RecoveryRef = blob.Ref
	r.Spec = nil
	r.SecretRef = ""
	r.SecretVersion = 0
	r.SealedSecrets = nil
	return r, nil
}

func commandCarriesRecoveryPayload(spec *models.CreateSandboxRequest, secretRef string, secretVersion int, sealed []byte) bool {
	return spec != nil || secretRef != "" || secretVersion != 0 || len(sealed) > 0
}

// replicateBlobToMembers pushes blob to every member concurrently. The PUTs
// are independent (same blob, keyed by Ref, different hosts), and this runs
// synchronously on the sandbox-create path — twice per create (opReserve and
// opPlace) — so the wall-clock cost must be the slowest peer, not the sum of
// all peers. Every member is attempted even when one fails, and the first
// error in member order is returned, matching the previous serial loop.
func replicateBlobToMembers(ctx context.Context, members []Member, blob RecoveryBlob, put func(context.Context, Member, RecoveryBlob) error) error {
	if len(members) == 1 {
		return put(ctx, members[0], blob)
	}
	errs := make([]error, len(members))
	var wg sync.WaitGroup
	for i, m := range members {
		wg.Add(1)
		go func(i int, m Member) {
			defer wg.Done()
			errs[i] = put(ctx, m, blob)
		}(i, m)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Cluster) storeAndReplicateRecoveryBlob(ctx context.Context, blob RecoveryBlob) error {
	if err := c.StoreRecoveryBlob(ctx, blob); err != nil {
		return err
	}
	peers := make([]Member, 0)
	for _, m := range c.recoveryServerMembers() {
		if m.NodeID == "" || m.NodeID == c.nodeID {
			continue
		}
		peers = append(peers, m)
	}
	return replicateBlobToMembers(ctx, peers, blob, c.putRecoveryBlobToMember)
}

func (a *Agent) replicateRecoveryBlob(ctx context.Context, blob RecoveryBlob) error {
	members := a.controlPlaneMembers()
	if len(members) == 0 {
		return errors.New("cluster agent: no live server-role control-plane members for recovery blob")
	}
	return replicateBlobToMembers(ctx, members, blob, a.putRecoveryBlobToMember)
}

func (c *Cluster) StoreRecoveryBlob(ctx context.Context, blob RecoveryBlob) error {
	_ = ctx
	return c.fsm.storeRecoveryBlob(blob)
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

func (c *Cluster) putRecoveryBlobToMember(ctx context.Context, m Member, blob RecoveryBlob) error {
	body, err := json.Marshal(blob)
	if err != nil {
		return err
	}
	path := recoveryBlobPath(blob.Ref)
	if c.internalClient != nil && m.InternalURL != "" {
		return doRecoveryHTTPRequest(ctx, c.internalClient, strings.TrimRight(m.InternalURL, "/")+path, http.MethodPut, c.patToken, body, nil)
	}
	if m.APIURL == "" {
		return errors.New("cluster: recovery blob peer API URL unknown for " + m.NodeID)
	}
	return doRecoveryHTTPRequest(ctx, c.httpClient, strings.TrimRight(m.APIURL, "/")+path, http.MethodPut, c.patToken, body, nil)
}

func (a *Agent) putRecoveryBlobToMember(ctx context.Context, m Member, blob RecoveryBlob) error {
	body, err := json.Marshal(blob)
	if err != nil {
		return err
	}
	path := recoveryBlobPath(blob.Ref)
	if a.internalClient != nil && m.InternalURL != "" {
		return doRecoveryHTTPRequest(ctx, a.internalClient, strings.TrimRight(m.InternalURL, "/")+path, http.MethodPut, a.patToken, body, nil)
	}
	if m.APIURL == "" {
		return errors.New("cluster agent: recovery blob peer API URL unknown for " + m.NodeID)
	}
	return doRecoveryHTTPRequest(ctx, a.httpClient, strings.TrimRight(m.APIURL, "/")+path, http.MethodPut, a.patToken, body, nil)
}

func (c *Cluster) getRecoveryBlobFromMember(ctx context.Context, m Member, ref string) (RecoveryBlob, bool, error) {
	var out RecoveryBlob
	path := recoveryBlobPath(ref)
	var err error
	if c.internalClient != nil && m.InternalURL != "" {
		err = doRecoveryHTTPRequest(ctx, c.internalClient, strings.TrimRight(m.InternalURL, "/")+path, http.MethodGet, c.patToken, nil, &out)
	} else if m.APIURL != "" {
		err = doRecoveryHTTPRequest(ctx, c.httpClient, strings.TrimRight(m.APIURL, "/")+path, http.MethodGet, c.patToken, nil, &out)
	} else {
		err = errors.New("cluster: recovery blob peer API URL unknown for " + m.NodeID)
	}
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
