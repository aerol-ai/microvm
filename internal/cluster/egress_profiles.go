package cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Named egress profiles over the cluster (plans/egress-domain-filtering.md
// D21, CEO D19). Writes go through a dedicated internal endpoint rather than
// the generic forwarded apply, for two reasons: the caller needs the
// stored record back (its generation), and a write may only be applied by a
// leader that has checked every Raft server's build. Only builds with this
// endpoint serve it, so an older leader can never commit a profile op its
// followers would apply and it wouldn't.
const (
	PublicInternalEgressProfileWritePath = "/v1/cluster/internal/egress-profiles/write"
	PublicInternalEgressProfileReadPath  = "/v1/cluster/internal/egress-profiles/read"
)

// Outcome codes of a profile write, carried in a 200 body so they survive
// any number of forwarding hops.
const (
	egressProfileCodeInUse          = "in_use"
	egressProfileCodeCapExceeded    = "cap_exceeded"
	egressProfileCodeClusterVersion = "cluster_version"
)

// EgressProfileWriteRequest puts (Delete false) or deletes one profile. A
// put carries the canonical entries and their hostname count.
type EgressProfileWriteRequest struct {
	Delete  bool                `json:"delete,omitempty"`
	Profile EgressProfileRecord `json:"profile"`
}

// EgressProfileWriteResponse is the outcome of a write. Code is set, and
// Profile empty, when the FSM refused it.
type EgressProfileWriteResponse struct {
	Profile EgressProfileRecord `json:"profile"`
	Changed bool                `json:"changed"`
	Code    string              `json:"code,omitempty"`
	Message string              `json:"message,omitempty"`
}

// EgressProfileReadRequest reads an owner's profiles: the named ones, or a
// page by name when Names is empty.
type EgressProfileReadRequest struct {
	Owner string   `json:"owner"`
	Names []string `json:"names,omitempty"`
	After string   `json:"after,omitempty"`
	Limit int      `json:"limit,omitempty"`
}

// EgressProfileReadResponse answers a read from a server's FSM. A name with
// no profile is simply absent.
type EgressProfileReadResponse struct {
	Profiles      []EgressProfileRecord `json:"profiles"`
	Authoritative bool                  `json:"authoritative"`
}

// EgressProfileWriteOutcome turns a write error into the body a peer gets,
// and a body back into the same error, so sentinels survive forwarding.
func EgressProfileWriteOutcome(err error) EgressProfileWriteResponse {
	switch {
	case errors.Is(err, ErrEgressProfileInUse):
		return EgressProfileWriteResponse{Code: egressProfileCodeInUse, Message: err.Error()}
	case errors.Is(err, ErrEgressProfileCapExceeded):
		return EgressProfileWriteResponse{Code: egressProfileCodeCapExceeded, Message: err.Error()}
	case errors.Is(err, ErrClusterVersion):
		return EgressProfileWriteResponse{Code: egressProfileCodeClusterVersion, Message: err.Error()}
	}
	return EgressProfileWriteResponse{}
}

func (r EgressProfileWriteResponse) err() error {
	var sentinel error
	switch r.Code {
	case "":
		return nil
	case egressProfileCodeInUse:
		sentinel = ErrEgressProfileInUse
	case egressProfileCodeCapExceeded:
		sentinel = ErrEgressProfileCapExceeded
	case egressProfileCodeClusterVersion:
		sentinel = ErrClusterVersion
	default:
		return fmt.Errorf("cluster: egress profile write: %s: %s", r.Code, r.Message)
	}
	return fmt.Errorf("%w (%s)", sentinel, r.Message)
}

// egressProfileWritesAllowed is the rolling-upgrade gate (D19): every server
// in the Raft configuration, failed ones included, must report an FSM op
// set that applies profile ops. A failed server counts at its last-known
// gossip meta because it replays the log when it returns; one with no gossip
// entry at all counts as an old build.
func (c *Cluster) egressProfileWritesAllowed() error {
	future := c.raft.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return fmt.Errorf("cluster: read raft configuration: %w", err)
	}
	for _, srv := range future.Configuration().Servers {
		id := string(srv.ID)
		v := 0
		if id == c.nodeID {
			v = fsmOpsVersion
		} else if c.gossip != nil {
			if m, ok := c.gossip.lookupMember(id); ok {
				v = m.FSMOpsVersion
			}
		}
		if v < egressProfileFSMOpsVersion {
			return fmt.Errorf("%w: server %s reports FSM ops version %d, profiles need %d", ErrClusterVersion, id, v, egressProfileFSMOpsVersion)
		}
	}
	return nil
}

// WriteEgressProfile puts or deletes a profile. The leader checks the
// upgrade gate and applies; a follower forwards one hop to the leader.
func (c *Cluster) WriteEgressProfile(ctx context.Context, req EgressProfileWriteRequest) (EgressProfileWriteResponse, error) {
	if c == nil || c.raft == nil || c.raft.raft == nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	if c.raft.raft.State() != raft.Leader {
		return c.forwardEgressProfileWrite(ctx, req)
	}
	if err := c.egressProfileWritesAllowed(); err != nil {
		return EgressProfileWriteResponse{}, err
	}
	op := opPutEgressProfile
	if req.Delete {
		op = opDeleteEgressProfile
	}
	profile := req.Profile
	payload, err := encodeCommand(command{Op: op, EgressProfile: &profile, StampUnixNano: time.Now().UnixNano()})
	if err != nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: encode command: %w", err)
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return EgressProfileWriteResponse{}, err
	}
	if applied, ok := result.(egressProfileApplyResult); ok {
		return EgressProfileWriteResponse{Profile: applied.Profile, Changed: applied.Changed}, nil
	}
	return EgressProfileWriteResponse{}, nil
}

func (c *Cluster) forwardEgressProfileWrite(ctx context.Context, req EgressProfileWriteRequest) (EgressProfileWriteResponse, error) {
	leader := c.Leader()
	if leader == "" {
		return EgressProfileWriteResponse{}, ErrNotLeader
	}
	if c.currentInternalClient() == nil || c.gossip == nil {
		return EgressProfileWriteResponse{}, ErrPeerInternalURLRequired
	}
	peerInternal := c.gossip.peerInternalURL(leader)
	if peerInternal == "" {
		return EgressProfileWriteResponse{}, ErrPeerInternalURLRequired
	}
	body, err := json.Marshal(req)
	if err != nil {
		return EgressProfileWriteResponse{}, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, strings.TrimRight(peerInternal, "/")+PublicInternalEgressProfileWritePath, bytes.NewReader(body))
	if err != nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: build egress profile write: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	SetPeerNodeIDHeader(httpReq, c.nodeID)
	if c.patToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.patToken)
	}
	resp, err := c.ClientForPeer(leader).Do(httpReq)
	if err != nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: egress profile write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode == http.StatusServiceUnavailable {
			return EgressProfileWriteResponse{}, ErrNotLeader
		}
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: egress profile write: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out EgressProfileWriteResponse
	if err := decodeControlPlaneJSON(resp.Body, &out); err != nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: decode egress profile write: %w", err)
	}
	return out, out.err()
}

// ReadEgressProfiles answers from this server's FSM.
func (c *Cluster) ReadEgressProfiles(_ context.Context, req EgressProfileReadRequest) (EgressProfileReadResponse, error) {
	if c == nil || c.fsm == nil {
		return EgressProfileReadResponse{}, fmt.Errorf("cluster: node holds no placement state")
	}
	return c.fsm.readEgressProfiles(req), nil
}

func (f *placementFSM) readEgressProfiles(req EgressProfileReadRequest) EgressProfileReadResponse {
	out := EgressProfileReadResponse{Profiles: []EgressProfileRecord{}, Authoritative: true}
	if len(req.Names) == 0 {
		out.Profiles = f.egressProfilesPage(req.Owner, req.After, req.Limit)
		return out
	}
	for _, name := range req.Names {
		if rec, ok := f.egressProfile(req.Owner, name); ok {
			out.Profiles = append(out.Profiles, rec)
		}
	}
	return out
}

// WriteEgressProfile sends a profile write to the server tier; any server
// takes it and forwards it to the leader.
func (a *Agent) WriteEgressProfile(ctx context.Context, req EgressProfileWriteRequest) (EgressProfileWriteResponse, error) {
	if a == nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out EgressProfileWriteResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalEgressProfileWritePath, PublicInternalEgressProfileWritePath, req, &out); err != nil {
		return EgressProfileWriteResponse{}, fmt.Errorf("cluster: write egress profile: %w", err)
	}
	a.profiles.forget(req.Profile.key())
	return out, out.err()
}

// ReadEgressProfiles reads profiles from the server tier. A dedicated
// worker holds no FSM, so point reads go through a cache refreshed every
// egressProfileCacheTTL (the poll the plan describes, done on demand by the
// re-apply pass and creates): a narrowed profile reaches a worker's
// sandboxes within egressProfileCacheTTL plus one re-apply interval. If the
// server tier can't be reached, entries up to egressProfileCacheMaxStale old
// still answer; past that the read fails and the caller fails closed.
func (a *Agent) ReadEgressProfiles(ctx context.Context, req EgressProfileReadRequest) (EgressProfileReadResponse, error) {
	if a == nil {
		return EgressProfileReadResponse{}, fmt.Errorf("cluster: agent is not configured")
	}
	if len(req.Names) == 0 {
		return a.readEgressProfilesRemote(ctx, req)
	}
	return a.profiles.read(ctx, req, a.readEgressProfilesRemote)
}

func (a *Agent) readEgressProfilesRemote(ctx context.Context, req EgressProfileReadRequest) (EgressProfileReadResponse, error) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var out EgressProfileReadResponse
	if err := a.doControlPlaneJSON(reqCtx, http.MethodPost, PublicInternalEgressProfileReadPath, PublicInternalEgressProfileReadPath, req, &out); err != nil {
		return EgressProfileReadResponse{}, fmt.Errorf("cluster: read egress profiles: %w", err)
	}
	if !out.Authoritative {
		return EgressProfileReadResponse{}, fmt.Errorf("cluster: egress profile read was not authoritative")
	}
	return out, nil
}

const (
	egressProfileCacheTTL      = 10 * time.Second
	egressProfileCacheMaxStale = 30 * time.Second
)

// egressProfileCache is a worker's view of the profiles its sandboxes use.
type egressProfileCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[EgressProfileKey]egressProfileCacheEntry
}

type egressProfileCacheEntry struct {
	rec   EgressProfileRecord
	found bool
	at    time.Time
}

func (c *egressProfileCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *egressProfileCache) forget(k EgressProfileKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, k)
}

func (c *egressProfileCache) read(ctx context.Context, req EgressProfileReadRequest, fetch func(context.Context, EgressProfileReadRequest) (EgressProfileReadResponse, error)) (EgressProfileReadResponse, error) {
	now := c.clock()
	out := EgressProfileReadResponse{Profiles: []EgressProfileRecord{}, Authoritative: true}
	var missing []string
	c.mu.Lock()
	for _, name := range req.Names {
		e, ok := c.entries[EgressProfileKey{req.Owner, name}]
		if ok && now.Sub(e.at) < egressProfileCacheTTL {
			if e.found {
				out.Profiles = append(out.Profiles, cloneEgressProfileRecord(e.rec))
			}
			continue
		}
		missing = append(missing, name)
	}
	c.mu.Unlock()
	if len(missing) == 0 {
		return out, nil
	}
	fetched, err := fetch(ctx, EgressProfileReadRequest{Owner: req.Owner, Names: missing})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[EgressProfileKey]egressProfileCacheEntry)
	}
	if err != nil {
		for _, name := range missing {
			e, ok := c.entries[EgressProfileKey{req.Owner, name}]
			if !ok || now.Sub(e.at) >= egressProfileCacheMaxStale {
				return EgressProfileReadResponse{}, err
			}
			if e.found {
				out.Profiles = append(out.Profiles, cloneEgressProfileRecord(e.rec))
			}
		}
		return out, nil
	}
	got := make(map[string]EgressProfileRecord, len(fetched.Profiles))
	for _, rec := range fetched.Profiles {
		got[rec.Name] = rec
	}
	for _, name := range missing {
		rec, found := got[name]
		c.entries[EgressProfileKey{req.Owner, name}] = egressProfileCacheEntry{rec: cloneEgressProfileRecord(rec), found: found, at: now}
		if found {
			out.Profiles = append(out.Profiles, cloneEgressProfileRecord(rec))
		}
	}
	return out, nil
}
