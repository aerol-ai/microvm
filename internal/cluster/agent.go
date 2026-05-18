package cluster

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/google/uuid"
)

const (
	PublicInternalApplyPath             = "/v1/cluster/internal/apply"
	PublicInternalPlacementPath         = "/v1/cluster/internal/placement/"
	PublicInternalPlacementByNamePath   = "/v1/cluster/internal/placement-by-name/"
	PublicInternalPlacementsPath        = "/v1/cluster/internal/placements"
	PublicInternalPlacementsQueryPath   = "/v1/cluster/internal/placements/query"
	PublicInternalPlacementsPagePath    = "/v1/cluster/internal/placements/page"
	PublicInternalSelectPlacementPath   = "/v1/cluster/internal/select-placement"
	PublicInternalDrainStatePath        = "/v1/cluster/internal/drain/"
	PublicInternalClusterLeaderPath     = "/v1/cluster/leader"
	controlPlaneRequestTimeout          = 5 * time.Second
	controlPlanePlacementRequestTimeout = 10 * time.Second
)

type PlacementLookupResponse struct {
	SandboxID string    `json:"sandbox_id"`
	Placement Placement `json:"placement"`
	Owner     OwnerInfo `json:"owner"`
	Orphaned  bool      `json:"orphaned"`
}

type SelectPlacementRequest struct {
	Request capacity.Request `json:"request"`
}

type SelectPlacementResponse struct {
	Target PlacementTarget `json:"target"`
	Error  string          `json:"error,omitempty"`
}

type DrainStateResponse struct {
	Drained bool `json:"drained"`
}

// Agent is the worker/ingress-side cluster client. It deliberately does not
// start Raft, does not create a placement FSM, and never joins the raft
// configuration as a non-voter. It only gossips local capacity/addresses and
// delegates every authoritative placement read/write to server-role nodes.
type Agent struct {
	cfg           config.Config
	logger        *slog.Logger
	nodeID        string
	apiURL        string
	dataPlaneHost string

	gossip *gossipNode

	patToken   string
	httpClient *http.Client

	internalURL    string
	tls            *ClusterTLS
	internalServer *internalServer
	internalClient *http.Client
	publicProxies  *proxyCache
	mtlsProxies    *proxyCache

	cacheMu        sync.RWMutex
	placementCache []Placement
	shardCache     map[string][]Placement
}

func NewAgent(cfg config.Config, logger *slog.Logger, admitter *capacity.Admitter) (*Agent, error) {
	if !cfg.EnableCluster {
		return nil, errors.New("cluster.NewAgent: cfg.EnableCluster is false; use NewNoop")
	}
	if cfg.IsServer() {
		return nil, fmt.Errorf("cluster.NewAgent: SB_NODE_ROLE=%q includes server; use New for server nodes", cfg.NodeRole)
	}
	nodeID := cfg.NodeID
	if nodeID == "" {
		nodeID = "node-" + uuid.NewString()[:8]
	}
	if cfg.SelfAPIAdvertiseURL == "" {
		return nil, errors.New("cluster.NewAgent: SelfAPIAdvertiseURL required in cluster mode")
	}

	clusterTLS, err := loadClusterTLS(cfg.ClusterTLSDir)
	if err != nil {
		return nil, fmt.Errorf("cluster.NewAgent: load tls: %w", err)
	}

	commitTimeout := cfg.ClusterRaftCommitTimeout
	if commitTimeout <= 0 {
		commitTimeout = 5 * time.Second
	}

	a := &Agent{
		cfg:           cfg,
		logger:        logger,
		nodeID:        nodeID,
		apiURL:        cfg.SelfAPIAdvertiseURL,
		dataPlaneHost: cfg.DataPlaneAdvertiseHost,
		patToken:      cfg.PATToken,
		httpClient:    &http.Client{Timeout: commitTimeout + 2*time.Second},
		tls:           clusterTLS,
		publicProxies: newProxyCache(defaultPublicTransport),
	}

	if clusterTLS != nil {
		mtlsTransport := &http.Transport{
			TLSClientConfig:   clusterTLS.clientConfig(),
			DisableKeepAlives: false,
			MaxIdleConns:      4,
			IdleConnTimeout:   30 * time.Second,
		}
		a.internalClient = &http.Client{
			Timeout:   commitTimeout + 2*time.Second,
			Transport: mtlsTransport,
		}
		a.mtlsProxies = newProxyCache(&http.Transport{
			TLSClientConfig:     clusterTLS.clientConfig(),
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		})
		is, err := startInternalServer(cfg.ClusterInternalListenAddr, clusterTLS, a.ApplyEncoded, logger)
		if err != nil {
			return nil, fmt.Errorf("cluster.NewAgent: internal server: %w", err)
		}
		a.internalServer = is
		a.internalURL = deriveInternalAdvertiseURL(cfg.ClusterInternalAdvertiseURL, cfg.ClusterInternalListenAddr, is.Addr())
	}

	secretKey, err := decodeGossipSecretKey(cfg.ClusterGossipSecretKey)
	if err != nil {
		if a.internalServer != nil {
			_ = a.internalServer.Close()
		}
		return nil, fmt.Errorf("cluster.NewAgent: %w", err)
	}
	if len(secretKey) == 0 {
		logger.Warn("cluster agent: gossip is unencrypted (SB_CLUSTER_INSECURE_GOSSIP=true); keep gossip ports on a private network")
	}

	gn, err := setupGossip(gossipSetupConfig{
		NodeID:         nodeID,
		BindAddr:       cfg.GossipBindAddr,
		AdvertiseAddr:  cfg.GossipAdvertiseAddr,
		APIURL:         cfg.SelfAPIAdvertiseURL,
		DataPlaneHost:  cfg.DataPlaneAdvertiseHost,
		RaftAddr:       "",
		InternalURL:    a.internalURL,
		Role:           cfg.NodeRole,
		BootstrapPeers: cfg.BootstrapPeers,
		GossipInterval: cfg.ClusterCapacityGossipInterval,
		SecretKey:      secretKey,
		Events:         nil,
	}, admitter, logger)
	if err != nil {
		if a.internalServer != nil {
			_ = a.internalServer.Close()
		}
		return nil, fmt.Errorf("cluster.NewAgent: gossip: %w", err)
	}
	a.gossip = gn
	return a, nil
}

func (a *Agent) SelfNodeID() string { return a.nodeID }
func (a *Agent) SelfAPIURL() string { return a.apiURL }

func (a *Agent) OwnerOf(sandboxID string) (OwnerInfo, error) {
	lookup, ok, err := a.lookupPlacement(context.Background(), sandboxID)
	if err != nil {
		return OwnerInfo{}, err
	}
	if !ok {
		return OwnerInfo{}, ErrUnknownSandbox
	}
	if lookup.Orphaned {
		return OwnerInfo{}, ErrOrphaned
	}
	owner := lookup.Owner
	owner.IsSelf = owner.NodeID == a.nodeID
	return owner, nil
}

func (a *Agent) OwnerOfName(name string) (string, OwnerInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), controlPlaneRequestTimeout)
	defer cancel()
	var lookup PlacementLookupResponse
	err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalPlacementByNamePath+base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(name))), PublicInternalPlacementByNamePath+base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(name))), nil, &lookup)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return "", OwnerInfo{}, ErrUnknownSandbox
		}
		return "", OwnerInfo{}, err
	}
	if lookup.Orphaned {
		return lookup.SandboxID, OwnerInfo{}, ErrOrphaned
	}
	owner := lookup.Owner
	owner.IsSelf = owner.NodeID == a.nodeID
	return lookup.SandboxID, owner, nil
}

func (a *Agent) SelectPlacement(req capacity.Request) (PlacementTarget, error) {
	ctx, cancel := context.WithTimeout(context.Background(), controlPlanePlacementRequestTimeout)
	defer cancel()
	var resp SelectPlacementResponse
	if err := a.doControlPlaneJSON(ctx, http.MethodPost, PublicInternalSelectPlacementPath, PublicInternalSelectPlacementPath, SelectPlacementRequest{Request: req}, &resp); err != nil {
		return PlacementTarget{}, err
	}
	if resp.Error != "" {
		if resp.Error == ErrNoPlacementTarget.Error() {
			return PlacementTarget{}, ErrNoPlacementTarget
		}
		return PlacementTarget{}, errors.New(resp.Error)
	}
	if resp.Target.NodeID == a.nodeID {
		resp.Target.APIURL = a.apiURL
		resp.Target.DataPlaneHost = a.dataPlaneHost
		resp.Target.InternalURL = a.internalURL
		resp.Target.IsSelf = true
	}
	return resp.Target, nil
}

func (a *Agent) RecordPlacement(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	cmd := command{
		Op:                 opPlace,
		SandboxID:          sandboxID,
		OwnerNodeID:        a.nodeID,
		OwnerAPIURL:        a.apiURL,
		OwnerDataPlaneHost: a.dataPlaneHost,
		Spec:               spec,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
		SealedSecrets:      cloneBytes(secrets.LegacySealed),
	}
	return a.applyCommand(ctx, cmd)
}

func (a *Agent) ClaimOrphan(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	cmd := command{
		Op:                 opClaimOrphan,
		SandboxID:          sandboxID,
		OwnerNodeID:        a.nodeID,
		OwnerAPIURL:        a.apiURL,
		OwnerDataPlaneHost: a.dataPlaneHost,
		Spec:               spec,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
		SealedSecrets:      cloneBytes(secrets.LegacySealed),
	}
	return a.applyCommand(ctx, cmd)
}

func (a *Agent) UpsertSpec(ctx context.Context, sandboxID string, spec *models.CreateSandboxRequest, secrets PlacementSecrets) error {
	if spec == nil && !secrets.hasUpdate() {
		return nil
	}
	return a.applyCommand(ctx, command{
		Op:            opUpsertSpec,
		SandboxID:     sandboxID,
		Spec:          spec,
		SecretRef:     secrets.Ref,
		SecretVersion: secrets.Version,
		SealedSecrets: cloneBytes(secrets.LegacySealed),
	})
}

func (a *Agent) SpecOf(sandboxID string) *models.CreateSandboxRequest {
	lookup, ok, err := a.lookupPlacement(context.Background(), sandboxID)
	if err != nil {
		a.logger.Warn("cluster agent: SpecOf control-plane lookup failed", "sandbox_id", sandboxID, "err", err)
		return nil
	}
	if !ok || lookup.Placement.Spec == nil {
		return nil
	}
	return cloneCreateSandboxRequest(lookup.Placement.Spec)
}

func (a *Agent) SecretsOf(sandboxID string) PlacementSecrets {
	lookup, ok, err := a.lookupPlacement(context.Background(), sandboxID)
	if err != nil {
		a.logger.Warn("cluster agent: SecretsOf control-plane lookup failed", "sandbox_id", sandboxID, "err", err)
		return PlacementSecrets{}
	}
	if !ok {
		return PlacementSecrets{}
	}
	return secretsFromPlacement(lookup.Placement)
}

func (a *Agent) SealedSecretsOf(sandboxID string) []byte { return a.SecretsOf(sandboxID).LegacySealed }

func (a *Agent) AddExposedPort(ctx context.Context, sandboxID string, port int, route ExposedPortRoute) error {
	if port <= 0 {
		return nil
	}
	cmd := command{Op: opAddExposedPort, SandboxID: sandboxID, Port: port, Protocol: route.Protocol, HostPort: route.HostPort, PublicURL: route.PublicURL}
	return a.applyCommand(ctx, cmd)
}

func (a *Agent) RemoveExposedPort(ctx context.Context, sandboxID string, port int) error {
	if port <= 0 {
		return nil
	}
	return a.applyCommand(ctx, command{Op: opRemoveExposedPort, SandboxID: sandboxID, Port: port})
}

func (a *Agent) ExposedPortsOf(sandboxID string) map[int]ExposedPortRoute {
	lookup, ok, err := a.lookupPlacement(context.Background(), sandboxID)
	if err != nil || !ok {
		return nil
	}
	return exposedPortRoutesForPlacement(lookup.Placement)
}

func (a *Agent) DeletePlacement(ctx context.Context, sandboxID string) error {
	return a.applyCommand(ctx, command{Op: opDelete, SandboxID: sandboxID})
}

func (a *Agent) ReserveOnTarget(ctx context.Context, sandboxID string, target PlacementTarget, redacted *models.CreateSandboxRequest, secrets PlacementSecrets, ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("cluster: reservation ttl must be > 0")
	}
	return a.applyCommand(ctx, command{
		Op:                 opReserve,
		SandboxID:          sandboxID,
		OwnerNodeID:        target.NodeID,
		OwnerAPIURL:        target.APIURL,
		OwnerDataPlaneHost: target.DataPlaneHost,
		Spec:               redacted,
		SecretRef:          secrets.Ref,
		SecretVersion:      secrets.Version,
		SealedSecrets:      cloneBytes(secrets.LegacySealed),
		ExpiresUnix:        time.Now().Add(ttl).Unix(),
	})
}

func (a *Agent) CancelReservation(ctx context.Context, sandboxID string) error {
	return a.applyCommand(ctx, command{Op: opCancelReserve, SandboxID: sandboxID})
}

func (a *Agent) SetNodeDrainState(ctx context.Context, nodeID string, drained bool) error {
	if nodeID == "" {
		return fmt.Errorf("cluster: SetNodeDrainState requires non-empty nodeID")
	}
	return a.applyCommand(ctx, command{Op: opSetNodeDrainState, NodeID: nodeID, Drained: drained})
}

func (a *Agent) IsNodeDrained(nodeID string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), controlPlaneRequestTimeout)
	defer cancel()
	var resp DrainStateResponse
	if err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalDrainStatePath+nodeID, PublicInternalDrainStatePath+nodeID, nil, &resp); err != nil {
		a.logger.Warn("cluster agent: drain-state lookup failed", "node_id", nodeID, "err", err)
		return false
	}
	return resp.Drained
}

func (a *Agent) ApplyEncoded(ctx context.Context, payload []byte) error {
	if _, err := decodeCommand(payload); err != nil {
		return fmt.Errorf("cluster: decode forwarded command: %w", err)
	}
	return a.applyEncodedToControlPlane(ctx, payload)
}

func (a *Agent) AssertOwnership(ctx context.Context, local []LocalSandboxState) error {
	var firstErr error
	for _, st := range local {
		if st.ID == "" {
			continue
		}
		existing, ok, err := a.lookupPlacement(ctx, st.ID)
		if err != nil {
			a.logger.Warn("cluster agent: AssertOwnership placement lookup failed; skipping local row",
				"sandbox_id", st.ID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		switch {
		case !ok:
			if err := a.RecordPlacement(ctx, st.ID, st.Spec, st.Secrets); err != nil && firstErr == nil {
				firstErr = err
			}
			for port, route := range st.ExposedPorts {
				if err := a.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		case existing.Placement.OwnerNodeID == a.nodeID && !existing.Placement.IsOrphaned():
			if existing.Placement.Spec == nil && st.Spec != nil {
				if err := a.UpsertSpec(ctx, st.ID, st.Spec, st.Secrets); err != nil && firstErr == nil {
					firstErr = err
				}
			}
			for port, route := range st.ExposedPorts {
				if err := a.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		case placementCanBeClaimedBy(existing.Placement, a.nodeID):
			if err := a.ClaimOrphan(ctx, st.ID, st.Spec, st.Secrets); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			for port, route := range st.ExposedPorts {
				if err := a.AddExposedPort(ctx, st.ID, port, route); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		default:
			a.logger.Warn("cluster agent: local sandbox row is stale or non-claimable; leaving FSM alone",
				"sandbox_id", st.ID,
				"fsm_owner", existing.Placement.OwnerNodeID,
				"owner_state", existing.Placement.OwnerState,
				"orphaned_owner", existing.Placement.OrphanedOwnerNodeID,
				"self", a.nodeID,
				"placement_version", existing.Placement.Version,
			)
		}
	}
	return firstErr
}

func (a *Agent) ForwardHTTP(target Endpoint, w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Cluster-Forwarded") == "1" {
		http.Error(w, "cluster: forwarding loop detected", http.StatusMisdirectedRequest)
		return
	}
	if a.mtlsProxies != nil && target.InternalURL != "" {
		serveProxy(a.mtlsProxies, target.InternalURL, w, r)
		return
	}
	if target.APIURL == "" {
		http.Error(w, "cluster: peer API URL unknown", http.StatusServiceUnavailable)
		return
	}
	serveProxy(a.publicProxies, target.APIURL, w, r)
}

func (a *Agent) AttachInternalHandler(h http.Handler) {
	if a.internalServer == nil {
		return
	}
	a.internalServer.SetExtraHandler(h)
}

func (a *Agent) Members() []Member {
	if a.gossip == nil {
		return nil
	}
	return a.gossip.members()
}

func (a *Agent) Placements() []Placement {
	return a.PlacementsForShards(PlacementShardFilter{})
}

func (a *Agent) PlacementsForShards(filter PlacementShardFilter) []Placement {
	filter = filter.Normalize()
	ctx, cancel := context.WithTimeout(context.Background(), controlPlanePlacementRequestTimeout)
	defer cancel()
	var out []Placement
	if filter.allShards() {
		if err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalPlacementsPath, PublicInternalPlacementsPath, nil, &out); err != nil {
			a.logger.Warn("cluster agent: placements lookup failed; using cached placement view", "err", err)
			return a.cachedPlacementsForShards(filter)
		}
	} else if err := a.doControlPlaneJSON(ctx, http.MethodPost, PublicInternalPlacementsQueryPath, PublicInternalPlacementsQueryPath, filter, &out); err != nil {
		a.logger.Warn("cluster agent: shard placement lookup failed; using cached shard view", "err", err, "shards", len(filter.Shards))
		return a.cachedPlacementsForShards(filter)
	}
	a.cacheMu.Lock()
	if filter.allShards() {
		a.placementCache = clonePlacements(out)
	}
	if a.shardCache == nil {
		a.shardCache = make(map[string][]Placement)
	}
	a.shardCache[placementShardFilterCacheKey(filter)] = clonePlacements(out)
	a.cacheMu.Unlock()
	return out
}

func (a *Agent) PlacementPage(req PlacementPageRequest) PlacementPageResponse {
	req = req.Normalize()
	ctx, cancel := context.WithTimeout(context.Background(), controlPlanePlacementRequestTimeout)
	defer cancel()
	var out PlacementPageResponse
	if err := a.doControlPlaneJSON(ctx, http.MethodPost, PublicInternalPlacementsPagePath, PublicInternalPlacementsPagePath, req, &out); err != nil {
		a.logger.Warn("cluster agent: placement page lookup failed", "err", err, "limit", req.Limit, "page_token", req.PageToken)
		return PlacementPageResponse{}
	}
	return out
}

func (a *Agent) PlacementOf(sandboxID string) (Placement, bool) {
	lookup, ok, err := a.lookupPlacement(context.Background(), sandboxID)
	if err != nil || !ok {
		return Placement{}, false
	}
	return lookup.Placement, true
}

func (a *Agent) PlacementVersion() uint64 {
	var max uint64
	for _, p := range a.Placements() {
		if p.Version > max {
			max = p.Version
		}
	}
	return max
}

func (a *Agent) SubscribePlacement(context.Context) <-chan struct{} { return nil }

func (a *Agent) Leader() string {
	ctx, cancel := context.WithTimeout(context.Background(), controlPlaneRequestTimeout)
	defer cancel()
	var resp map[string]string
	if err := a.doControlPlaneJSON(ctx, http.MethodGet, PublicInternalClusterLeaderPath, PublicInternalClusterLeaderPath, nil, &resp); err != nil {
		return ""
	}
	return resp["leader"]
}

func (a *Agent) Close() error {
	var firstErr error
	if a.gossip != nil {
		if err := a.gossip.Close(); err != nil {
			firstErr = fmt.Errorf("cluster agent: gossip close: %w", err)
		}
	}
	if a.internalServer != nil {
		if err := a.internalServer.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("cluster agent: internal server close: %w", err)
		}
	}
	return firstErr
}

func (a *Agent) lookupPlacement(ctx context.Context, sandboxID string) (PlacementLookupResponse, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, controlPlaneRequestTimeout)
	defer cancel()
	var lookup PlacementLookupResponse
	err := a.doControlPlaneJSON(reqCtx, http.MethodGet, PublicInternalPlacementPath+sandboxID, PublicInternalPlacementPath+sandboxID, nil, &lookup)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return PlacementLookupResponse{}, false, nil
		}
		return PlacementLookupResponse{}, false, err
	}
	return lookup, true, nil
}

func (a *Agent) applyCommand(ctx context.Context, cmd command) error {
	payload, err := encodeCommand(cmd)
	if err != nil {
		return fmt.Errorf("cluster: encode command: %w", err)
	}
	return a.applyEncodedToControlPlane(ctx, payload)
}

func (a *Agent) applyEncodedToControlPlane(ctx context.Context, payload []byte) error {
	return a.doControlPlaneBytes(ctx, http.MethodPost, PublicInternalApplyPath, InternalAPIPath, payload, nil)
}

func (a *Agent) doControlPlaneJSON(ctx context.Context, method, publicPath, internalPath string, in any, out any) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	return a.doControlPlaneBytes(ctx, method, publicPath, internalPath, body, out)
}

func (a *Agent) doControlPlaneBytes(ctx context.Context, method, publicPath, internalPath string, body []byte, out any) error {
	members := a.controlPlaneMembers()
	if len(members) == 0 {
		return errors.New("cluster agent: no live server-role control-plane members")
	}
	var firstErr error
	for _, m := range members {
		err := a.tryControlPlaneMember(ctx, m, method, publicPath, internalPath, body, out)
		if err == nil {
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if isStatus(err, http.StatusServiceUnavailable) || errors.Is(err, ErrNotLeader) {
			continue
		}
		return err
	}
	if firstErr != nil {
		return firstErr
	}
	return ErrNotLeader
}

func (a *Agent) tryControlPlaneMember(ctx context.Context, m Member, method, publicPath, internalPath string, body []byte, out any) error {
	if a.internalClient != nil && m.InternalURL != "" {
		err := a.doHTTPRequest(ctx, a.internalClient, strings.TrimRight(m.InternalURL, "/")+internalPath, method, body, out)
		if err == nil {
			return nil
		}
		if !isStatus(err, http.StatusServiceUnavailable) {
			return err
		}
		return err
	}
	if m.APIURL == "" {
		return errors.New("cluster agent: server API URL unknown for " + m.NodeID)
	}
	return a.doHTTPRequest(ctx, a.httpClient, strings.TrimRight(m.APIURL, "/")+publicPath, method, body, out)
}

func (a *Agent) doHTTPRequest(ctx context.Context, client *http.Client, endpoint, method string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.patToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.patToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if resp.StatusCode == http.StatusServiceUnavailable && strings.Contains(string(msg), ErrNotLeader.Error()) {
			return ErrNotLeader
		}
		return statusError{status: resp.StatusCode, message: strings.TrimSpace(string(msg))}
	}
	if out == nil {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a *Agent) controlPlaneMembers() []Member {
	if a.gossip == nil {
		return nil
	}
	var out []Member
	for _, m := range a.gossip.members() {
		if m.NodeID == "" || m.NodeID == a.nodeID || !m.Alive {
			continue
		}
		if !CanServeControlPlaneRole(m.Role) {
			continue
		}
		if m.APIURL == "" && m.InternalURL == "" {
			continue
		}
		out = append(out, m)
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func (a *Agent) cachedPlacements() []Placement {
	return a.cachedPlacementsForShards(PlacementShardFilter{})
}

func (a *Agent) cachedPlacementsForShards(filter PlacementShardFilter) []Placement {
	filter = filter.Normalize()
	a.cacheMu.RLock()
	defer a.cacheMu.RUnlock()
	if filter.allShards() {
		return clonePlacements(a.placementCache)
	}
	if cached, ok := a.shardCache[placementShardFilterCacheKey(filter)]; ok {
		return clonePlacements(cached)
	}
	return clonePlacements(a.placementCache)
}

func placementShardFilterCacheKey(filter PlacementShardFilter) string {
	filter = filter.Normalize()
	var b strings.Builder
	b.WriteString(strconv.Itoa(filter.ShardCount))
	b.WriteByte(':')
	for i, shard := range filter.Shards {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(shard))
	}
	return b.String()
}

type statusError struct {
	status  int
	message string
}

func (e statusError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("cluster control-plane request failed with status %d", e.status)
	}
	return fmt.Sprintf("cluster control-plane request failed with status %d: %s", e.status, e.message)
}

func isStatus(err error, status int) bool {
	var se statusError
	return errors.As(err, &se) && se.status == status
}

func clonePlacements(in []Placement) []Placement {
	if len(in) == 0 {
		return nil
	}
	out := make([]Placement, len(in))
	for i := range in {
		out[i] = clonePlacement(in[i])
	}
	return out
}
