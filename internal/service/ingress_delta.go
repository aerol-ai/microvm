package service

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

const clusterIngressFullGCInterval = time.Minute

type ingressRouteSurface string

const (
	ingressSurfaceHTTP ingressRouteSurface = "http"
	ingressSurfaceTCP  ingressRouteSurface = "tcp"
	ingressSurfaceTLS  ingressRouteSurface = "tls"
)

type ingressRouteIntent struct {
	key         string
	surface     ingressRouteSurface
	routeID     string
	fingerprint uint64
	apply       func(context.Context) error
	delete      func(context.Context) error
}

func clusterIngressShardFilter(c cluster.Client, self string) cluster.PlacementShardFilter {
	if c == nil || self == "" {
		return cluster.PlacementShardFilter{}
	}

	members := c.Members()
	ids := make([]string, 0, len(members)+1)
	seen := make(map[string]struct{}, len(members)+1)
	for _, m := range members {
		if m.NodeID == "" || !m.Alive || !cluster.CanServeIngressRole(m.Role) {
			continue
		}
		if _, ok := seen[m.NodeID]; ok {
			continue
		}
		seen[m.NodeID] = struct{}{}
		ids = append(ids, m.NodeID)
	}
	if _, ok := seen[self]; !ok {
		ids = append(ids, self)
	}
	sort.Strings(ids)
	selfIndex := -1
	for i, id := range ids {
		if id == self {
			selfIndex = i
			break
		}
	}
	if selfIndex < 0 || len(ids) == 0 {
		return cluster.PlacementShardFilter{}
	}

	shards := make([]int, 0, cluster.DefaultPlacementShardCount/len(ids)+1)
	for shard := 0; shard < cluster.DefaultPlacementShardCount; shard++ {
		if shard%len(ids) == selfIndex {
			shards = append(shards, shard)
		}
	}
	return cluster.PlacementShardFilter{
		ShardCount: cluster.DefaultPlacementShardCount,
		Shards:     shards,
	}
}

func (s *Service) buildClusterIngressIntents(placements []cluster.Placement, self string) (map[string]ingressRouteIntent, bool) {
	intents := make(map[string]ingressRouteIntent)
	needL4 := s.cfg.Domain != ""
	tlsPeerPort := l4ListenPort(s.cfg.L4TLSListen)

	for _, placement := range placements {
		p := placement
		if p.SandboxID == "" || p.OwnerNodeID == self {
			continue
		}

		ownerHost := dataPlaneHostForPlacement(p)
		if p.OwnerNodeID == "" || ownerHost == "" {
			s.addClusterIngressInFluxIntents(intents, p)
			continue
		}

		if s.cfg.Domain != "" {
			needL4 = true
			if tlsPeerPort > 0 {
				routeID := caddy.IngressSandboxSNIRouteID(p.SandboxID)
				sni := p.SandboxID + "." + s.cfg.Domain
				intents[ingressIntentKey(ingressSurfaceTLS, routeID)] = ingressRouteIntent{
					key:         ingressIntentKey(ingressSurfaceTLS, routeID),
					surface:     ingressSurfaceTLS,
					routeID:     routeID,
					fingerprint: ingressFingerprint("live-sni-sandbox", p.SandboxID, ownerHost, sni, strconv.Itoa(tlsPeerPort), strconv.FormatUint(p.Version, 10)),
					apply: func(ctx context.Context) error {
						return s.caddy.UpsertSNIPassthroughRoute(ctx, routeID, sni, ownerHost, tlsPeerPort)
					},
					delete: func(ctx context.Context) error {
						return s.caddy.DeleteRouteByID(ctx, routeID)
					},
				}
			}
		} else {
			routeID := "sandbox-" + p.SandboxID
			intents[ingressIntentKey(ingressSurfaceHTTP, routeID)] = ingressRouteIntent{
				key:         ingressIntentKey(ingressSurfaceHTTP, routeID),
				surface:     ingressSurfaceHTTP,
				routeID:     routeID,
				fingerprint: ingressFingerprint("live-http-sandbox", p.SandboxID, ownerHost, strconv.FormatUint(p.Version, 10)),
				apply: func(ctx context.Context) error {
					return s.caddy.UpsertSandboxRouteToPeer(ctx, p.SandboxID, ownerHost)
				},
				delete: func(ctx context.Context) error {
					return s.caddy.DeleteSandboxRoute(ctx, p.SandboxID)
				},
			}
		}

		for port, exposedRoute := range cluster.ExposedPortRoutesForPlacement(p) {
			port := port
			route := exposedRoute
			protocol := route.Protocol
			if protocol == "" {
				protocol = models.ExposedPortProtocolHTTP
			}
			switch protocol {
			case models.ExposedPortProtocolHTTP:
				if s.cfg.Domain != "" {
					needL4 = true
					if tlsPeerPort <= 0 {
						continue
					}
					routeID := caddy.IngressPortSNIRouteID(p.SandboxID, port)
					sni := fmt.Sprintf("%s-%d.%s", p.SandboxID, port, s.cfg.Domain)
					intents[ingressIntentKey(ingressSurfaceTLS, routeID)] = ingressRouteIntent{
						key:         ingressIntentKey(ingressSurfaceTLS, routeID),
						surface:     ingressSurfaceTLS,
						routeID:     routeID,
						fingerprint: ingressFingerprint("live-sni-port", p.SandboxID, strconv.Itoa(port), ownerHost, sni, strconv.Itoa(tlsPeerPort), strconv.FormatUint(p.Version, 10)),
						apply: func(ctx context.Context) error {
							return s.caddy.UpsertSNIPassthroughRoute(ctx, routeID, sni, ownerHost, tlsPeerPort)
						},
						delete: func(ctx context.Context) error {
							return s.caddy.DeleteRouteByID(ctx, routeID)
						},
					}
				} else {
					routeID := fmt.Sprintf("sandbox-%s-port-%d", p.SandboxID, port)
					intents[ingressIntentKey(ingressSurfaceHTTP, routeID)] = ingressRouteIntent{
						key:         ingressIntentKey(ingressSurfaceHTTP, routeID),
						surface:     ingressSurfaceHTTP,
						routeID:     routeID,
						fingerprint: ingressFingerprint("live-http-port", p.SandboxID, strconv.Itoa(port), ownerHost, strconv.FormatUint(p.Version, 10)),
						apply: func(ctx context.Context) error {
							return s.caddy.UpsertPortRouteToPeer(ctx, p.SandboxID, port, ownerHost)
						},
						delete: func(ctx context.Context) error {
							return s.caddy.DeletePortRoute(ctx, p.SandboxID, port)
						},
					}
				}
			case models.ExposedPortProtocolTCP:
				if route.HostPort <= 0 {
					s.logger.Warn("cluster ingress: tcp exposure has no replicated host port; skipping",
						"sandbox_id", p.SandboxID, "port", port, "owner", p.OwnerNodeID)
					continue
				}
				needL4 = true
				routeID := fmt.Sprintf("tcp-port-%d", route.HostPort)
				hostPort := route.HostPort
				intents[ingressIntentKey(ingressSurfaceTCP, routeID)] = ingressRouteIntent{
					key:         ingressIntentKey(ingressSurfaceTCP, routeID),
					surface:     ingressSurfaceTCP,
					routeID:     routeID,
					fingerprint: ingressFingerprint("live-tcp-port", p.SandboxID, strconv.Itoa(port), ownerHost, strconv.Itoa(hostPort), strconv.FormatUint(p.Version, 10)),
					apply: func(ctx context.Context) error {
						return s.caddy.UpsertTCPProxyRoute(ctx, p.SandboxID, port, hostPort, ownerHost, hostPort)
					},
					delete: func(ctx context.Context) error {
						return s.caddy.DeleteTCPRoute(ctx, hostPort)
					},
				}
			case models.ExposedPortProtocolTLS:
				if s.cfg.Domain == "" || tlsPeerPort <= 0 {
					continue
				}
				needL4 = true
				routeID := caddy.IngressPortSNIRouteID(p.SandboxID, port)
				sni := fmt.Sprintf("%s-%d.%s", p.SandboxID, port, s.cfg.Domain)
				intents[ingressIntentKey(ingressSurfaceTLS, routeID)] = ingressRouteIntent{
					key:         ingressIntentKey(ingressSurfaceTLS, routeID),
					surface:     ingressSurfaceTLS,
					routeID:     routeID,
					fingerprint: ingressFingerprint("live-tls-port", p.SandboxID, strconv.Itoa(port), ownerHost, sni, strconv.Itoa(tlsPeerPort), strconv.FormatUint(p.Version, 10)),
					apply: func(ctx context.Context) error {
						return s.caddy.UpsertSNIPassthroughRoute(ctx, routeID, sni, ownerHost, tlsPeerPort)
					},
					delete: func(ctx context.Context) error {
						return s.caddy.DeleteRouteByID(ctx, routeID)
					},
				}
			}
		}
	}

	return intents, needL4
}

func (s *Service) addClusterIngressInFluxIntents(intents map[string]ingressRouteIntent, p cluster.Placement) {
	routeID := caddy.InFluxSandboxRouteID(p.SandboxID)
	pCopy := p
	intents[ingressIntentKey(ingressSurfaceHTTP, routeID)] = ingressRouteIntent{
		key:         ingressIntentKey(ingressSurfaceHTTP, routeID),
		surface:     ingressSurfaceHTTP,
		routeID:     routeID,
		fingerprint: ingressFingerprint("in-flux-sandbox", p.SandboxID, strconv.FormatUint(p.Version, 10)),
		apply: func(ctx context.Context) error {
			return s.applyInFluxSandboxRoute(ctx, pCopy)
		},
		delete: func(ctx context.Context) error {
			return s.caddy.DeleteInFluxSandboxRoute(ctx, pCopy.SandboxID)
		},
	}

	for port, exposedRoute := range cluster.ExposedPortRoutesForPlacement(p) {
		port := port
		route := exposedRoute
		if route.Protocol == models.ExposedPortProtocolTCP {
			continue
		}
		routeID := caddy.InFluxPortRouteID(p.SandboxID, port)
		pCopy := p
		intents[ingressIntentKey(ingressSurfaceHTTP, routeID)] = ingressRouteIntent{
			key:         ingressIntentKey(ingressSurfaceHTTP, routeID),
			surface:     ingressSurfaceHTTP,
			routeID:     routeID,
			fingerprint: ingressFingerprint("in-flux-port", p.SandboxID, strconv.Itoa(port), strconv.FormatUint(p.Version, 10)),
			apply: func(ctx context.Context) error {
				return s.applyInFluxPortRoute(ctx, pCopy, port)
			},
			delete: func(ctx context.Context) error {
				return s.caddy.DeleteInFluxPortRoute(ctx, pCopy.SandboxID, port)
			},
		}
	}
}

func (s *Service) planClusterIngressDelta(desired map[string]ingressRouteIntent) ([]func(context.Context) error, func()) {
	s.ingressRouteMu.Lock()
	defer s.ingressRouteMu.Unlock()

	ops := make([]func(context.Context) error, 0)
	for key, intent := range desired {
		if previous, ok := s.ingressRouteCache[key]; ok && previous.fingerprint == intent.fingerprint {
			continue
		}
		ops = append(ops, intent.apply)
	}
	for key, previous := range s.ingressRouteCache {
		if _, ok := desired[key]; ok {
			continue
		}
		ops = append(ops, previous.delete)
	}

	next := make(map[string]ingressRouteIntent, len(desired))
	for key, intent := range desired {
		next[key] = intent
	}
	commit := func() {
		s.ingressRouteMu.Lock()
		defer s.ingressRouteMu.Unlock()
		s.ingressRouteCache = next
	}
	return ops, commit
}

func (s *Service) shouldRunClusterIngressFullGC() bool {
	now := time.Now().Unix()
	last := s.ingressLastFullGCUnix.Load()
	if last > 0 && now-last < int64(clusterIngressFullGCInterval.Seconds()) {
		return false
	}
	return s.ingressLastFullGCUnix.CompareAndSwap(last, now)
}

func ingressIntentKey(surface ingressRouteSurface, routeID string) string {
	return string(surface) + ":" + routeID
}

func ingressFingerprint(parts ...string) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

func expectedIngressRoutesFromIntents(intents map[string]ingressRouteIntent) (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	expectedHTTP := make(map[string]struct{})
	expectedTCPServers := make(map[string]struct{})
	expectedTLSRoutes := make(map[string]struct{})
	for _, intent := range intents {
		switch intent.surface {
		case ingressSurfaceHTTP:
			expectedHTTP[intent.routeID] = struct{}{}
		case ingressSurfaceTCP:
			expectedTCPServers[intent.routeID] = struct{}{}
		case ingressSurfaceTLS:
			expectedTLSRoutes[intent.routeID] = struct{}{}
		}
	}
	return expectedHTTP, expectedTCPServers, expectedTLSRoutes
}

func (s *Service) addLocalIngressExpectedRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes map[string]struct{}, sandboxes []*models.Sandbox) {
	for _, sb := range sandboxes {
		if sb == nil || sb.Status == models.SandboxStatusDestroyed {
			continue
		}
		expectedHTTP["sandbox-"+sb.ID] = struct{}{}
		for _, p := range sb.ExposedPorts {
			switch p.Protocol {
			case "", models.ExposedPortProtocolHTTP:
				expectedHTTP[fmt.Sprintf("sandbox-%s-port-%d", sb.ID, p.Port)] = struct{}{}
			case models.ExposedPortProtocolTCP:
				if p.HostPort > 0 {
					expectedTCPServers[fmt.Sprintf("tcp-port-%d", p.HostPort)] = struct{}{}
				}
			case models.ExposedPortProtocolTLS:
				expectedTLSRoutes[fmt.Sprintf("sandbox-%s-port-%d-tls", sb.ID, p.Port)] = struct{}{}
			}
		}
	}
}

func (s *Service) gcUnexpectedClusterIngressRoutes(ctx context.Context, desired map[string]ingressRouteIntent) error {
	if !s.caddy.Enabled() {
		return nil
	}
	expectedHTTP, expectedTCPServers, expectedTLSRoutes := expectedIngressRoutesFromIntents(desired)
	if s.store != nil {
		local, err := s.store.List(ctx)
		if err != nil {
			return fmt.Errorf("cluster ingress gc list sandboxes: %w", err)
		}
		s.addLocalIngressExpectedRoutes(expectedHTTP, expectedTCPServers, expectedTLSRoutes, local)
	}

	snap, err := s.caddy.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("cluster ingress caddy snapshot: %w", err)
	}
	var firstErr error
	for _, id := range snap.HTTPRouteIDs {
		if _, ok := expectedHTTP[id]; ok {
			continue
		}
		if err := s.caddy.DeleteRouteByID(ctx, id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, sid := range snap.L4TCPServerIDs {
		if _, ok := expectedTCPServers[sid]; ok {
			continue
		}
		if err := s.caddy.DeleteTCPServer(ctx, sid); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, id := range snap.L4TLSRouteIDs {
		if _, ok := expectedTLSRoutes[id]; ok {
			continue
		}
		if err := s.caddy.DeleteRouteByID(ctx, id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Service) applyInFluxSandboxRoute(ctx context.Context, p cluster.Placement) error {
	var firstErr error
	if s.cfg.Domain == "" {
		if err := s.caddy.DeleteSandboxRoute(ctx, p.SandboxID); err != nil {
			firstErr = err
		}
	} else {
		if err := s.caddy.DeleteRouteByID(ctx, caddy.IngressSandboxSNIRouteID(p.SandboxID)); err != nil {
			firstErr = err
		}
	}
	if err := s.caddy.UpsertInFluxSandboxRoute(ctx, p.SandboxID); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func (s *Service) applyInFluxPortRoute(ctx context.Context, p cluster.Placement, port int) error {
	var firstErr error
	if s.cfg.Domain == "" {
		if err := s.caddy.DeletePortRoute(ctx, p.SandboxID, port); err != nil {
			firstErr = err
		}
	} else {
		if err := s.caddy.DeleteRouteByID(ctx, caddy.IngressPortSNIRouteID(p.SandboxID, port)); err != nil {
			firstErr = err
		}
	}
	if err := s.caddy.UpsertInFluxPortRoute(ctx, p.SandboxID, port); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func routeShardFilterLogValue(filter cluster.PlacementShardFilter) string {
	filter = filter.Normalize()
	if len(filter.Shards) == 0 {
		return "all"
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(len(filter.Shards)))
	b.WriteString("/")
	b.WriteString(strconv.Itoa(filter.ShardCount))
	return b.String()
}
