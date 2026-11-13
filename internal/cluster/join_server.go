package cluster

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// The join listener (plans/kubectl-style-cluster-ops.md eng D3): its own
// port, 7003, on server nodes only. It presents this server's node cert
// (signed by the cluster CA, which is what --ca-cert-hash pins), asks for no
// client cert, and serves exactly three paths. 7002 is untouched and keeps
// demanding a client cert on every connection, so nothing there can be
// reached without one.
//
// Every call is rate-limited per source address, and every call that passes
// the limiter is audited, success or failure. A refused-by-limit call is
// counted (aerolvm_join_attempts_total{reason="rate_limited"}) but not
// audited, so a spray cannot fill the audit log.

// joinService is what the listener calls; *Cluster implements it.
type joinService interface {
	ClusterInfo(tokenID string) (ClusterInfo, error)
	Join(ctx context.Context, req JoinRequest, source netip.Addr) (JoinResponse, error)
	JoinPreflight(ctx context.Context, req PreflightRequest, source netip.Addr) (PreflightResponse, error)
	JoinByCert(ctx context.Context, leaf *x509.Certificate, req JoinByCertRequest, source netip.Addr) (JoinResponse, error)
}

// Limits on the join listener.
const (
	// joinRatePerSecond / joinRateBurst: per source address. A NAT gateway
	// in front of an autoscaling group shares one address, so the burst
	// fits a scale-out step; a token sprayer still gets ~1 guess a second.
	joinRatePerSecond = 1
	joinRateBurst     = 20
	// joinRateMaxSources bounds the limiter's memory. Past it the source
	// seen longest ago is forgotten (it gets a fresh bucket if it comes
	// back) instead of refusing the new one: refusing let anyone holding
	// many addresses lock every real joiner out (J13).
	joinRateMaxSources = 10_000
	joinRateIdle       = 10 * time.Minute
	// joinRateIPv6Prefix groups IPv6 sources: one host or site is handed
	// at least a /64, so a bucket per address would give it 2^64 buckets.
	joinRateIPv6Prefix = 64
	// joinMaxBody caps a join body: a CSR and a token are a few KiB.
	joinMaxBody = 64 << 10
	// joinRequestTimeout bounds one join, dial-back and Raft write included.
	joinRequestTimeout = 30 * time.Second
)

// JoinAuditEvent is one join call for the audit log. It never carries the
// token's secret: only its public id.
type JoinAuditEvent struct {
	Route   string
	Result  string // "success" or "failure"
	Reason  string
	Source  string
	TokenID string
	NodeID  string
	Role    string
}

// JoinAuditRecorder is the optional half of SandboxRecreator that writes
// join records (internal/service). Like FailoverRefusalRecorder, the
// cluster package only calls it.
type JoinAuditRecorder interface {
	RecordClusterJoin(JoinAuditEvent)
}

type joinServer struct {
	srv      *http.Server
	listener net.Listener
	svc      joinService
	limiter  *joinRateLimiter
	audit    func(JoinAuditEvent)
	logger   *slog.Logger
}

// joinTLSConfig serves this node's cert and asks for no client cert. In
// external-CA mode it verifies one when given, against the bank's CA: a
// join by certificate is that certificate (JoinByCertPath), and a caller
// with none still reaches the token paths, which refuse in that mode.
func joinTLSConfig(ct *ClusterTLS, externalCA bool) *tls.Config {
	cfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return ct.certificateForHandshake()
		},
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS12,
	}
	if externalCA {
		cfg.ClientAuth, cfg.ClientCAs = tls.VerifyClientCertIfGiven, ct.caPool
	}
	return cfg
}

// startJoinServer binds addr and serves the join paths.
func startJoinServer(addr string, ct *ClusterTLS, svc joinService, audit func(JoinAuditEvent), logger *slog.Logger) (*joinServer, error) {
	return startJoinServerMode(addr, ct, svc, audit, logger, false)
}

// startJoinServerMode is startJoinServer, in external-CA mode or not.
func startJoinServerMode(addr string, ct *ClusterTLS, svc joinService, audit func(JoinAuditEvent), logger *slog.Logger, externalCA bool) (*joinServer, error) {
	if ct == nil {
		return nil, errors.New("cluster join server: TLS material required")
	}
	s := &joinServer{svc: svc, limiter: newJoinRateLimiter(), audit: audit, logger: logger}
	ln, err := tls.Listen("tcp", addr, joinTLSConfig(ct, externalCA))
	if err != nil {
		return nil, fmt.Errorf("cluster join server: listen on %q: %w", addr, err)
	}
	s.listener = ln
	s.srv = &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      joinRequestTimeout + 10*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && logger != nil {
			logger.Warn("cluster join server stopped", "error", err)
		}
	}()
	if logger != nil {
		logger.Info("cluster join listener up (TLS, no client cert, join paths only)", "addr", ln.Addr().String())
	}
	return s, nil
}

// handler is the whole surface: three paths, everything else 404.
func (s *joinServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+JoinClusterInfoPath, s.limited(s.clusterInfo))
	mux.HandleFunc("POST "+JoinPath, s.limited(s.join))
	mux.HandleFunc("POST "+JoinPreflightPath, s.limited(s.preflight))
	mux.HandleFunc("POST "+JoinByCertPath, s.limited(s.joinByCert))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeJoinJSON(w, http.StatusNotFound, joinErrorBody{Reason: "not_found", Error: "not found: the join port serves only " + JoinClusterInfoPath + ", " + JoinPath + ", " + JoinPreflightPath + " and " + JoinByCertPath})
	})
	return mux
}

func (s *joinServer) Addr() string { return s.listener.Addr().String() }

// Close stops the listener, letting in-flight joins finish for up to 5 s.
func (s *joinServer) Close() error {
	if s == nil || s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// sourceAddr is the TCP peer, the only address the join path trusts: no
// proxy sits in front of 7003, so no forwarded header is read.
func sourceAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func (s *joinServer) limited(next func(http.ResponseWriter, *http.Request, netip.Addr)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		src := sourceAddr(r)
		if !src.IsValid() || !s.limiter.allow(src) {
			if r.URL.Path == JoinPath {
				recordJoinAttempt("failure", "rate_limited")
			}
			w.Header().Set("Retry-After", "1")
			writeJoinJSON(w, http.StatusTooManyRequests, joinErrorBody{Reason: "rate_limited", Error: "too many join calls from this address"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, joinMaxBody)
		next(w, r, src)
	}
}

func (s *joinServer) clusterInfo(w http.ResponseWriter, r *http.Request, src netip.Addr) {
	tokenID := strings.TrimSpace(r.URL.Query().Get("token_id"))
	ev := JoinAuditEvent{Route: JoinClusterInfoPath, Source: src.String(), TokenID: tokenID}
	if !ValidJoinTokenID(tokenID) {
		s.fail(w, ev, fmt.Errorf("%w: token_id must be the 6-character id before the dot", ErrJoinBadRequest), nil)
		return
	}
	info, err := s.svc.ClusterInfo(tokenID)
	if err != nil {
		s.fail(w, ev, err, nil)
		return
	}
	s.succeed(w, ev, info)
}

func (s *joinServer) join(w http.ResponseWriter, r *http.Request, src netip.Addr) {
	ev := JoinAuditEvent{Route: JoinPath, Source: src.String()}
	var req JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, ev, fmt.Errorf("%w: invalid JSON body", ErrJoinBadRequest), nil)
		return
	}
	ev.TokenID, ev.NodeID, ev.Role = publicTokenID(req.Token), strings.TrimSpace(req.NodeID), strings.TrimSpace(req.Role)
	ctx, cancel := context.WithTimeout(r.Context(), joinRequestTimeout)
	defer cancel()
	resp, err := s.svc.Join(ctx, req, src)
	if err != nil {
		var dbe *JoinDialBackError
		var results []DialBackResult
		if errors.As(err, &dbe) {
			results = dbe.Results
		}
		s.fail(w, ev, err, results)
		return
	}
	ev.Role = resp.Role
	if resp.Replay {
		ev.Reason = "replay"
	}
	s.succeed(w, ev, resp)
}

// joinByCert is a join by certificate: the client certificate, verified by
// the handshake against the bank's CA, is the credential.
func (s *joinServer) joinByCert(w http.ResponseWriter, r *http.Request, src netip.Addr) {
	ev := JoinAuditEvent{Route: JoinByCertPath, Source: src.String()}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		s.fail(w, ev, ErrJoinCertRequired, nil)
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	ev.NodeID = ExtractPeerNodeID(leaf)
	var req JoinByCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, ev, fmt.Errorf("%w: invalid JSON body", ErrJoinBadRequest), nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), joinRequestTimeout)
	defer cancel()
	resp, err := s.svc.JoinByCert(ctx, leaf, req, src)
	if err != nil {
		var dbe *JoinDialBackError
		var results []DialBackResult
		if errors.As(err, &dbe) {
			results = dbe.Results
		}
		s.fail(w, ev, err, results)
		return
	}
	ev.Role = resp.Role
	if resp.Replay {
		ev.Reason = "replay"
	}
	s.succeed(w, ev, resp)
}

func (s *joinServer) preflight(w http.ResponseWriter, r *http.Request, src netip.Addr) {
	ev := JoinAuditEvent{Route: JoinPreflightPath, Source: src.String()}
	var req PreflightRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, ev, fmt.Errorf("%w: invalid JSON body", ErrJoinBadRequest), nil)
		return
	}
	ev.TokenID, ev.Role, ev.NodeID = publicTokenID(req.Token), strings.TrimSpace(req.Role), strings.TrimSpace(req.NodeID)
	ctx, cancel := context.WithTimeout(r.Context(), joinRequestTimeout)
	defer cancel()
	resp, err := s.svc.JoinPreflight(ctx, req, src)
	if err != nil {
		s.fail(w, ev, err, nil)
		return
	}
	ev.Role = resp.Role
	if !resp.OK {
		ev.Reason = "dial_back"
		if resp.NodeIDInUse {
			ev.Reason = "node_id_in_use"
		}
		s.record(ev, "failure")
	} else {
		s.record(ev, "success")
	}
	writeJoinJSON(w, http.StatusOK, resp)
}

// publicTokenID is the id half of a token, for audit; never the secret.
func publicTokenID(token string) string {
	id, _, _ := strings.Cut(strings.TrimSpace(token), ".")
	if ValidJoinTokenID(id) {
		return id
	}
	return ""
}

func (s *joinServer) succeed(w http.ResponseWriter, ev JoinAuditEvent, body any) {
	if ev.Reason == "" {
		ev.Reason = "ok"
	}
	s.record(ev, "success")
	writeJoinJSON(w, http.StatusOK, body)
}

// joinErrorBody is a refusal on the join port.
type joinErrorBody struct {
	Error    string           `json:"error"`
	Reason   string           `json:"reason"`
	DialBack []DialBackResult `json:"dial_back,omitempty"`
}

func (s *joinServer) fail(w http.ResponseWriter, ev JoinAuditEvent, err error, results []DialBackResult) {
	ev.Reason = JoinReason(err)
	s.record(ev, "failure")
	writeJoinJSON(w, JoinErrorStatus(err), joinErrorBody{Error: err.Error(), Reason: ev.Reason, DialBack: results})
}

// record counts, logs and audits one call.
func (s *joinServer) record(ev JoinAuditEvent, result string) {
	ev.Result = result
	if ev.Route == JoinPath || ev.Route == JoinByCertPath {
		recordJoinAttempt(result, ev.Reason)
	}
	if s.logger != nil {
		s.logger.Info("cluster: join call", "route", ev.Route, "result", result, "reason", ev.Reason,
			"source", ev.Source, "token_id", ev.TokenID, "node_id", ev.NodeID, "role", ev.Role)
	}
	if s.audit != nil {
		s.audit(ev)
	}
}

// JoinErrorStatus maps a join refusal to its HTTP status.
func JoinErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrJoinBadRequest), errors.Is(err, ErrJoinNodeIDInvalid), errors.Is(err, ErrJoinTokenFormat),
		errors.Is(err, ErrJoinTTLInvalid):
		return http.StatusBadRequest
	case errors.Is(err, ErrJoinTokenInvalid), errors.Is(err, ErrJoinTokenExpired), errors.Is(err, ErrJoinTokenUsed),
		errors.Is(err, ErrJoinRoleMismatch), errors.Is(err, ErrJoinKeyRevoked), errors.Is(err, ErrJoinTTLNeedsWrappedCustody),
		errors.Is(err, ErrPeerNotServer):
		return http.StatusForbidden
	case errors.Is(err, ErrNodeIDInUse), errors.Is(err, ErrJoinKeyInUse), errors.Is(err, ErrClusterVersion),
		errors.Is(err, ErrRekeyConflict), errors.Is(err, ErrJoinTokenIDTaken):
		return http.StatusConflict
	case errors.Is(err, ErrJoinVersion), errors.Is(err, ErrJoinDialBack), errors.Is(err, ErrNotAdmitted),
		errors.Is(err, ErrExternalCAMode), errors.Is(err, ErrJoinByCertOff):
		return http.StatusPreconditionFailed
	case errors.Is(err, ErrJoinCertRequired):
		return http.StatusUnauthorized
	case errors.Is(err, ErrNoCASigner), errors.Is(err, ErrNotLeader):
		return http.StatusServiceUnavailable
	}
	// A worker or gateway relays join calls to a server: the server's own
	// refusal keeps its status (an external-CA cluster's 412 on a token).
	if s := ForwardedStatus(err); s != 0 {
		return s
	}
	return http.StatusInternalServerError
}

// writeJoinJSON writes one JSON answer. The cluster package can't import
// pkg/api/apihttp (it imports this package), so the join port has its own.
func writeJoinJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// joinRateLimiter is a token bucket per source: an IPv4 address, or an
// IPv6 /64. Sources sit in a list from most to least recently seen, so
// both forgetting the oldest at the cap and dropping idle ones cost no
// scan of the whole map.
type joinRateLimiter struct {
	mu      sync.Mutex
	sources map[netip.Addr]*list.Element // of *joinRateEntry
	byAge   *list.List                   // front: seen most recently
	now     func() time.Time
	limit   rate.Limit
	burst   int
	max     int
}

type joinRateEntry struct {
	key  netip.Addr
	lim  *rate.Limiter
	seen time.Time
}

func newJoinRateLimiter() *joinRateLimiter {
	return &joinRateLimiter{
		sources: map[netip.Addr]*list.Element{}, byAge: list.New(), now: time.Now,
		limit: rate.Limit(joinRatePerSecond), burst: joinRateBurst, max: joinRateMaxSources,
	}
}

// joinRateKey is the bucket a source address shares.
func joinRateKey(src netip.Addr) netip.Addr {
	src = src.Unmap()
	if src.Is4() {
		return src
	}
	return netip.PrefixFrom(src, joinRateIPv6Prefix).Masked().Addr()
}

func (l *joinRateLimiter) allow(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := joinRateKey(src)
	l.dropIdle(now)
	var e *joinRateEntry
	if el, ok := l.sources[key]; ok {
		e = el.Value.(*joinRateEntry)
		l.byAge.MoveToFront(el)
	} else {
		for l.byAge.Len() >= max(l.max, 1) {
			l.forget(l.byAge.Back())
		}
		e = &joinRateEntry{key: key, lim: rate.NewLimiter(l.limit, l.burst)}
		l.sources[key] = l.byAge.PushFront(e)
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// dropIdle forgets sources not seen for joinRateIdle: by then their
// bucket has refilled anyway.
func (l *joinRateLimiter) dropIdle(now time.Time) {
	for el := l.byAge.Back(); el != nil && now.Sub(el.Value.(*joinRateEntry).seen) >= joinRateIdle; el = l.byAge.Back() {
		l.forget(el)
	}
}

func (l *joinRateLimiter) forget(el *list.Element) {
	delete(l.sources, el.Value.(*joinRateEntry).key)
	l.byAge.Remove(el)
}
