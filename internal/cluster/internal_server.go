package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// InternalAPIPath is the URL path served by the cluster-internal mTLS
// listener. Distinct from the public /v1/cluster/internal/apply route so a
// misconfigured load balancer can't accidentally tunnel public traffic into
// the cluster-internal channel.
const InternalAPIPath = "/internal/apply"

// internalServer is the mTLS HTTPS server that accepts leader-forwarded raft
// applies AND owner-API forwards from peer nodes. The server cert + the
// required client cert are both verified against the cluster CA — possession
// of the PAT alone is no longer enough to forge an internal call, since the
// TLS handshake fails before the request body is read.
//
// Two surfaces share this listener:
//
//   - POST /internal/apply: leader-forwarded raft applies (the apply handler).
//   - everything else: delegated to the extra http.Handler installed via
//     SetExtraHandler. cmd/sandboxd wires the public v1 mux there so peers can
//     reverse-proxy owner API calls over the cert-pinned channel. Until the
//     handler is attached the listener returns 503 — peers that forwarded
//     to us mid-boot just retry on the public path.
type internalServer struct {
	srv      *http.Server
	listener net.Listener
	logger   *slog.Logger
	// extra is loaded atomically so AttachInternalHandler is lock-free for
	// the hot path (every incoming forward reads it once per request).
	extra atomic.Pointer[http.Handler]
}

// startInternalServer binds bindAddr with the cluster mTLS config and spawns
// the serve goroutine. Returns the constructed server (caller owns Close) and
// the actual bound address (useful when bindAddr used :0).
func startInternalServer(bindAddr string, ct *ClusterTLS, applyHandler func(context.Context, []byte) error, logger *slog.Logger) (*internalServer, error) {
	if ct == nil {
		return nil, errors.New("cluster internal server: TLS material required")
	}
	is := &internalServer{logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+InternalAPIPath, func(w http.ResponseWriter, r *http.Request) {
		// The TLS handshake already verified the peer cert chains to the
		// cluster CA — so we know the caller is a cluster member. We still
		// cap the body to a sane size so a misbehaving peer can't OOM us.
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if applyErr := applyHandler(r.Context(), body); applyErr != nil {
			if errors.Is(applyErr, ErrNotLeader) {
				// 503 mirrors the existing public-API leader-forward semantics:
				// the forwarder retries against a refreshed leader URL.
				http.Error(w, applyErr.Error(), http.StatusServiceUnavailable)
				return
			}
			if errors.Is(applyErr, ErrCreateBackpressure) {
				w.Header().Set("Retry-After", fmt.Sprint(CreateBackpressureRetryAfterSeconds))
				http.Error(w, applyErr.Error(), http.StatusTooManyRequests)
				return
			}
			if errors.Is(applyErr, ErrCapacityExceeded) || errors.Is(applyErr, ErrNoPlacementTarget) {
				w.Header().Set("Retry-After", fmt.Sprint(CapacityRetryAfterSeconds))
				http.Error(w, applyErr.Error(), http.StatusServiceUnavailable)
				return
			}
			http.Error(w, applyErr.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// Catch-all delegate: anything that isn't the raft-apply endpoint runs
	// through the registered extra handler. We register on "/" so the ServeMux
	// "longest prefix wins" rule still routes POST /internal/apply to the
	// dedicated handler above.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hp := is.extra.Load()
		if hp == nil || *hp == nil {
			// Boot-window: peer forwarded to us before AttachInternalHandler
			// fired. Same 503 semantics the public path uses for "not ready".
			http.Error(w, "cluster: internal API not yet attached", http.StatusServiceUnavailable)
			return
		}
		(*hp).ServeHTTP(w, r)
	})

	tlsListener, err := tls.Listen("tcp", bindAddr, ct.serverConfig())
	if err != nil {
		return nil, fmt.Errorf("cluster internal server: listen on %q: %w", bindAddr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	is.srv = srv
	is.listener = tlsListener
	go func() {
		if err := srv.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("cluster internal server stopped", "error", err)
		}
	}()
	logger.Info("cluster internal mTLS server listening", "addr", tlsListener.Addr().String())
	return is, nil
}

// SetExtraHandler installs the http.Handler used for every non-/internal/apply
// path. Safe to call concurrently with serving — the load is atomic. Pass nil
// to detach (the listener then 503s every non-apply path again).
func (s *internalServer) SetExtraHandler(h http.Handler) {
	if s == nil {
		return
	}
	if h == nil {
		s.extra.Store(nil)
		return
	}
	s.extra.Store(&h)
}

func (s *internalServer) Addr() string { return s.listener.Addr().String() }

// Close stops the listener and waits up to 5s for in-flight applies to drain.
func (s *internalServer) Close() error {
	if s == nil || s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}
