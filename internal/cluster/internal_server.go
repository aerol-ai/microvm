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
	"time"
)

// InternalAPIPath is the URL path served by the cluster-internal mTLS
// listener. Distinct from the public /v1/cluster/internal/apply route so a
// misconfigured load balancer can't accidentally tunnel public traffic into
// the cluster-internal channel.
const InternalAPIPath = "/internal/apply"

// internalServer is the mTLS HTTPS server that accepts leader-forwarded raft
// applies from peer nodes. The server cert + the required client cert are
// both verified against the cluster CA — possession of the PAT alone is no
// longer enough to forge an internal apply, since the TLS handshake fails
// before the request body is read.
type internalServer struct {
	srv      *http.Server
	listener net.Listener
	logger   *slog.Logger
}

// startInternalServer binds bindAddr with the cluster mTLS config and spawns
// the serve goroutine. Returns the constructed server (caller owns Close) and
// the actual bound address (useful when bindAddr used :0).
func startInternalServer(bindAddr string, ct *ClusterTLS, applyHandler func(context.Context, []byte) error, logger *slog.Logger) (*internalServer, error) {
	if ct == nil {
		return nil, errors.New("cluster internal server: TLS material required")
	}
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
			http.Error(w, applyErr.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	tlsListener, err := tls.Listen("tcp", bindAddr, ct.serverConfig())
	if err != nil {
		return nil, fmt.Errorf("cluster internal server: listen on %q: %w", bindAddr, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	is := &internalServer{srv: srv, listener: tlsListener, logger: logger}
	go func() {
		if err := srv.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("cluster internal server stopped", "error", err)
		}
	}()
	logger.Info("cluster internal mTLS server listening", "addr", tlsListener.Addr().String())
	return is, nil
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
