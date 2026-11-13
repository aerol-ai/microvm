package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/kubeapi"
	"github.com/aerol-ai/microvm/internal/kubeview"
)

// The agent-sandbox API on a gateway (plans/kubernetes-v2-architecture.md
// §16, C17). With SB_AGENT_SANDBOX_API on, every ingress node of a cluster
// serves it on its own TLS listener, which the Kubernetes APIService points
// at:
//
//	placement feed ──▶ kubeview hub ──▶ kubeapi.Server ◀── kube-apiserver (front-proxy mTLS)
//	                                         │
//	                                         └──▶ this node's /v1 handler, in process (writes)
//
// Each piece that depends on the cluster around it comes up on its own: the
// listener serves health at once; requests are refused (401) until the
// cluster's front-proxy CA has been read, and answered 503 until the hub
// has its first view.

// kubeClient is what the wiring needs from the kube-apiserver.
type kubeClient interface {
	FrontProxyConfig(ctx context.Context) (*kubeapi.FrontProxy, error)
	SubjectAccessReview(ctx context.Context, u kubeapi.User, a kubeapi.Attributes) (bool, string, error)
	// The templates and warm pools, kept in the internal CRDs.
	kubeapi.ObjectStore
}

// newKubeClient is the in-cluster client; tests replace it.
var newKubeClient = func() (kubeClient, error) { return kubeapi.InClusterClient() }

// frontProxyRetry is the first wait between reads of the front-proxy CA.
var frontProxyRetry = 2 * time.Second

// frontProxyHolder authenticates with the front-proxy settings once they
// are read, and refuses until then.
type frontProxyHolder struct {
	p atomic.Pointer[kubeapi.FrontProxy]
}

func (h *frontProxyHolder) Authenticate(r *http.Request) (kubeapi.User, error) {
	fp := h.p.Load()
	if fp == nil {
		return kubeapi.User{}, kubeapi.ErrUnauthenticated
	}
	return fp.Authenticate(r)
}

// load reads the settings until it succeeds or ctx ends.
func (h *frontProxyHolder) load(ctx context.Context, kc kubeClient, logger *slog.Logger) {
	wait := frontProxyRetry
	for {
		fp, err := kc.FrontProxyConfig(ctx)
		if err == nil {
			h.p.Store(fp)
			logger.Info("agent-sandbox API: front-proxy CA loaded")
			return
		}
		logger.Warn("agent-sandbox API: cannot read the front-proxy CA yet", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, time.Minute)
	}
}

// certReloader serves the pair on disk, read again when either file changes
// (cert-manager renews it in place).
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
}

func (c *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	newest := time.Time{}
	for _, f := range []string{c.certFile, c.keyFile} {
		st, err := os.Stat(f)
		if err != nil {
			return nil, err
		}
		if st.ModTime().After(newest) {
			newest = st.ModTime()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && !newest.After(c.modTime) {
		return c.cert, nil
	}
	pair, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil // a half-written renewal: keep the last good pair
		}
		return nil, err
	}
	c.cert, c.modTime = &pair, newest
	return c.cert, nil
}

// agentSandboxTLS is the listener's TLS: the reloaded pair, and the
// front-proxy CAs a client certificate is checked against once known.
func agentSandboxTLS(certs *certReloader, fp *frontProxyHolder) *tls.Config {
	base := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := base.Clone()
		cfg.GetConfigForClient = nil
		cfg.ClientAuth = tls.RequestClientCert
		if p := fp.p.Load(); p != nil {
			cfg.ClientAuth, cfg.ClientCAs = tls.VerifyClientCertIfGiven, p.CAs
		}
		return cfg, nil
	}
	return base
}

// startAgentSandboxAPI serves the API on this node if it should, and
// returns its server (nil when it does not run here).
func startAgentSandboxAPI(ctx context.Context, cfg config.Config, c cluster.Client, backend kubeapi.Backend, logger *slog.Logger) (*http.Server, error) {
	if !cfg.AgentSandboxAPI || !cfg.EnableCluster || !cfg.IsIngress() {
		return nil, nil
	}
	feed, ok := c.(cluster.PlacementFeedWatcher)
	if !ok {
		return nil, errors.New("agent-sandbox API: this node's cluster client has no placement feed")
	}
	kc, err := newKubeClient()
	if err != nil {
		return nil, err
	}
	hub := kubeview.New(kubeview.Options{})
	if !hub.Follow(ctx, feed) {
		return nil, errors.New("agent-sandbox API: the placement feed is off (SB_INGRESS_PROXY_ROUTING=false)")
	}
	fp := &frontProxyHolder{}
	go fp.load(ctx, kc, logger)
	srv := &http.Server{
		Addr: cfg.AgentSandboxAPIAddr,
		Handler: &kubeapi.Server{
			Hub:     hub,
			Auth:    fp,
			Authz:   &kubeapi.CachedAuthorizer{Next: kubeapi.AuthorizerFunc(kc.SubjectAccessReview), TTL: 10 * time.Second},
			Backend: backend,
			Store:   kc,
			Owners:  kubeapi.OwnerMap{Explicit: cfg.AgentSandboxAPINamespaces},
		},
		TLSConfig:         agentSandboxTLS(&certReloader{certFile: cfg.AgentSandboxAPICertFile, keyFile: cfg.AgentSandboxAPIKeyFile}, fp),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("agent-sandbox API stopped", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	logger.Info("agent-sandbox API listening", "addr", cfg.AgentSandboxAPIAddr)
	return srv, nil
}
