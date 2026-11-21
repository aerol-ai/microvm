// Package rootd is the root helper's server (plans/security-gaps-m1-m4.md
// §3.3): one gRPC server on one Unix socket, carrying the helper's own
// versioned API (rootdpb) and, for every other call, containerd's API
// behind the gate (internal/rootd/gate).
//
// One listener means one peer check (eng review D3). On every connection
// the helper reads SO_PEERCRED and refuses any uid but the agent's, so the
// helper's calls and containerd's API cannot drift apart on who may use
// them. The socket is 0660 to root and the agent's group, so the
// filesystem turns everyone else away before that.
//
// Calls run in parallel, each on the goroutine gRPC gives it (eng review
// D11). Calls that name one object, a container's files or a network
// namespace, take that object's lock (keyedLocks), so calls for one
// sandbox run one at a time and in order; calls for different sandboxes
// never wait on each other, and what they share keeps only its own locks.
//
// Under the runtime supervisor the socket is the supervisor's, passed down
// (Options.Listener), and one helper hands it to the next on a signed swap
// (eng review D4). The handover is exclusive (outside review O6): Shutdown
// stops accepting and lets every call in flight finish, and the
// supervisor starts the next helper only once this one, and every process
// it started, has exited (its cgroup is empty, internal/supervisor
// HelperGroup), so two helpers never serve at once and a late call from
// the old one cannot undo the new one's work for the same sandbox.
//
// Nothing runs this yet: cmd/aerolvm-rootd is the binary, and the agent
// moves onto it in a later PR (task T4).
package rootd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/version"
)

// Refusal is one refused connection or call. It has the gate's shape
// (gate.Refusal converts to it), so one callback hears both.
type Refusal struct {
	// Method is the full gRPC method, or MethodConnect.
	Method string
	// Reason is a short, stable code, fit for a metric label.
	Reason string
	// Detail says what broke the rule.
	Detail string
}

// A connection the peer check refuses never gets as far as a call.
const (
	MethodConnect = "connect"
	ReasonPeer    = "peer_not_allowed"
)

// RefusalFunc hears every refusal. Calls arrive in parallel.
type RefusalFunc func(ctx context.Context, r Refusal)

// LogRefusal logs each refusal: the helper's own record of it. A refusal
// should never happen, since the agent only sends what its own code built,
// so each one means drift or a compromised agent (eng review D9).
//
// The agent records every refusal it is answered with (internal/rootclient:
// an audit event, and aerolvm_rootd_refusals_total, which the alert reads),
// but an agent someone controls can drop its own record, and answer its
// caller as it likes. This line it cannot touch: the helper writes it as
// root to its own output, which is the runtime container's log on
// Kubernetes (the supervisor starts the helper there and passes its output
// on) and the aerolvm-rootd unit's journal on a VM, both out of the
// agent's reach. It is also the only record of a peer refusal, a process
// other than the agent, which the agent never hears of.
// refusals_since_start lets the latest line alone say how many there were;
// there is no listener to read a counter from, on purpose (no new root
// surface).
func LogRefusal(log *slog.Logger) RefusalFunc {
	var count atomic.Uint64
	return func(_ context.Context, r Refusal) {
		log.Error("root helper refused", "call", rootdpb.CallName(r.Method), "method", r.Method, "reason", r.Reason,
			"detail", r.Detail, "refusals_since_start", count.Add(1))
	}
}

// Options are the parts of the server that are not config.
type Options struct {
	// Containerd serves every call that is not the helper's own: the gate.
	Containerd grpc.StreamHandler
	// ServerOptions go to the gRPC server first (the gate's message size
	// limits). The server's own unknown-service handler comes after them,
	// so it replaces any they set; it hands such calls to Containerd.
	ServerOptions []grpc.ServerOption
	// Peer vets each connection. Nil means egress.UnixPeerCheck for the
	// agent's uid and cgroup, which exists on Linux only.
	Peer egress.PeerCheck
	// OnRefusal hears every connection the peer check refuses. Nil logs it.
	OnRefusal RefusalFunc
	// Listener, when set, is the socket to serve: the supervisor's,
	// inherited (rootswap.InheritedListener). The server then neither
	// makes the socket nor removes it: the supervisor keeps it, and the
	// next helper serves it. Nil: the server makes its own (listen).
	Listener *net.UnixListener
	// Network does the network calls' kernel and CNI work. Nil: the
	// helper's own, opened from Config.Network on the first network call
	// (openNetwork); with no Config.Network either, the helper serves no
	// network call.
	Network NetworkHost
}

// Server is the helper's socket and gRPC server.
type Server struct {
	cfg        Config
	log        *slog.Logger
	files      *files
	srv        *grpc.Server
	ln         *net.UnixListener
	sock       os.FileInfo // the socket file this server made; nil when inherited
	containerd grpc.StreamHandler
	onRefusal  RefusalFunc
	stopOnce   sync.Once

	// endless are the cancels of calls in flight that only their caller
	// ends (endlessCalls); draining is set once Shutdown began.
	endlessMu sync.Mutex
	endless   map[*grpc.ServerStream]context.CancelFunc
	draining  bool
}

// New makes the socket and the server. Serve starts serving.
func New(cfg Config, opts Options, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if opts.Containerd == nil {
		return nil, errors.New("root helper: a containerd handler (the gate) is required")
	}
	peer := opts.Peer
	if peer == nil {
		if !havePeerCred {
			// egress.UnixPeerCheck lets everyone in off Linux.
			return nil, errors.New("root helper: no SO_PEERCRED here; the helper runs on Linux only")
		}
		peer = egress.UnixPeerCheck([]uint32{cfg.AgentUID}, cfg.AgentCgroup)
	}
	s := &Server{cfg: cfg, log: log, containerd: opts.Containerd, onRefusal: opts.OnRefusal,
		endless: map[*grpc.ServerStream]context.CancelFunc{}}
	if s.onRefusal == nil {
		s.onRefusal = LogRefusal(log)
	}
	// The helper's folders come before the socket: a layout someone else
	// can write stops the helper before any agent reaches it.
	f, err := openFiles(cfg)
	if err != nil {
		return nil, err
	}
	ln, sock := opts.Listener, os.FileInfo(nil)
	if ln == nil {
		if ln, sock, err = listen(cfg.Socket, cfg.SocketGID); err != nil {
			f.close()
			return nil, err
		}
	}
	s.files, s.ln, s.sock = f, ln, sock
	sopts := append(slices.Clone(opts.ServerOptions),
		grpc.Creds(peerCreds{check: peer, refused: s.peerRefused}),
		grpc.UnknownServiceHandler(s.route),
		grpc.ChainUnaryInterceptor(answeredUnary),
		grpc.ChainStreamInterceptor(answeredStream, s.endOnDrain))
	s.srv = grpc.NewServer(sopts...)
	locks := &keyedLocks{}
	rootdpb.RegisterRootHelperServer(s.srv, helper{log: log, files: f, onRefusal: s.onRefusal, locks: locks,
		net: newNetwork(cfg, opts.Network, locks)})
	return s, nil
}

// Serve serves until Shutdown. It returns nil after a Shutdown, also one
// that came first.
func (s *Server) Serve() error {
	if err := s.srv.Serve(s.ln); !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// Shutdown stops taking connections and waits for calls in flight until
// ctx ends, then cuts the rest. Calls that only their caller ends
// (containerd's event subscription) are ended first, at once: waiting for
// them would hold every swap to its deadline while the agent's other
// calls wait for the next helper. It removes the socket if it is one this
// server made.
func (s *Server) Shutdown(ctx context.Context) {
	s.stopOnce.Do(func() {
		s.endEndless()
		done := make(chan struct{})
		go func() {
			s.srv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			s.srv.Stop()
			<-done
		}
		_ = s.ln.Close() // Serve may never have run, and only it closes the listener
		if s.sock != nil {
			if cur, err := os.Lstat(s.cfg.Socket); err == nil && os.SameFile(cur, s.sock) {
				_ = os.Remove(s.cfg.Socket)
			}
		}
		// No call is left running to use the folders closed here: done
		// waits, in both cases above, for GracefulStop, which returns only
		// after every handler has.
		s.files.close()
	})
}

// endlessCalls end only when their caller ends them: the agent's
// containerd event subscription. Ending one is safe for the helper: it is
// a read, and the agent subscribes again, to the next helper. Unlike a
// containerd restart, containerd keeps sending events while the agent has
// no subscription, and none is replayed, so the agent must check its
// tasks' states once it has subscribed again (its split-mode wiring).
var endlessCalls = map[string]bool{"/containerd.services.events.v1.Events/Subscribe": true}

// endOnDrain gives each endless call a cancel that Shutdown uses, and
// turns one away once Shutdown has begun.
func (s *Server) endOnDrain(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if !endlessCalls[info.FullMethod] {
		return h(srv, ss)
	}
	ctx, cancel := context.WithCancel(ss.Context())
	defer cancel()
	key := &ss
	s.endlessMu.Lock()
	if s.draining {
		s.endlessMu.Unlock()
		return status.Error(codes.Unavailable, "root helper is stopping")
	}
	s.endless[key] = cancel
	s.endlessMu.Unlock()
	defer func() {
		s.endlessMu.Lock()
		delete(s.endless, key)
		s.endlessMu.Unlock()
	}()
	return h(srv, contextStream{ServerStream: ss, ctx: ctx})
}

// endEndless ends every endless call in flight, and any that starts after.
func (s *Server) endEndless() {
	s.endlessMu.Lock()
	defer s.endlessMu.Unlock()
	s.draining = true
	for _, cancel := range s.endless {
		cancel()
	}
}

// contextStream is a stream with a context of the server's own.
type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (c contextStream) Context() context.Context { return c.ctx }

// answered is the trailer that says this server handled the call
// (rootdpb.AnsweredTrailer), so the agent can tell containerd's own
// Unavailable, passed on by the gate, from a helper it could not reach.
var answered = metadata.Pairs(rootdpb.AnsweredTrailer, "1")

func answeredUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	_ = grpc.SetTrailer(ctx, answered)
	return h(ctx, req)
}

// answeredStream covers the gate too: gRPC runs stream interceptors for
// the unknown-service handler.
func answeredStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	ss.SetTrailer(answered)
	return h(srv, ss)
}

func (s *Server) peerRefused(err error) {
	s.onRefusal(context.Background(), Refusal{Method: MethodConnect, Reason: ReasonPeer, Detail: err.Error()})
}

// route takes every call no registered service has. One in the helper's
// own API is a call this helper is too old for: Unimplemented, which the
// agent reads as "the helper lacks this". Handing it to the gate instead
// would count a version skew as a hostile call and page someone.
func (s *Server) route(srv any, ss grpc.ServerStream) error {
	name, _ := grpc.MethodFromServerStream(ss)
	if strings.HasPrefix(name, rootdpb.ServicePrefix) {
		return status.Errorf(codes.Unimplemented, "root helper %s (API %d) has no call %s", version.Version, rootdpb.APIVersion, name)
	}
	return s.containerd(srv, ss)
}

// features is what this helper implements, as Version lists it. A call
// joins when it is built; until then the agent refuses it before asking.
var features = []string{
	rootdpb.FeatureEnsureHostFiles,
	rootdpb.FeatureEnsureTaskFIFOs,
	rootdpb.FeatureEnsureRunscConfig,
	rootdpb.FeatureEnsureReadySocket,
	rootdpb.FeatureRemoveContainerFiles,
}

// helper is the helper's own API.
type helper struct {
	rootdpb.UnimplementedRootHelperServer
	log       *slog.Logger
	files     *files
	onRefusal RefusalFunc
	locks     *keyedLocks
	// net serves the network calls; nil when this helper has no network
	// configuration (tests), and then it lists none of them.
	net *network
}

func (h helper) Version(_ context.Context, req *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	h.log.Info("root helper: agent handshake", "agent_version", req.GetAgentVersion(), "agent_api", req.GetAgentApi(),
		"helper_version", version.Version, "helper_api", rootdpb.APIVersion)
	served := slices.Clone(features)
	if h.net != nil {
		served = append(served, networkFeatures...)
	}
	return &rootdpb.VersionResponse{HelperVersion: version.Version, Api: rootdpb.APIVersion, Features: served}, nil
}

// containerKey is the per-object lock key of a container's files (D11).
func containerKey(id string) string { return "container/" + id }

func (helper) EnsureHost(context.Context, *rootdpb.EnsureHostRequest) (*rootdpb.EnsureHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "root helper %s: EnsureHost is not built yet", version.Version)
}

func (h helper) EnsureHostFiles(ctx context.Context, req *rootdpb.EnsureHostFilesRequest) (*rootdpb.EnsureHostFilesResponse, error) {
	unlock := h.locks.lock(containerKey(req.GetContainerId()))
	resp, err := h.files.ensureHostFiles(req)
	unlock()
	return answer(ctx, h, rootdpb.RootHelper_EnsureHostFiles_FullMethodName, resp, err)
}

func (h helper) EnsureTaskFIFOs(ctx context.Context, req *rootdpb.EnsureTaskFIFOsRequest) (*rootdpb.EnsureTaskFIFOsResponse, error) {
	unlock := h.locks.lock(containerKey(req.GetContainerId()))
	resp, err := h.files.ensureTaskFIFOs(req)
	unlock()
	return answer(ctx, h, rootdpb.RootHelper_EnsureTaskFIFOs_FullMethodName, resp, err)
}

func (h helper) EnsureRunscConfig(ctx context.Context, req *rootdpb.EnsureRunscConfigRequest) (*rootdpb.EnsureRunscConfigResponse, error) {
	resp, err := h.files.ensureRunscConfig(req)
	return answer(ctx, h, rootdpb.RootHelper_EnsureRunscConfig_FullMethodName, resp, err)
}

func (h helper) EnsureReadySocket(ctx context.Context, req *rootdpb.EnsureReadySocketRequest) (*rootdpb.EnsureReadySocketResponse, error) {
	unlock := h.locks.lock(containerKey(req.GetContainerId()))
	resp, err := h.files.ensureReadySocket(req)
	unlock()
	return answer(ctx, h, rootdpb.RootHelper_EnsureReadySocket_FullMethodName, resp, err)
}

func (h helper) RemoveContainerFiles(ctx context.Context, req *rootdpb.RemoveContainerFilesRequest) (*rootdpb.RemoveContainerFilesResponse, error) {
	unlock := h.locks.lock(containerKey(req.GetContainerId()))
	resp, err := h.files.removeContainerFiles(req)
	unlock()
	return answer(ctx, h, rootdpb.RootHelper_RemoveContainerFiles_FullMethodName, resp, err)
}

func (h helper) EnsureHostNetwork(ctx context.Context, _ *rootdpb.EnsureHostNetworkRequest) (*rootdpb.EnsureHostNetworkResponse, error) {
	if h.net == nil {
		return nil, noNetwork(rootdpb.FeatureEnsureHostNetwork)
	}
	resp, err := h.net.ensureHost()
	return answer(ctx, h, rootdpb.RootHelper_EnsureHostNetwork_FullMethodName, resp, err)
}

func (h helper) RealizeNetns(ctx context.Context, req *rootdpb.RealizeNetnsRequest) (*rootdpb.RealizeNetnsResponse, error) {
	if h.net == nil {
		return nil, noNetwork(rootdpb.FeatureRealizeNetns)
	}
	resp, err := h.net.realize(ctx, req)
	return answer(ctx, h, rootdpb.RootHelper_RealizeNetns_FullMethodName, resp, err)
}

func (h helper) RemoveNetns(ctx context.Context, req *rootdpb.RemoveNetnsRequest) (*rootdpb.RemoveNetnsResponse, error) {
	if h.net == nil {
		return nil, noNetwork(rootdpb.FeatureRemoveNetns)
	}
	resp, err := h.net.remove(ctx, req)
	return answer(ctx, h, rootdpb.RootHelper_RemoveNetns_FullMethodName, resp, err)
}

func (h helper) DisableNetnsIPv6(ctx context.Context, req *rootdpb.DisableNetnsIPv6Request) (*rootdpb.DisableNetnsIPv6Response, error) {
	if h.net == nil {
		return nil, noNetwork(rootdpb.FeatureDisableNetnsIPv6)
	}
	resp, err := h.net.disableIPv6(req)
	return answer(ctx, h, rootdpb.RootHelper_DisableNetnsIPv6_FullMethodName, resp, err)
}

func (h helper) NetnsAddrs(ctx context.Context, req *rootdpb.NetnsAddrsRequest) (*rootdpb.NetnsAddrsResponse, error) {
	if h.net == nil {
		return nil, noNetwork(rootdpb.FeatureNetnsAddrs)
	}
	resp, err := h.net.addrs(req)
	return answer(ctx, h, rootdpb.RootHelper_NetnsAddrs_FullMethodName, resp, err)
}

// noNetwork answers a network call on a helper with no network
// configuration as one it lacks, which is what Version told the agent.
func noNetwork(call string) error {
	return status.Errorf(codes.Unimplemented, "root helper %s: %s needs a CNI configuration this helper was not given", version.Version, call)
}

// answer turns a call's error into its status. A refused request is
// reported (the agent only sends what its own code built, so each refusal
// means drift or a broken agent) and keeps its own code, with its reason
// as a rootdpb.HelperRefused detail for the agent to record; any other
// failure is the helper's, logged here and answered Internal.
func answer[T any](ctx context.Context, h helper, method string, resp T, err error) (T, error) {
	var zero T
	var fe *fileError
	switch {
	case err == nil:
		return resp, nil
	case errors.As(err, &fe):
		if fe.reason == "" {
			return zero, status.Error(fe.code, fe.msg)
		}
		h.onRefusal(ctx, Refusal{Method: method, Reason: fe.reason, Detail: fe.msg})
		return zero, rootdpb.Refused(fe.code, fe.reason, fe.msg)
	}
	h.log.Error("root helper: call failed", "call", method, "error", err)
	return zero, status.Error(codes.Internal, err.Error())
}
