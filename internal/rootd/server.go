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
// Calls run in parallel, each on the goroutine gRPC gives it; the server
// holds no lock around a call (eng review D11).
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

// LogRefusal logs each refusal. A refusal should never happen, since the
// agent only sends what its own code built, so each one means drift or a
// compromised agent (eng review D9). The audit event, the metric and the
// alert come with task T5.
func LogRefusal(log *slog.Logger) RefusalFunc {
	return func(_ context.Context, r Refusal) {
		log.Error("root helper refused", "call", r.Method, "reason", r.Reason, "detail", r.Detail)
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
}

// Server is the helper's socket and gRPC server.
type Server struct {
	cfg        Config
	log        *slog.Logger
	files      *files
	srv        *grpc.Server
	ln         *net.UnixListener
	sock       os.FileInfo // the socket file this server made
	containerd grpc.StreamHandler
	onRefusal  RefusalFunc
	stopOnce   sync.Once
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
	s := &Server{cfg: cfg, log: log, containerd: opts.Containerd, onRefusal: opts.OnRefusal}
	if s.onRefusal == nil {
		s.onRefusal = LogRefusal(log)
	}
	// The helper's folders come before the socket: a layout someone else
	// can write stops the helper before any agent reaches it.
	f, err := openFiles(cfg)
	if err != nil {
		return nil, err
	}
	ln, sock, err := listen(cfg.Socket, cfg.SocketGID)
	if err != nil {
		f.close()
		return nil, err
	}
	s.files, s.ln, s.sock = f, ln, sock
	sopts := append(slices.Clone(opts.ServerOptions),
		grpc.Creds(peerCreds{check: peer, refused: s.peerRefused}),
		grpc.UnknownServiceHandler(s.route),
		grpc.ChainUnaryInterceptor(answeredUnary),
		grpc.ChainStreamInterceptor(answeredStream))
	s.srv = grpc.NewServer(sopts...)
	rootdpb.RegisterRootHelperServer(s.srv, helper{log: log, files: f, onRefusal: s.onRefusal})
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
// ctx ends, then cuts the rest: a stream that never ends by itself, such as
// containerd's event subscription, would otherwise hold it forever. It
// removes the socket if it is still the one this server made.
func (s *Server) Shutdown(ctx context.Context) {
	s.stopOnce.Do(func() {
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
		if cur, err := os.Lstat(s.cfg.Socket); err == nil && os.SameFile(cur, s.sock) {
			_ = os.Remove(s.cfg.Socket)
		}
		// No call is left running to use the folders closed here: done
		// waits, in both cases above, for GracefulStop, which returns only
		// after every handler has.
		s.files.close()
	})
}

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
}

func (h helper) Version(_ context.Context, req *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	h.log.Info("root helper: agent handshake", "agent_version", req.GetAgentVersion(), "agent_api", req.GetAgentApi(),
		"helper_version", version.Version, "helper_api", rootdpb.APIVersion)
	return &rootdpb.VersionResponse{HelperVersion: version.Version, Api: rootdpb.APIVersion, Features: slices.Clone(features)}, nil
}

func (helper) EnsureHost(context.Context, *rootdpb.EnsureHostRequest) (*rootdpb.EnsureHostResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "root helper %s: EnsureHost is not built yet", version.Version)
}

func (h helper) EnsureHostFiles(ctx context.Context, req *rootdpb.EnsureHostFilesRequest) (*rootdpb.EnsureHostFilesResponse, error) {
	resp, err := h.files.ensureHostFiles(req)
	return answer(ctx, h, rootdpb.RootHelper_EnsureHostFiles_FullMethodName, resp, err)
}

func (h helper) EnsureTaskFIFOs(ctx context.Context, req *rootdpb.EnsureTaskFIFOsRequest) (*rootdpb.EnsureTaskFIFOsResponse, error) {
	resp, err := h.files.ensureTaskFIFOs(req)
	return answer(ctx, h, rootdpb.RootHelper_EnsureTaskFIFOs_FullMethodName, resp, err)
}

func (h helper) EnsureRunscConfig(ctx context.Context, req *rootdpb.EnsureRunscConfigRequest) (*rootdpb.EnsureRunscConfigResponse, error) {
	resp, err := h.files.ensureRunscConfig(req)
	return answer(ctx, h, rootdpb.RootHelper_EnsureRunscConfig_FullMethodName, resp, err)
}

func (h helper) EnsureReadySocket(ctx context.Context, req *rootdpb.EnsureReadySocketRequest) (*rootdpb.EnsureReadySocketResponse, error) {
	resp, err := h.files.ensureReadySocket(req)
	return answer(ctx, h, rootdpb.RootHelper_EnsureReadySocket_FullMethodName, resp, err)
}

func (h helper) RemoveContainerFiles(ctx context.Context, req *rootdpb.RemoveContainerFilesRequest) (*rootdpb.RemoveContainerFilesResponse, error) {
	resp, err := h.files.removeContainerFiles(req)
	return answer(ctx, h, rootdpb.RootHelper_RemoveContainerFiles_FullMethodName, resp, err)
}

// answer turns a call's error into its status. A refused request is
// reported (the agent only sends what its own code built, so each refusal
// means drift or a broken agent) and keeps its own code; any other failure
// is the helper's, logged here and answered Internal.
func answer[T any](ctx context.Context, h helper, method string, resp T, err error) (T, error) {
	var zero T
	var fe *fileError
	switch {
	case err == nil:
		return resp, nil
	case errors.As(err, &fe):
		if fe.reason != "" {
			h.onRefusal(ctx, Refusal{Method: method, Reason: fe.reason, Detail: fe.msg})
		}
		return zero, status.Error(fe.code, fe.msg)
	}
	h.log.Error("root helper: call failed", "call", method, "error", err)
	return zero, status.Error(codes.Internal, err.Error())
}
