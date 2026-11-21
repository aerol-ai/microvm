package rootclient_test

// A refusal as the API sees it (eng review D9): the helper's real server
// and its real containerd gate refuse, the agent's client records the
// refusal once with its call and reason, and the API answers 500, on
// containerd's path (through containerd's own client and its error
// conversion) and on the helper's own calls.

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	cntr "github.com/containerd/containerd/v2/client"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/gate"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
)

// heard collects both sides' records of each refusal.
type heard struct {
	mu     sync.Mutex
	agent  []rootclient.Refusal
	helper []rootd.Refusal
}

func (h *heard) onAgent(_ context.Context, r rootclient.Refusal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.agent = append(h.agent, r)
}

func (h *heard) onHelper(_ context.Context, r rootd.Refusal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.helper = append(h.helper, r)
}

func (h *heard) take() ([]rootclient.Refusal, []rootd.Refusal) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, b := h.agent, h.helper
	h.agent, h.helper = nil, nil
	return a, b
}

// gatedHelper serves the helper's real server with the real gate in front
// of a containerd no refused call ever reaches, both reporting to h.
func gatedHelper(t *testing.T, h *heard) string {
	t.Helper()
	p, cfg := helperConfig(t)
	// Nothing listens here: a call that got past the gate would fail
	// Unavailable, not be refused.
	upstream, err := grpc.NewClient("unix://"+p+".containerd", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	g, err := gate.New(gate.Config{Policy: cfg.Policy, Upstream: upstream,
		OnRefusal: func(ctx context.Context, r gate.Refusal) { h.onHelper(ctx, rootd.Refusal(r)) }})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := rootd.New(cfg, rootd.Options{Containerd: g.Handle, ServerOptions: g.ServerOptions(), OnRefusal: h.onHelper,
		Peer: egress.UnixPeerCheck([]uint32{uint32(os.Getuid())}, "")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	return p
}

func want500(t *testing.T, what string, err error) {
	t.Helper()
	cl := apihttp.Classify(err)
	if !errors.Is(err, rootclient.ErrRefused) || errors.Is(err, rootclient.ErrUnavailable) || errors.Is(err, rootclient.ErrUnsupported) ||
		cl.Status != http.StatusInternalServerError {
		t.Fatalf("%s: %v; Is ErrRefused %v, Is ErrUnavailable %v, status %d; want a 500 refusal", what, err,
			errors.Is(err, rootclient.ErrRefused), errors.Is(err, rootclient.ErrUnavailable), cl.Status)
	}
}

// TestRefusalsAre500AndRecordedOnce: one refusal is one record on each
// side, the agent's with the short call and the helper's reason, and a
// 500. A method the gate does not pass goes through containerd's error
// conversion; a call in another containerd namespace is refused on a
// stream; a value the helper's own call refuses is a typed call.
func TestRefusalsAre500AndRecordedOnce(t *testing.T) {
	h := &heard{}
	p := gatedHelper(t, h)
	c := rootclient.New(rootclient.Config{Socket: p, Timeout: time.Second, HelperUID: uint32(os.Getuid()), OnRefusal: h.onAgent})
	t.Cleanup(func() { _ = c.Close() })

	for _, tc := range []struct {
		name   string
		do     func() error
		call   string
		reason string
	}{
		{"a method the gate does not pass", func() error {
			return containerd(t, c).NamespaceService().Create(ctx5(t), "other", nil)
		}, "Namespaces.Create", gate.ReasonMethod},
		{"a stream in another namespace", func() error {
			ctr, err := cntr.New(c.Socket(), append(c.ContainerdOptions(), cntr.WithDefaultNamespace("default"))...)
			if err != nil {
				return err
			}
			defer ctr.Close()
			_, err = ctr.ContainerService().List(ctx5(t))
			return err
		}, "Containers.ListStream", gate.ReasonNamespace},
		{"a value the helper refuses", func() error {
			_, err := c.EnsureTaskFIFOs(ctx5(t), "../etc")
			return err
		}, "RootHelper.EnsureTaskFIFOs", rootd.ReasonBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want500(t, tc.name, tc.do())
			agent, helper := h.take()
			if len(agent) != 1 || agent[0] != (rootclient.Refusal{Call: tc.call, Reason: tc.reason}) {
				t.Fatalf("the agent recorded %+v, want one {%s %s}", agent, tc.call, tc.reason)
			}
			if len(helper) != 1 || helper[0].Reason != tc.reason {
				t.Fatalf("the helper recorded %+v, want one %s", helper, tc.reason)
			}
		})
	}
}
