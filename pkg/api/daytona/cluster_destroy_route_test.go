package daytona

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	apiclient "github.com/daytonaio/daytona/libs/api-client-go"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A Daytona DELETE of a sandbox left on a node an operator deleted
// (clusterroute abandoned.go). A gateway or worker sends it to a server;
// the server, which has no row for it, deletes the placement and answers
// with the Sandbox body the Daytona SDKs parse.

const abandonedDeletedNode = "wkr-deleted"

// abandonedDaytonaGateway is a gateway's view of the cluster: placements,
// the name index (owner + "/" + name) and the deleted node. It may not
// delete another node's placement, so it sends such a DELETE to a server.
type abandonedDaytonaGateway struct {
	*cluster.Noop
	mu         sync.Mutex
	placements map[string]cluster.Placement
	names      map[string]string
	toServer   int
}

func newAbandonedDaytonaGateway(ps ...cluster.Placement) *abandonedDaytonaGateway {
	c := &abandonedDaytonaGateway{Noop: cluster.NewNoop("gw-1", "http://gw-1", ""),
		placements: map[string]cluster.Placement{}, names: map[string]string{}}
	for _, p := range ps {
		c.placements[p.SandboxID] = p
		if p.Name != "" {
			c.names[p.OwnerRef+"/"+p.Name] = p.SandboxID
		}
	}
	return c
}

func (c *abandonedDaytonaGateway) PlacementOf(id string) (cluster.Placement, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.placements[id]
	return p, ok
}

func (c *abandonedDaytonaGateway) OwnerOf(id string) (cluster.OwnerInfo, error) {
	p, ok := c.PlacementOf(id)
	switch {
	case !ok:
		return cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	case p.IsOrphaned():
		return cluster.OwnerInfo{}, cluster.ErrOrphaned
	}
	return cluster.OwnerInfo{NodeID: p.OwnerNodeID, APIURL: "http://" + p.OwnerNodeID}, nil
}

func (c *abandonedDaytonaGateway) OwnerOfName(owner, name string) (string, cluster.OwnerInfo, error) {
	c.mu.Lock()
	id, ok := c.names[owner+"/"+name]
	c.mu.Unlock()
	if !ok {
		return "", cluster.OwnerInfo{}, cluster.ErrUnknownSandbox
	}
	info, err := c.OwnerOf(id)
	return id, info, err
}

func (c *abandonedDaytonaGateway) IsNodeDenied(id string) bool { return id == abandonedDeletedNode }

func (c *abandonedDaytonaGateway) ForwardToServer(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	c.toServer++
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// abandonedDaytonaServer is a server: it reads the leader's placements and
// deletes an abandoned one (an exact delete of that lifetime).
type abandonedDaytonaServer struct {
	*abandonedDaytonaGateway
	deletes int
}

func (c *abandonedDaytonaServer) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := map[string]cluster.Placement{}
	for _, id := range ids {
		if p, ok := c.PlacementOf(id); ok {
			out[id] = p
		}
	}
	return out, nil
}

func (c *abandonedDaytonaServer) DeleteAbandonedPlacement(_ context.Context, p cluster.Placement) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, ok := c.placements[p.SandboxID]; ok && cur.IncarnationID == p.IncarnationID {
		delete(c.placements, p.SandboxID)
		c.deletes++
	}
	return nil
}

func abandonedDaytonaPlacement(id, name, owner string, edit func(*cluster.Placement)) cluster.Placement {
	p := cluster.Placement{
		SandboxID: id, OwnerNodeID: abandonedDeletedNode, IncarnationID: "inc-" + id, OwnerRef: owner, Name: name,
		CreatedUnix: time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC).Unix(),
		Spec: &models.CreateSandboxRequest{Image: "alpine:3.20", Name: name, CPU: 2, MemoryMB: 4096, DiskGB: 10,
			OSUser: "daytona", Tags: map[string]string{"team": "a"}},
	}
	if edit != nil {
		edit(&p)
	}
	return p
}

// abandonedDaytonaNode serves the real Daytona routes on a cluster node in
// front of c, with a store that holds no row for any sandbox. A request's
// X-Test-Owner header makes it that tenant's; with none it is the fleet
// operator's.
func abandonedDaytonaNode(t *testing.T, c cluster.Client) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{EnableCluster: true}, logger, st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(c)
	mux := http.NewServeMux()
	RegisterRoutes(mux, Deps{Service: svc, Logger: logger, Auth: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			access := controlplane.Access{Fleet: true}
			if owner := r.Header.Get("X-Test-Owner"); owner != "" {
				access = controlplane.Access{Identity: controlplane.Identity{OwnerRef: owner}}
			}
			next.ServeHTTP(w, r.WithContext(controlplane.ContextWithAccess(r.Context(), access)))
		})
	}})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// daytonaAPI is the Daytona SDK's generated client, as the SDK builds it,
// calling as owner ("" for the operator).
func daytonaAPI(srv *httptest.Server, owner string) *apiclient.APIClient {
	cfg := apiclient.NewConfiguration()
	cfg.Servers = apiclient.ServerConfigurations{{URL: srv.URL + PathPrefix}}
	cfg.HTTPClient = srv.Client()
	cfg.AddDefaultHeader("Authorization", "Bearer tok")
	if owner != "" {
		cfg.AddDefaultHeader("X-Test-Owner", owner)
	}
	return apiclient.NewAPIClient(cfg)
}

func statusOf(t *testing.T, resp *http.Response) int {
	t.Helper()
	if resp == nil {
		t.Fatal("no response")
	}
	return resp.StatusCode
}

// On a gateway the DELETE route is the delete (clusterDestroyForwardWrap,
// Destroy: true): a sandbox left on a deleted node, named by id or by the
// caller's name, goes to a server once. Any other call for it is not a
// delete: it waits (503) or is gone (410), and is never sent.
func TestDaytonaDeleteRouteSendsAnAbandonedSandboxToAServer(t *testing.T) {
	for name, edit := range map[string]func(*cluster.Placement){
		"still on the deleted node": nil,
		"orphaned from the deleted node": func(p *cluster.Placement) {
			p.OwnerNodeID, p.OwnerState, p.OrphanedOwnerNodeID = "", cluster.PlacementOwnerStateOrphaned, abandonedDeletedNode
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newAbandonedDaytonaGateway(abandonedDaytonaPlacement("sb-gone-1", "web", "acct-a", edit))
			srv := abandonedDaytonaNode(t, c)
			for i, ref := range []string{"sb-gone-1", "web"} {
				_, resp, _ := daytonaAPI(srv, "acct-a").SandboxAPI.DeleteSandbox(context.Background(), ref).Execute()
				if code := statusOf(t, resp); code != http.StatusOK || c.toServer != i+1 {
					t.Fatalf("DELETE %s = %d, sent to a server %d times; want it sent", ref, code, c.toServer)
				}
			}
			_, resp, _ := daytonaAPI(srv, "acct-a").SandboxAPI.GetSandbox(context.Background(), "sb-gone-1").Execute()
			if code := statusOf(t, resp); c.toServer != 2 || (code != http.StatusServiceUnavailable && code != http.StatusGone) {
				t.Fatalf("GET = %d, sent to a server %d times; want 503 or 410 and no send", code, c.toServer)
			}
		})
	}
}

// On the server, which has no row: the delete removes the placement and
// answers with a Sandbox the SDK's model accepts (every field it requires),
// built from the placement. A retry is 404, as a second DELETE is anywhere.
// Another tenant's sandbox is 404 by id and by name, and stays.
func TestDaytonaDeleteOfAnAbandonedSandboxOnAServer(t *testing.T) {
	ctx := context.Background()

	t.Run("by id, as the operator", func(t *testing.T) {
		c := &abandonedDaytonaServer{abandonedDaytonaGateway: newAbandonedDaytonaGateway(
			abandonedDaytonaPlacement("sb-gone-1", "web", "acct-a", nil))}
		srv := abandonedDaytonaNode(t, c)
		sb, resp, err := daytonaAPI(srv, "").SandboxAPI.DeleteSandbox(ctx, "sb-gone-1").Execute()
		if err != nil || statusOf(t, resp) != http.StatusOK {
			t.Fatalf("DELETE = %v, %v; want 200 and a Sandbox the SDK parses", resp.Status, err)
		}
		if sb.Id != "sb-gone-1" || sb.Name != "web" || sb.GetState() != apiclient.SANDBOXSTATE_DESTROYED || sb.Cpu != 2 || sb.Memory != 4 ||
			sb.Disk != 10 || sb.User != "daytona" || sb.Labels["team"] != "a" || sb.Env == nil || sb.GetCreatedAt() == "" {
			t.Fatalf("Sandbox = %+v", sb)
		}
		if _, ok := c.PlacementOf("sb-gone-1"); ok || c.deletes != 1 {
			t.Fatalf("placement left, or deleted %d times; want it deleted once", c.deletes)
		}
		_, resp, _ = daytonaAPI(srv, "").SandboxAPI.DeleteSandbox(ctx, "sb-gone-1").Execute()
		if code := statusOf(t, resp); code != http.StatusNotFound {
			t.Fatalf("retry = %d, want 404", code)
		}
	})

	t.Run("by name, as its tenant", func(t *testing.T) {
		c := &abandonedDaytonaServer{abandonedDaytonaGateway: newAbandonedDaytonaGateway(
			abandonedDaytonaPlacement("sb-gone-2", "web", "acct-a", nil))}
		srv := abandonedDaytonaNode(t, c)
		sb, resp, err := daytonaAPI(srv, "acct-a").SandboxAPI.DeleteSandbox(ctx, "web").Execute()
		if err != nil || statusOf(t, resp) != http.StatusOK || sb.Id != "sb-gone-2" || sb.Name != "web" {
			t.Fatalf("DELETE by name = %+v, %v", sb, err)
		}
		if _, ok := c.PlacementOf("sb-gone-2"); ok {
			t.Fatal("placement left after the delete by name")
		}
	})

	t.Run("another tenant's, by id and by name", func(t *testing.T) {
		c := &abandonedDaytonaServer{abandonedDaytonaGateway: newAbandonedDaytonaGateway(
			abandonedDaytonaPlacement("sb-gone-3", "web", "acct-a", nil))}
		srv := abandonedDaytonaNode(t, c)
		for _, ref := range []string{"sb-gone-3", "web"} {
			_, resp, err := daytonaAPI(srv, "acct-b").SandboxAPI.DeleteSandbox(ctx, ref).Execute()
			if code := statusOf(t, resp); code != http.StatusNotFound || err == nil {
				t.Fatalf("another tenant's DELETE %s = %d, want 404", ref, code)
			}
		}
		if _, ok := c.PlacementOf("sb-gone-3"); !ok || c.deletes != 0 {
			t.Fatal("another tenant's DELETE touched the placement")
		}
	})

	t.Run("a facade state that does not decode costs only its fields", func(t *testing.T) {
		c := &abandonedDaytonaServer{abandonedDaytonaGateway: newAbandonedDaytonaGateway(
			abandonedDaytonaPlacement("sb-gone-4", "web", "acct-a", func(p *cluster.Placement) {
				p.Spec.CompatState = map[string]string{models.FacadeDaytona: "{not json"}
			}))}
		srv := abandonedDaytonaNode(t, c)
		sb, resp, err := daytonaAPI(srv, "").SandboxAPI.DeleteSandbox(ctx, "sb-gone-4").Execute()
		if err != nil || statusOf(t, resp) != http.StatusOK || sb.Id != "sb-gone-4" || sb.Name != "web" {
			t.Fatalf("DELETE = %+v, %v", sb, err)
		}
	})

	t.Run("its facade state, when the spec carries it", func(t *testing.T) {
		c := &abandonedDaytonaServer{abandonedDaytonaGateway: newAbandonedDaytonaGateway(
			abandonedDaytonaPlacement("sb-gone-5", "web", "acct-a", func(p *cluster.Placement) {
				p.Spec.CompatState = map[string]string{models.FacadeDaytona: `{"target":"eu","snapshot":"py-3.12"}`}
			}))}
		srv := abandonedDaytonaNode(t, c)
		sb, _, err := daytonaAPI(srv, "").SandboxAPI.DeleteSandbox(ctx, "sb-gone-5").Execute()
		if err != nil || sb.Target != "eu" || sb.GetSnapshot() != "py-3.12" {
			t.Fatalf("DELETE = %+v, %v; want the replicated target and snapshot", sb, err)
		}
	})
}

// A leader that cannot be read is a 503 with Retry-After, and the placement
// stays for the retry.
func TestDaytonaDeleteOfAnAbandonedSandboxRetries(t *testing.T) {
	c := &unreadableLeaderServer{abandonedDaytonaServer: &abandonedDaytonaServer{abandonedDaytonaGateway: newAbandonedDaytonaGateway(
		abandonedDaytonaPlacement("sb-gone-6", "web", "acct-a", nil))}}
	srv := abandonedDaytonaNode(t, c)
	_, resp, _ := daytonaAPI(srv, "").SandboxAPI.DeleteSandbox(context.Background(), "sb-gone-6").Execute()
	if code := statusOf(t, resp); code != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("DELETE = %d (Retry-After %q), want 503 with Retry-After", code, resp.Header.Get("Retry-After"))
	}
	if _, ok := c.PlacementOf("sb-gone-6"); !ok {
		t.Fatal("a failed DELETE lost the placement")
	}
}

type unreadableLeaderServer struct{ *abandonedDaytonaServer }

func (c *unreadableLeaderServer) AuthoritativePlacementsByIDs(context.Context, []string) (map[string]cluster.Placement, error) {
	return nil, errors.New("cluster: no leader")
}
