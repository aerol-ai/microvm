package cluster

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAgentDelegatesVolumeReadWriteToServerControlPlane(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}

	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	serverAPIURL := "http://" + apiListener.Addr().String()
	server, cleanupServer := newTestClusterWithAPI(t, "srv-agent-vol", true, nil, serverAPIURL)
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)

	srv := startAgentControlPlaneServerWithVolumes(t, server, apiListener)
	defer srv.Close()

	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-agent-vol", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	waitForGossipMember(t, server, "wkr-agent-vol", 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	v := models.Volume{ID: "vol-agent", Tenant: "t-a", Name: "data", Backend: "s3", Source: "bucket/t-a/data"}
	row, created, err := agent.VolumeUpsert(ctx, v, 0)
	if err != nil || !created || row.ID != "vol-agent" {
		t.Fatalf("agent VolumeUpsert = %+v created=%v err=%v", row, created, err)
	}
	if got, err := agent.VolumeByID(ctx, "t-a", "vol-agent"); err != nil || got.Name != "data" {
		t.Fatalf("agent VolumeByID = %+v, %v", got, err)
	}
	vols, err := agent.VolumesForTenant(ctx, "t-a")
	if err != nil || len(vols) != 1 {
		t.Fatalf("agent VolumesForTenant = %+v, %v", vols, err)
	}
	exists, err := agent.VolumeExistsForSource(ctx, "bucket/t-a/data")
	if err != nil || !exists {
		t.Fatalf("agent VolumeExistsForSource = %v, %v", exists, err)
	}
	attach := models.VolumeAttachment{
		Tenant: "t-a", VolumeID: "vol-agent", SandboxID: "sb-1", Target: "/data", Source: "bucket/t-a/data",
	}
	if err := agent.PutVolumeAttachments(ctx, []models.VolumeAttachment{attach}); err != nil {
		t.Fatalf("agent PutVolumeAttachments: %v", err)
	}
	count, err := agent.VolumeAttachmentCount(ctx, "t-a", "vol-agent")
	if err != nil || count != 1 {
		t.Fatalf("agent VolumeAttachmentCount = %d, %v", count, err)
	}
	if err := agent.DeleteVolumeAttachmentsForSandbox(ctx, "sb-1"); err != nil {
		t.Fatalf("agent DeleteVolumeAttachmentsForSandbox: %v", err)
	}
	if err := agent.VolumeDelete(ctx, "t-a", "vol-agent"); err != nil {
		t.Fatalf("agent VolumeDelete: %v", err)
	}
}

func TestAgentVolumeValidation(t *testing.T) {
	a := &Agent{}
	ctx := context.Background()
	_, _, err := a.VolumeUpsert(ctx, models.Volume{Name: "n"}, 0)
	if err == nil {
		t.Fatal("VolumeUpsert validation: expected error")
	}
	if err := a.VolumeDelete(ctx, "", "vol-1"); err == nil {
		t.Fatal("VolumeDelete validation: expected error")
	}
	if err := a.PutVolumeAttachments(ctx, nil); err != nil {
		t.Fatalf("PutVolumeAttachments empty: %v", err)
	}
	if err := a.DeleteVolumeAttachmentsForSandbox(ctx, " "); err != nil {
		t.Fatalf("DeleteVolumeAttachmentsForSandbox whitespace: %v", err)
	}
}

func startAgentControlPlaneServerWithVolumes(t *testing.T, c *Cluster, ln net.Listener) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(PublicInternalApplyPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := c.ApplyEncoded(r.Context(), body); err != nil {
			if err == ErrNotLeader {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc(PublicInternalVolumePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		tenant := q.Get("tenant")
		switch q.Get("kind") {
		case "id":
			v, err := c.VolumeByID(r.Context(), tenant, q.Get("id"))
			if err != nil {
				http.Error(w, "no such volume", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &v})
		case "name":
			v, err := c.VolumeByName(r.Context(), tenant, q.Get("name"))
			if err != nil {
				http.Error(w, "no such volume", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volume: &v})
		case "list":
			vols, err := c.VolumesForTenant(r.Context(), tenant)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Volumes: vols})
		case "source":
			exists, err := c.VolumeExistsForSource(r.Context(), q.Get("source"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Exists: exists})
		case "attachment_count":
			count, err := c.VolumeAttachmentCount(r.Context(), tenant, q.Get("id"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(VolumeQueryResponse{Count: count})
		default:
			http.Error(w, "unknown volume query kind", http.StatusBadRequest)
		}
	})
	mux.HandleFunc(PublicInternalPlacementPath, func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, PublicInternalPlacementPath)
		p, ok := c.PlacementOf(id)
		if !ok {
			http.Error(w, "no placement record", http.StatusNotFound)
			return
		}
		owner, err := c.OwnerOf(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		p.SecretRef = ""
		p.SecretVersion = 0
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PlacementLookupResponse{SandboxID: id, Placement: p, Owner: owner})
	})
	c.AttachInternalHandler(mux)
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: mux}}
	srv.Start()
	return srv
}
