package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (errReadCloser) Close() error             { return nil }

type drainableMembersCluster struct {
	membersStubCluster
	drained map[string]bool
}

func (c *drainableMembersCluster) IsNodeDrained(nodeID string) bool {
	return c.drained != nil && c.drained[nodeID]
}

func TestClusterHelpersCoverage(t *testing.T) {
	if !clusterMemberSupportsRuntime(cluster.Member{}, "") {
		t.Fatal("empty runtime should match")
	}
	if !clusterMemberSupportsRuntime(cluster.Member{
		Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeDocker}},
	}, models.RuntimeDocker) {
		t.Fatal("docker runtime should match")
	}
	if clusterMemberSupportsRuntime(cluster.Member{
		Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}},
	}, models.RuntimeDocker) {
		t.Fatal("docker runtime should not match firecracker-only member")
	}

	if !clusterSelfCanOwnSandbox(nil) {
		t.Fatal("nil cluster should allow self ownership")
	}
	serverCluster := &membersStubCluster{
		Noop: cluster.NewNoop("server-a", "http://server-a", ""),
		members: []cluster.Member{
			{NodeID: "server-a", Role: config.NodeRoleServer},
		},
	}
	if clusterSelfCanOwnSandbox(serverCluster) {
		t.Fatal("server role should not own sandboxes")
	}
	workerCluster := &membersStubCluster{
		Noop: cluster.NewNoop("worker-a", "http://worker-a", ""),
		members: []cluster.Member{
			{NodeID: "worker-a", Role: config.NodeRoleWorker},
		},
	}
	if !clusterSelfCanOwnSandbox(workerCluster) {
		t.Fatal("worker role should own sandboxes")
	}
	if !clusterSelfCanOwnSandbox(&membersStubCluster{Noop: cluster.NewNoop("orphan", "", "")}) {
		t.Fatal("missing self member should default to true")
	}
}

func TestClusterTemplatePeersFiltersMembers(t *testing.T) {
	if clusterTemplatePeers(nil) != nil {
		t.Fatal("nil cluster should return nil peers")
	}
	c := &drainableMembersCluster{
		membersStubCluster: membersStubCluster{
			Noop: cluster.NewNoop("server-a", "http://server-a", ""),
			members: []cluster.Member{
				{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
				{NodeID: "dead", APIURL: "http://dead", Alive: false, Role: config.NodeRoleWorker},
				{NodeID: "drained", APIURL: "http://drained", Alive: true, Role: config.NodeRoleWorker, Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}}},
				{NodeID: "docker-only", APIURL: "http://docker-only", Alive: true, Role: config.NodeRoleWorker, Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeDocker}}},
				{NodeID: "fc-peer", APIURL: "http://fc-peer", InternalURL: "https://fc-peer:21443", Alive: true, Role: config.NodeRoleWorker, Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}}},
			},
		},
		drained: map[string]bool{"drained": true},
	}
	peers := clusterTemplatePeers(c)
	if len(peers) != 1 || peers[0].NodeID != "fc-peer" {
		t.Fatalf("peers = %+v, want only fc-peer", peers)
	}
}

func TestClusterBuildImageWrapCoverageBranches(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo hi"
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	builder := &fakeImageBuilder{}

	t.Run("fanout_header_bypass", func(t *testing.T) {
		h := &handlers{deps: Deps{Builder: builder, Logger: logger}}
		req := httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body)))
		req.Header.Set(clusterImageBuildFanoutHeader, "1")
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("build_nil_cluster", func(t *testing.T) {
		svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.ClearClusterForTest()
		h := &handlers{deps: Deps{Service: svc, Builder: builder, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader("{")))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("read_body_error", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true}, logger, nil, nil, nil, nil, nil, nil, nil)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		req := httptest.NewRequest(http.MethodPost, "/v1/images/build", nil)
		req.Body = errReadCloser{}
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("push_skips_fanout", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(dockerFanoutCluster("ingress-a", "http://worker.invalid"))
		h := &handlers{deps: Deps{Service: svc, Builder: builder, Logger: logger}}
		pushBody, _ := json.Marshal(buildImageRequest{
			DockerfileContent: dockerfile,
			Push:              &buildImagePushSpec{Registry: "registry.example.com", Username: "u", Password: "p"},
		})
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(pushBody))))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("context_hashes_skip_fanout", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(dockerFanoutCluster("ingress-a", "http://127.0.0.1:1"))
		h := &handlers{deps: Deps{Service: svc, Builder: builder, Logger: logger}}
		ctxBody, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile, ContextHashes: []string{"abc"}})
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(ctxBody))))
		if rr.Code == http.StatusBadGateway {
			t.Fatalf("context_hashes build should skip fanout; got 502")
		}
	})

	t.Run("no_docker_workers_falls_back_local", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(&membersStubCluster{
			Noop: cluster.NewNoop("ingress-a", "http://ingress-a", ""),
			members: []cluster.Member{
				{NodeID: "ingress-a", APIURL: "http://ingress-a", Alive: true, Role: config.NodeRoleServer},
			},
		})
		h := &handlers{deps: Deps{Service: svc, Builder: builder, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("peer_network_error", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(dockerFanoutCluster("ingress-a", "http://127.0.0.1:1"))
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", rr.Code)
		}
	})

	t.Run("peer_non_200_status", func(t *testing.T) {
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "build failed", http.StatusInternalServerError)
		}))
		defer remote.Close()
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		svc.AttachCluster(dockerFanoutCluster("ingress-a", remote.URL))
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterBuildImageWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body))))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", rr.Code)
		}
	})
}

func TestRunImageBuildOnTargetCoverage(t *testing.T) {
	dockerfile := "FROM alpine\nRUN echo local"
	body, _ := json.Marshal(buildImageRequest{DockerfileContent: dockerfile})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	builder := &fakeImageBuilder{}

	t.Run("self_local_build", func(t *testing.T) {
		h := &handlers{deps: Deps{Builder: builder, Logger: logger}}
		parent := httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body)))
		parent.Header.Set("Content-Type", "application/json")
		status, header, respBody, err := h.runImageBuildOnTarget(nil, parent, body, cluster.Member{NodeID: "self"}, true)
		if err != nil || status != http.StatusOK {
			t.Fatalf("self build: status=%d err=%v body=%s", status, err, respBody)
		}
		if header.Get("Content-Type") == "" {
			t.Fatal("expected response headers from local build")
		}
	})

	t.Run("remote_forwards_auth_and_content_type", func(t *testing.T) {
		var gotAuth, gotCT string
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotCT = r.Header.Get("Content-Type")
			_ = json.NewEncoder(w).Encode(buildImageResponse{Image: docker.BuildTagFor(dockerfile, nil)})
		}))
		defer remote.Close()

		h := &handlers{deps: Deps{Logger: logger}}
		parent := httptest.NewRequest(http.MethodPost, "/v1/images/build", strings.NewReader(string(body)))
		parent.Header.Set("Authorization", "Bearer tok")
		parent.Header.Set("Content-Type", "application/json")
		c := &membersStubCluster{Noop: cluster.NewNoop("self", "http://self", ""), internalClient: remote.Client()}
		status, _, _, err := h.runImageBuildOnTarget(c, parent, body, cluster.Member{NodeID: "worker", InternalURL: remote.URL}, false)
		if err != nil || status != http.StatusOK {
			t.Fatalf("remote build: status=%d err=%v", status, err)
		}
		if gotAuth != "Bearer tok" || gotCT != "application/json" {
			t.Fatalf("auth/ct = %q/%q", gotAuth, gotCT)
		}
	})
}

func dockerFanoutCluster(selfID, workerURL string) cluster.Client {
	return &membersStubCluster{
		Noop:           cluster.NewNoop(selfID, "http://"+selfID, ""),
		internalClient: http.DefaultClient,
		members: []cluster.Member{
			{NodeID: selfID, APIURL: "http://" + selfID, Alive: true, Role: config.NodeRoleServer},
			{
				NodeID: "worker-docker", APIURL: workerURL, InternalURL: workerURL, Alive: true, Role: config.NodeRoleWorker,
				Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeDocker}},
			},
		},
	}
}

func TestClusterTemplateWrapCoverageBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("list_forwarded_header_hits_listTemplates", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
		req.Header.Set(clusterTemplateForwardedHeader, "1")
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("list_forwarded_header_store_error", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		_ = env.store.Close()
		req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
		req.Header.Set(clusterTemplateForwardedHeader, "1")
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK {
			t.Fatal("expected store error from listTemplates")
		}
	})

	t.Run("create_forwarded_header_invalid_json", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader("{bad"))
		req.Header.Set(clusterTemplateForwardedHeader, "1")
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("create_self_target", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.AttachCluster(&createForwardCluster{
			Noop:   cluster.NewNoop("worker-fc", "http://worker-fc", ""),
			target: cluster.PlacementTarget{NodeID: "worker-fc", IsSelf: true},
			members: []cluster.Member{
				{NodeID: "worker-fc", APIURL: "http://worker-fc", Alive: true, Role: config.NodeRoleWorker},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`))
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("create_placement_errors", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		tests := []struct {
			name       string
			err        error
			wantStatus int
		}{
			{name: "no_target", err: cluster.ErrNoPlacementTarget, wantStatus: http.StatusServiceUnavailable},
			{name: "invalid_topology", err: cluster.ErrInvalidTopology, wantStatus: http.StatusServiceUnavailable},
			{name: "generic", err: errors.New("boom"), wantStatus: http.StatusInternalServerError},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				env.svc.AttachCluster(&createForwardCluster{
					Noop:      cluster.NewNoop("server-a", "http://server-a", ""),
					selectErr: tc.err,
				})
				req := httptest.NewRequest(http.MethodPost, "/v1/templates", strings.NewReader(`{"image":"docker://alpine:3.20"}`))
				rr := httptest.NewRecorder()
				env.handler.ServeHTTP(rr, req)
				if rr.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d: %s", rr.Code, tc.wantStatus, rr.Body.String())
				}
			})
		}
	})

	t.Run("create_read_body_error", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.AttachCluster(templateMembersCluster("server-a", "http://fc.invalid"))
		req := httptest.NewRequest(http.MethodPost, "/v1/templates", nil)
		req.Body = errReadCloser{}
		rr := httptest.NewRecorder()
		(&handlers{deps: Deps{Service: env.svc, Logger: logger}}).clusterCreateTemplateWrap(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("list_peer_failures_still_return_local", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		badPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusInternalServerError)
		}))
		defer badPeer.Close()
		env.svc.AttachCluster(templateMembersCluster("server-a", badPeer.URL))
		req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("list_peer_network_error", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.AttachCluster(templateMembersCluster("server-a", "http://127.0.0.1:1"))
		req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
	})

	t.Run("list_fanout_cap_exceeded", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		members := []cluster.Member{
			{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
		}
		for i := 0; i <= clusterListMaxFanoutPeers; i++ {
			members = append(members, cluster.Member{
				NodeID: fmt.Sprintf("fc-%d", i), APIURL: fmt.Sprintf("http://fc-%d", i), InternalURL: fmt.Sprintf("http://fc-%d", i), Alive: true,
				Role: config.NodeRoleWorker, Capacity: capacity.Snapshot{SupportedRuntimes: []string{models.RuntimeFirecracker}},
			})
		}
		env.svc.AttachCluster(&membersStubCluster{Noop: cluster.NewNoop("server-a", "http://server-a", ""), members: members})
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
	})

	t.Run("list_local_error_when_no_rows", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		_ = env.store.Close()
		env.svc.AttachCluster(templateMembersCluster("server-a", "http://fc.invalid"))
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
		if rr.Code == http.StatusOK {
			t.Fatal("expected store error when local list fails and merge is empty")
		}
	})

	t.Run("item_peer_non_404_response", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad", http.StatusInternalServerError)
		}))
		defer peer.Close()
		env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/tpl-remote", nil))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
	})

	t.Run("item_read_body_error", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.AttachCluster(templateMembersCluster("server-a", "http://fc.invalid"))
		req := httptest.NewRequest(http.MethodPost, "/v1/templates/tpl-x/rebuild", nil)
		req.Body = errReadCloser{}
		rr := httptest.NewRecorder()
		itemHandler := (&handlers{deps: Deps{Service: env.svc, Logger: logger}}).clusterTemplateItemWrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}))
		itemHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("item_peer_request_error_falls_back_local", func(t *testing.T) {
		env := newTemplateV1TestEnv(t)
		env.svc.AttachCluster(templateMembersCluster("server-a", "http://127.0.0.1:1"))
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates/missing-tpl", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}

func TestClusterCreateWrapLocalImageCoverageBranches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	builtBody := `{"image":"` + docker.BuiltImageNamespace + `/abc:latest"}`

	t.Run("forwarded_local_image_without_reservation_id", func(t *testing.T) {
		rt := &apiRecordingRuntime{}
		fake := &createForwardCluster{Noop: cluster.NewNoop("worker-b", "http://worker-b", "")}
		h, _ := newClusterCreateHarness(t, rt, fake)
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(builtBody))
		req.Header.Set(clusterCreateTargetHeader, "worker-b")
		rr := httptest.NewRecorder()
		h.clusterCreateWrap(rr, req)
		if rr.Code == http.StatusBadRequest && strings.Contains(rr.Body.String(), clusterCreateIDHeader) {
			t.Fatalf("local image forward should not require create id: %s", rr.Body.String())
		}
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("mixed_worker_drained", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleMixed}, logger, nil, nil, nil, nil, nil, nil, nil)
		fake := &createForwardCluster{
			Noop: cluster.NewNoop("mixed-a", "http://mixed-a", ""),
			members: []cluster.Member{
				{NodeID: "mixed-a", APIURL: "http://mixed-a", Alive: true, Role: config.NodeRoleMixed},
			},
			drained: map[string]bool{"mixed-a": true},
		}
		svc.AttachCluster(fake)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(builtBody)))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
	})

	t.Run("placement_self_drained", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		fake := &createForwardCluster{
			Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
			target: cluster.PlacementTarget{NodeID: "worker-b", APIURL: "http://worker-b", IsSelf: true},
			members: []cluster.Member{
				{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
			},
			drained: map[string]bool{"server-a": true},
		}
		svc.AttachCluster(fake)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(builtBody)))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rr.Code)
		}
	})

	t.Run("placement_empty_target_urls_still_forwards", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		fake := &createForwardCluster{
			Noop:   cluster.NewNoop("server-a", "http://server-a", ""),
			target: cluster.PlacementTarget{NodeID: "worker-b", IsSelf: false},
			members: []cluster.Member{
				{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
				{NodeID: "worker-b", APIURL: "http://worker-b", Alive: true, Role: config.NodeRoleWorker},
			},
		}
		svc.AttachCluster(fake)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(builtBody)))
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 forward", rr.Code)
		}
		if fake.forwardedTarget != "worker-b" {
			t.Fatalf("forwarded target = %q", fake.forwardedTarget)
		}
	})

	t.Run("placement_generic_error", func(t *testing.T) {
		svc := service.New(config.Config{EnableCluster: true, NodeRole: config.NodeRoleServer}, logger, nil, nil, nil, nil, nil, nil, nil)
		fake := &createForwardCluster{
			Noop: cluster.NewNoop("server-a", "http://server-a", ""),
			members: []cluster.Member{
				{NodeID: "server-a", APIURL: "http://server-a", Alive: true, Role: config.NodeRoleServer},
			},
			selectErr: errors.New("placement boom"),
		}
		svc.AttachCluster(fake)
		h := &handlers{deps: Deps{Service: svc, Logger: logger}}
		rr := httptest.NewRecorder()
		h.clusterCreateWrap(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(builtBody)))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
	})
}

func TestClusterListTemplatesPeerDecodeError(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/templates", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestClusterListTemplatesWithAuthHeader(t *testing.T) {
	env := newTemplateV1TestEnv(t)
	var gotAuth string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode([]*models.Template{})
	}))
	defer peer.Close()
	env.svc.AttachCluster(templateMembersCluster("server-a", peer.URL))
	req := httptest.NewRequest(http.MethodGet, "/v1/templates", nil)
	req.Header.Set("Authorization", "Bearer list-tok")
	rr := httptest.NewRecorder()
	env.handler.ServeHTTP(rr, req)
	if gotAuth != "Bearer list-tok" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
}
