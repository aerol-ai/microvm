package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/kubeapi"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/api/remotemcp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// KubeBackend is the agent-sandbox API's write side (internal/kubeapi.
// Backend, C17): each write is a call to this server's own /v1 handler, in
// process, as the Kubernetes user, the way a remote MCP tool calls it
// (remotemcp.NewInProcessTransport). So a Kubernetes create meets the same
// route permission, owner scoping, create policy, quota, idempotency and
// cluster forwarding as an SDK create, and its audit record names the
// Kubernetes user, on the "kubernetes" surface. Kubernetes RBAC has
// already allowed the request; the role here (runner, on the namespace's
// owner) only bounds what that can reach.
type KubeBackend struct {
	handler http.Handler
	specs   func() cluster.SpecSummaryReader
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]cachedSpec
}

type cachedSpec struct {
	summary     kubeapi.SpecSummary
	incarnation string
	at          time.Time
}

const (
	// kubeSpecTTL bounds how stale a shown image or size may be (a resize
	// changes them; a stop does not).
	kubeSpecTTL = time.Minute
	// maxKubeSpecCache bounds the cache; past it, it starts over.
	maxKubeSpecCache = 200000
)

// KubeBackend returns the backend over this server's handler.
func (s *Server) KubeBackend() *KubeBackend {
	return &KubeBackend{
		handler: s.Handler(),
		specs: func() cluster.SpecSummaryReader {
			r, _ := s.service.Cluster().(cluster.SpecSummaryReader)
			return r
		},
		now: time.Now,
	}
}

func (b *KubeBackend) client(ctx context.Context, owner string) *http.Client {
	u, _ := kubeapi.UserFromContext(ctx)
	access := controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: owner, Role: controlplane.RoleRunner, Name: u.Name},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalKubernetes, ID: "kubernetes:" + u.Name, Name: u.Name},
	}
	return &http.Client{Transport: remotemcp.NewInProcessTransport(b.handler, access, auditlog.SurfaceKubernetes)}
}

// call makes one in-process API call and turns a refusal into the status
// the Kubernetes client gets.
func (b *KubeBackend) call(ctx context.Context, owner, method, path string, body any, header map[string]string, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://in-process"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := b.client(ctx, owner).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e models.ErrorResponse
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &kubeapi.StatusError{Code: resp.StatusCode, Reason: kubeReason(resp.StatusCode), Message: msg}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// kubeReason is the Kubernetes Status reason for an AerolVM answer.
func kubeReason(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "BadRequest"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusUnprocessableEntity:
		return "Invalid"
	case http.StatusTooManyRequests:
		return "TooManyRequests"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	case http.StatusGatewayTimeout:
		return "Timeout"
	}
	return "InternalError"
}

// Create makes the sandbox through POST /v1/sandboxes.
func (b *KubeBackend) Create(ctx context.Context, owner string, req models.CreateSandboxRequest, key string) (string, error) {
	var out models.Sandbox
	if err := b.call(ctx, owner, http.MethodPost, "/v1/sandboxes", req, map[string]string{clustercreate.HeaderIdempotencyKey: key}, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("the create answered without a sandbox id")
	}
	return out.ID, nil
}

// Delete destroys the sandbox.
func (b *KubeBackend) Delete(ctx context.Context, owner, id string) error {
	return b.call(ctx, owner, http.MethodDelete, "/v1/sandboxes/"+url.PathEscape(id), nil, nil, nil)
}

// SetRunning starts or stops the sandbox.
func (b *KubeBackend) SetRunning(ctx context.Context, owner, id string, running bool) error {
	verb := "stop"
	if running {
		verb = "start"
	}
	return b.call(ctx, owner, http.MethodPost, "/v1/sandboxes/"+url.PathEscape(id)+"/"+verb, nil, nil, nil)
}

// Specs summarizes the sandboxes from the servers, in batches, cached for a
// minute per lifetime (an ID made again is read again). A failed read
// leaves those sandboxes without a spec.
func (b *KubeBackend) Specs(ctx context.Context, refs []kubeapi.SpecRef) map[string]kubeapi.SpecSummary {
	out := make(map[string]kubeapi.SpecSummary, len(refs))
	now := b.now()
	var missing []string
	incarnation := make(map[string]string, len(refs))
	b.mu.Lock()
	for _, r := range refs {
		if c, ok := b.cache[r.ID]; ok && c.incarnation == r.Incarnation && now.Sub(c.at) < kubeSpecTTL {
			out[r.ID] = c.summary
		} else {
			missing = append(missing, r.ID)
			incarnation[r.ID] = r.Incarnation
		}
	}
	b.mu.Unlock()
	reader := b.specs()
	if reader == nil || len(missing) == 0 {
		return out
	}
	for start := 0; start < len(missing); start += cluster.MaxSpecSummaryBatch {
		batch := missing[start:min(start+cluster.MaxSpecSummaryBatch, len(missing))]
		got, err := reader.SpecSummaries(ctx, batch)
		if err != nil {
			continue
		}
		b.mu.Lock()
		if b.cache == nil || len(b.cache)+len(got) > maxKubeSpecCache {
			b.cache = map[string]cachedSpec{}
		}
		for id, s := range got {
			sum := kubeapi.SpecSummary{Image: s.Image, Runtime: s.Runtime, CPU: s.CPU, MemoryMB: s.MemoryMB, Command: s.Command, Tags: s.Tags}
			b.cache[id] = cachedSpec{summary: sum, incarnation: incarnation[id], at: now}
			out[id] = sum
		}
		b.mu.Unlock()
	}
	return out
}
