package kubeapi

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

// allNamespaces lists every stored object of a kind, as a cluster-wide
// list of the kube-apiserver does.
type allNamespaces struct {
	items map[string][]any
	err   error
}

func (a *allNamespaces) List(_ context.Context, resource, ns string, _ url.Values) (map[string]any, error) {
	if ns != "" {
		return nil, errors.New("asked for one namespace")
	}
	return map[string]any{"items": a.items[resource]}, a.err
}

func warmTemplate(ns, name, image, class string, command ...any) map[string]any {
	c := map[string]any{"name": "main", "image": image}
	if len(command) > 0 {
		c["command"] = command
	}
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"podTemplate": map[string]any{"spec": map[string]any{"runtimeClassName": class, "containers": []any{c}}}}}
}

func warmPool(ns, name, template string, replicas float64) map[string]any {
	return map[string]any{"metadata": map[string]any{"name": name, "namespace": ns},
		"spec": map[string]any{"replicas": replicas, "sandboxTemplateRef": map[string]any{"name": template}}}
}

func TestWarmDepths(t *testing.T) {
	store := &allNamespaces{items: map[string][]any{
		SandboxTemplatesResource: {
			warmTemplate("a", "py", "python:3.12", "gvisor"),
			warmTemplate("b", "py", "python:3.12", "gvisor"),
			warmTemplate("b", "alp", "alpine:3.20", "runc"),
			warmTemplate("a", "cmd", "python:3.12", "gvisor", "sleep", "infinity"),
			warmTemplate("a", "bad", "", "gvisor"),
		},
		SandboxWarmPoolsResource: {
			warmPool("a", "p1", "py", 2),
			warmPool("b", "p2", "py", 3),
			warmPool("b", "p3", "alp", 1),
			warmPool("a", "p4", "cmd", 4),     // its own command: a slot cannot serve it
			warmPool("a", "p5", "missing", 1), // no template
			warmPool("a", "p6", "bad", 1),     // a template that would not create
			warmPool("a", "p7", "py", 0),      // nothing to park
			warmPool("c", "p8", "py", 1),      // the template is in another namespace
		},
	}}
	got, err := WarmDepths(context.Background(), store, time.Unix(1700000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	want := []cluster.KubeWarmDepth{{Image: "alpine:3.20", Runtime: "docker", Depth: 1}, {Image: "python:3.12", Runtime: "gvisor", Depth: 5}}
	if !equalDepths(got, want) {
		t.Fatalf("depths = %+v, want %+v", got, want)
	}
	// The sum never passes a pool's depth limit.
	big := &allNamespaces{items: map[string][]any{
		SandboxTemplatesResource: {warmTemplate("a", "py", "python:3.12", "gvisor")},
		SandboxWarmPoolsResource: {warmPool("a", "p1", "py", 100), warmPool("a", "p2", "py", 100)},
	}}
	if got, _ := WarmDepths(context.Background(), big, time.Now()); len(got) != 1 || got[0].Depth != 128 {
		t.Fatalf("capped = %+v", got)
	}
	store.err = errors.New("kube-apiserver away")
	if _, err := WarmDepths(context.Background(), store, time.Now()); err == nil {
		t.Fatal("a failed list passed")
	}
}

// fakeDepthWriter is the cluster's set, read and replaced.
type fakeDepthWriter struct {
	mu       sync.Mutex
	held     []cluster.KubeWarmDepth
	writes   int
	readErr  error
	writeErr error
}

func (f *fakeDepthWriter) ReadWarmPools(context.Context, cluster.WarmPoolReadRequest) (cluster.WarmPoolReadResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cluster.WarmPoolReadResponse{Authoritative: true, Kube: f.held}, f.readErr
}

func (f *fakeDepthWriter) WriteWarmPool(_ context.Context, req cluster.WarmPoolWriteRequest) (cluster.WarmPoolWriteResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return cluster.WarmPoolWriteResponse{}, f.writeErr
	}
	f.writes++
	f.held = req.Kube.Depths
	return cluster.WarmPoolWriteResponse{Changed: true}, nil
}

func TestSyncWarmDepthsWritesOnlyAChange(t *testing.T) {
	ctx := context.Background()
	store := &allNamespaces{items: map[string][]any{
		SandboxTemplatesResource: {warmTemplate("a", "py", "python:3.12", "gvisor")},
		SandboxWarmPoolsResource: {warmPool("a", "p1", "py", 2)},
	}}
	w := &fakeDepthWriter{}
	if wrote, err := SyncWarmDepths(ctx, store, w, time.Now()); err != nil || !wrote || w.writes != 1 {
		t.Fatalf("first sync = %v %v writes %d", wrote, err, w.writes)
	}
	if wrote, err := SyncWarmDepths(ctx, store, w, time.Now()); err != nil || wrote || w.writes != 1 {
		t.Fatalf("an unchanged sum wrote: %v %v", wrote, err)
	}
	// The last pool deleted: an empty set is written, so slots stop.
	store.items[SandboxWarmPoolsResource] = nil
	if wrote, _ := SyncWarmDepths(ctx, store, w, time.Now()); !wrote || len(w.held) != 0 {
		t.Fatalf("after the last pool went: %v %+v", wrote, w.held)
	}
	w.readErr = errors.New("server tier away")
	if _, err := SyncWarmDepths(ctx, store, w, time.Now()); err == nil {
		t.Fatal("a failed read passed")
	}
	w.readErr = nil
	store.items[SandboxWarmPoolsResource] = []any{warmPool("a", "p1", "py", 1)}
	w.writeErr = cluster.ErrClusterVersion
	if _, err := SyncWarmDepths(ctx, store, w, time.Now()); !errors.Is(err, cluster.ErrClusterVersion) {
		t.Fatalf("a refused write = %v", err)
	}
	store.err = errors.New("list failed")
	if _, err := SyncWarmDepths(ctx, store, w, time.Now()); err == nil {
		t.Fatal("a failed list passed")
	}
}

// The loop writes at once, logs a failure once, and stops with ctx.
func TestRunWarmDepthSync(t *testing.T) {
	store := &allNamespaces{items: map[string][]any{
		SandboxTemplatesResource: {warmTemplate("a", "py", "python:3.12", "gvisor")},
		SandboxWarmPoolsResource: {warmPool("a", "p1", "py", 1)},
	}}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	w := &fakeDepthWriter{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunWarmDepthSync(ctx, store, w, logger); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		w.mu.Lock()
		n := w.writes
		w.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if w.writes != 1 || !strings.Contains(logs.String(), "depths written") {
		t.Fatalf("writes %d, logs %s", w.writes, logs.String())
	}
	// A refused write is logged at info during an upgrade, once.
	logs.Reset()
	w2 := &fakeDepthWriter{writeErr: cluster.ErrClusterVersion}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { RunWarmDepthSync(ctx2, store, w2, logger); close(done2) }()
	time.Sleep(50 * time.Millisecond)
	cancel2()
	<-done2
	if !strings.Contains(logs.String(), "not written yet") || !strings.Contains(logs.String(), "level=INFO") {
		t.Fatalf("logs = %s", logs.String())
	}
}
