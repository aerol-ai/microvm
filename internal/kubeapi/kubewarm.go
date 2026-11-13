package kubeapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Warm pools that pre-start sandboxes (C17, plans/kubernetes-v2-architecture.md
// §16.1). A gateway with the API on sums its SandboxWarmPools' replicas per
// template image and runtime, and writes the sum to the cluster when it
// moved (cluster.KubeWarmDepth): every worker running that runtime then
// keeps that many slots of the image ready, and a claim on one adopts a
// slot instead of a cold create.
//
//	every warmSyncEvery ─► list SandboxWarmPools and SandboxTemplates (all
//	  namespaces) ─► each pool's template as a claim would create it
//	  ─► kept if a parked slot can serve it (the image's own entrypoint)
//	  ─► replicas summed per image and runtime ─► written if not what the
//	     cluster holds
//
// replicas is per worker here, as every AerolVM warm pool is; upstream
// counts the whole cluster. Several gateways write the same set: the write
// replaces it whole, so they agree.

// warmSyncEvery spaces the gateways' reads of the warm pools: a new pool's
// slots start parking within one interval and a worker's own sync.
const warmSyncEvery = 15 * time.Second

// WarmDepthStore reads the stored kinds (KubeClient).
type WarmDepthStore interface {
	List(ctx context.Context, resource, ns string, q url.Values) (map[string]any, error)
}

// WarmDepthWriter reads and replaces the cluster's set (cluster.Agent).
type WarmDepthWriter interface {
	ReadWarmPools(context.Context, cluster.WarmPoolReadRequest) (cluster.WarmPoolReadResponse, error)
	WriteWarmPool(context.Context, cluster.WarmPoolWriteRequest) (cluster.WarmPoolWriteResponse, error)
}

// WarmDepths is the set the stored warm pools ask for. A pool whose
// template is missing or would not create, or runs its own command (a
// parked slot runs the image's), parks nothing.
func WarmDepths(ctx context.Context, store WarmDepthStore, now time.Time) ([]cluster.KubeWarmDepth, error) {
	pools, err := listItems(ctx, store, SandboxWarmPoolsResource)
	if err != nil {
		return nil, err
	}
	templates, err := listItems(ctx, store, SandboxTemplatesResource)
	if err != nil {
		return nil, err
	}
	byName := make(map[[2]string]map[string]any, len(templates))
	for _, t := range templates {
		md := mapAt(t, "metadata")
		ns, _ := md["namespace"].(string)
		name, _ := md["name"].(string)
		byName[[2]string{ns, name}] = t
	}
	sums := map[[2]string]int{}
	for _, wp := range pools {
		md := mapAt(wp, "metadata")
		ns, _ := md["namespace"].(string)
		replicas, _ := mapAt(wp, "spec")["replicas"].(float64)
		ref, _ := mapAt(wp, "spec", "sandboxTemplateRef")["name"].(string)
		tpl, ok := byName[[2]string{ns, ref}]
		if replicas < 1 || !ok {
			continue
		}
		probe, err := json.Marshal(map[string]any{"metadata": map[string]any{"name": "warm"}, "spec": blueprint(mapAt(tpl, "spec"))})
		if err != nil {
			continue
		}
		req, _, err := CreateFrom(probe, now, func() string { return "" })
		if err != nil || len(req.ContainerCommand) > 0 {
			continue
		}
		key := [2]string{req.Image, req.Runtime}
		sums[key] = min(sums[key]+int(replicas), models.MaxWarmPoolDepth)
	}
	out := make([]cluster.KubeWarmDepth, 0, len(sums))
	for k, d := range sums {
		out = append(out, cluster.KubeWarmDepth{Image: k[0], Runtime: k[1], Depth: d})
	}
	return cluster.NormalizeKubeWarmDepths(out)
}

func listItems(ctx context.Context, store WarmDepthStore, resource string) ([]map[string]any, error) {
	list, err := store.List(ctx, resource, "", nil)
	if err != nil {
		return nil, err
	}
	raw, _ := list["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// SyncWarmDepths writes the set the warm pools ask for when the cluster
// holds another. It reports whether it wrote.
func SyncWarmDepths(ctx context.Context, store WarmDepthStore, w WarmDepthWriter, now time.Time) (bool, error) {
	want, err := WarmDepths(ctx, store, now)
	if err != nil {
		return false, err
	}
	have, err := w.ReadWarmPools(ctx, cluster.WarmPoolReadRequest{})
	if err != nil {
		return false, err
	}
	held, _ := cluster.NormalizeKubeWarmDepths(have.Kube)
	if equalDepths(want, held) {
		return false, nil
	}
	if _, err := w.WriteWarmPool(ctx, cluster.WarmPoolWriteRequest{Kube: &cluster.KubeWarmSet{Depths: want}}); err != nil {
		return false, err
	}
	return true, nil
}

func equalDepths(a, b []cluster.KubeWarmDepth) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunWarmDepthSync keeps the cluster's set in step until ctx ends. A
// cluster part way through an upgrade refuses the write (an older server
// cannot apply it): that is logged once and retried.
func RunWarmDepthSync(ctx context.Context, store WarmDepthStore, w WarmDepthWriter, logger *slog.Logger) {
	t := time.NewTicker(warmSyncEvery)
	defer t.Stop()
	failing := false
	for {
		wrote, err := SyncWarmDepths(ctx, store, w, time.Now())
		switch {
		case err != nil && !failing && logger != nil:
			level := slog.LevelWarn
			if errors.Is(err, cluster.ErrClusterVersion) {
				level = slog.LevelInfo
			}
			logger.Log(ctx, level, "agent-sandbox warm pools: not written yet", "error", err)
		case err == nil && wrote && logger != nil:
			logger.Info("agent-sandbox warm pools: depths written")
		}
		failing = err != nil
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
