package cluster

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The agent-sandbox API's warm pools (C17, plans/kubernetes-v2-architecture.md
// §16.1): their replicas summed per image and runtime, next to the
// operator's own entries (fsm_warm_pools.go) and never among them, so they
// are not shown in /v1 and do not count toward models.MaxWarmPools.
//
//	gateways (the API on) ─► sum SandboxWarmPool replicas per template image
//	  and runtime ─► WriteWarmPool{Kube} when the sum moved ─► the leader:
//	  fv gate ─► opSetKubeWarmDepths, the whole set, replaced
//	worker ─► the warm-pool read it already polls carries them ─► its pool
//	  for that runtime parks depth more slots of that image
//
// Depth is per worker, like every AerolVM warm pool: each worker whose pool
// runs that runtime keeps that many ready. Nothing about placement or
// ownership reads it.
const opSetKubeWarmDepths opCode = 53

// kubeWarmFSMOpsVersion is the build that applies opSetKubeWarmDepths.
const kubeWarmFSMOpsVersion = 20

// maxKubeWarmDepths bounds the set: one entry per image and runtime the
// cluster's warm pools use.
const maxKubeWarmDepths = 256

// ErrKubeWarmDepths is a set the FSM refuses: an entry with no image or
// runtime, a depth out of range, a duplicate, or too many.
var ErrKubeWarmDepths = errors.New("cluster: agent-sandbox warm pool depths refused")

// KubeWarmDepth is how many slots of one image each worker running Runtime
// keeps ready for the agent-sandbox API's warm pools.
type KubeWarmDepth struct {
	Image   string `json:"image"`
	Runtime string `json:"runtime"`
	Depth   int    `json:"depth"`
}

// NormalizeKubeWarmDepths checks a set and puts it in its one order (image,
// then runtime), so equal sets compare equal.
func NormalizeKubeWarmDepths(in []KubeWarmDepth) ([]KubeWarmDepth, error) {
	if len(in) > maxKubeWarmDepths {
		return nil, fmt.Errorf("%w: %d entries, at most %d", ErrKubeWarmDepths, len(in), maxKubeWarmDepths)
	}
	out := make([]KubeWarmDepth, 0, len(in))
	seen := make(map[[2]string]bool, len(in))
	for _, d := range in {
		d.Image, d.Runtime = strings.TrimSpace(d.Image), strings.TrimSpace(d.Runtime)
		switch {
		case d.Image == "" || d.Runtime == "":
			return nil, fmt.Errorf("%w: an entry needs an image and a runtime", ErrKubeWarmDepths)
		case d.Depth < 1 || d.Depth > models.MaxWarmPoolDepth:
			return nil, fmt.Errorf("%w: %s on %s: depth %d is not 1 to %d", ErrKubeWarmDepths, d.Image, d.Runtime, d.Depth, models.MaxWarmPoolDepth)
		case seen[[2]string{d.Image, d.Runtime}]:
			return nil, fmt.Errorf("%w: %s on %s is listed twice", ErrKubeWarmDepths, d.Image, d.Runtime)
		}
		seen[[2]string{d.Image, d.Runtime}] = true
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Image != out[j].Image {
			return out[i].Image < out[j].Image
		}
		return out[i].Runtime < out[j].Runtime
	})
	return out, nil
}

func sameKubeWarmDepths(a, b []KubeWarmDepth) bool {
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

// applySetKubeWarmDepthsLocked replaces the set. The same set again changes
// nothing, so a worker's cursor stays current.
func (f *placementFSM) applySetKubeWarmDepthsLocked(cmd command) (any, error) {
	set, err := NormalizeKubeWarmDepths(cmd.KubeWarm)
	if err != nil {
		return nil, err
	}
	if sameKubeWarmDepths(set, f.kubeWarm) {
		return kubeWarmApplyResult{}, nil
	}
	f.kubeWarm = set
	f.warmPoolsVersion = f.version
	return kubeWarmApplyResult{Changed: true}, nil
}

// kubeWarmApplyResult is the leader FSM's answer to opSetKubeWarmDepths.
type kubeWarmApplyResult struct {
	Changed bool
}

func (f *placementFSM) kubeWarmSnapshotLocked() []KubeWarmDepth {
	return append([]KubeWarmDepth(nil), f.kubeWarm...)
}

// restoreKubeWarmLocked loads a snapshot's set; a snapshot from before it
// has none.
func (f *placementFSM) restoreKubeWarmLocked(set []KubeWarmDepth) {
	f.kubeWarm = nil
	if norm, err := NormalizeKubeWarmDepths(set); err == nil {
		f.kubeWarm = norm
	}
}
