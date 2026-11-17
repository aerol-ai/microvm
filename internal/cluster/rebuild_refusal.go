package cluster

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/volumes"
)

// Sandboxes with host-only settings are not rebuilt on another node.
//
// A node that rebuilds a sandbox it never had (a failover recreate, a
// stuck-placement reassign, a move, a WASM import) reads the spec the
// sandbox's last owner replicated, with no caller behind it. Some settings
// only a host-capable caller (the operator, an admin) may set: raw mounts,
// which run on the host; and a WASM module or JS bundle read from a host
// path. The rebuilding node runs its create without host powers
// (controlplane.ContextWithoutHostPowers), so it refuses those settings
// instead of taking them on the last owner's word, and says so
// (ErrHostOnlySpec). A platform volume is not one: the replicated spec
// carries it as a mount, which the node takes when it is the sandbox's own
// volume on this node's backend (volumes.PlatformMountFor).
//
//	leader, deciding a move     HostOnlySettings (no node's volume config):
//	  dead owner, stuck reassign, orphan retry, decommission
//	                            ─► not moved; a dead owner's is orphaned and
//	                               its own node takes it back when it returns
//	node that rebuilds          the service's full check ─► ErrHostOnlySpec
//	                            ─► owner watcher: never retried here, run
//	                               state failed with the reason, refusal
//	                               counted, logged and audited

// ErrHostOnlySpec is a rebuild refused because the sandbox has settings
// only its original owner may run (see above). It is permanent for the
// node that returned it: the owner watcher does not retry or move it.
var ErrHostOnlySpec = errors.New("cluster: the sandbox has host-only settings (raw mounts, or a module or bundle read from a host path), which are not rebuilt on another node")

// FailoverRefusalReasonHostOnly names a move or rebuild refused because of
// ErrHostOnlySpec.
const FailoverRefusalReasonHostOnly = "host_only_settings"

// HostOnlySettings lists the settings in p's spec that rule out a rebuild
// on another node, as far as anyone can tell without that node's volume and
// module configuration: a mount that is not shaped like one of the
// sandbox's own platform volumes, and a WASM module or JS bundle reference
// that is a host path. The node that rebuilds checks again with its own
// configuration; this is the leader's filter for where it moves sandboxes.
func HostOnlySettings(p Placement) []string {
	spec := p.Spec
	if spec == nil {
		return nil
	}
	var out []string
	// A replicated spec carries its platform volumes resolved into mounts
	// (the cluster create resolves them first); unresolved ones would be
	// resolved again in whatever scope the rebuild runs in.
	if len(spec.PlatformVolumes) > 0 {
		out = append(out, "platform_volumes")
	}
	tenant := volumes.TenantForOwnerRef(p.OwnerRef)
	for _, m := range spec.Mounts {
		if !volumes.PlatformMountShape(m, tenant) {
			out = append(out, "mounts")
			break
		}
	}
	ref := models.ModuleRefForCreate(*spec)
	switch strings.TrimSpace(spec.Runtime) {
	case models.RuntimeWasm:
		if hostPathModuleRef(ref) {
			out = append(out, "module_ref")
		}
	case models.RuntimeIsolate:
		_, local, _ := models.ParseJSBundleNodeRef(ref)
		if jsbundle.IsFileRef(local) {
			out = append(out, "module_ref")
		}
	}
	return out
}

// hostPathModuleRef reports whether a WASM module reference names a host
// path in a form no configuration can make anything else: file://, an
// absolute path, or a relative path. A bare name may be a reserved keyword
// or a catalogue entry, which only the node that rebuilds can tell.
func hostPathModuleRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	switch {
	case ref == "":
		return false
	case strings.HasPrefix(ref, "file://"), strings.HasPrefix(ref, "/"):
		return true
	}
	return strings.Contains(ref, "/") && !strings.Contains(ref, "://")
}

// hostOnlyRefusal is ErrHostOnlySpec naming p's host-only settings, or nil
// when it has none.
func hostOnlyRefusal(p Placement) error {
	why := HostOnlySettings(p)
	if len(why) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrHostOnlySpec, strings.Join(why, ", "))
}

// placementRebuildsElsewhere reports whether the leader may move p to
// another node to be rebuilt there: it asked for failover recreate and has
// no host-only settings.
func placementRebuildsElsewhere(p Placement) bool {
	return placementWantsFailoverRecreate(p) && len(HostOnlySettings(p)) == 0
}

// rebuildRefusalReport is everything reporting one refused rebuild takes,
// on a server (Cluster) or a worker (Agent).
type rebuildRefusalReport struct {
	selfNodeID string
	logger     *slog.Logger
	recreator  SandboxRecreator
	runStates  RunStatePublisher
}

// report records that this node will not rebuild p (ErrHostOnlySpec): the
// placement's run state becomes failed with the reason, so the sandbox
// shows why it is not running; the refusal is counted and audited like a
// refused failover. Each step is best effort: the owner watcher has already
// stopped retrying it.
func (r rebuildRefusalReport) report(ctx context.Context, id string, p Placement, cause error) {
	clusterFailoverRefused.Add(FailoverRefusalReasonHostOnly, 1)
	if r.logger != nil {
		r.logger.Error("cluster: not rebuilding a sandbox with host-only settings on this node; it stays failed until it is deleted or its own node takes it back",
			"sandbox_id", id, "node_id", r.selfNodeID, "err", cause)
	}
	reason := cause.Error()
	if len(reason) > 200 {
		reason = reason[:200]
	}
	if r.runStates != nil {
		if _, err := r.runStates.SetRunStates(ctx, []RunStateReport{{
			SandboxID: id, IncarnationID: strings.TrimSpace(p.IncarnationID), OwnerNodeID: r.selfNodeID,
			State: RunStateFailed, Reason: reason,
		}}); err != nil && r.logger != nil {
			r.logger.Warn("cluster: could not record a refused rebuild's run state", "sandbox_id", id, "err", err)
		}
	}
	if rec, ok := r.recreator.(FailoverRefusalRecorder); ok {
		rec.RecordFailoverRefused(FailoverRefusal{
			SandboxID:     id,
			IncarnationID: strings.TrimSpace(p.IncarnationID),
			OwnerRef:      strings.TrimSpace(p.OwnerRef),
			FromNodeID:    r.selfNodeID,
			Reason:        FailoverRefusalReasonHostOnly,
			Rule:          reason,
		})
	}
}
