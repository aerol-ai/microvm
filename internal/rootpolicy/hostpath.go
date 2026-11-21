package rootpolicy

import (
	runcoptions "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"

	"github.com/aerol-ai/microvm/internal/rootfolder"
)

// CheckFolder is the rule for each folder on the way to a host path root
// acts on (a bind source, a stdio FIFO, a runsc config, the helper's own
// socket): it belongs to root, or to owner (a test's own user in place of
// root), and no one else can write it, or, with sticky allowed, it is a
// sticky folder. It is rootfolder.CheckFolder, which the runtime
// supervisor shares without linking this package.
//
// mode and uid come from the caller's stat of the open folder; this does
// no I/O itself.
func CheckFolder(at string, mode, uid, owner uint32, sticky bool) error {
	return rootfolder.CheckFolder(at, mode, uid, owner, sticky)
}

// RootRead is a host path containerd's shim, runc, runsc or aerolvm-runsc
// will read as root because a container record names it.
type RootRead struct {
	Path string
	// Folder: the path is a folder (a checkpoint image), not a file (a
	// runsc config).
	Folder bool
	// Rule is the rule a path that fails its on-disk check breaks.
	Rule Rule
}

// ContainerRootReads lists the paths c makes root read: the runsc config
// (it names the binary runsc runs and can turn on host networking), runc's
// checkpoint folders, and the restore image a moved gVisor sandbox starts
// from. CheckContainer checks their names; the gate checks each on disk,
// since a name in the right folder is only as good as that folder.
func ContainerRootReads(c Container) ([]RootRead, error) {
	out, err := runtimeRootReads(c.Runtime)
	if err != nil {
		return nil, err
	}
	s, err := DecodeSpec(c.Spec)
	if err != nil {
		return nil, err
	}
	if p := s.Annotations[RestoreAnnotation]; p != "" {
		out = append(out, RootRead{Path: p, Folder: true, Rule: RuleCheckpoint})
	}
	return out, nil
}

// runtimeRootReads is the runtime options' part of ContainerRootReads.
func runtimeRootReads(r Runtime) ([]RootRead, error) {
	var out []RootRead
	switch {
	case r.Name == RuntimeRunsc:
		var o runtimeoptions.Options
		if err := decodeOptions(r, &o); err != nil {
			return nil, err
		}
		if p := o.GetConfigPath(); p != "" {
			out = append(out, RootRead{Path: p, Rule: RuleRuntimeOptions})
		}
	case r.Name == RuntimeRunc && (r.OptionsTypeURL != "" || len(r.Options) > 0):
		var o runcoptions.Options
		if err := decodeOptions(r, &o); err != nil {
			return nil, err
		}
		for _, p := range []string{o.GetCriuImagePath(), o.GetCriuWorkPath()} {
			if p != "" {
				out = append(out, RootRead{Path: p, Folder: true, Rule: RuleCheckpoint})
			}
		}
	}
	return out, nil
}
