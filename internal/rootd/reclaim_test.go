package rootd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// recordReclaim stands in for mount and umount.
func recordReclaim(t *testing.T, fail map[string]error) *[]string {
	t.Helper()
	var mu sync.Mutex
	var cmds []string
	prev := reclaimRun
	reclaimRun = func(_ context.Context, _ []string, name string, args ...string) error {
		mu.Lock()
		cmds = append(cmds, name+" "+strings.Join(args, " "))
		mu.Unlock()
		return fail[name]
	}
	t.Cleanup(func() { reclaimRun = prev })
	return &cmds
}

func reclaimRig(t *testing.T) (*rig, rootdpb.RootHelperClient) {
	t.Helper()
	r := newRig(t, func(c *Config, _ *Options) {
		c.Reclaim = &ReclaimConfig{Export: rootpolicy.NFSExport{Server: "10.0.0.9", Export: "/exports/vols"},
			Options: "vers=4.1,soft", ScratchDir: filepath.Join(t.TempDir(), "reclaim")}
	})
	return r, rootdpb.NewRootHelperClient(r.conn)
}

// TestReclaimVolume: the helper mounts one volume's folder of its own
// export, with its own options and nosuid,nodev,noexec last, in its own
// scratch folder, empties it and unmounts it.
func TestReclaimVolume(t *testing.T) {
	cmds := recordReclaim(t, nil)
	r, c := reclaimRig(t)
	const src = "10.0.0.9:/exports/vols/t-0123/data"
	if _, err := c.ReclaimVolume(callCtx(t), &rootdpb.ReclaimVolumeRequest{Source: src}); err != nil {
		t.Fatal(err)
	}
	if len(*cmds) != 2 || !strings.HasPrefix((*cmds)[0], "mount -t nfs -o vers=4.1,soft,nosuid,nodev,noexec "+src+" "+r.cfg.Reclaim.ScratchDir+"/vol-reclaim-") ||
		!strings.HasPrefix((*cmds)[1], "umount "+r.cfg.Reclaim.ScratchDir+"/") {
		t.Fatalf("commands %q", *cmds)
	}
	if len(r.refused()) != 0 {
		t.Fatal(r.refused())
	}
}

// What a broken agent could name instead of a volume's folder is refused,
// and nothing is mounted.
func TestReclaimVolumeRefusals(t *testing.T) {
	cmds := recordReclaim(t, nil)
	r, c := reclaimRig(t)
	for _, src := range []string{"10.0.0.9:/exports/vols", "10.0.0.9:/exports/vols/t-1", "10.0.0.9:/exports/vols/t-1/../../../etc",
		"10.0.0.9:/etc/x/y", "10.6.6.6:/exports/vols/t-1/a", "/exports/vols/t-1/a"} {
		_, err := c.ReclaimVolume(callCtx(t), &rootdpb.ReclaimVolumeRequest{Source: src})
		if reason, ok := rootdpb.RefusalReason(err); !ok || reason != string(rootpolicy.RuleReclaim) {
			t.Errorf("%s: %v", src, err)
		}
	}
	newer := &rootdpb.ReclaimVolumeRequest{Source: "10.0.0.9:/exports/vols/t-1/a"}
	newer.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1))
	if _, err := c.ReclaimVolume(callCtx(t), newer); status.Code(err) != codes.Unimplemented {
		t.Fatalf("an unknown field: %v", err)
	}
	if len(*cmds) != 0 {
		t.Fatalf("ran %q", *cmds)
	}
	if len(r.refused()) != 6 {
		t.Fatalf("refusals %v", r.refused())
	}
}

func TestReclaimVolumeFailuresAndAbsence(t *testing.T) {
	recordReclaim(t, map[string]error{"mount": errors.New("mount.nfs: access denied")})
	_, c := reclaimRig(t)
	if _, err := c.ReclaimVolume(callCtx(t), &rootdpb.ReclaimVolumeRequest{Source: "10.0.0.9:/exports/vols/t-1/a"}); status.Code(err) != codes.Internal ||
		!strings.Contains(err.Error(), "access denied") {
		t.Fatalf("%v", err)
	}
	plain := rootdpb.NewRootHelperClient(newRig(t, nil).conn)
	if _, err := plain.ReclaimVolume(callCtx(t), &rootdpb.ReclaimVolumeRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("no NFS backend: %v", err)
	}
	// A scratch folder that cannot be made stops the helper.
	cfg := testConfig(t)
	cfg.Reclaim = &ReclaimConfig{Export: rootpolicy.NFSExport{Server: "h", Export: "/e"}, ScratchDir: "/proc/no/such"}
	if _, err := newReclaimCalls(cfg, &keyedLocks{}, nil); err == nil {
		t.Fatal("an unusable scratch folder passed")
	}
}
