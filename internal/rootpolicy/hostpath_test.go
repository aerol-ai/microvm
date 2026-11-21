package rootpolicy

import (
	"slices"
	"strings"
	"testing"

	runcoptions "github.com/containerd/containerd/api/types/runc/options"
	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"google.golang.org/protobuf/proto"
)

// POSIX mode bits for the cases below (rootfolder.CheckFolder reads them).
const (
	modeFolder = 0o040000
	modeSticky = 0o1000
)

func TestCheckFolder(t *testing.T) {
	const owner = 1000
	for _, tc := range []struct {
		name   string
		mode   uint32
		uid    uint32
		sticky bool
		want   string // "" passes
	}{
		{"root's, 0755", modeFolder | 0o755, 0, false, ""},
		{"the owner's, 0700", modeFolder | 0o700, owner, false, ""},
		{"someone else's", modeFolder | 0o755, 65531, false, "belongs to uid 65531"},
		{"group can write", modeFolder | 0o775, 0, false, "can be written by others"},
		{"anyone can write (an emptyDir)", modeFolder | 0o777, 0, false, "can be written by others"},
		{"sticky, where sticky is enough", modeFolder | modeSticky | 0o777, 0, true, ""},
		{"sticky, where it is not", modeFolder | modeSticky | 0o777, 0, false, "can be written by others"},
		{"open but not sticky, where sticky is enough", modeFolder | 0o777, 0, true, "can be written by others"},
		{"not a folder", 0o100000 | 0o644, 0, false, "not a folder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFolder("/x", tc.mode, tc.uid, owner, tc.sticky)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CheckFolder = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestContainerRootReads lists what a container makes root read, so the
// gate can check each on disk.
func TestContainerRootReads(t *testing.T) {
	runcOpts := func(o *runcoptions.Options) Runtime {
		b, err := proto.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		return Runtime{Name: RuntimeRunc, OptionsTypeURL: "containerd.runc.v1.Options", Options: b}
	}
	for _, tc := range []struct {
		name string
		c    func() Container
		want []RootRead
	}{
		{"a runc sandbox reads nothing extra", func() Container { return baselineContainer(t, baselineSpec(t)) }, nil},
		{"a moved gVisor sandbox: its config and its restore image", func() Container {
			c := baselineContainer(t, gvisorSpec(t))
			c.Runtime = runscRuntime(t, &runtimeoptions.Options{TypeUrl: RunscOptionsTypeURL, ConfigPath: testRestore})
			return c
		}, []RootRead{
			{Path: testRestore, Rule: RuleRuntimeOptions},
			{Path: testMoves + "/in/" + testID, Folder: true, Rule: RuleCheckpoint},
		}},
		{"runc checkpoint folders", func() Container {
			c := baselineContainer(t, baselineSpec(t))
			c.Runtime = runcOpts(&runcoptions.Options{CriuImagePath: testMoves + "/a", CriuWorkPath: testMoves + "/w"})
			return c
		}, []RootRead{
			{Path: testMoves + "/a", Folder: true, Rule: RuleCheckpoint},
			{Path: testMoves + "/w", Folder: true, Rule: RuleCheckpoint},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ContainerRootReads(tc.c())
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("reads %+v, want %+v", got, tc.want)
			}
		})
	}
	for name, c := range map[string]Container{
		"runsc options that do not decode": {Runtime: Runtime{Name: RuntimeRunsc, OptionsTypeURL: "runtimeoptions.v1.Options", Options: []byte{0xff}}},
		"runc options that do not decode":  {Runtime: Runtime{Name: RuntimeRunc, OptionsTypeURL: "containerd.runc.v1.Options", Options: []byte{0xff}}},
		"a spec that does not decode":      {Runtime: Runtime{Name: RuntimeRunc}, Spec: []byte("{")},
	} {
		if _, err := ContainerRootReads(c); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
