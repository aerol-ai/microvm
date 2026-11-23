package containerd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"

	"github.com/aerol-ai/microvm/internal/rootclient"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/internal/runscwrap"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/runtime/movebundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// moveSide is one real helper with gVisor moves on (M1 PR 13): its runsc is
// a script that saves a checkpoint's files into the image path and notes
// its arguments, and its client is the agent's real one.
type moveSide struct {
	client *rootclient.Client
	moves  string
	log    string
}

func startMoveHelper(t *testing.T) moveSide {
	t.Helper()
	var s moveSide
	bin := t.TempDir()
	s.log = filepath.Join(bin, "runsc.log")
	script := "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --image-path=*) d=\"${a#--image-path=}\";; esac; done\n" +
		"echo \"$@\" >> " + s.log + "\nprintf state > \"$d/checkpoint.img\"\nprintf memory > \"$d/pages.img\"\n"
	if err := os.WriteFile(filepath.Join(bin, "runsc"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s.client = startHelperWith(t, func(c *rootd.Config, _ *rootd.Options) {
		s.moves = c.Policy.MovesDir
		c.Moves = &rootd.MovesConfig{Runsc: filepath.Join(bin, "runsc"), StateRoot: "/run/containerd/runsc", MaxBundleBytes: 1 << 20, MaxStaged: 4}
	})
	return s
}

// splitMoveDriver is a split driver over a fake containerd holding cs,
// taking its move calls from m.
func splitMoveDriver(t *testing.T, m MoveHelper, cs ...*fakeContainer) (*Driver, *fakeTransport) {
	t.Helper()
	d, tr := driverWith(t, cs...)
	d.SetRootHelper(newPartsHelper(t))
	d.SetMoveHelper(m)
	return d, tr
}

// TestSplitMoveThroughTheRealHelper: a split node's move stop has the helper
// checkpoint the sandbox into its own moves folder, the export sends that
// checkpoint as a move bundle, the target's helper stages it, and the
// restore's create names that staged checkpoint, which the gate takes for
// that container only; the used checkpoint is dropped. The agent's own run
// dir holds no move file at any step.
func TestSplitMoveThroughTheRealHelper(t *testing.T) {
	stubToolboxProbe(t)
	noHostNaming(t)
	ctx := context.Background()
	src, dst := startMoveHelper(t), startMoveHelper(t)
	c := gvisorContainer("sb-g")
	c.labels = map[string]string{containerIPLabelKey: "10.88.0.9"}
	from, _ := splitMoveDriver(t, src.client, c)
	if err := from.Stop(sbruntime.WithCheckpoint(ctx), "sb-g"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	ran, _ := os.ReadFile(src.log)
	if got := strings.TrimSpace(string(ran)); got != "--root=/run/containerd/runsc/aerolvm checkpoint --image-path="+filepath.Join(src.moves, "out", "sb-g")+" sb-g" {
		t.Fatalf("runsc ran with %q", got)
	}
	if c.task.deletes == 0 {
		t.Fatal("the task was not reaped")
	}
	var bundle bytes.Buffer
	if err := from.ExportSandboxSnapshot(ctx, "sb-g", &bundle); err != nil {
		t.Fatal(err)
	}
	if m, err := movebundle.ReadDir(ctx, bytes.NewReader(bundle.Bytes()), t.TempDir(), "sb-g"); err != nil || !slices.Equal(m.Files, []string{runscwrap.CheckpointFile, "pages.img"}) {
		t.Fatalf("the export is not a move bundle: %v %v", m, err)
	}

	r := newSplitCreateRig(t)
	r.d.SetMoveHelper(dst.client)
	if err := r.d.ImportSandboxSnapshot(ctx, "sb-g", bytes.NewReader(bundle.Bytes())); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dst.moves, "in", "sb-g")
	if b, err := os.ReadFile(filepath.Join(staged, "pages.img")); err != nil || string(b) != "memory" {
		t.Fatalf("staged: %q %v", b, err)
	}
	if _, err := r.d.Create(sbruntime.WithRestore(ctx), models.CreateSandboxRequest{Image: "cfg:test", Runtime: models.RuntimeGvisor}, "sb-g", "tok", nil); err != nil {
		t.Fatalf("restore: %v", err)
	}
	spec := r.specs.last(t)
	if got := spec.Annotations[runscwrap.RestoreAnnotation]; got != staged {
		t.Fatalf("the restore names %q, want %q", got, staged)
	}
	if got := r.h.prepares[0].GetSetup().GetRunscConfig(); got != rootdpb.RunscConfig_RUNSC_CONFIG_RESTORE {
		t.Fatalf("the restore's runsc config is %v", got)
	}
	p := rootpolicy.Policy{MovesDir: dst.moves}
	if err := rootpolicy.CheckRestorePath(p, "sb-g", spec.Annotations[runscwrap.RestoreAnnotation]); err != nil {
		t.Fatalf("the gate would refuse the restore: %v", err)
	}
	if err := rootpolicy.CheckRestorePath(p, "sb-other", spec.Annotations[runscwrap.RestoreAnnotation]); err == nil {
		t.Fatal("the gate would let another container restore it")
	}
	if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the used checkpoint stayed: %v", err)
	}
	for _, d := range []*Driver{from, r.d} {
		if _, err := os.Stat(filepath.Join(d.runDir(), movesDirName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a split driver made move files of its own: %v", err)
		}
	}
	// A start of the source container makes its checkpoint stale: the
	// helper drops it.
	if _, err := from.Start(ctx, "sb-g"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src.moves, "out", "sb-g")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a start kept the stale checkpoint: %v", err)
	}
}

// TestSplitAndSingleMoveToEachOther: the bundle is one format, so a
// single node's export stages on a split node, and a split node's on a
// single node.
func TestSplitAndSingleMoveToEachOther(t *testing.T) {
	stubToolboxProbe(t)
	ctx := context.Background()
	helper := startMoveHelper(t)

	single, _ := driverWith(t, gvisorContainer("sb-s"))
	stubRunsc(t, nil, savedCheckpoint)
	if err := single.Stop(sbruntime.WithCheckpoint(ctx), "sb-s"); err != nil {
		t.Fatal(err)
	}
	var fromSingle bytes.Buffer
	if err := single.ExportSandboxSnapshot(ctx, "sb-s", &fromSingle); err != nil {
		t.Fatal(err)
	}
	split, _ := splitMoveDriver(t, helper.client, gvisorContainer("sb-t"))
	if err := split.ImportSandboxSnapshot(ctx, "sb-s", &fromSingle); err != nil {
		t.Fatalf("a split node took no single node's bundle: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(helper.moves, "in", "sb-s", "pages.img")); err != nil || string(b) != savedCheckpoint["pages.img"] {
		t.Fatalf("staged %d bytes, %v", len(b), err)
	}

	if err := split.Stop(sbruntime.WithCheckpoint(ctx), "sb-t"); err != nil {
		t.Fatal(err)
	}
	var fromSplit bytes.Buffer
	if err := split.ExportSandboxSnapshot(ctx, "sb-t", &fromSplit); err != nil {
		t.Fatal(err)
	}
	other, _ := driverWith(t)
	if err := other.ImportSandboxSnapshot(ctx, "sb-t", &fromSplit); err != nil || !other.staged("sb-t") {
		t.Fatalf("a single node took no split node's bundle: %v", err)
	}
}

// recordingMoves records the move calls a split driver makes.
type recordingMoves struct {
	mu     sync.Mutex
	calls  []string
	staged string
	err    error
}

func (m *recordingMoves) note(s string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, s)
	return m.err
}

func (m *recordingMoves) CheckpointMove(_ context.Context, id string) error {
	return m.note("checkpoint " + id)
}
func (m *recordingMoves) ExportMove(_ context.Context, id string, _ io.Writer) error {
	return m.note("export " + id)
}
func (m *recordingMoves) ImportMove(_ context.Context, id string, _ io.Reader) (string, error) {
	return "", m.note("import " + id)
}
func (m *recordingMoves) StagedMove(_ context.Context, id string) (string, error) {
	return m.staged, m.note("staged " + id)
}
func (m *recordingMoves) DropMove(_ context.Context, id string, sides ...rootdpb.MoveSide) error {
	var s []string
	for _, side := range sides {
		s = append(s, side.String())
	}
	return m.note("drop " + id + " " + strings.Join(s, ","))
}

func (m *recordingMoves) seen() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

// TestSplitMoveCalls: what a split driver asks of the helper, and when:
// a stale checkpoint goes on a gVisor start only, both sides with a
// gVisor sandbox's destroy only; a helper's failure is the call's.
func TestSplitMoveCalls(t *testing.T) {
	stubToolboxProbe(t)
	ctx := context.Background()
	m := &recordingMoves{}
	runc := &fakeContainer{id: "sb-r", runtime: containers.RuntimeInfo{Name: "io.containerd.runc.v2"}, task: &fakeTask{status: cntr.Stopped},
		labels: map[string]string{containerIPLabelKey: "10.88.0.9"}}
	gv := gvisorContainer("sb-g")
	gv.task.status, gv.labels = cntr.Stopped, map[string]string{containerIPLabelKey: "10.88.0.9"}
	d, _ := splitMoveDriver(t, m, runc, gv)
	for _, id := range []string{"sb-r", "sb-g"} {
		if _, err := d.Start(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.seen(); !slices.Equal(got, []string{"drop sb-g MOVE_SIDE_OUT"}) {
		t.Fatalf("starts asked %v", got)
	}
	for _, sb := range []*models.Sandbox{{ID: "sb-r", Runtime: models.RuntimeDocker}, {ID: "sb-g", Runtime: models.RuntimeGvisor}} {
		if err := d.Destroy(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.seen(); !slices.Equal(got[1:], []string{"drop sb-g MOVE_SIDE_OUT,MOVE_SIDE_IN"}) {
		t.Fatalf("destroys asked %v", got[1:])
	}
	if err := d.DropImportedSnapshot(ctx, "sb-g"); err != nil {
		t.Fatal(err)
	}
	m.err = errors.New("root helper unavailable")
	if err := d.ExportSandboxSnapshot(ctx, "sb-g", io.Discard); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("export = %v", err)
	}
	if err := d.ImportSandboxSnapshot(ctx, "sb-g", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("import = %v", err)
	}
	live := gvisorContainer("sb-l")
	d2, _ := splitMoveDriver(t, m, live)
	if err := d2.Stop(sbruntime.WithCheckpoint(ctx), "sb-l"); err == nil || !strings.Contains(err.Error(), "unavailable") || live.task.deletes != 0 {
		t.Fatalf("a failed checkpoint: %v, task deleted %d times", err, live.task.deletes)
	}
	// A failed drop is the sweep's to finish: a destroy still goes on.
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-g", Runtime: models.RuntimeGvisor}); err != nil {
		t.Fatal(err)
	}
	// A hostile ID reaches no helper.
	before := len(m.seen())
	for _, id := range []string{"../x", "a/b"} {
		if err := d.ExportSandboxSnapshot(ctx, id, io.Discard); err == nil {
			t.Fatalf("export %q", id)
		}
		if err := d.ImportSandboxSnapshot(ctx, id, strings.NewReader("")); err == nil {
			t.Fatalf("import %q", id)
		}
		if err := d.DropImportedSnapshot(ctx, id); err == nil {
			t.Fatalf("drop %q", id)
		}
		d.splitDropMove(ctx, id, rootdpb.MoveSide_MOVE_SIDE_IN)
	}
	if got := m.seen(); len(got) != before {
		t.Fatalf("hostile IDs reached the helper: %v", got[before:])
	}
}

// TestSplitRestoreNeedsAStagedCheckpoint: a split restore names only a
// checkpoint the helper says it staged, and a split node with no move
// calls wired moves nothing.
func TestSplitRestoreNeedsAStagedCheckpoint(t *testing.T) {
	ctx := sbruntime.WithRestore(context.Background())
	req := models.CreateSandboxRequest{Image: "cfg:test", Runtime: models.RuntimeGvisor}
	r := newSplitCreateRig(t)
	m := &recordingMoves{}
	r.d.SetMoveHelper(m)
	if _, err := r.d.Create(ctx, req, "sb-1", "tok", nil); err == nil || !strings.Contains(err.Error(), "no gVisor checkpoint is staged") {
		t.Fatalf("restore with nothing staged: %v", err)
	}
	m.err = errors.New("root helper unavailable")
	if _, err := r.d.Create(ctx, req, "sb-1", "tok", nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("restore with the helper down: %v", err)
	}
	runc := req
	runc.Runtime = models.RuntimeDocker
	if _, err := r.d.Create(ctx, runc, "sb-1", "tok", nil); err == nil || !strings.Contains(err.Error(), "no gVisor checkpoint is staged") {
		t.Fatalf("a runc restore: %v", err)
	}
	if len(r.snap.prepared) != 0 {
		t.Fatal("a refused restore prepared a snapshot")
	}

	none, _ := splitMoveDriver(t, nil, gvisorContainer("sb-n"))
	none.SetMoveHelper(nil)
	for name, err := range map[string]error{
		"checkpoint": none.Stop(sbruntime.WithCheckpoint(context.Background()), "sb-n"),
		"export":     none.ExportSandboxSnapshot(context.Background(), "sb-n", io.Discard),
		"import":     none.ImportSandboxSnapshot(context.Background(), "sb-n", strings.NewReader("")),
		"drop":       none.DropImportedSnapshot(context.Background(), "sb-n"),
	} {
		if !errors.Is(err, errSplitNoMoves) {
			t.Fatalf("%s with no move calls: %v", name, err)
		}
	}
	if _, err := none.restoreSpec(context.Background(), "sb-n"); !errors.Is(err, errSplitNoMoves) {
		t.Fatalf("restore with no move calls: %v", err)
	}
	none.splitStaleCheckpoint(context.Background(), nil)
}
