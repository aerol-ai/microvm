package containerd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/runscwrap"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/internal/runtime/movebundle"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stubRunsc replaces the runsc the driver runs. write, when set, is what a
// checkpoint leaves in its --image-path.
func stubRunsc(t *testing.T, err error, write map[string]string) *[][]string {
	t.Helper()
	var calls [][]string
	orig := runscCommandFn
	runscCommandFn = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		for _, a := range args {
			if dir, ok := strings.CutPrefix(a, "--image-path="); ok {
				for name, body := range write {
					_ = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
				}
			}
		}
		if err != nil {
			return []byte("runsc: it broke"), err
		}
		return nil, nil
	}
	t.Cleanup(func() { runscCommandFn = orig })
	return &calls
}

func gvisorContainer(id string) *fakeContainer {
	return &fakeContainer{id: id, runtime: containers.RuntimeInfo{Name: runscShimName}, task: &fakeTask{status: cntr.Running}}
}

func driverWith(t *testing.T, cs ...*fakeContainer) (*Driver, *fakeTransport) {
	t.Helper()
	d := newTestDriver(t)
	tr := newFakeTransport()
	for _, c := range cs {
		tr.containers[c.id] = c
	}
	d.SetClient(NewTestClient("aerolvm", tr))
	return d, tr
}

var savedCheckpoint = map[string]string{runscwrap.CheckpointFile: "state", "pages.img": strings.Repeat("p", 5000), "pages_meta.img": "m"}

// A move's stop saves the running gVisor sandbox with runsc, on the shim's
// state root, then reaps the task; the target stages what the source
// exports, and a dropped move leaves nothing there.
func TestCheckpointMoveSourceToTarget(t *testing.T) {
	stubToolboxProbe(t)
	ctx := context.Background()
	c := gvisorContainer("sb-g")
	c.labels = map[string]string{containerIPLabelKey: "10.88.0.9"}
	src, _ := driverWith(t, c)
	calls := stubRunsc(t, nil, savedCheckpoint)

	if err := src.Stop(sbruntime.WithCheckpoint(ctx), "sb-g"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	out := src.moveDir(moveOut, "sb-g")
	want := []string{"--root=/run/containerd/runsc/aerolvm", "checkpoint", "--image-path=" + out, "sb-g"}
	if len(*calls) != 1 || !slices.Equal((*calls)[0], want) {
		t.Fatalf("runsc %q, want %q", *calls, want)
	}
	if c.task.deletes == 0 || c.task.killed != 0 {
		t.Fatalf("task: %d deletes, %d kills; want reaped, not killed", c.task.deletes, c.task.killed)
	}
	var bundle bytes.Buffer
	if err := src.ExportSandboxSnapshot(ctx, "sb-g", &bundle); err != nil {
		t.Fatal(err)
	}

	dst, _ := driverWith(t)
	if err := dst.ImportSandboxSnapshot(ctx, "sb-g", bytes.NewReader(bundle.Bytes())); err != nil {
		t.Fatal(err)
	}
	if !dst.staged("sb-g") {
		t.Fatal("nothing staged")
	}
	got, _ := os.ReadFile(filepath.Join(dst.moveDir(moveIn, "sb-g"), "pages.img"))
	if string(got) != savedCheckpoint["pages.img"] {
		t.Fatalf("pages: %d bytes", len(got))
	}
	// An import again replaces what was staged.
	if err := dst.ImportSandboxSnapshot(ctx, "sb-g", bytes.NewReader(bundle.Bytes())); err != nil {
		t.Fatal(err)
	}
	if err := dst.DropImportedSnapshot(ctx, "sb-g"); err != nil || dst.staged("sb-g") {
		t.Fatalf("drop: %v, staged %v", err, dst.staged("sb-g"))
	}
	// A start on the source makes its checkpoint stale.
	if _, err := src.Start(ctx, "sb-g"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if runscwrap.HasCheckpoint(out) {
		t.Fatal("a start kept the stale checkpoint")
	}
	if err := src.ExportSandboxSnapshot(ctx, "sb-g", &bytes.Buffer{}); err == nil {
		t.Fatal("exported a checkpoint that is gone")
	}
}

func TestCheckpointRefusals(t *testing.T) {
	ctx := sbruntime.WithCheckpoint(context.Background())
	parked := gvisorContainer("sb-p")
	parked.specOverride = &oci.Spec{Process: &specs.Process{Env: []string{"SB_POOL_PARKED=1"}}}
	stopped := gvisorContainer("sb-s")
	stopped.task.status = cntr.Stopped
	noTask := gvisorContainer("sb-n")
	noTask.taskErr = errdefs.ErrNotFound
	for _, tc := range []struct {
		name  string
		c     *fakeContainer
		err   error
		write map[string]string
		want  error
	}{
		{"a runc sandbox", &fakeContainer{id: "sb-r", runtime: containers.RuntimeInfo{Name: "io.containerd.runc.v2"}, task: &fakeTask{status: cntr.Running}}, nil, savedCheckpoint, errNotCheckpointable},
		{"a stopped sandbox", stopped, nil, savedCheckpoint, errNotCheckpointable},
		{"no task", noTask, nil, savedCheckpoint, errNotCheckpointable},
		{"a warm-pool sandbox", parked, nil, savedCheckpoint, errWarmPoolMove},
		{"runsc fails", gvisorContainer("sb-f"), errors.New("exit status 1"), savedCheckpoint, nil},
		{"runsc writes nothing", gvisorContainer("sb-e"), nil, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := driverWith(t, tc.c)
			stubRunsc(t, tc.err, tc.write)
			err := d.Stop(ctx, tc.c.id)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("stop = %v, want %v", err, tc.want)
			}
			if runscwrap.HasCheckpoint(d.moveDir(moveOut, tc.c.id)) {
				t.Fatal("a failed checkpoint left files")
			}
			if tc.c.task != nil && tc.c.task.deletes != 0 {
				t.Fatal("a refused checkpoint stopped the sandbox")
			}
		})
	}
	// A plain stop of a sandbox with no task is fine, as before.
	d, _ := driverWith(t, func() *fakeContainer { c := gvisorContainer("sb-x"); c.taskErr = errdefs.ErrNotFound; return c }())
	if err := d.Stop(context.Background(), "sb-x"); err != nil {
		t.Fatal(err)
	}
}

func TestMoveBundleRefusals(t *testing.T) {
	ctx := context.Background()
	d, _ := driverWith(t)
	if err := d.ExportSandboxSnapshot(ctx, "../x", &bytes.Buffer{}); err == nil {
		t.Fatal("exported a bad id")
	}
	if err := d.ImportSandboxSnapshot(ctx, "../x", strings.NewReader("")); err == nil {
		t.Fatal("imported a bad id")
	}
	if err := d.DropImportedSnapshot(ctx, "../x"); err == nil {
		t.Fatal("dropped a bad id")
	}
	if err := d.ImportSandboxSnapshot(ctx, "sb-1", strings.NewReader("not a tar")); err == nil || d.staged("sb-1") {
		t.Fatal("imported garbage")
	}
	// A bundle of files without the checkpoint itself.
	only := t.TempDir()
	if err := os.WriteFile(filepath.Join(only, "pages.img"), []byte("p"), 0o600); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := movebundle.WriteDir(ctx, &b, only, "sb-1"); err != nil {
		t.Fatal(err)
	}
	if err := d.ImportSandboxSnapshot(ctx, "sb-1", &b); err == nil || d.staged("sb-1") {
		t.Fatal("imported a bundle with no checkpoint")
	}
	entries, _ := os.ReadDir(filepath.Join(d.runDir(), movesDirName, moveIn))
	if len(entries) != 0 {
		t.Fatalf("failed imports left %d entries", len(entries))
	}
}

// captureRuntime makes the fake's NewContainer keep the shim it was given.
func captureRuntime(tr *fakeTransport) {
	tr.newContainerFn = func(ctx context.Context, id string, opts ...cntr.NewContainerOpts) (cntr.Container, error) {
		var info containers.Container
		for _, o := range opts {
			func() {
				defer func() { _ = recover() }() // spec options need a live client
				_ = o(ctx, nil, &info)
			}()
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		if _, exists := tr.containers[id]; exists {
			return nil, errdefs.ErrAlreadyExists
		}
		c := &fakeContainer{id: id, labels: info.Labels, runtime: info.Runtime}
		tr.containers[id] = c
		return c, nil
	}
}

// A move's recreate builds the container as any create does, with the shim
// running aerolvm-runsc and the spec naming the staged checkpoint; the
// checkpoint is gone once the sandbox runs.
func TestCreateRestoresAStagedCheckpoint(t *testing.T) {
	stubToolboxProbe(t)
	ctx := sbruntime.WithRestore(context.Background())
	d, tr := driverWith(t)
	captureRuntime(tr)
	req := models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeGvisor, ContainerCommand: []string{"sleep", "inf"}}

	if _, err := d.Create(ctx, req, "sb-m", "tok", nil); err == nil {
		t.Fatal("restored with nothing staged")
	}
	dir := d.moveDir(moveIn, "sb-m")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, runscwrap.CheckpointFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	runc := req
	runc.Runtime = models.RuntimeDocker
	if _, err := d.Create(ctx, runc, "sb-m", "tok", nil); err == nil {
		t.Fatal("restored a runc sandbox")
	}
	state, err := d.Create(ctx, req, "sb-m", "tok", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if state.ContainerIP != "10.88.0.9" {
		t.Fatalf("address %q", state.ContainerIP)
	}
	rt := tr.containers["sb-m"].runtime
	if rt.Name != runscShimName {
		t.Fatalf("shim %q", rt.Name)
	}
	var opts runtimeoptions.Options
	if err := typeurl.UnmarshalTo(rt.Options, &opts); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(opts.ConfigPath, runscRestoreConfigRelPath) {
		t.Fatalf("shim config %q", opts.ConfigPath)
	}
	body, _ := os.ReadFile(opts.ConfigPath)
	if !strings.Contains(string(body), `binary_name = "/usr/local/bin/aerolvm-runsc"`) || !strings.Contains(string(body), runscFlagsSection) {
		t.Fatalf("restore config:\n%s", body)
	}
	if d.staged("sb-m") {
		t.Fatal("the used checkpoint stayed")
	}
	// The spec names the checkpoint for the wrapper.
	var spec oci.Spec
	if err := d.restoreSpecOpt("sb-m")(context.Background(), nil, nil, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Annotations[runscwrap.RestoreAnnotation] != dir {
		t.Fatalf("annotations %v", spec.Annotations)
	}
	// Deleted, the sandbox takes its move files with it.
	if err := os.MkdirAll(d.moveDir(moveOut, "sb-m"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-m"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.moveDir(moveOut, "sb-m")); !os.IsNotExist(err) {
		t.Fatal("destroy kept the move files")
	}
}
