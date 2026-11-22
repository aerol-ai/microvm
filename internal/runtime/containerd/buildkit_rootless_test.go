package containerd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
)

// fakeArchiveImporter stands in for the driver's import of a rootless
// build: read takes what buildctl streams, and the import then asks
// finished, as the driver does before it names the image.
type fakeArchiveImporter struct {
	read     func(io.Reader) error
	ref      string
	max      int64
	got      []byte
	finished bool
}

func (f *fakeArchiveImporter) ImportBuildArchive(_ context.Context, ref string, r io.Reader, max int64, finished func() error) error {
	f.ref, f.max = ref, max
	read := f.read
	if read == nil {
		read = func(r io.Reader) error {
			var err error
			f.got, err = io.ReadAll(r)
			return err
		}
	}
	if err := read(r); err != nil {
		return err
	}
	f.finished = true
	return finished()
}

// writeScriptBuildctl writes a stand-in buildctl that records its
// arguments in dir/args and then runs body.
func writeScriptBuildctl(t *testing.T, body string) (path, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	path = filepath.Join(dir, "buildctl")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, argsFile
}

func readArgs(t *testing.T, argsFile string) string {
	t.Helper()
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func rootlessRequest() docker.BuildImageRequest {
	return docker.BuildImageRequest{Tag: builtTag, DockerfileContent: "FROM alpine\nRUN true"}
}

// A rootless build asks buildctl for an OCI archive on stdout, never for an
// image in containerd, and hands every byte to the importer, with the
// build's tag and the node's bound.
func TestBuildKitBuilderRootlessImportsTheArchive(t *testing.T) {
	path, argsFile := writeScriptBuildctl(t, "printf 'archive-bytes'")
	imp := &fakeArchiveImporter{}
	b := NewBuildKitBuilder("unix:///run/aerolvm-buildkit/buildkitd.sock", path, nil).WithArchiveImport(imp, 1234)
	if !b.ImportsArchives() {
		t.Fatal("ImportsArchives = false after WithArchiveImport")
	}
	if err := b.BuildImage(context.Background(), rootlessRequest()); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if string(imp.got) != "archive-bytes" || imp.ref != builtTag || imp.max != 1234 || !imp.finished {
		t.Fatalf("importer got %q ref %q max %d finished %v", imp.got, imp.ref, imp.max, imp.finished)
	}
	args := readArgs(t, argsFile)
	if !strings.Contains(args, "--output type=oci,dest=-") || strings.Contains(args, "type=image") || strings.Contains(args, builtTag) {
		t.Fatalf("buildctl args %q: want an OCI archive on stdout and no image name", args)
	}
	if !strings.Contains(args, "--addr unix:///run/aerolvm-buildkit/buildkitd.sock") {
		t.Fatalf("buildctl args %q: want the rootless socket", args)
	}
}

// The root buildkitd's path is unchanged: its containerd worker names and
// unpacks the image.
func TestBuildKitBuilderRootKeepsTheContainerdWorker(t *testing.T) {
	path, argsFile := writeScriptBuildctl(t, "exit 0")
	b := NewBuildKitBuilder("", path, nil)
	if b.ImportsArchives() {
		t.Fatal("a root builder imports archives")
	}
	if err := b.BuildImage(context.Background(), rootlessRequest()); err != nil {
		t.Fatalf("BuildImage: %v", err)
	}
	if args := readArgs(t, argsFile); !strings.Contains(args, "--output type=image,name="+builtTag+",unpack=true") {
		t.Fatalf("buildctl args %q", args)
	}
}

func TestBuildKitBuilderRootlessFailures(t *testing.T) {
	boom := errors.New("not an OCI image layout")
	cases := []struct {
		name string
		body string
		read func(io.Reader) error
		want []string
		not  []string
	}{
		{
			// A RUN step failed: buildctl writes no archive and says why,
			// and that is the error reported, not the empty archive's.
			name: "buildctl fails before the archive",
			body: "echo 'process \"/bin/sh -c false\" did not complete successfully' 1>&2\nexit 1",
			read: func(r io.Reader) error { _, _ = io.ReadAll(r); return boom },
			want: []string{"did not complete successfully"},
			not:  []string{"OCI image layout"},
		},
		{
			// The archive was read, but buildctl then failed: the image is
			// not named (finished returns buildctl's error).
			name: "buildctl fails after the archive",
			body: "printf 'archive'\necho 'error: session closed' 1>&2\nexit 1",
			want: []string{"session closed"},
		},
		{
			// The importer refuses the archive while buildctl still writes:
			// buildctl is stopped and the import's reason is reported.
			name: "the import refuses a stream still running",
			body: "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done",
			read: func(r io.Reader) error {
				_, _ = io.ReadFull(r, make([]byte, 4096))
				return boom
			},
			want: []string{"import the image", "not an OCI image layout"},
		},
		{
			// More than a tar's padding after the archive's end.
			name: "output past the archive",
			body: "head -c 200000 /dev/zero",
			read: func(r io.Reader) error { _, err := io.ReadFull(r, make([]byte, 10)); return err },
			want: []string{"past the end of the image archive"},
		},
	}
	orig := buildctlWaitDelay
	buildctlWaitDelay = 100 * time.Millisecond
	t.Cleanup(func() { buildctlWaitDelay = orig })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := writeScriptBuildctl(t, tc.body)
			imp := &fakeArchiveImporter{read: tc.read}
			b := NewBuildKitBuilder("", path, nil).WithArchiveImport(imp, 1<<20)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := b.BuildImage(ctx, rootlessRequest())
			if err == nil {
				t.Fatal("BuildImage succeeded")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("err = %v, want %q", err, w)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(err.Error(), n) {
					t.Fatalf("err = %v, must not say %q", err, n)
				}
			}
			if ctx.Err() != nil {
				t.Fatal("BuildImage only returned at the test's deadline: buildctl was not stopped")
			}
		})
	}
}

func TestBuildKitBuilderRootlessBuildctlMissing(t *testing.T) {
	b := NewBuildKitBuilder("", filepath.Join(t.TempDir(), "no-buildctl"), nil).WithArchiveImport(&fakeArchiveImporter{}, 1)
	if err := b.BuildImage(context.Background(), rootlessRequest()); err == nil || !strings.Contains(err.Error(), "buildctl build") {
		t.Fatalf("err = %v", err)
	}
}
