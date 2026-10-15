package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeBuilder records what the service asks of the engine's builder.
type fakeBuilder struct {
	exists      map[string]bool
	existsErr   error
	builds      []docker.BuildImageRequest
	deadlines   []bool
	buildErr    error
	pushes      []docker.PushImageRequest
	pushErr     error
	refreshes   []string
	removes     []string
	refreshFail error
}

func (f *fakeBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	f.builds = append(f.builds, req)
	_, hasDeadline := ctx.Deadline()
	f.deadlines = append(f.deadlines, hasDeadline)
	if f.buildErr != nil {
		return f.buildErr
	}
	if f.exists == nil {
		f.exists = map[string]bool{}
	}
	f.exists[req.Tag] = true
	return nil
}

func (f *fakeBuilder) ImageExists(_ context.Context, ref string) (bool, error) {
	return f.exists[ref], f.existsErr
}

func (f *fakeBuilder) PushImage(_ context.Context, req docker.PushImageRequest) (string, error) {
	f.pushes = append(f.pushes, req)
	return req.DestRef, f.pushErr
}

func (f *fakeBuilder) RefreshTag(_ context.Context, ref string) error {
	f.refreshes = append(f.refreshes, ref)
	return f.refreshFail
}

func (f *fakeBuilder) RemoveImage(_ context.Context, ref string) error {
	f.removes = append(f.removes, ref)
	return nil
}

// newBuildService is a service with a real store (snapshot names, the GC
// ledger) building through builder.
func newBuildService(t *testing.T, cfg config.Config, builder ImageBuilder) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := &Service{cfg: cfg, store: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if builder != nil {
		svc.SetImageBuilder(builder)
	}
	return svc, st
}

// A build is tagged for its caller: an operator's as before, a tenant's
// under its owner namespace — so two tenants building one Dockerfile get two
// tags and the cache never hands one tenant the other's result — and, in a
// cluster, bound to the node that built it. A tenant's build always pulls.
func TestBuildImageTagsByOwner(t *testing.T) {
	builder := &fakeBuilder{}
	svc, _ := newBuildService(t, config.Config{}, builder)
	const dockerfile = "FROM python:3.12\nRUN pip install requests"

	op, err := svc.BuildImage(operatorCtx(), BuildImageRequest{Dockerfile: dockerfile})
	if err != nil || op.Image != docker.BuildTagFor(dockerfile, nil) || !op.Fresh || builder.builds[0].ForcePull {
		t.Fatalf("operator build = %+v, %v (force pull %v)", op, err, builder.builds[0].ForcePull)
	}
	acme, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: dockerfile})
	if err != nil || acme.Image != docker.BuildTagForOwner(dockerfile, nil, "", snapshotOwnerNamespace("acme")) || !builder.builds[1].ForcePull {
		t.Fatalf("tenant build = %+v, %v", acme, err)
	}
	if docker.BuiltImageOwnerNamespace(acme.Image) != snapshotOwnerNamespace("acme") {
		t.Fatalf("tenant tag %q has no owner namespace", acme.Image)
	}
	globex, err := svc.BuildImage(userCtx("globex"), BuildImageRequest{Dockerfile: dockerfile})
	if err != nil || globex.Image == acme.Image || globex.Image == op.Image || len(builder.builds) != 3 {
		t.Fatalf("second tenant's build = %+v, %v after %d builds; want its own tag, built", globex, err, len(builder.builds))
	}
	again, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: dockerfile})
	if err != nil || again.Image != acme.Image || again.Fresh || len(builder.builds) != 3 || !slices.Contains(builder.refreshes, acme.Image) {
		t.Fatalf("cached build = %+v, %v (builds %d, refreshes %v)", again, err, len(builder.builds), builder.refreshes)
	}

	clustered, _ := newBuildService(t, config.Config{EnableCluster: true, ImageBuildTimeout: time.Minute}, builder)
	clustered.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	bound, err := clustered.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: dockerfile})
	node, ok := docker.BuiltImagePlacementNode(bound.Image)
	if err != nil || !ok || node != "node-a" || docker.BuiltImageOwnerNamespace(bound.Image) != snapshotOwnerNamespace("acme") {
		t.Fatalf("cluster build = %+v, %v (node %q %v)", bound, err, node, ok)
	}
	if !builder.deadlines[len(builder.deadlines)-1] {
		t.Fatal("a build ran without the configured timeout")
	}
}

// Every failure is one typed error, which every surface maps to one status.
func TestBuildImageErrors(t *testing.T) {
	ctx := operatorCtx()
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		builder *fakeBuilder
		req     BuildImageRequest
		want    error
	}{
		{"no dockerfile", config.Config{}, &fakeBuilder{}, BuildImageRequest{Dockerfile: "  "}, ErrBuildInvalid},
		{"context without the flag", config.Config{}, &fakeBuilder{}, BuildImageRequest{Dockerfile: "FROM a\nCOPY . /", ContextHashes: []string{"h"}}, ErrBuildInvalid},
		{"context with the flag", config.Config{ImageBuildContextEnabled: true}, &fakeBuilder{}, BuildImageRequest{Dockerfile: "FROM a\nCOPY . /", ContextHashes: []string{"h"}}, ErrBuildNotImplemented},
		{"push without a registry", config.Config{}, &fakeBuilder{}, BuildImageRequest{Dockerfile: "FROM a", Push: &ImagePush{}}, ErrBuildInvalid},
		{"push without a credential", config.Config{}, &fakeBuilder{}, BuildImageRequest{Dockerfile: "FROM a", Push: &ImagePush{Registry: "r.example/x"}}, ErrBuildInvalid},
		{"no builder", config.Config{}, nil, BuildImageRequest{Dockerfile: "FROM a\nRUN true"}, ErrBuilderUnavailable},
		{"cache check fails", config.Config{}, &fakeBuilder{existsErr: errors.New("daemon down")}, BuildImageRequest{Dockerfile: "FROM a\nRUN true"}, ErrBuildFailed},
		{"build fails", config.Config{}, &fakeBuilder{buildErr: errors.New("exit 1")}, BuildImageRequest{Dockerfile: "FROM a\nRUN true"}, ErrBuildFailed},
		{"build times out", config.Config{}, &fakeBuilder{buildErr: context.DeadlineExceeded}, BuildImageRequest{Dockerfile: "FROM a\nRUN true"}, ErrBuildTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var builder ImageBuilder
			if tc.builder != nil {
				builder = tc.builder
			}
			svc, _ := newBuildService(t, tc.cfg, builder)
			if _, err := svc.BuildImage(ctx, tc.req); !errors.Is(err, tc.want) {
				t.Fatalf("BuildImage = %v, want %v", err, tc.want)
			}
		})
	}
}

// A push that fails hands the fresh build to the image GC; a push that works
// reports where it went. Pushing always builds: the shortcut is for a plain
// pull, and a push is a copy.
func TestBuildImagePush(t *testing.T) {
	auth := models.RegistryAuth{Username: "u", Password: "p"}
	builder := &fakeBuilder{}
	svc, st := newBuildService(t, config.Config{ImageBuildGCEnabled: true}, builder)
	got, err := svc.BuildImage(operatorCtx(), BuildImageRequest{Dockerfile: "FROM alpine", BaseShortcut: true, Push: &ImagePush{Registry: "r.example/app", Tag: "v1", Auth: auth}})
	if err != nil || got.Pushed != "r.example/app:v1" || len(builder.builds) != 1 {
		t.Fatalf("push = %+v, %v (builds %d)", got, err, len(builder.builds))
	}
	failing := &fakeBuilder{pushErr: context.DeadlineExceeded}
	svc, st = newBuildService(t, config.Config{ImageBuildGCEnabled: true}, failing)
	if _, err := svc.BuildImage(operatorCtx(), BuildImageRequest{Dockerfile: "FROM alpine\nRUN true", Push: &ImagePush{Registry: "r.example/app", Auth: auth}}); !errors.Is(err, ErrBuildTimeout) {
		t.Fatalf("push timeout = %v", err)
	}
	pending, err := st.ListPendingImageGCDue(context.Background(), time.Now().Add(time.Hour), 10)
	if err != nil || len(pending) != 1 || pending[0].Image != docker.BuildTagFor("FROM alpine\nRUN true", nil) {
		t.Fatalf("pending GC after a failed push = %+v, %v", pending, err)
	}
}

// A Dockerfile that is only `FROM <image>` resolves to the image without a
// build when the caller allows it, and with no builder at all.
func TestBuildImageBaseShortcut(t *testing.T) {
	svc, _ := newBuildService(t, config.Config{}, nil)
	got, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: "# base\nFROM alpine:3.20\n", BaseShortcut: true})
	if err != nil || got.Image != "alpine:3.20" || got.Fresh {
		t.Fatalf("shortcut = %+v, %v", got, err)
	}
	if _, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: "FROM alpine:3.20"}); !errors.Is(err, ErrBuilderUnavailable) {
		t.Fatalf("no shortcut, no builder = %v", err)
	}
	for in, want := range map[string]string{"FROM a\nRUN b": "", "RUN b": "", "FROM": "", "FROM a b": "", "\n# x\nfrom  a  \n": "a"} {
		if got, ok := singleLineFrom(in); got != want || ok != (want != "") {
			t.Errorf("singleLineFrom(%q) = %q, %v", in, got, ok)
		}
	}
}

// A tenant's Dockerfile may not name an image only this node has — a
// snapshot (by name or tag), a build, an image id — anywhere a build would
// resolve one. The forced pull already keeps such a build from reading it;
// refusing up front gives a clear error instead of a pull of some public
// image with the same name. Stage names, scratch, variables and heredoc
// bodies are not references. An operator may build from anything.
func TestTenantBuildsStartFromRegistryImages(t *testing.T) {
	builder := &fakeBuilder{}
	svc, st := newBuildService(t, config.Config{}, builder)
	if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{Name: "snap-globex", Image: docker.SnapshotImageTag("snap-globex"), SourceSandboxID: "sb", OwnerRef: "globex", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	refused := []string{
		"FROM " + docker.SnapshotImageTag("snap-globex"),
		"FROM docker.io/aerolvm-snapshot/abc",
		"FROM aerolvm-build/0123456789abcdef:latest",
		"FROM snapshots/demo:v1",
		"FROM sha256:" + strings.Repeat("a", 64),
		"FROM 4f1a2b",
		"FROM --platform=linux/amd64 snap-globex:latest AS x",
		"FROM python:3.12\nCOPY --from=snap-globex / /x",
		"FROM python:3.12\nRUN --mount=type=bind,from=aerolvm-build/abc,target=/x true",
		"FROM python:3.12\nONBUILD COPY --from=4f1a / /x",
		"# syntax=aerolvm-snapshot/frontend\nFROM python:3.12",
		"FROM python:3.12\nCOPY \\\n  --from=snap-globex / /x",
	}
	for _, dockerfile := range refused {
		if _, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: dockerfile + "\nRUN true"}); !errors.Is(err, ErrBuildInvalid) {
			t.Errorf("tenant build of %q = %v; want refused", dockerfile, err)
		}
	}
	if len(builder.builds) != 0 {
		t.Fatalf("a refused build reached the builder %d times", len(builder.builds))
	}
	allowed := []string{
		"FROM python:3.12 AS base\nFROM base\nCOPY --from=base / /x\nCOPY --from=0 / /y",
		"FROM scratch\nCOPY --from=python:3.12 /usr/bin/python3 /",
		"ARG BASE=python:3.12\nFROM ${BASE}",
		"FROM python:3.12\nRUN <<EOF\nFROM aerolvm-build/abc\nEOF\nRUN true",
		"# escape=`\nFROM python:3.12\nRUN echo `\n  hi",
	}
	for _, dockerfile := range allowed {
		if _, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: dockerfile}); err != nil {
			t.Errorf("tenant build of %q = %v", dockerfile, err)
		}
	}
	if _, err := svc.BuildImage(operatorCtx(), BuildImageRequest{Dockerfile: refused[0] + "\nRUN true"}); err != nil {
		t.Fatalf("operator build from a local image = %v", err)
	}
}

// The reader finds every reference a build resolves.
func TestDockerfileImageRefs(t *testing.T) {
	got := dockerfileImageRefs(strings.Join([]string{
		"# syntax=docker/dockerfile:1",
		"# escape=\\",
		"FROM --platform=$BUILDPLATFORM golang:1.26 AS build",
		"RUN --mount=type=cache,target=/root/.cache \\",
		"    --mount=type=bind,from=tools:latest,source=/,target=/t go build",
		"FROM build AS test",
		"FROM gcr.io/distroless/static",
		"COPY --from=build /app /app",
		"COPY --chown=1 --from=helper:2 /h /h",
		"ONBUILD ADD --from=trigger:1 / /",
		"RUN cat <<-'END'",
		"FROM ignored:1",
		"END",
		"RUN <<",
	}, "\n"))
	want := []string{"docker/dockerfile:1", "golang:1.26", "tools:latest", "gcr.io/distroless/static", "helper:2", "trigger:1"}
	if !slices.Equal(got, want) {
		t.Fatalf("refs = %q\nwant  %q", got, want)
	}
}

// A snapshot built from a Dockerfile registers the build; when registration
// fails the fresh build goes to the image GC. A reserved name is refused
// before anything is built.
func TestRegisterSnapshotFromDockerfile(t *testing.T) {
	builder := &fakeBuilder{}
	svc, st := newBuildService(t, config.Config{ImageBuildGCEnabled: true}, builder)
	const dockerfile = "FROM python:3.12\nRUN pip install requests"
	snap, err := svc.RegisterSnapshotFromDockerfile(userCtx("acme"), &models.SandboxSnapshot{Name: "py-ready"}, BuildImageRequest{Dockerfile: dockerfile})
	want := docker.BuildTagForOwner(dockerfile, nil, "", snapshotOwnerNamespace("acme"))
	if err != nil || snap.Image != want || snap.OwnerRef != "acme" {
		t.Fatalf("register = %+v, %v; want image %q", snap, err, want)
	}
	if base, err := svc.RegisterSnapshotFromDockerfile(userCtx("acme"), &models.SandboxSnapshot{Name: "py-base"}, BuildImageRequest{Dockerfile: "FROM python:3.12"}); err != nil || base.Image != "python:3.12" {
		t.Fatalf("single-line register = %+v, %v", base, err)
	}
	if _, err := svc.RegisterSnapshotFromDockerfile(userCtx("globex"), &models.SandboxSnapshot{Name: "py-ready"}, BuildImageRequest{Dockerfile: dockerfile + "\nRUN true"}); !errors.Is(err, store.ErrSnapshotNameConflict) {
		t.Fatalf("taken name = %v", err)
	}
	pending, err := st.ListPendingImageGCDue(context.Background(), time.Now().Add(time.Hour), 10)
	if err != nil || len(pending) != 1 || pending[0].Image != docker.BuildTagForOwner(dockerfile+"\nRUN true", nil, "", snapshotOwnerNamespace("globex")) {
		t.Fatalf("pending GC after a failed registration = %+v, %v", pending, err)
	}
	builds := len(builder.builds)
	for _, name := range []string{"aerolvm-build/x", "aerolvm-snapshot/x", ""} {
		if _, err := svc.RegisterSnapshotFromDockerfile(userCtx("acme"), &models.SandboxSnapshot{Name: name}, BuildImageRequest{Dockerfile: dockerfile}); err == nil {
			t.Errorf("register %q succeeded", name)
		}
	}
	if _, err := svc.RegisterSnapshotFromDockerfile(userCtx("acme"), nil, BuildImageRequest{Dockerfile: dockerfile}); err == nil {
		t.Error("register without a snapshot succeeded")
	}
	if len(builder.builds) != builds {
		t.Fatalf("a refused registration built %d images", len(builder.builds)-builds)
	}
}

// A tenant starts a build only from its own namespace. A build with no owner
// in its tag (an operator's, or one from before builds had owners) is
// reachable only through a snapshot the tenant can see that holds it.
// Operators start anything.
func TestBuiltImagesBelongToTheirOwner(t *testing.T) {
	svc, st := newBuildService(t, config.Config{}, &fakeBuilder{})
	normalize := func(ctx context.Context, image string) error {
		req := models.CreateSandboxRequest{Image: image}
		return svc.NormalizeCreateImageDistribution(ctx, &req)
	}
	acme, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: "FROM alpine\nRUN true"})
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{acme.Image, "docker.io/" + acme.Image} {
		if err := normalize(userCtx("acme"), image); err != nil {
			t.Errorf("owner start of %q = %v", image, err)
		}
		if err := normalize(userCtx("globex"), image); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("other tenant start of %q = %v; want not found", image, err)
		}
		if err := normalize(operatorCtx(), image); err != nil {
			t.Errorf("operator start of %q = %v", image, err)
		}
	}
	legacy := docker.BuildTagFor("FROM alpine\nRUN legacy", nil)
	if err := normalize(userCtx("acme"), legacy); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant start of an unowned build = %v; want not found", err)
	}
	if err := st.CreateSnapshot(context.Background(), &models.SandboxSnapshot{Name: "acme-legacy", Image: legacy, OwnerRef: "acme", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{legacy, "acme-legacy"} {
		if err := normalize(userCtx("acme"), image); err != nil {
			t.Errorf("tenant start of %q through its snapshot = %v", image, err)
		}
	}
	if err := normalize(userCtx("globex"), legacy); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other tenant start of an unowned build = %v; want not found", err)
	}
	if _, err := svc.RegisterSnapshot(userCtx("globex"), &models.SandboxSnapshot{Name: "globex-legacy", Image: legacy}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other tenant registering an unowned build = %v; want not found", err)
	}
}

// logBuilder is a fakeBuilder whose builds write a log line.
type logBuilder struct{ fakeBuilder }

func (b *logBuilder) BuildImage(ctx context.Context, req docker.BuildImageRequest) error {
	if req.OnLog != nil {
		req.OnLog("step 1/2")
	}
	return b.fakeBuilder.BuildImage(ctx, req)
}

// The edges: whether a builder is wired, a cache refresh that fails (the
// build is still served), build logs, a build failing inside a snapshot
// registration, and a catalog that cannot be read while checking a
// tenant's Dockerfile or an unowned build.
func TestBuildImageEdges(t *testing.T) {
	bare, _ := newBuildService(t, config.Config{}, nil)
	if bare.ImageBuilderConfigured() {
		t.Fatal("a service with no builder reported one")
	}
	builder := &logBuilder{fakeBuilder{refreshFail: errors.New("tag gone")}}
	svc, st := newBuildService(t, config.Config{}, builder)
	if !svc.ImageBuilderConfigured() {
		t.Fatal("a wired builder was not reported")
	}
	first, err := svc.BuildImage(operatorCtx(), BuildImageRequest{Dockerfile: "FROM a\nRUN b"})
	if err != nil {
		t.Fatal(err)
	}
	if again, err := svc.BuildImage(operatorCtx(), BuildImageRequest{Dockerfile: "FROM a\nRUN b"}); err != nil || again.Image != first.Image {
		t.Fatalf("cache hit with a failing refresh = %+v, %v", again, err)
	}
	failing, _ := newBuildService(t, config.Config{}, &fakeBuilder{buildErr: errors.New("exit 1")})
	if _, err := failing.RegisterSnapshotFromDockerfile(operatorCtx(), &models.SandboxSnapshot{Name: "x"}, BuildImageRequest{Dockerfile: "FROM a\nRUN b"}); !errors.Is(err, ErrBuildFailed) {
		t.Fatalf("register with a failing build = %v", err)
	}
	_ = st.Close()
	if _, err := svc.BuildImage(userCtx("acme"), BuildImageRequest{Dockerfile: "FROM python:3.12\nRUN b"}); err == nil || errors.Is(err, ErrBuildInvalid) {
		t.Fatalf("tenant build with an unreadable catalog = %v; want the read error", err)
	}
	req := models.CreateSandboxRequest{Image: docker.BuildTagFor("FROM a\nRUN legacy", nil)}
	if err := svc.NormalizeCreateImageDistribution(userCtx("acme"), &req); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant start of an unowned build with an unreadable catalog = %v; want the read error", err)
	}
	if refs := dockerfileImageRefs("FROM --platform=linux/amd64\nONBUILD\nFROM alpine"); !slices.Equal(refs, []string{"alpine"}) {
		t.Fatalf("refs = %q", refs)
	}
}
