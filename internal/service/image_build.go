package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ImageBuilder compiles Dockerfiles into local images: the Docker engine
// client, or the containerd engine's BuildKit builder. Every API surface
// builds through Service.BuildImage, never through the builder directly, so
// a build has one owner rule, one tag scheme and one set of errors.
type ImageBuilder interface {
	BuildImage(ctx context.Context, req docker.BuildImageRequest) error
	ImageExists(ctx context.Context, imageRef string) (bool, error)
	PushImage(ctx context.Context, req docker.PushImageRequest) (string, error)
	// RefreshTag bumps a tag's last-tag time, so the built-image janitor
	// does not remove a tag a build just handed out from its cache.
	RefreshTag(ctx context.Context, fullRef string) error
	RemoveImage(ctx context.Context, imageRef string) error
}

// Build errors. The API surfaces map each to one status
// (apihttp.WriteStoreAwareError), so a build fails the same way everywhere.
var (
	// ErrBuildInvalid is a build request the daemon will not run: no
	// Dockerfile, a missing push credential, or (for a tenant) a Dockerfile
	// naming an image only this node has.
	ErrBuildInvalid = errors.New("invalid image build")
	// ErrBuildNotImplemented is a build needing context uploads, which the
	// daemon has no resolver for yet.
	ErrBuildNotImplemented = errors.New("image build context uploads are not supported on this daemon")
	// ErrBuilderUnavailable is a daemon started without an image builder.
	ErrBuilderUnavailable = errors.New("image builder is not configured on this daemon")
	// ErrBuildTimeout is a build or push that ran past the build timeout.
	ErrBuildTimeout = errors.New("image build exceeded timeout")
	// ErrBuildFailed is the engine failing a build or a push.
	ErrBuildFailed = errors.New("image build failed")
)

// BuildImageRequest is one Dockerfile build.
type BuildImageRequest struct {
	Dockerfile    string
	ContextHashes []string
	// BaseShortcut lets a Dockerfile that is only `FROM <image>` resolve to
	// that image without building: the engine pulls it like any image.
	BaseShortcut bool
	// Push, when set, copies the built image to a registry.
	Push *ImagePush
}

// ImagePush is where a build is pushed. The credential lives only for the
// request: it goes to the engine and is never stored.
type ImagePush struct {
	Registry string
	Tag      string
	Auth     models.RegistryAuth
}

// BuiltImage is a build's result.
type BuiltImage struct {
	// Image is the image to start: the built tag, or the base image under
	// BaseShortcut.
	Image string
	// Fresh reports that this call built Image (not the cache, not the
	// shortcut): the tag to hand to DiscardBuiltImage if the next step
	// fails.
	Fresh bool
	// Pushed is the registry ref the build was pushed to, if any.
	Pushed string
}

// SetImageBuilder wires the engine's image builder. A daemon without one
// answers every build with ErrBuilderUnavailable.
func (s *Service) SetImageBuilder(builder ImageBuilder) {
	s.imageBuilderMu.Lock()
	defer s.imageBuilderMu.Unlock()
	s.imageBuilder = builder
}

func (s *Service) builder() ImageBuilder {
	s.imageBuilderMu.RLock()
	defer s.imageBuilderMu.RUnlock()
	return s.imageBuilder
}

// ImageBuilderConfigured reports whether builds can run on this daemon.
func (s *Service) ImageBuilderConfigured() bool {
	return s.builder() != nil
}

// BuildImage builds a Dockerfile into a local image tagged for its caller.
//
// The tag is content-addressed (a retry, or the same Dockerfile again, is
// served from the cache), bound to this node in a cluster (the create that
// uses it is routed back here), and, for a user token, under the caller's
// owner namespace: one tenant's build is never another's tag, so neither
// starting it by name nor the build cache crosses tenants.
//
// A user token's build resolves every image it names from its registry
// (docker.BuildImageRequest.ForcePull), so a Dockerfile — FROM, COPY
// --from, a base image's ONBUILD triggers, a short image id — can never read
// another tenant's snapshot or build off this node. A Dockerfile that names
// such an image outright is refused up front with a clear error rather
// than failing a pull. Operators build as before.
func (s *Service) BuildImage(ctx context.Context, req BuildImageRequest) (BuiltImage, error) {
	dockerfile := strings.TrimSpace(req.Dockerfile)
	if dockerfile == "" {
		return BuiltImage{}, fmt.Errorf("%w: a Dockerfile is required", ErrBuildInvalid)
	}
	owner, scoped := ownerScope(ctx)
	if scoped {
		if err := s.checkTenantBuildRefs(ctx, dockerfile); err != nil {
			return BuiltImage{}, err
		}
	}
	if base, ok := singleLineFrom(dockerfile); ok && req.BaseShortcut && len(req.ContextHashes) == 0 && req.Push == nil {
		return BuiltImage{Image: base}, nil
	}
	if len(req.ContextHashes) > 0 {
		if !s.cfg.ImageBuildContextEnabled {
			return BuiltImage{}, fmt.Errorf("%w: context hashes need operator-side context upload support (set SB_IMAGE_BUILD_CONTEXT_ENABLED=true)", ErrBuildInvalid)
		}
		// The hash-to-blob resolver is not wired yet; failing loudly keeps
		// COPY/ADD steps from silently building without their files.
		return BuiltImage{}, ErrBuildNotImplemented
	}
	if req.Push != nil {
		if strings.TrimSpace(req.Push.Registry) == "" {
			return BuiltImage{}, fmt.Errorf("%w: push.registry is required when push is set", ErrBuildInvalid)
		}
		if req.Push.Auth.Username == "" || req.Push.Auth.Password == "" {
			return BuiltImage{}, fmt.Errorf("%w: push.username and push.password are required when push is set", ErrBuildInvalid)
		}
	}
	builder := s.builder()
	if builder == nil {
		return BuiltImage{}, ErrBuilderUnavailable
	}

	nodeID := ""
	if s.ClusterEnabled() {
		if c := s.Cluster(); c != nil {
			nodeID = c.SelfNodeID()
		}
	}
	namespace := ""
	if scoped {
		namespace = snapshotOwnerNamespace(owner)
	}
	tag := docker.BuildTagForOwner(dockerfile, req.ContextHashes, nodeID, namespace)
	result := BuiltImage{Image: tag}
	exists, err := builder.ImageExists(ctx, tag)
	if err != nil {
		return BuiltImage{}, fmt.Errorf("%w: check built image cache: %v", ErrBuildFailed, err)
	}
	if exists {
		if err := builder.RefreshTag(ctx, tag); err != nil && s.logger != nil {
			// Only narrows the janitor's window for this tag.
			s.logger.Warn("image build cache refresh-tag failed", "tag", tag, "error", err)
		}
	} else {
		buildCtx, cancel := s.buildContext(ctx)
		err := builder.BuildImage(buildCtx, docker.BuildImageRequest{
			Tag:               tag,
			DockerfileContent: dockerfile,
			ForcePull:         scoped,
			OnLog: func(line string) {
				if s.logger != nil {
					s.logger.Debug("image build", "tag", tag, "line", line)
				}
			},
		})
		cancel()
		if err != nil {
			return BuiltImage{}, buildError("build image", err)
		}
		result.Fresh = true
	}

	if req.Push != nil {
		dest := strings.TrimSpace(req.Push.Registry)
		if t := strings.TrimSpace(req.Push.Tag); t != "" {
			dest += ":" + t
		}
		pushCtx, cancel := s.buildContext(ctx)
		pushed, err := builder.PushImage(pushCtx, docker.PushImageRequest{SourceTag: tag, DestRef: dest, Auth: req.Push.Auth})
		cancel()
		if err != nil {
			if result.Fresh {
				s.DiscardBuiltImage(ctx, tag)
			}
			return BuiltImage{}, buildError("push image", err)
		}
		result.Pushed = pushed
	}
	return result, nil
}

// DiscardBuiltImage undoes a fresh build (BuiltImage.Fresh) whose next step
// failed, so no sandbox or snapshot came of it. The tag goes to the
// pending-image GC rather than being removed here: a concurrent request for
// the same build may have been handed the tag from the cache meanwhile, and
// the GC removes it only once nothing uses it.
func (s *Service) DiscardBuiltImage(ctx context.Context, tag string) {
	if tag = strings.TrimSpace(tag); tag != "" {
		s.schedulePendingImageGC(context.WithoutCancel(ctx), "", tag)
	}
}

// RegisterSnapshotFromDockerfile builds a Dockerfile and registers the result
// as a snapshot, discarding a fresh build when the registration fails.
func (s *Service) RegisterSnapshotFromDockerfile(ctx context.Context, snapshot *models.SandboxSnapshot, build BuildImageRequest) (*models.SandboxSnapshot, error) {
	if snapshot == nil {
		return nil, errors.New("snapshot is required")
	}
	if err := validateSnapshotName(strings.TrimSpace(snapshot.Name)); err != nil {
		return nil, err
	}
	build.BaseShortcut = true
	built, err := s.BuildImage(ctx, build)
	if err != nil {
		return nil, err
	}
	snapshot.Image = built.Image
	registered, err := s.RegisterSnapshot(ctx, snapshot)
	if err != nil {
		if built.Fresh {
			s.DiscardBuiltImage(ctx, built.Image)
		}
		return nil, err
	}
	return registered, nil
}

func (s *Service) buildContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if timeout := s.cfg.ImageBuildTimeout; timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithCancel(ctx)
}

func buildError(step string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s: %v", ErrBuildTimeout, step, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrBuildFailed, step, err)
}

// checkTenantBuildRefs refuses a tenant's Dockerfile that names an image
// only this node has: a snapshot (by name or by its tag), a build, or an
// image id. The forced pull would already keep such a build from reading
// the image (BuildImage); this turns what would be a confusing pull of a
// same-named public image, or a pull failure, into a clear error. A
// reference that uses a build variable cannot be checked here and is left
// to the forced pull.
func (s *Service) checkTenantBuildRefs(ctx context.Context, dockerfile string) error {
	for _, ref := range dockerfileImageRefs(dockerfile) {
		if strings.Contains(ref, "$") {
			continue
		}
		local := docker.LooksLikeImageID(ref) || docker.IsSnapshotImageRef(ref) || docker.IsBuiltImageRef(ref) || docker.IsLocalOnlyImageRef(ref)
		if !local {
			_, err := s.store.GetSnapshotByNames(ctx, docker.EquivalentImageNames(ref))
			switch {
			case err == nil:
				local = true
			case !errors.Is(err, store.ErrNotFound):
				return err
			}
		}
		if local {
			return fmt.Errorf("%w: a build can start only from registry images, and %q is an image on this node (start a sandbox from the snapshot instead)", ErrBuildInvalid, ref)
		}
	}
	return nil
}

// singleLineFrom reports a Dockerfile that is only `FROM <image>` (comments
// and blank lines aside) and returns the image.
func singleLineFrom(dockerfile string) (string, bool) {
	var image string
	for _, line := range strings.Split(dockerfile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if image != "" || len(fields) != 2 || !strings.EqualFold(fields[0], "FROM") {
			return "", false
		}
		image = fields[1]
	}
	return image, image != ""
}

// dockerfileImageRefs returns the image references a build of dockerfile
// would resolve: each stage's FROM image (not an earlier stage, not
// scratch), COPY/ADD --from images, RUN --mount from= images, the same
// inside ONBUILD, and a `# syntax=` frontend. It is a reader for refusing
// obvious local references early, not a full Dockerfile parser: line
// continuations, comments, the escape directive and heredoc bodies are
// handled; anything it cannot see is still covered by the forced pull.
func dockerfileImageRefs(dockerfile string) []string {
	lines := strings.Split(strings.ReplaceAll(dockerfile, "\r\n", "\n"), "\n")
	escape := byte('\\')
	var refs []string
	stages := map[string]bool{}

	// Parser directives: comment lines of the form "# key=value" before
	// anything else.
	i := 0
	for ; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "#")), "=")
		if !strings.HasPrefix(line, "#") || !ok || strings.ContainsAny(strings.TrimSpace(key), " \t") {
			break
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "syntax":
			refs = append(refs, strings.TrimSpace(value))
		case "escape":
			if v := strings.TrimSpace(value); len(v) == 1 {
				escape = v[0]
			}
		}
	}

	var heredocEnds []string
	var logical strings.Builder
	flush := func() {
		instruction := strings.TrimSpace(logical.String())
		logical.Reset()
		if instruction == "" {
			return
		}
		heredocEnds = append(heredocEnds, heredocTerminators(instruction)...)
		refs = append(refs, instructionImageRefs(instruction, stages)...)
	}
	for ; i < len(lines); i++ {
		raw := lines[i]
		if len(heredocEnds) > 0 {
			if strings.TrimSpace(raw) == heredocEnds[0] {
				heredocEnds = heredocEnds[1:]
			}
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, string(escape)) {
			logical.WriteString(strings.TrimSuffix(trimmed, string(escape)))
			logical.WriteByte(' ')
			continue
		}
		logical.WriteString(trimmed)
		flush()
	}
	flush()
	return refs
}

// instructionImageRefs returns the image references one instruction names,
// recording a FROM's stage name in stages.
func instructionImageRefs(instruction string, stages map[string]bool) []string {
	fields := strings.Fields(instruction)
	if len(fields) == 0 {
		return nil
	}
	external := func(ref string) bool {
		ref = strings.TrimSpace(ref)
		if ref == "" || stages[strings.ToLower(ref)] || strings.EqualFold(ref, "scratch") {
			return false
		}
		for _, c := range ref {
			if c < '0' || c > '9' {
				return true
			}
		}
		return false // a stage index
	}
	var refs []string
	switch strings.ToUpper(fields[0]) {
	case "ONBUILD":
		return instructionImageRefs(strings.Join(fields[1:], " "), stages)
	case "FROM":
		args := nonFlags(fields[1:])
		if len(args) == 0 {
			return nil
		}
		if external(args[0]) {
			refs = append(refs, args[0])
		}
		if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
			stages[strings.ToLower(args[2])] = true
		}
	case "COPY", "ADD":
		for _, flag := range fields[1:] {
			if from, ok := strings.CutPrefix(flag, "--from="); ok && external(from) {
				refs = append(refs, from)
			}
		}
	case "RUN":
		for _, flag := range fields[1:] {
			mount, ok := strings.CutPrefix(flag, "--mount=")
			if !ok {
				continue
			}
			for _, option := range strings.Split(mount, ",") {
				if from, ok := strings.CutPrefix(option, "from="); ok && external(from) {
					refs = append(refs, from)
				}
			}
		}
	}
	return refs
}

func nonFlags(fields []string) []string {
	var out []string
	for _, field := range fields {
		if !strings.HasPrefix(field, "--") {
			out = append(out, field)
		}
	}
	return out
}

// heredocTerminators returns the end markers of the heredocs an
// instruction opens (`<<EOF`, `<<-EOF`, `<<"EOF"`), in order.
func heredocTerminators(instruction string) []string {
	var ends []string
	for rest := instruction; ; {
		at := strings.Index(rest, "<<")
		if at < 0 {
			return ends
		}
		rest = strings.TrimPrefix(rest[at+2:], "-")
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return ends
		}
		word := strings.Trim(fields[0], `"'`)
		if word != "" && !strings.ContainsAny(word, "<>|&;") {
			ends = append(ends, word)
		}
	}
}
