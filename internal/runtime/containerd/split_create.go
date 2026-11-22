package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/defaults"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
)

// A create in privilege mode split (M1 PR 7). Single mode's create does
// three things as root the agent cannot: it writes the container's files
// (split_files.go), it reads the image's /etc/passwd and /etc/group from
// the container's snapshot (oci.WithImageConfig, through a mount or
// containerd's in-process reader of the layer folders), and, with a disk
// limit, it puts the writable layer in an XFS project. Split mode has the
// root helper do all three in one call, the create's PrepareSandbox with
// the files, image_user and disk_quota parts, made just before the
// container:
//
//  1. the agent prepares the container's snapshot itself, through the
//     gate, under a lease of its own until the container holds it
//     (prepareSplitSnapshotFn), where single mode's NewContainer prepares
//     it under NewContainer's lease;
//  2. it binds the ready socket;
//  3. one call: the helper makes the files, limits the layer it finds
//     from the snapshot containerd names, and resolves the image's user
//     from the image's own layers;
//  4. the spec takes the image's env, command and working folder as
//     oci.WithImageConfig sets them, and the user the helper answered
//     (withImageConfigAnswer).
//
// The agent caches the image's user by the image config's digest and the
// USER string, so a create of an image it has created before sends no
// image_user part: the warm path reads no image file at all.

// splitSnapshotter is the snapshotter of a split create's snapshot:
// containerd's default, which the helper's policy requires (overlayfs), as
// cntr.WithNewSnapshot resolves it for a namespace with no default label
// (the gate refuses one).
const splitSnapshotter = defaults.DefaultSnapshotter

// errSplitSnapshotExists: a split create's snapshot was there already,
// another create of the same ID's.
var errSplitSnapshotExists = errors.New("the container's snapshot already exists")

// prepareSplitSnapshotFn prepares container key's snapshot from image's
// layers, as cntr.WithNewSnapshot does, under a lease of its own that keeps
// containerd's collector off it until the container holds it. It returns
// the lease's context, which the container's create must use, and the
// lease's end. Tests replace it.
var prepareSplitSnapshotFn = func(ctx context.Context, client *Client, key string, image cntr.Image) (context.Context, func(context.Context) error, error) {
	raw := client.Raw()
	if raw == nil {
		return nil, nil, errors.New("containerd: no client to prepare a snapshot with")
	}
	lctx, done, err := raw.WithLease(client.withNS(ctx))
	if err != nil {
		return nil, nil, fmt.Errorf("lease for the snapshot: %w", err)
	}
	diffIDs, err := image.RootFS(lctx)
	if err == nil {
		_, err = raw.SnapshotService(splitSnapshotter).Prepare(lctx, key, identity.ChainID(diffIDs).String())
	}
	if err != nil {
		_ = done(context.WithoutCancel(lctx))
		return nil, nil, err
	}
	return lctx, done, nil
}

// withPreparedSnapshot names the snapshot a split create prepared as the
// container's root filesystem, as cntr.WithNewSnapshot would.
func withPreparedSnapshot(key string) cntr.NewContainerOpts {
	return func(_ context.Context, _ *cntr.Client, c *containers.Container) error {
		c.Snapshotter, c.SnapshotKey = splitSnapshotter, key
		return nil
	}
}

// splitCreate is what a split create's one helper call made for it.
type splitCreate struct {
	files  *rootdpb.SandboxFilePaths
	user   *rootdpb.ImageUserAnswer
	config ocispec.Image
	// ready is the agent's ready socket, bound before the call named it.
	ready *dockerpkg.ReadyListener
	// leaseCtx carries the snapshot's lease, for the container's create;
	// done ends the lease once the container holds the snapshot.
	leaseCtx context.Context
	done     func(context.Context) error
}

// release ends the snapshot's lease; the container holds the snapshot by
// then, or the create's undo removes it.
func (s *splitCreate) release(ctx context.Context) {
	if s != nil && s.done != nil {
		_ = s.done(context.WithoutCancel(ctx))
		s.done = nil
	}
}

// prepareSplitCreate does a split create's root work before its container
// (above). On error it leaves nothing behind: the snapshot it prepared,
// its lease, the ready socket and the helper's files go. A snapshot that
// was there already is errSplitSnapshotExists, and stays: it is another
// create's.
func (d *Driver) prepareSplitCreate(ctx context.Context, client *Client, image cntr.Image, sandboxID, toolboxToken string,
	req createParts) (_ *splitCreate, err error) {
	cfgDigest, cfg, err := readSplitImageConfig(ctx, client, image)
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}
	s := &splitCreate{config: cfg}
	if s.leaseCtx, s.done, err = prepareSplitSnapshotFn(ctx, client, sandboxID, image); err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil, errSplitSnapshotExists
		}
		return nil, fmt.Errorf("prepare snapshot: %w", err)
	}
	called := false
	defer func() {
		if err == nil {
			return
		}
		uctx, cancel := undoContext(ctx)
		defer cancel()
		if s.ready != nil {
			_ = s.ready.Close()
			dockerpkg.RemoveReadySocketsForSandbox(d.cfg.ReadyDir, sandboxID)
		}
		if called {
			d.releaseHelperFiles(uctx, sandboxID)
		}
		if rerr := removeSnapshot(uctx, client, sandboxID); rerr != nil && d.logger != nil {
			d.logger.Warn("containerd: a failed split create's snapshot was not removed; the next create of the id meets it",
				"sandbox_id", sandboxID, "error", rerr)
		}
		s.release(uctx)
	}()
	var nonce string
	if d.cfg.ReadyEnabled {
		if err = dockerpkg.EnsureReadyDir(d.cfg.ReadyDir); err != nil {
			return nil, err
		}
		if nonce, err = dockerpkg.MintReadyNonce(); err != nil {
			return nil, err
		}
		if s.ready, err = dockerpkg.NewReadyListener(d.cfg.ReadyDir, sandboxID, toolboxToken, nonce); err != nil {
			return nil, err
		}
	}
	user := cfg.Config.User
	cacheKey := cfgDigest + "\x00" + user
	cached, haveUser := d.imageUsers.get(cacheKey)
	called = true
	resp, err := d.containerCall(ctx, sandboxID, nonce, runscConfigFor(req.OCIRuntime, req.Restore), func(p *rootdpb.PrepareSandboxRequest) {
		if !haveUser {
			p.Parts = append(p.Parts, rootdpb.PartImageUser)
			p.ImageUser = &rootdpb.ImageUser{User: user}
		}
		if req.DiskBytes > 0 {
			p.Parts = append(p.Parts, rootdpb.PartDiskQuota)
			p.DiskQuota = &rootdpb.DiskQuota{Bytes: req.DiskBytes}
		}
	})
	if err != nil {
		return nil, err
	}
	s.files, s.user = resp.GetFiles(), cached
	if !haveUser {
		if s.user = resp.GetImageUser(); s.user == nil {
			return nil, errors.New("root helper: the answer lacks the image's user")
		}
		d.imageUsers.put(cacheKey, s.user)
	}
	return s, nil
}

// createParts is what of a create decides its helper parts.
type createParts struct {
	OCIRuntime string
	Restore    bool
	// DiskBytes is the disk limit, 0 for none.
	DiskBytes uint64
}

// readSplitImageConfig reads image's config once, for the whole split
// create: its digest (the agent's image-user cache key), its USER, and
// what withImageConfigAnswer sets.
func readSplitImageConfig(ctx context.Context, client *Client, image cntr.Image) (string, ocispec.Image, error) {
	var cfg ocispec.Image
	desc, err := image.Config(ctx)
	if err != nil {
		return "", cfg, err
	}
	if !images.IsConfigType(desc.MediaType) {
		return "", cfg, fmt.Errorf("unknown image config media type %s", desc.MediaType)
	}
	if client == nil || client.contentProvider() == nil {
		return "", cfg, errors.New("content store unavailable")
	}
	body, err := content.ReadBlob(ctx, client.contentProvider(), desc)
	if err != nil {
		return "", cfg, err
	}
	if err := json.Unmarshal(body, &cfg); err != nil {
		return "", cfg, err
	}
	return desc.Digest.String(), cfg, nil
}

// imageCommandOf is imageConfigCommand for a config already read.
func imageCommandOf(cfg ocispec.Image) []string {
	return append(append([]string{}, cfg.Config.Entrypoint...), cfg.Config.Cmd...)
}

// defaultUnixEnv is containerd's PATH for an image that sets no env
// (pkg/oci defaultUnixEnv); TestSplitImageConfigMatchesContainerd pins it.
var defaultUnixEnv = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

// withImageConfigAnswer is oci.WithImageConfig for privilege mode split:
// the image's env, command and working folder exactly as containerd sets
// them on a Linux spec, and the user the root helper resolved from the
// image's own files with containerd's own code.
func withImageConfigAnswer(cfg ocispec.Image, u *rootdpb.ImageUserAnswer) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, c *containers.Container, s *oci.Spec) error {
		if s.Process == nil {
			s.Process = &specs.Process{}
		}
		if s.Linux == nil {
			return errors.New("containerd: a split create's spec has no Linux section")
		}
		config := cfg.Config
		env := config.Env
		if len(env) == 0 {
			env = defaultUnixEnv
		}
		// containerd: the image's env first, the spec's own over it.
		own := s.Process.Env
		s.Process.Env = slices.Clone(env)
		if err := oci.WithEnv(own)(ctx, client, c, s); err != nil {
			return err
		}
		s.Process.Args = append(config.Entrypoint, config.Cmd...)
		s.Process.Cwd = config.WorkingDir
		if s.Process.Cwd == "" {
			s.Process.Cwd = "/"
		}
		s.Process.User.UID, s.Process.User.GID = u.GetUid(), u.GetGid()
		s.Process.User.AdditionalGids = slices.Clone(u.GetAdditionalGids())
		return nil
	}
}

// imageUserCache is the agent's own cache of image users, by image config
// digest and USER (prepareSplitCreate): a fixed bound, cleared when full.
type imageUserCache struct {
	mu sync.Mutex
	m  map[string]*rootdpb.ImageUserAnswer
}

const maxImageUsers = 4096

func (c *imageUserCache) get(key string) (*rootdpb.ImageUserAnswer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[key]
	return a, ok
}

func (c *imageUserCache) put(key string, a *rootdpb.ImageUserAnswer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= maxImageUsers {
		c.m = map[string]*rootdpb.ImageUserAnswer{}
	}
	c.m[key] = a
}

// helperHostFiles are the helper's host files as the spec builder takes
// them. Dir is empty: the folder is the helper's to remove.
func helperHostFiles(f *rootdpb.SandboxFilePaths) *sandboxHostFiles {
	return &sandboxHostFiles{ResolvConf: f.GetResolvConfPath(), Hosts: f.GetHostsPath(), Hostname: f.GetHostnamePath()}
}

// runscConfigFor names the runsc config a runtime uses: none for runc.
func runscConfigFor(ociRuntime string, restore bool) rootdpb.RunscConfig {
	switch {
	case ociRuntime != "runsc":
		return rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED
	case restore:
		return rootdpb.RunscConfig_RUNSC_CONFIG_RESTORE
	}
	return rootdpb.RunscConfig_RUNSC_CONFIG_DEFAULT
}

// runtimeContainerOptAt is runtimeContainerOptFor with the runsc config the
// helper made, at configPath, in place of this process's own.
func runtimeContainerOptAt(ociRuntime, configPath string) cntr.NewContainerOpts {
	name := containerdRuntimeName(ociRuntime)
	if ociRuntime != "runsc" {
		if name == "" {
			return nil
		}
		return cntr.WithRuntime(name, nil)
	}
	return cntr.WithRuntime(name, &runtimeoptions.Options{TypeUrl: runscOptionsTypeUrl, ConfigPath: configPath})
}

// readyMount binds the ready socket's name in the helper's folder. Read
// only, as the gate requires of every file there: a socket still takes
// connections through a read-only bind.
func readyMount(source string) specs.Mount {
	return specs.Mount{Type: "bind", Source: source, Destination: dockerpkg.GuestReadySocketPath, Options: []string{"rbind", "ro"}}
}

// splitResizeDisk sets a resize's disk limit through the helper's
// disk_quota part, alone. The helper finds the layer from the container's
// own snapshot, whose key is the container's ID.
func (d *Driver) splitResizeDisk(ctx context.Context, container cntr.Container, snapshotKey string, diskGB int) error {
	if d.parts == nil {
		return errors.New("containerd: privilege mode split needs the root helper's container parts to set a disk limit")
	}
	if snapshotKey != container.ID() {
		return fmt.Errorf("containerd: container %s's snapshot is %q, not its own key; the helper limits only that", container.ID(), snapshotKey)
	}
	_, err := d.parts.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartDiskQuota}, ContainerId: container.ID(),
		DiskQuota: &rootdpb.DiskQuota{Bytes: uint64(diskGB) << 30}})
	if err != nil {
		return fmt.Errorf("root helper: disk limit: %w", err)
	}
	return nil
}
