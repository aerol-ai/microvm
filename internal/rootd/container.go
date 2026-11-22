package rootd

import (
	"context"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// A container's parts of PrepareSandbox and ReleaseSandbox (M1 PR 7): the
// root work a containerd create and start need that is the container's,
// not its network's. They are named by the request's container_id and come
// together, with no namespace, address, rules or cgroup: the network's
// parts come earlier, from the netns pool, and the cgroup part after the
// task starts. So a create makes one call for all of them, just before the
// container is made, and a start one before its task.
//
// Part "files" is the T2b calls (files.go) in one part: the host files,
// fresh task FIFOs, the name of the agent's ready socket, the runsc config
// the container's runtime options name, and the toolbox binary the spec
// binds. Part "image_user" (imageuser.go) resolves the user the image runs
// as, and part "disk_quota" (quota.go) limits the writable layer; both read
// the container's snapshot from containerd. Every value is checked before
// anything is made, so a refused request changes nothing. A create sends
// all three in one call, once its snapshot exists and before its container
// does; a start sends files; a resize sends disk_quota.
// ReleaseSandbox's "files" part removes the files.
//
// D11: one container's calls run in order under its lock (containerKey),
// the same lock the T2b calls take.

// allContainerParts are the parts that name a container. A request with
// one of them carries only them.
var allContainerParts = []string{rootdpb.PartFiles, rootdpb.PartImageUser, rootdpb.PartDiskQuota}

// hasContainerPart reports whether parts lists a container's part.
func hasContainerPart(parts []string) bool {
	return slices.ContainsFunc(parts, func(p string) bool { return slices.Contains(allContainerParts, p) })
}

// containerCalls serves the container's parts that read its snapshot.
type containerCalls struct {
	policy rootpolicy.Policy
	// snaps reads containerd's snapshots; nil, and then the helper serves
	// neither snapshot part (tests that give it none).
	snaps SnapshotReader
	// readImageFiles reads an image's user files (imageuser_linux.go),
	// with emptyDir, an empty folder of the helper's own, as the bottom
	// layer.
	readImageFiles ImageFileReader
	snapshotsDir   string
	emptyDir       string
	users          userCache
	quota          QuotaOps
	ready          quotaReady
}

func newContainerCalls(cfg Config, opts Options) *containerCalls {
	c := &containerCalls{policy: cfg.Policy, snaps: opts.Snapshots, readImageFiles: opts.ReadImageFiles, quota: opts.Quota,
		snapshotsDir: filepath.Join(cfg.Policy.SnapshotterRoot, "snapshots"), emptyDir: cfg.Files.ImageRoot}
	if c.readImageFiles == nil {
		c.readImageFiles = readImageFiles
	}
	if c.quota == nil {
		c.quota = defaultQuota
	}
	return c
}

// served are the container's parts this helper serves: files always, the
// snapshot's two with a snapshot reader.
func (c *containerCalls) served() []string {
	if c == nil || c.snaps == nil {
		return []string{rootdpb.PartFiles}
	}
	return slices.Clone(allContainerParts)
}

// prepareContainer serves PrepareSandbox's container parts.
func (h helper) prepareContainer(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	parts, err := partsOf(req.GetParts(), h.servedParts())
	if err != nil {
		return nil, err
	}
	for p := range parts {
		if !slices.Contains(allContainerParts, p) {
			return nil, badRequest("root helper: part %q does not come with a container's parts", p)
		}
	}
	if req.GetNetnsName() != "" || req.GetContainerIp() != "" || req.GetFirewall() != nil || req.GetCgroup() != nil {
		return nil, badRequest("root helper: a container's parts come alone, named by container_id")
	}
	for _, f := range []struct {
		part string
		set  bool
	}{{rootdpb.PartFiles, req.GetSetup() != nil}, {rootdpb.PartImageUser, req.GetImageUser() != nil}, {rootdpb.PartDiskQuota, req.GetDiskQuota() != nil}} {
		if f.set != parts[f.part] {
			return nil, badRequest("root helper: part %s and its values come together", f.part)
		}
	}
	id := req.GetContainerId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	var plan setupPlan
	if parts[rootdpb.PartFiles] {
		if plan, err = h.files.checkSetup(req.GetSetup()); err != nil {
			return nil, err
		}
	}
	user := req.GetImageUser().GetUser()
	if err := rootpolicy.CheckImageUser(user); err != nil {
		return nil, refusedRule(codes.InvalidArgument, err)
	}
	if parts[rootdpb.PartDiskQuota] {
		if err := rootpolicy.CheckQuotaBytes(req.GetDiskQuota().GetBytes()); err != nil {
			return nil, refusedRule(codes.InvalidArgument, err)
		}
	}
	unlock, err := h.locks.lock(ctx, containerKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	resp := &rootdpb.PrepareSandboxResponse{}
	// The limit first: nothing has run in the layer yet.
	if parts[rootdpb.PartDiskQuota] {
		if err := h.ct.diskQuota(ctx, id, req.GetDiskQuota().GetBytes()); err != nil {
			return nil, err
		}
	}
	if parts[rootdpb.PartImageUser] {
		if resp.ImageUser, err = h.ct.imageUser(ctx, id, user); err != nil {
			return nil, err
		}
	}
	if parts[rootdpb.PartFiles] {
		if resp.Files, err = h.files.setup(id, plan); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// releaseContainer serves ReleaseSandbox's files part: everything the
// helper made for the container goes. Gone already counts as done.
func (h helper) releaseContainer(ctx context.Context, req *rootdpb.ReleaseSandboxRequest) (*rootdpb.ReleaseSandboxResponse, error) {
	if err := noUnknownFields(req); err != nil {
		return nil, err
	}
	if _, err := partsOf(req.GetParts(), h.servedParts()); err != nil {
		return nil, err
	}
	if !slices.Equal(req.GetParts(), []string{rootdpb.PartFiles}) || req.GetNetnsName() != "" || req.GetContainerIp() != "" {
		return nil, badRequest("root helper: ReleaseSandbox's files part comes alone, named by container_id")
	}
	id := req.GetContainerId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	unlock, err := h.locks.lock(ctx, containerKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := h.files.removeContainerFiles(&rootdpb.RemoveContainerFilesRequest{ContainerId: id}); err != nil {
		return nil, err
	}
	return &rootdpb.ReleaseSandboxResponse{}, nil
}

// setupPlan is a files part's checked request.
type setupPlan struct {
	naming     *rootdpb.EnsureHostFilesRequest
	fifos      bool
	readyNonce string
	runsc      rootdpb.RunscConfig
	toolbox    bool
}

// checkSetup checks every value of a files part before anything is made:
// the host files' names and addresses (as EnsureHostFiles checks them), the
// ready nonce and the runsc config's name. A part that asks for nothing is
// refused: the agent never sends one.
func (f *files) checkSetup(s *rootdpb.ContainerSetup) (setupPlan, error) {
	var p setupPlan
	if s == nil {
		return p, badRequest("root helper: the files part has no container setup")
	}
	if n := s.GetNaming(); n != nil {
		p.naming = &rootdpb.EnsureHostFilesRequest{Hostname: n.GetHostname(), Hosts: n.GetHosts(),
			Nameservers: n.GetNameservers(), Search: n.GetSearch(), DnsOptions: n.GetDnsOptions()}
		if _, err := checkName("hostname", p.naming.GetHostname()); err != nil {
			return p, err
		}
		if _, err := renderHosts(p.naming.GetHosts()); err != nil {
			return p, err
		}
	}
	if p.readyNonce = s.GetReadyNonce(); p.readyNonce != "" {
		if err := rootpolicy.CheckReadyNonce(p.readyNonce); err != nil {
			return p, badRequest("%v", err)
		}
	}
	if p.runsc = s.GetRunscConfig(); p.runsc != rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED {
		if _, _, err := runscConfig(p.runsc); err != nil {
			return p, err
		}
	}
	p.fifos, p.toolbox = s.GetTaskFifos(), s.GetToolbox()
	if p.naming == nil && !p.fifos && p.readyNonce == "" && p.runsc == rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED && !p.toolbox {
		return p, badRequest("root helper: the files part asks for nothing")
	}
	return p, nil
}

// setup makes what a checked files part asks for, for container id, in the
// helper's own folders, and answers with the paths. The caller holds the
// container's lock.
//
// The two steps that can refuse on what they find (the toolbox, which
// must be a regular file of the agent's; the ready socket, which must be
// the agent's socket) come first, before anything of the container is
// written, so a refused part leaves nothing behind: the ready step's own
// folder goes again when the refusal leaves it empty. A failure after
// them (the disk full) can leave files the call made; the agent's undo
// releases them (ReleaseSandbox's files part), and the helper's sweep
// takes them if the agent never comes back.
func (f *files) setup(id string, p setupPlan) (*rootdpb.SandboxFilePaths, error) {
	out := &rootdpb.SandboxFilePaths{}
	if p.toolbox {
		path, err := f.toolboxPath()
		if err != nil {
			return nil, err
		}
		out.ToolboxPath = path
	}
	if p.readyNonce != "" {
		r, err := f.ensureReadySocket(&rootdpb.EnsureReadySocketRequest{ContainerId: id, Nonce: p.readyNonce})
		if err != nil {
			// The folder this call may have made, if it holds nothing: a
			// folder with an earlier start's name in it fails ENOTEMPTY.
			_ = unix.Unlinkat(f.ready, id, unix.AT_REMOVEDIR)
			return nil, err
		}
		out.ReadySocketPath = r.GetPath()
	}
	if p.naming != nil {
		p.naming.ContainerId = id
		r, err := f.ensureHostFiles(p.naming)
		if err != nil {
			return nil, err
		}
		out.HostnamePath, out.HostsPath, out.ResolvConfPath = r.GetHostnamePath(), r.GetHostsPath(), r.GetResolvConfPath()
	}
	if p.fifos {
		r, err := f.ensureTaskFIFOs(&rootdpb.EnsureTaskFIFOsRequest{ContainerId: id})
		if err != nil {
			return nil, err
		}
		out.StdoutPath, out.StderrPath = r.GetStdoutPath(), r.GetStderrPath()
	}
	if p.runsc != rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED {
		r, err := f.ensureRunscConfig(&rootdpb.EnsureRunscConfigRequest{Config: p.runsc})
		if err != nil {
			return nil, err
		}
		out.RunscConfigPath = r.GetPath()
	}
	return out, nil
}
