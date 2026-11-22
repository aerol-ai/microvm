package rootd

import (
	"context"
	"slices"

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
// binds. Every value is checked before any file is written, so a refused
// request changes nothing. ReleaseSandbox's "files" part removes them all.
//
// D11: one container's calls run in order under its lock (containerKey),
// the same lock the T2b calls take.

// containerParts are the parts that name a container. A request with one
// of them carries only them.
var containerParts = []string{rootdpb.PartFiles}

// hasContainerPart reports whether parts lists a container's part.
func hasContainerPart(parts []string) bool {
	return slices.ContainsFunc(parts, func(p string) bool { return slices.Contains(containerParts, p) })
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
		if !slices.Contains(containerParts, p) {
			return nil, badRequest("root helper: part %q does not come with a container's parts", p)
		}
	}
	if req.GetNetnsName() != "" || req.GetContainerIp() != "" || req.GetFirewall() != nil || req.GetCgroup() != nil {
		return nil, badRequest("root helper: a container's parts come alone, named by container_id")
	}
	if req.GetSetup() != nil && !parts[rootdpb.PartFiles] {
		return nil, badRequest("root helper: a container setup sent without the files part")
	}
	id := req.GetContainerId()
	if err := checkID(id); err != nil {
		return nil, err
	}
	plan, err := h.files.checkSetup(req.GetSetup())
	if err != nil {
		return nil, err
	}
	unlock, err := h.locks.lock(ctx, containerKey(id))
	if err != nil {
		return nil, err
	}
	defer unlock()
	paths, err := h.files.setup(id, plan)
	if err != nil {
		return nil, err
	}
	return &rootdpb.PrepareSandboxResponse{Files: paths}, nil
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
	if len(req.GetParts()) != 1 || req.GetNetnsName() != "" || req.GetContainerIp() != "" {
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
func (f *files) setup(id string, p setupPlan) (*rootdpb.SandboxFilePaths, error) {
	out := &rootdpb.SandboxFilePaths{}
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
	if p.readyNonce != "" {
		r, err := f.ensureReadySocket(&rootdpb.EnsureReadySocketRequest{ContainerId: id, Nonce: p.readyNonce})
		if err != nil {
			return nil, err
		}
		out.ReadySocketPath = r.GetPath()
	}
	if p.runsc != rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED {
		r, err := f.ensureRunscConfig(&rootdpb.EnsureRunscConfigRequest{Config: p.runsc})
		if err != nil {
			return nil, err
		}
		out.RunscConfigPath = r.GetPath()
	}
	if p.toolbox {
		path, err := f.toolboxPath()
		if err != nil {
			return nil, err
		}
		out.ToolboxPath = path
	}
	return out, nil
}
