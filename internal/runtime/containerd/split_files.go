package containerd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/runtime/resolvconf"
	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
)

// Container files in privilege mode split (M1 PR 7). runc, runsc and the
// containerd shim open, as root, files a container names: the host files
// its spec binds, its ready socket, its task's stdout and stderr, its runsc
// config and the toolbox binary. In single mode sandboxd makes them in its
// run dir. In split mode sandboxd cannot, and must not: any folder it can
// write is one where it could swap a file for a link before root opens it.
// So the root helper makes them in its own folders, from typed values, as
// one part of the create's one call before the container exists
// (PrepareSandbox, part "files"), and again before each start, which needs
// fresh FIFOs and a fresh ready socket name. The spec and the task use the
// paths the helper answers; the gate accepts them because they are in the
// helper's folders. ReleaseSandbox's files part removes them when the
// container goes, or when its create fails.
//
// What the agent keeps: it binds the ready socket in its own ready folder
// and accepts on it, as before (the helper only gives it a second name),
// and it reads the FIFOs, root's, through its group, into its own task log.

// ContainerParts is the root helper's PrepareSandbox and ReleaseSandbox as
// the driver uses them for a container's parts (*rootclient.Client).
type ContainerParts interface {
	PrepareSandbox(ctx context.Context, req *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error)
	ReleaseSandbox(ctx context.Context, req *rootdpb.ReleaseSandboxRequest) error
}

// localhostEntries are the hosts file's lines single mode writes
// (prepareSandboxHostFiles).
var localhostEntries = []*rootdpb.HostEntry{
	{Address: "127.0.0.1", Names: []string{"localhost"}},
	{Address: "::1", Names: []string{"localhost", "ip6-localhost", "ip6-loopback"}},
}

// hostNaming is what single mode's host files hold for a container, as
// values: its ID as the hostname, the localhost lines, and the host's
// resolver settings, read as resolvconf.Generate reads them. The helper
// renders the same bytes (TestHelperHostFilesMatchTheDriver).
func hostNaming(containerID string) (*rootdpb.HostNaming, error) {
	dns, err := resolvconf.Parse(resolvconf.HostPath)
	if err != nil {
		return nil, err
	}
	return &rootdpb.HostNaming{Hostname: containerID, Hosts: localhostEntries,
		Nameservers: dns.Nameservers, Search: dns.Search, DnsOptions: dns.Options}, nil
}

// hostNamingFn is hostNaming; tests replace it to read no host file.
var hostNamingFn = hostNaming

// helperFiles has the helper make a container's files for a create or a
// start, and checks the answer names each one asked for. readyNonce is the
// nonce of the ready socket the agent has bound for it ("" for none);
// runsc names the runsc config its runtime options use (UNSPECIFIED for
// runc). Host files, fresh FIFOs and the toolbox are always asked for.
func (d *Driver) helperFiles(ctx context.Context, containerID, readyNonce string, runsc rootdpb.RunscConfig) (*rootdpb.SandboxFilePaths, error) {
	if d.parts == nil {
		return nil, errors.New("containerd: privilege mode split needs the root helper's container parts")
	}
	naming, err := hostNamingFn(containerID)
	if err != nil {
		return nil, err
	}
	resp, err := d.parts.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: containerID,
		Setup: &rootdpb.ContainerSetup{Naming: naming, TaskFifos: true, ReadyNonce: readyNonce, RunscConfig: runsc, Toolbox: true}})
	if err != nil {
		return nil, fmt.Errorf("root helper: container files: %w", err)
	}
	f := resp.GetFiles()
	missing := f.GetHostnamePath() == "" || f.GetHostsPath() == "" || f.GetResolvConfPath() == "" ||
		f.GetStdoutPath() == "" || f.GetStderrPath() == "" || f.GetToolboxPath() == "" ||
		(readyNonce != "") != (f.GetReadySocketPath() != "") ||
		(runsc != rootdpb.RunscConfig_RUNSC_CONFIG_UNSPECIFIED) != (f.GetRunscConfigPath() != "")
	if missing {
		return nil, fmt.Errorf("root helper: container files: the answer lacks a path asked for (%v)", f)
	}
	return f, nil
}

// releaseHelperFiles has the helper remove everything it made for a
// container. A failure is logged and left to the helper's sweep of gone
// containers' files: the caller is tearing down.
func (d *Driver) releaseHelperFiles(ctx context.Context, containerID string) {
	if d.parts == nil || validateSandboxID(containerID) != nil {
		return
	}
	err := d.parts.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: containerID})
	if err != nil && d.logger != nil {
		d.logger.Warn("containerd: the root helper did not remove a container's files; its sweep removes them later",
			"container_id", containerID, "error", err)
	}
}

// taskLogIOAt is taskLogIO for a task whose stdout and stderr are the
// helper's FIFOs: this process opens them (root's, readable by its group)
// and drains them into the task log, as it drains its own.
func (d *Driver) taskLogIOAt(path string, f *rootdpb.SandboxFilePaths) (cio.Creator, func(), error) {
	l, err := openTaskLog(path, false)
	if err != nil {
		return nil, nil, err
	}
	attach := l.attach()
	stdout, stderr := f.GetStdoutPath(), f.GetStderrPath()
	return func(id string) (cio.IO, error) {
		d.drainedTasks.Store(id, l)
		l.onClose = func() { d.drainedTasks.CompareAndDelete(id, l) }
		// No closer: the FIFOs are the helper's, removed with the
		// container's other files.
		return attach(cio.NewFIFOSet(cio.Config{Stdout: stdout, Stderr: stderr}, nil))
	}, l.release, nil
}

// splitReadyResume rebinds, for a start, the ready socket a stored spec
// names in the helper's folder: <helper ready>/<id>/<nonce>.sock. The
// agent binds <id>.<nonce>.sock in its own ready folder, with the token in
// the spec's env, and the start's files call names it again. Nil when the
// spec has no ready mount, or one in another shape.
func (d *Driver) splitReadyResume(spec *specs.Spec) (*dockerpkg.ReadyListener, string) {
	if spec == nil || spec.Process == nil {
		return nil, ""
	}
	var source string
	for _, m := range spec.Mounts {
		if m.Destination == dockerpkg.GuestReadySocketPath {
			source = filepath.Clean(m.Source)
			break
		}
	}
	nonce, ok := strings.CutSuffix(filepath.Base(source), ".sock")
	id := filepath.Base(filepath.Dir(source))
	if source == "" || !ok || nonce == "" || validateSandboxID(id) != nil {
		return nil, ""
	}
	var token string
	for _, e := range spec.Process.Env {
		if v, found := strings.CutPrefix(e, "SB_TOOLBOX_TOKEN="); found {
			token = v
			break
		}
	}
	if token == "" {
		return nil, ""
	}
	rl, err := dockerpkg.NewReadyListener(d.cfg.ReadyDir, id, token, nonce)
	if err != nil {
		return nil, ""
	}
	return rl, nonce
}
