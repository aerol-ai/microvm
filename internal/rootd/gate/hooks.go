package gate

import (
	"context"
	"fmt"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// StdioChecker checks a task's stdio path on disk. rootpolicy.CheckTaskIO
// checks the text only, and the runc shim opens each path as root and
// follows links: a non-FIFO stdout is opened O_WRONLY|O_APPEND, so a symlink
// there would append the sandbox's output to any host file. The helper makes
// the FIFOs, in a folder only root can write (plan T2), and the checker
// makes sure the path is one of those.
type StdioChecker interface {
	CheckStdio(path string) error
}

// BindChecker checks a spec's bind source on disk, from the bind root
// rootpolicy.BindRootFor names. rootpolicy.CheckBindSource checks the text
// only, and runc follows links in a source: a hosts/<id>/resolv.conf the
// agent turned into a link to / binds the host's whole filesystem in. The
// check walks the path without following links, and requires every folder
// from the root down to be root's alone, so the agent cannot swap the
// source between the check and the mount (plan T2: the helper writes those
// files).
type BindChecker interface {
	CheckBind(root, src string) error
}

// ReadChecker checks, on disk, a path root reads because a container
// record names it (rootpolicy.ContainerRootReads): the runsc config, which
// names the binary runsc runs and can turn on host networking, and a
// restore image. CheckContainer checks the name; a name in the right folder
// is only as good as who can write that folder.
type ReadChecker interface {
	CheckRead(r rootpolicy.RootRead) error
}

// NetnsBinding says whether a named network namespace is the one the helper
// made for a container. The netns pool moves into the helper in T2; until it
// is wired, Config.NetnsBinding is nil and only the name's form is checked
// (rootpolicy.CheckNetnsPath), so a broken agent can put one sandbox in
// another's namespace. That is not root: a broken agent already reaches
// every sandbox on its node (plans/security-gaps-m1-m4.md, R9).
type NetnsBinding interface {
	Bound(ctx context.Context, netns, containerID string) (bool, error)
}

// checkNetns asks the binding, when there is one, about the namespace c
// joins. A lookup that fails fails the call, unforwarded: it is not a
// refusal, since nothing says the request was hostile.
func (g *Gate) checkNetns(ctx context.Context, c rootpolicy.Container) error {
	if g.netns == nil {
		return nil
	}
	name, err := rootpolicy.ContainerNetns(c)
	if err != nil || name == "" {
		return err
	}
	bound, err := g.netns.Bound(ctx, name, c.ID)
	if err != nil {
		return fmt.Errorf("containerd gate: which sandbox owns network namespace %s: %w", name, err)
	}
	if !bound {
		return &rootpolicy.Violation{Rule: rootpolicy.RuleHostNamespace,
			Detail: fmt.Sprintf("network namespace %q is not the one the helper made for %s", name, c.ID)}
	}
	return nil
}

// checkBinds walks every bind source of c on disk.
func (g *Gate) checkBinds(c rootpolicy.Container) error {
	sources, err := rootpolicy.SpecBindSources(c)
	if err != nil {
		return err
	}
	for _, src := range sources {
		root, ok := rootpolicy.BindRootFor(g.policy, src)
		if !ok { // CheckContainer has refused this already; stay closed anyway
			return bindViolation(src, "outside every bind root")
		}
		if err := g.binds.CheckBind(root, src); err != nil {
			return err
		}
	}
	return nil
}

// checkReads walks every path c makes root read on disk.
func (g *Gate) checkReads(c rootpolicy.Container) error {
	reads, err := rootpolicy.ContainerRootReads(c)
	if err != nil {
		return err
	}
	for _, r := range reads {
		if err := g.reads.CheckRead(r); err != nil {
			return err
		}
	}
	return nil
}

func readViolation(r rootpolicy.RootRead, format string, args ...any) error {
	return &rootpolicy.Violation{Rule: r.Rule, Detail: fmt.Sprintf("%q, which root reads: ", r.Path) + fmt.Sprintf(format, args...)}
}

func bindViolation(src, format string, args ...any) error {
	return &rootpolicy.Violation{Rule: rootpolicy.RuleMount, Detail: fmt.Sprintf("bind source %q: ", src) + fmt.Sprintf(format, args...)}
}

func stdioViolation(path, format string, args ...any) error {
	return &rootpolicy.Violation{Rule: rootpolicy.RuleTaskIO, Detail: fmt.Sprintf("task stdio %q: ", path) + fmt.Sprintf(format, args...)}
}
