//go:build !linux

package gate

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

func TestHostPathsRefusedOffLinux(t *testing.T) {
	if err := defaultStdioChecker().CheckStdio("/run/aerolvm/fifo/1/out"); rootpolicy.RuleOf(err) != rootpolicy.RuleTaskIO {
		t.Fatalf("stdio: %v", err)
	}
	if err := defaultBindChecker().CheckBind("/var/lib/sandboxd/containerd/hosts", "/var/lib/sandboxd/containerd/hosts/sb-1/hosts", false); rootpolicy.RuleOf(err) != rootpolicy.RuleMount {
		t.Fatalf("bind: %v", err)
	}
	if err := defaultReadChecker().CheckRead(rootpolicy.RootRead{Path: "/var/lib/aerolvm-rootd/runsc/config.toml", Rule: rootpolicy.RuleRuntimeOptions}); rootpolicy.RuleOf(err) != rootpolicy.RuleRuntimeOptions {
		t.Fatalf("read: %v", err)
	}
}
