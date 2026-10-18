package harness

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/internal/identity"
)

// Where the identity fixture lives on every node. The identity scenarios set
// SB_IDENTITY_ENABLED=true and SB_IDENTITY_FILE=IdentityFilePath in their
// tfvars (extra_sandboxd_env); the file is absent at boot, which T6 treats
// as "OIDC answers 503 until a good file loads" while the PAT and avm_
// tokens work, and the suite installs it before the first OIDC use case.
const (
	IdentityFilePath = "/etc/sandboxd/itest-identity.yaml"
	IssuerJWKSPath   = "/etc/sandboxd/itest-jwks.json"
	K8sJWKSPath      = "/etc/sandboxd/itest-k8s-jwks.json"
)

// IdentityFileSpec is what varies between the identity files the suite
// pushes: the issuer URL changes every run (the issuer's port), the MCP
// resource follows the leased domain, and UC-276 adds a deny entry.
type IdentityFileSpec struct {
	// IssuerURL is the test issuer's URL (TestIssuer.URL).
	IssuerURL string
	// MCPResource is https://<domain>/mcp. Empty leaves remote-MCP OAuth
	// unconfigured (no domain to name).
	MCPResource string
	// DenySubjects are subs of the test issuer on the emergency deny list.
	DenySubjects []string
}

// identityBinding is one row of the test file's binding table.
type identityBinding struct {
	group, role, team string
}

// identityBindings is the test identity file's binding table, in file
// order. auditor and admin leave the team out: both are bound to every team
// by definition, and the file accepts the omission.
var identityBindings = []identityBinding{
	{GroupPaymentsEng, "runner", TeamPayments},
	{GroupCheckoutEng, "runner", TeamCheckout},
	{GroupPaymentsViewers, "viewer", TeamPayments},
	{GroupFleetViewers, "viewer", "*"},
	{GroupAuditors, "auditor", ""},
	{GroupAdmins, "admin", ""},
}

// RenderIdentityFile renders the test identity file and checks it with the
// daemon's own parser, so a file the nodes would refuse fails here, on the
// operator's machine, and not as a run of OIDC cases that all answer 503.
// It is built from identity.File, the struct the daemon decodes, so a
// schema change in T6 breaks this at compile time rather than on a node.
func RenderIdentityFile(spec IdentityFileSpec) ([]byte, error) {
	if strings.TrimSpace(spec.IssuerURL) == "" {
		return nil, fmt.Errorf("identity file: no issuer URL")
	}
	main := identity.FileIssuer{
		Name:        IssuerName,
		DisplayName: "AerolVM itest",
		Kind:        "oidc",
		URL:         spec.IssuerURL,
		JWKSFile:    IssuerJWKSPath,
		Audiences:   []string{WorkloadAudience, CLIClientID, DashboardClientID},
	}
	main.Clients.CLI = CLIClientID
	main.Clients.Dashboard = DashboardClientID
	if spec.MCPResource != "" {
		// The resource URL doubles as the access tokens' audience, the RFC
		// 8707 convention most providers follow.
		main.MCP = true
		main.MCPAudiences = []string{spec.MCPResource}
	}
	k8s := identity.FileIssuer{
		Name:      K8sIssuerName,
		Kind:      "oidc",
		URL:       K8sIssuerURL,
		JWKSFile:  K8sJWKSPath,
		Audiences: []string{K8sAudience},
	}
	f := identity.File{
		Version: identity.FileVersion,
		Issuers: []identity.FileIssuer{main, k8s},
	}
	for _, b := range identityBindings {
		f.Bindings = append(f.Bindings, identity.FileBinding{Issuer: IssuerName, Group: b.group, Role: b.role, Team: b.team})
	}
	// A projected service-account token has no groups: the binding matches
	// its sub, the way an operator binds one workload.
	f.Bindings = append(f.Bindings, identity.FileBinding{
		Issuer: K8sIssuerName,
		Claim:  map[string]string{"sub": K8sServiceAccount},
		Role:   "runner",
		Team:   TeamPayments,
	})
	for _, sub := range spec.DenySubjects {
		f.DenySubjects = append(f.DenySubjects, IssuerName+":"+sub)
	}
	if spec.MCPResource != "" {
		f.MCP = &identity.FileMCP{Resource: spec.MCPResource}
	}
	raw, err := yaml.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	if _, err := identity.Parse(raw); err != nil {
		return nil, fmt.Errorf("the rendered identity file is one the daemon would refuse: %w", err)
	}
	return raw, nil
}

// nodeFileInstallScript writes stdin to path, root-owned and 0644, by a
// rename in the same directory: a reader (the identity watcher's poll, a
// key refetch under load in UC-293) sees the old file or the new one, never
// half of one. Paths are the constants above, so %q quoting is plain sh.
func nodeFileInstallScript(path string) string {
	return fmt.Sprintf(`set -e; d=$(dirname %[1]q); sudo install -d -m 0755 "$d"; tmp=$(sudo mktemp "$d/.itest.XXXXXX"); sudo tee "$tmp" >/dev/null; sudo chmod 0644 "$tmp"; sudo mv -f "$tmp" %[1]q; echo INSTALLED`, path)
}

// identityReloadScript sends SIGHUP to sandboxd's main process only, which
// reloads the identity file at once (and the egress operator file, which
// shares the signal). --kill-who=main keeps the signal away from every
// other process in the unit's cgroup.
const identityReloadScript = `sudo systemctl kill --kill-who=main --signal=HUP sandboxd && echo RELOADED`

// InstallNodeFile writes content to path on node. The content travels on
// stdin, never in argv: sudo logs the full command line.
func InstallNodeFile(t *testing.T, node IntegrationNode, path string, content []byte) error {
	t.Helper()
	target, ok := SSHTarget(node)
	if !ok {
		return fmt.Errorf("node %s has no SSH address", node.Name)
	}
	out, err := SSHRunStdin(t, target, nodeFileInstallScript(path), string(content))
	if err != nil || !strings.Contains(out, "INSTALLED") {
		return fmt.Errorf("install %s on %s: %v: %s", path, node.Name, err, strings.TrimSpace(out))
	}
	return nil
}

// ReloadNodeIdentity makes node's sandboxd reload its identity file now
// rather than at the next poll.
func ReloadNodeIdentity(t *testing.T, node IntegrationNode) error {
	t.Helper()
	target, ok := SSHTarget(node)
	if !ok {
		return fmt.Errorf("node %s has no SSH address", node.Name)
	}
	out, err := SSHRun(t, target, identityReloadScript)
	if err != nil || !strings.Contains(out, "RELOADED") {
		return fmt.Errorf("SIGHUP sandboxd on %s: %v: %s", node.Name, err, strings.TrimSpace(out))
	}
	return nil
}
