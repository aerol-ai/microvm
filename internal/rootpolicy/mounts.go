package rootpolicy

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// The rules for the root helper's external mounts (M1 PR 8; plan §3.3,
// "Mounts"). A mount spec becomes a root-run mount(8) of an NFS share, or a
// FUSE mount the helper makes and a tool it starts, so the helper checks
// every spec itself, with the same code the agent runs at create:
//
//   - the secrets rule first (models.MountSpec.ValidateSecretsPlacement):
//     no credential in the source or the options, which reach a command
//     line. It names a field and a shape, never a value, so a refusal
//     never carries a secret into a log;
//   - the spec rules (models.MountSpec.Validate): a known type, a clean
//     target, a source no tool reads as an option;
//   - the tool allow lists (ValidateToolOptions; for a running mount kept
//     as it runs, ValidateRunningToolOptions);
//   - credentials: only the keys the type's tool reads
//     (adapters.CredentialKeys).
//
// The agent never names a host path. Every mount point is
// <root>/<sandbox ID>/<index>, built here, and the containerd gate lets a
// container bind only its own (CheckMountBind).

// RuleExternalMount is a refused external mount.
const RuleExternalMount Rule = "external_mount"

// CheckMountSandboxID checks the sandbox ID a mount call names: one path
// component, as every mount point and log file is named after it.
func CheckMountSandboxID(id string) error {
	if err := models.ValidateSandboxID(id); err != nil {
		return violate(RuleExternalMount, "mount sandbox ID: %v", err)
	}
	return nil
}

// CheckExternalMounts checks a sandbox's mount set. running is a mount set
// kept as it runs: its tool options are held to the lists a running mount
// may keep. Nothing is started for such a set.
func CheckExternalMounts(specs []models.MountSpec, running bool) error {
	if len(specs) == 0 {
		return violate(RuleExternalMount, "no mounts")
	}
	if len(specs) > models.MaxMountsPerSandbox {
		return violate(RuleExternalMount, "%d mounts; a sandbox has at most %d", len(specs), models.MaxMountsPerSandbox)
	}
	for i := range specs {
		if err := CheckExternalMount(&specs[i], running); err != nil {
			return violate(RuleExternalMount, "mount %d: %v", i, err)
		}
	}
	return nil
}

// CheckExternalMount checks one mount. Its errors name fields and flags,
// never a credential's value.
func CheckExternalMount(m *models.MountSpec, running bool) error {
	if m == nil {
		return violate(RuleExternalMount, "mount is nil")
	}
	if err := m.ValidateSecretsPlacement(); err != nil {
		return violate(RuleExternalMount, "%v", err)
	}
	if err := m.Validate(""); err != nil {
		return violate(RuleExternalMount, "%v", err)
	}
	check := m.ValidateToolOptions
	if running {
		check = m.ValidateRunningToolOptions
	}
	if err := check(); err != nil {
		return violate(RuleExternalMount, "%v", err)
	}
	keys := adapters.CredentialKeys(m.Type)
	for _, k := range sortedKeys(m.Credentials) {
		if !slices.Contains(keys, k) {
			return violate(RuleExternalMount, "credentials.%s is not one the %s tool reads", printable(k), m.Type)
		}
	}
	return nil
}

// printable is a credential's name as a message may show it: names are
// short words, and anything else is cut, so a value pasted as a name
// cannot reach a log whole.
func printable(s string) string {
	if len(s) > 32 {
		s = s[:32] + "..."
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// MountPoint is where mount index of a sandbox lands under the mounts
// folder root: <root>/<id>/<index>.
func MountPoint(root, sandboxID string, index int) (string, error) {
	if !cleanAbs(root) || root == "/" {
		return "", violate(RuleExternalMount, "mounts folder %q is not a clean absolute folder other than /", root)
	}
	if err := CheckMountSandboxID(sandboxID); err != nil {
		return "", err
	}
	if index < 0 || index >= models.MaxMountsPerSandbox {
		return "", violate(RuleExternalMount, "mount index %d is outside 0-%d", index, models.MaxMountsPerSandbox-1)
	}
	return path.Join(root, sandboxID, strconv.Itoa(index)), nil
}

// CheckMountBind is the containerd gate's rule for a bind from an external
// mounts folder (a bind root): a container binds only a mount point of its
// own, <root>/<container ID>/<index>. Not the sandbox's folder, which
// holds the tools' logs, not a log, and not another sandbox's mount.
func CheckMountBind(root, containerID, src string) error {
	if models.ValidateSandboxID(containerID) != nil {
		return violate(RuleMount, "bind source %q: container %q has no mount points", src, containerID)
	}
	rest, ok := strings.CutPrefix(src, root+"/")
	if !ok {
		return violate(RuleMount, "bind source %q is not inside the mounts folder %s", src, root)
	}
	id, index, found := strings.Cut(rest, "/")
	if !found || id != containerID {
		return violate(RuleMount, "bind source %q is not a mount point of container %q", src, containerID)
	}
	n, err := strconv.Atoi(index)
	if err != nil || strconv.Itoa(n) != index || n < 0 || n >= models.MaxMountsPerSandbox {
		return violate(RuleMount, "bind source %q is not a mount point (<folder>/<container>/<index>)", src)
	}
	return nil
}
