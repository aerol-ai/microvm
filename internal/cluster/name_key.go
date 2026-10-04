package cluster

import (
	"encoding/base64"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Sandbox name keys (plans/mcp-server-and-agent-cli.md §5.6, eng review D8/D9).
//
// Sandbox names are unique per owner, but the FSM keeps a single nameIndex
// keyed by whatever specName(cmd.Spec) returns. The apply path is left
// untouched on purpose: during a rolling upgrade, old and new replicas apply
// the same log, and they only reach the same nameIndex if the key comes from
// the command bytes alone. So the proposer (the node that builds the command)
// writes the owner-qualified key into Spec.Name before the command is encoded:
//
//	owner_ref ""  → Spec.Name = "my-agent"                     operator: plain, global
//	owner_ref "A" → Spec.Name = "owner:<base64url(A)>/my-agent"
//	apply (old or new replica): specName(Spec) → nameIndex[key]  same bytes ⇒ same result
//	lookup(A, "my-agent"): qualified key, else plain key whose OwnerRef == A (legacy)
//
// Placement.Name follows Spec.Name (splitPlacement), so it holds the key too.
// Code that turns a replicated spec back into a local sandbox (failover
// recreate) decodes the key to the user's name. models.ValidateSandboxName
// rejects new names that start with the prefix, so a qualified key can't be
// forged by another tenant.

// QualifiedSandboxName returns the nameIndex key for a sandbox called name
// owned by ownerRef. Operator sandboxes (ownerRef "") and unnamed sandboxes
// keep their plain name. A name that already carries the reserved prefix is
// returned unchanged, which makes the encoder idempotent: a spec read back
// from the FSM (SpecOf) and replayed through UpsertSpec keeps its key, and a
// legacy name that predates the reservation keeps the key it was indexed
// under.
func QualifiedSandboxName(ownerRef, name string) string {
	name = strings.TrimSpace(name)
	ownerRef = strings.TrimSpace(ownerRef)
	if name == "" || ownerRef == "" || strings.HasPrefix(name, models.SandboxNameOwnerPrefix) {
		return name
	}
	return models.SandboxNameOwnerPrefix + base64.RawURLEncoding.EncodeToString([]byte(ownerRef)) + "/" + name
}

// DecodeSandboxNameKey splits a nameIndex key into its owner and user name.
// qualified is false for a plain key. A key that starts with the prefix but
// isn't exactly what QualifiedSandboxName would produce (a legacy name that
// began with "owner:" before the prefix was reserved) also reports false and
// decodes to itself: decoding never fails, it only declines to rewrite.
func DecodeSandboxNameKey(key string) (ownerRef, name string, qualified bool) {
	key = strings.TrimSpace(key)
	rest, ok := strings.CutPrefix(key, models.SandboxNameOwnerPrefix)
	if !ok {
		return "", key, false
	}
	encodedOwner, userName, ok := strings.Cut(rest, "/")
	if !ok || encodedOwner == "" || userName == "" {
		return "", key, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(encodedOwner)
	if err != nil || len(raw) == 0 {
		return "", key, false
	}
	if QualifiedSandboxName(string(raw), userName) != key {
		return "", key, false
	}
	return string(raw), userName, true
}

// SandboxNameFromKey returns the user-visible name for a nameIndex key.
func SandboxNameFromKey(key string) string {
	_, name, _ := DecodeSandboxNameKey(key)
	return name
}

// QualifySpecName returns spec with Name rewritten to its nameIndex key for
// ownerRef. It returns spec itself when nothing changes (operator, unnamed,
// already qualified), so the operator create path allocates nothing; when it
// rewrites, it returns a shallow copy and never mutates the caller's spec.
func QualifySpecName(spec *models.CreateSandboxRequest, ownerRef string) *models.CreateSandboxRequest {
	if spec == nil {
		return nil
	}
	key := QualifiedSandboxName(ownerRef, spec.Name)
	if key == spec.Name {
		return spec
	}
	cp := *spec
	cp.Name = key
	return &cp
}

// DecodeSpecName returns spec with an owner-qualified Name turned back into
// the user's name. This is the choke point for recreating a local sandbox
// from a replicated spec: the local store keeps user names, unique per owner.
func DecodeSpecName(spec models.CreateSandboxRequest) models.CreateSandboxRequest {
	spec.Name = SandboxNameFromKey(spec.Name)
	return spec
}

// specNeedsOwnerForName reports whether a proposer has to know the sandbox's
// owner before it can write spec into a command: only a named spec whose name
// is not already a key can be rewritten.
func specNeedsOwnerForName(spec *models.CreateSandboxRequest) bool {
	if spec == nil {
		return false
	}
	name := strings.TrimSpace(spec.Name)
	return name != "" && !strings.HasPrefix(name, models.SandboxNameOwnerPrefix)
}

// resolveOwnerName runs the per-owner name lookup over a raw nameIndex read.
// lookupKey returns the sandbox ID holding key and that placement's OwnerRef.
// The qualified key wins; the plain key is accepted only when its placement
// belongs to the same owner, which keeps tenant sandboxes created before
// per-owner names resolvable without letting one tenant reach another's.
func resolveOwnerName(ownerRef, name string, lookupKey func(key string) (sandboxID, placementOwnerRef string, ok bool)) (string, bool) {
	name = strings.TrimSpace(name)
	ownerRef = strings.TrimSpace(ownerRef)
	if name == "" {
		return "", false
	}
	if ownerRef != "" {
		if key := QualifiedSandboxName(ownerRef, name); key != name {
			if id, _, ok := lookupKey(key); ok {
				return id, true
			}
		}
	}
	id, placementOwnerRef, ok := lookupKey(name)
	if !ok || strings.TrimSpace(placementOwnerRef) != ownerRef {
		return "", false
	}
	return id, true
}
