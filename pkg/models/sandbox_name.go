package models

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// SandboxNameOwnerPrefix marks an owner-qualified sandbox name key in the
// cluster's replicated name index ("owner:<base64url(owner_ref)>/<name>").
// Names are unique per owner, and the cluster keeps one global index, so a
// tenant's name is stored under a key that carries its owner. The prefix is
// reserved: a caller-supplied name that starts with it could collide with
// another tenant's key, so new creates reject it.
const SandboxNameOwnerPrefix = "owner:"

// generatedSandboxIDPattern is the shape generateSandboxID produces
// ("sb-" + 16 lowercase hex). Clients route a reference by this shape alone:
// a ref that matches is an ID, anything else is a name. A name with this
// shape would be unreachable by name, so creates reject it.
var generatedSandboxIDPattern = regexp.MustCompile(`^sb-[0-9a-f]{16}$`)

// ErrInvalidSandboxName is returned when a create carries a name that the
// name rules reserve. It maps to HTTP 400 through the default branch of
// apihttp.WriteStoreAwareError.
var ErrInvalidSandboxName = errors.New("invalid sandbox name")

// IsGeneratedSandboxID reports whether ref has the shape of a daemon-generated
// sandbox ID. Agent clients use it to decide between an ID lookup and a name
// lookup with one request.
func IsGeneratedSandboxID(ref string) bool {
	return generatedSandboxIDPattern.MatchString(ref)
}

// ValidateSandboxName applies the intake rules for a new sandbox name. Empty
// is allowed (an unnamed sandbox). The rules are intake-only: a stored spec
// replayed on failover keeps whatever name it already had, including legacy
// names created before these rules existed.
func ValidateSandboxName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if strings.HasPrefix(name, SandboxNameOwnerPrefix) {
		return fmt.Errorf("%w %q: the %q prefix is reserved", ErrInvalidSandboxName, name, SandboxNameOwnerPrefix)
	}
	if IsGeneratedSandboxID(name) {
		return fmt.Errorf("%w %q: names shaped like a sandbox ID (sb- plus 16 hex) are reserved", ErrInvalidSandboxName, name)
	}
	return nil
}
