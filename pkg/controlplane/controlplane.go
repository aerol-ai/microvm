// Package controlplane is the neutral seam between sandboxd and an optional
// managed control plane. It declares small capability interfaces — caller-token
// validation, usage-sample reporting, and standing-driven fleet enforcement —
// and ships a no-op implementation that is the default in the open-source build.
//
// The open-source daemon links only against this package. A managed build wires
// a concrete Provider (backed by a private client) at startup; nothing about
// that client's behavior lives here. With the no-op Provider, sandboxd behaves
// byte-for-byte as it did before this seam existed: user tokens are rejected
// (leaving only the operator PAT path), usage reporting is discarded, and the
// enforcement loop does nothing.
package controlplane

import (
	"context"
	"errors"
	"time"
)

// ErrTokenRejected is returned by Validator.Validate for any token the control
// plane declines (or for every token under the no-op Provider). The API edge
// maps it to 401.
var ErrTokenRejected = errors.New("controlplane: token rejected")

// Identity is the account a caller token resolves to. OwnerRef is the stable
// account key stamped onto sandboxes and usage samples; ExternalID is
// informational only.
type Identity struct {
	ExternalID string
	OwnerRef   string
}

// Sample is one neutral usage record. It carries units, never money — the
// managed side is solely responsible for any interpretation of these values.
type Sample struct {
	EventID     string
	OwnerRef    string
	SandboxID   string
	Kind        string
	Value       float64
	Unit        string
	WindowStart time.Time
	WindowEnd   time.Time
}

// Validator resolves a caller token to an Identity. Implementations are
// expected to cache internally; the daemon calls this per authenticated request
// for non-PAT tokens.
type Validator interface {
	Validate(ctx context.Context, token string) (Identity, error)
}

// Reporter ships usage samples toward the managed ingest. Implementations must
// be non-blocking enough to sit on the daemon's background loops without
// stalling them.
type Reporter interface {
	Report(ctx context.Context, batch []Sample) error
}

// FleetController is implemented by the service layer so the managed build can
// converge the fleet to a standing directive without the control-plane client
// knowing any orchestration internals. Every method must be idempotent.
type FleetController interface {
	StopByOwner(ctx context.Context, ownerRef string) error
	RestoreByOwner(ctx context.Context, ownerRef string) error
	DeleteByOwner(ctx context.Context, ownerRef string) error
	FireWebhook(ctx context.Context, ownerRef, level string) error
}

// Enforcement is the background standing loop. Start is called once at daemon
// boot by the managed build; the no-op Start returns immediately.
type Enforcement interface {
	Start(ctx context.Context)
}

// Provider bundles the capabilities a build supplies to the daemon. The
// open-source build uses Noop(); a managed build constructs one backed by the
// private client. Passed explicitly into the API server and background wiring —
// there is no global registry, so the dependency stays visible and testable.
type Provider struct {
	Validator   Validator
	Reporter    Reporter
	Enforcement Enforcement
}

// Noop returns a Provider whose capabilities do nothing: every token is
// rejected, every report is dropped, and enforcement never runs. This is the
// open-source default and the safe fallback whenever the feature is disabled.
func Noop() Provider {
	return Provider{
		Validator:   noopValidator{},
		Reporter:    noopReporter{},
		Enforcement: noopEnforcement{},
	}
}

// WithDefaults fills any nil capability on p with its no-op equivalent, so a
// managed build can supply only the pieces it has wired without risking a nil
// dereference on the others.
func (p Provider) WithDefaults() Provider {
	if p.Validator == nil {
		p.Validator = noopValidator{}
	}
	if p.Reporter == nil {
		p.Reporter = noopReporter{}
	}
	if p.Enforcement == nil {
		p.Enforcement = noopEnforcement{}
	}
	return p
}

type noopValidator struct{}

func (noopValidator) Validate(context.Context, string) (Identity, error) {
	return Identity{}, ErrTokenRejected
}

type noopReporter struct{}

func (noopReporter) Report(context.Context, []Sample) error { return nil }

type noopEnforcement struct{}

func (noopEnforcement) Start(context.Context) {}
