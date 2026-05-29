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

// ErrAdmissionDenied is returned by Admitter.Admit when the caller's account is
// not permitted to create a sandbox right now (e.g. its access has been
// suspended or terminated by the control plane). It is a definite "no": the API
// edge maps it to 403. Distinct from ErrAdmissionUnavailable, which is a
// retryable "ask again later".
var ErrAdmissionDenied = errors.New("controlplane: admission denied")

// ErrAdmissionUnavailable is returned by Admitter.Admit when the control plane
// cannot vouch for the caller right now (standing data is not yet known and the
// contract's grace window has elapsed). It is retryable; the API edge maps it
// to 503 with a Retry-After hint.
var ErrAdmissionUnavailable = errors.New("controlplane: admission temporarily unavailable")

// Identity is the account a caller token resolves to. OwnerRef is the stable
// account key stamped onto sandboxes and usage samples; ExternalID is
// informational only.
type Identity struct {
	ExternalID string
	OwnerRef   string
}

// Access is the authenticated caller context attached by the API auth
// middleware and read by the service layer to enforce owner scoping. Operator
// is true for the PAT path (operator/admin: bypasses scoping, sees the whole
// fleet); for a validated user token Operator is false and Identity.OwnerRef is
// the tenant the request is scoped to.
//
// Background loops and internal calls run with no Access in context. The
// service layer treats "no Access present" as unscoped (fleet-wide) so those
// paths are never accidentally constrained — only an explicit non-operator
// Access narrows visibility.
type Access struct {
	Identity Identity
	Operator bool
}

type accessCtxKey struct{}

// ContextWithAccess returns a child context carrying a. The auth middleware
// calls this after authenticating; downstream service methods read it back via
// AccessFromContext.
func ContextWithAccess(ctx context.Context, a Access) context.Context {
	return context.WithValue(ctx, accessCtxKey{}, a)
}

// AccessFromContext returns the Access attached to ctx, if any. ok is false for
// background loops and internal calls that never went through the auth edge —
// callers must treat that as unscoped (operator-equivalent) access.
func AccessFromContext(ctx context.Context) (Access, bool) {
	a, ok := ctx.Value(accessCtxKey{}).(Access)
	return a, ok
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

// Admitter is the create-admission gate. The daemon consults it before
// reserving capacity for a new sandbox: a non-nil error refuses the create
// (e.g. the owner's account is suspended, or fleet standing is unknown beyond
// the contract grace). The no-op Admitter admits everything, so the
// open-source build never gates creates.
type Admitter interface {
	Admit(ctx context.Context, ownerRef string) error
}

// Provider bundles the capabilities a build supplies to the daemon. The
// open-source build uses Noop(); a managed build constructs one backed by the
// private client. Passed explicitly into the API server and background wiring —
// there is no global registry, so the dependency stays visible and testable.
//
// EnforcementFor is a factory rather than a ready Enforcement because the
// FleetController it drives is the service layer, which only exists partway
// through daemon boot. The daemon calls EnforcementFor(svc).Start(ctx) once the
// service is constructed. A nil factory (or one returning the no-op) means no
// enforcement loop runs.
type Provider struct {
	Validator      Validator
	Reporter       Reporter
	Admitter       Admitter
	EnforcementFor func(FleetController) Enforcement
}

// Noop returns a Provider whose capabilities do nothing: every token is
// rejected, every report is dropped, every create is admitted, and enforcement
// never runs. This is the open-source default and the safe fallback whenever
// the feature is disabled.
func Noop() Provider {
	return Provider{
		Validator:      noopValidator{},
		Reporter:       noopReporter{},
		Admitter:       noopAdmitter{},
		EnforcementFor: func(FleetController) Enforcement { return noopEnforcement{} },
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
	if p.Admitter == nil {
		p.Admitter = noopAdmitter{}
	}
	if p.EnforcementFor == nil {
		p.EnforcementFor = func(FleetController) Enforcement { return noopEnforcement{} }
	}
	return p
}

type noopValidator struct{}

func (noopValidator) Validate(context.Context, string) (Identity, error) {
	return Identity{}, ErrTokenRejected
}

type noopReporter struct{}

func (noopReporter) Report(context.Context, []Sample) error { return nil }

type noopAdmitter struct{}

func (noopAdmitter) Admit(context.Context, string) error { return nil }

type noopEnforcement struct{}

func (noopEnforcement) Start(context.Context) {}
