package controlplane

import (
	"context"
	"testing"
)

func TestNoopProviderRejectsTokens(t *testing.T) {
	p := Noop()
	ctx := context.Background()

	if _, err := p.Validator.Validate(ctx, "anything"); err != ErrTokenRejected {
		t.Errorf("noop Validate = %v, want ErrTokenRejected", err)
	}
	if err := p.Reporter.Report(ctx, []Sample{{OwnerRef: "x"}}); err != nil {
		t.Errorf("noop Report = %v, want nil", err)
	}
	if err := p.Admitter.Admit(ctx, "x"); err != nil {
		t.Errorf("noop Admit = %v, want nil (admit all)", err)
	}
	if _, err := p.Witness.WitnessHeads(ctx, nil); err != nil {
		t.Errorf("noop Witness = %v, want nil", err)
	}
	if head, ok, err := p.Witness.LastWitnessedHead(ctx, "n1"); err != nil || ok || head != "" {
		t.Errorf("noop LastWitnessedHead = (%q, %v, %v), want (\"\", false, nil)", head, ok, err)
	}
	if p.HasExternalWitness() {
		t.Error("noop provider must not report an external witness")
	}
	// Must not panic or block.
	p.EnforcementFor(stubController{}).Start(ctx)
}

func TestProviderWithDefaultsFillsNils(t *testing.T) {
	p := Provider{}.WithDefaults()
	if p.Validator == nil || p.Reporter == nil || p.Admitter == nil || p.Witness == nil || p.EnforcementFor == nil {
		t.Fatalf("WithDefaults left a nil capability: %+v", p)
	}
	ctx := context.Background()
	if _, err := p.Validator.Validate(ctx, "tok"); err != ErrTokenRejected {
		t.Errorf("filled validator should be no-op reject, got %v", err)
	}
	if p.EnforcementFor(stubController{}) == nil {
		t.Errorf("filled EnforcementFor returned nil enforcement")
	}
}

// stubController proves the FleetController interface is satisfiable by a host
// type; the managed build supplies the real one.
type stubController struct{}

func (stubController) StopByOwner(context.Context, string) error         { return nil }
func (stubController) RestoreByOwner(context.Context, string) error      { return nil }
func (stubController) DeleteByOwner(context.Context, string) error       { return nil }
func (stubController) FireWebhook(context.Context, string, string) error { return nil }

func TestFleetControllerIsImplementable(t *testing.T) {
	var _ FleetController = stubController{}
}

func TestContextWithAccess(t *testing.T) {
	ctx := context.Background()
	access := Access{Identity: Identity{OwnerRef: "test-acc"}, Operator: false}

	ctx2 := ContextWithAccess(ctx, access)
	access2, ok := AccessFromContext(ctx2)

	if !ok {
		t.Fatal("expected ok")
	}
	if access2.Identity.OwnerRef != "test-acc" {
		t.Fatal("wrong owner ref")
	}
}
