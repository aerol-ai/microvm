package cluster

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestCustomDomainsBoundRoundTrip(t *testing.T) {
	b := CustomDomainsBound{SandboxID: "sb-1", Hostnames: []string{"app.customer.com", "shop.customer.com"}}
	got, ok := ParseCustomDomainsBound(b.encode())
	if !ok || got.SandboxID != "sb-1" || len(got.Hostnames) != 2 {
		t.Fatalf("round trip = %+v, %v", got, ok)
	}
	if !got.Covers("sb-1", "shop.customer.com") || got.Covers("sb-2", "shop.customer.com") || got.Covers("sb-1", "other.customer.com") || got.Covers(" ", "app.customer.com") {
		t.Fatal("Covers matches only the sandbox and the names it bound")
	}
	tooMany := make([]string, 26)
	for i := range tooMany {
		tooMany[i] = "h" + strings.Repeat("x", i+1) + ".customer.com"
	}
	for _, v := range []string{
		"", "sb-1", "sb-1 ", " app.customer.com", "../x app.customer.com", "sb-1 App.Customer.com",
		"sb-1 app.customer.com,", "sb-1 localhost", "sb-1 " + strings.Join(tooMany, ","),
	} {
		if _, ok := ParseCustomDomainsBound(v); ok {
			t.Errorf("ParseCustomDomainsBound(%q) accepted", v)
		}
	}
}

func TestContextWithCustomDomainsBound(t *testing.T) {
	ctx := context.Background()
	if _, ok := CustomDomainsBoundFromContext(ContextWithCustomDomainsBound(ctx, CustomDomainsBound{SandboxID: "sb-1"})); ok {
		t.Fatal("a marker with no names recorded something")
	}
	if _, ok := CustomDomainsBoundFromContext(ContextWithCustomDomainsBound(ctx, CustomDomainsBound{Hostnames: []string{"a.b.com"}})); ok {
		t.Fatal("a marker with no sandbox recorded something")
	}
	b := CustomDomainsBound{SandboxID: "sb-1", Hostnames: []string{"app.customer.com"}}
	got, ok := CustomDomainsBoundFromContext(ContextWithCustomDomainsBound(ctx, b))
	if !ok || !got.Covers("sb-1", "app.customer.com") {
		t.Fatalf("marker = %+v, %v", got, ok)
	}
}

// A forward carries the marker only from its own context, never from a
// header that came in with the request.
func TestStampForwardCustomDomainsBound(t *testing.T) {
	b := CustomDomainsBound{SandboxID: "sb-1", Hostnames: []string{"app.customer.com"}}
	out := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil).WithContext(ContextWithCustomDomainsBound(context.Background(), b))
	StampForward(out, controlplane.Access{})
	if got := out.Header.Get(HeaderCustomDomainsBound); got != "sb-1 app.customer.com" {
		t.Fatalf("header = %q", got)
	}
	plain := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
	plain.Header.Set(HeaderCustomDomainsBound, "sb-1 app.customer.com")
	StampForward(plain, controlplane.Access{})
	if got := plain.Header.Get(HeaderCustomDomainsBound); got != "" {
		t.Fatalf("a header that came in was forwarded: %q", got)
	}
}

// A server binds with an explicit incarnation (the create's reservation,
// which this node's FSM copy may not show yet); one missing is refused.
func TestAddCustomDomainForIncarnation(t *testing.T) {
	c := stampLeader(t, "ldr-bind-inc", workerMember("wkr-9", ""))
	place, _ := encodeCommand(command{Op: opPlace, SandboxID: "sb-b", OwnerNodeID: "wkr-9", IncarnationID: "inc-b"})
	if err := c.ApplyEncoded(workerApplyCtx("wkr-9"), place); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, args := range [][3]string{{"", "inc-b", "a.customer.com"}, {"sb-b", " ", "a.customer.com"}, {"sb-b", "inc-b", ""}} {
		if err := c.AddCustomDomainForIncarnation(ctx, args[0], args[1], args[2]); !errors.Is(err, ErrIncarnationConflict) {
			t.Errorf("bind %v = %v", args, err)
		}
	}
	if err := c.AddCustomDomainForIncarnation(ctx, "sb-b", "inc-other", "a.customer.com"); !errors.Is(err, ErrIncarnationConflict) {
		t.Fatalf("bind at a stale incarnation = %v", err)
	}
	if err := c.AddCustomDomainForIncarnation(ctx, "sb-b", "inc-b", "a.customer.com"); err != nil {
		t.Fatal(err)
	}
	if got := c.CustomDomainsOf("sb-b"); len(got) != 1 || got[0] != "a.customer.com" {
		t.Fatalf("bound %v", got)
	}
}

// The leader's refusal of a proposal reaches the worker as
// ErrPeerProposalRefused, on both hops.
func TestProposalRefusalCrossesTheWire(t *testing.T) {
	msg := ErrPeerProposalRefused.Error() + `: node "wkr-1" (role worker) sent op 13`
	if err := forwardApplyStatus(http.StatusForbidden, msg); !errors.Is(err, ErrPeerProposalRefused) {
		t.Fatalf("forwardApplyStatus = %v", err)
	}
	if err := forwardApplyStatus(http.StatusForbidden, "some other refusal"); errors.Is(err, ErrPeerProposalRefused) {
		t.Fatal("another 403 read as a role refusal")
	}
	if !errors.Is(statusError{status: http.StatusForbidden, message: msg}, ErrPeerProposalRefused) {
		t.Fatal("agent status error does not match the refusal")
	}
	if errors.Is(statusError{status: http.StatusServiceUnavailable, message: msg}, ErrPeerProposalRefused) {
		t.Fatal("a 503 read as a role refusal")
	}
}
