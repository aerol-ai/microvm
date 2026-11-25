package containerd

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/network/netns"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// One owner gives an address back (give_back.go): these pin that every
// path goes through it, that a second caller finds nothing to do, and that
// a late caller never clears an address the pool has handed on.

// recordGiveBacks records the owner of every giveBack call for one test.
func recordGiveBacks(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var owners []string
	testHookGiveBack = func(owner string) {
		mu.Lock()
		defer mu.Unlock()
		owners = append(owners, owner)
	}
	t.Cleanup(func() { testHookGiveBack = nil })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(owners)
	}
}

// The race the slot lock closes (#1459 review): the pool's retry and a
// retried create's removal of the same leftover both give sb-a's address
// back. Here the retry reaches giveBack, then the removal gives the
// address back first and the pool hands it to sb-new, which puts its own
// rules on it. The retry, coming second, must find nothing to do: before,
// it cleared the address it had read, and sb-new lost its rules.
func TestGiveBackRaceLeavesTheNextHoldersRules(t *testing.T) {
	ctx := context.Background()
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	be := singleModeRules(t, r.d, r.parkIP)
	r.busy.Store(false)
	newRules, fired := 0, false
	testHookGiveBack = func(owner string) {
		if owner != "sb-a" || fired {
			return
		}
		fired = true
		if err := r.d.Destroy(ctx, leftoverStub(r.parkIP)); err != nil {
			t.Errorf("the removal: %v", err)
		}
		if _, ip, err := r.h.Provision(ctx, "sb-new"); err != nil || ip != r.parkIP {
			t.Errorf("sb-new got %q, %v; want %s", ip, err, r.parkIP)
		}
		if err := r.d.ApplyEgressPolicy(r.parkIP, []string{"10.5.0.0/16"}, nil); err != nil {
			t.Error(err)
		}
		newRules = len(be.rulesOf(r.parkIP))
	}
	t.Cleanup(func() { testHookGiveBack = nil })
	if err := r.retry(t); err != nil {
		t.Fatal(err)
	}
	if !fired {
		t.Fatal("the pool's retry never gave sb-a's address back")
	}
	if got := len(be.rulesOf(r.parkIP)); newRules == 0 || got != newRules {
		t.Fatalf("sb-new's rules on %s: %d left of %d", r.parkIP, got, newRules)
	}
	if held, _ := r.h.Address(ctx, "sb-new"); held != r.parkIP {
		t.Fatalf("sb-new holds %q, want %s", held, r.parkIP)
	}
}

// Two claims of sb-a failed. The first one's address went to sb-other, and
// sb-a now holds the second claim's slot. A removal that names no address
// clears the slot sb-a holds, never the first claim's address.
func TestClaimLeftoverDestroyTakesTheSlotTheIDHolds(t *testing.T) {
	ctx := context.Background()
	r := newDoubleFailureRig(t, false)
	r.failClaim(t)
	if err := r.h.Release(ctx, "sb-a"); err != nil {
		t.Fatal(err)
	}
	if _, x, err := r.h.Provision(ctx, "sb-other"); err != nil || x != r.parkIP {
		t.Fatalf("sb-other got %q, %v; want %s", x, err, r.parkIP)
	}
	_, y, err := r.h.Provision(ctx, "sb-a")
	if err != nil || y == "" || y == r.parkIP {
		t.Fatalf("sb-a got %q, %v", y, err)
	}
	r.d.claimLeftovers.remember("park-b", "sb-a", y)
	be := singleModeRules(t, r.d, y)
	if err := r.d.ApplyEgressPolicy(r.parkIP, []string{"10.6.0.0/16"}, nil); err != nil {
		t.Fatal(err)
	}
	others := len(be.rulesOf(r.parkIP))
	if got := r.d.claimLeftoverAddress(ctx, "sb-a"); got != y {
		t.Fatalf("the address told for the removal is %q, want the second claim's %s", got, y)
	}
	r.busy.Store(false)
	if err := r.d.Destroy(ctx, leftoverStub("")); err != nil {
		t.Fatal(err)
	}
	if left := be.rulesOf(y); len(left) > 0 {
		t.Fatalf("rules left on %s: %v", y, left)
	}
	if got := len(be.rulesOf(r.parkIP)); got != others {
		t.Fatalf("sb-other's rules on %s: %d left of %d", r.parkIP, got, others)
	}
	if held, _ := r.h.Address(ctx, "sb-a"); held != "" {
		t.Fatalf("sb-a still holds %s", held)
	}
	if held, _ := r.h.Address(ctx, "sb-other"); held != r.parkIP {
		t.Fatalf("sb-other holds %q, want %s", held, r.parkIP)
	}
}

// Every path that ends a holder gives its address back through giveBack.
func TestEveryPathGivesItsAddressBackThroughGiveBack(t *testing.T) {
	ctx := context.Background()
	t.Run("Destroy of a sandbox", func(t *testing.T) {
		got := recordGiveBacks(t)
		d := New(Config{}, nil, nil)
		d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
		d.SetNetnsHandoff(&fakeNetnsHandoff{})
		if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-n", ContainerIP: "10.88.0.5"}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got(), []string{"sb-n"}) {
			t.Fatalf("giveBack calls %v", got())
		}
	})
	t.Run("Destroy of a leftover", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		r.busy.Store(false)
		got := recordGiveBacks(t)
		if err := r.d.Destroy(ctx, leftoverStub(r.parkIP)); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got(), []string{"sb-a"}) {
			t.Fatalf("giveBack calls %v", got())
		}
	})
	t.Run("the pool's retry: destroyParked, then the free step", func(t *testing.T) {
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		r.busy.Store(false)
		got := recordGiveBacks(t)
		r.pool.Close()
		if !slices.Equal(got(), []string{"park-a", "sb-a"}) {
			t.Fatalf("giveBack calls %v", got())
		}
	})
	t.Run("a failed claim's discard", func(t *testing.T) {
		r := newTeardownRig(t, false)
		r.fw.liftErr = context.Canceled
		got := recordGiveBacks(t)
		r.claim(ctx, t)
		if !slices.Equal(got(), []string{"park-a", "sb-a"}) {
			t.Fatalf("giveBack calls %v", got())
		}
	})
	t.Run("a failed cold create's undo", func(t *testing.T) {
		stubToolboxProbe(t)
		r := newDoubleFailureRig(t, false)
		r.failClaim(t)
		r.busy.Store(false)
		r.pool.Close()
		got := recordGiveBacks(t)
		if err := r.coldCreate(t, false); err == nil {
			t.Fatal("setup: the rig's cold create is meant to stop after its netns step")
		}
		if !slices.Equal(got(), []string{"sb-a"}) {
			t.Fatalf("giveBack calls %v", got())
		}
	})
}

// A sandbox that holds no slot gives back the address its row names only
// when the pool never had that address (a sandbox made before the native
// pool was turned on). An address the pool has is only its holder's to
// clear.
func TestDestroyClearsAnAddressThePoolNeverHad(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SeedContainerNetnsSlot(ctx, "slot-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	h := netns.NewRuntimeHandoff(netns.New(st), netns.NewFakeHost())
	_, pooled, err := h.Provision(ctx, "sb-pooled")
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{}, nil, nil)
	d.SetClient(NewTestClient("aerolvm", newFakeTransport()))
	d.SetNetnsHandoff(h)
	const legacy = "10.88.7.7"
	be := &addressMemBackend{netrulesMemBackend: &netrulesMemBackend{}}
	d.SetHostFirewall(netrules.NewWithBackend(be))
	for _, ip := range []string{legacy, pooled} {
		if err := d.ApplyNetworkBlockAll(ip); err != nil {
			t.Fatal(err)
		}
	}
	// No slot, and the pool never had the address: its rules go.
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-legacy", ContainerIP: legacy}); err != nil {
		t.Fatal(err)
	}
	if left := be.rulesOf(legacy); len(left) > 0 {
		t.Fatalf("rules left on %s: %v", legacy, left)
	}
	// No slot, but the pool's address (held by sb-pooled): untouched.
	if err := d.Destroy(ctx, &models.Sandbox{ID: "sb-gone", ContainerIP: pooled}); err != nil {
		t.Fatal(err)
	}
	if len(be.rulesOf(pooled)) == 0 {
		t.Fatalf("sb-pooled's rules on %s were cleared", pooled)
	}
}

// Without a netns pool an address is the container's: giveBack clears the
// known address's rules and frees no slot.
func TestGiveBackWithoutAPool(t *testing.T) {
	d := New(Config{}, nil, nil)
	var cleared []string
	ip, err := d.giveBack(context.Background(), giveBackReq{owner: "sb-1", known: "10.88.0.4", clear: func(ip string) { cleared = append(cleared, ip) }})
	if err != nil || ip != "10.88.0.4" || !slices.Equal(cleared, []string{"10.88.0.4"}) {
		t.Fatalf("giveBack = %q, %v, clears %v", ip, err, cleared)
	}
	d.SetNetnsHandoff(&fakeNetnsHandoff{})
	if ip, _ := d.giveBack(context.Background(), giveBackReq{owner: "", known: "10.88.0.4"}); ip != "" {
		t.Fatalf("giveBack with no owner = %q", ip)
	}
	if ip, _ := d.giveBack(context.Background(), giveBackReq{owner: "sb-1", match: true}); ip != "" {
		t.Fatalf("giveBack matching no address = %q", ip)
	}
}

// TestGiveBackOwnsEveryRuleClearAndRelease reads this package's code: a
// netns slot is released only in giveBack, and an address's rules are
// cleared only by the clear a giveBack caller hands it (a function literal
// in a function that calls giveBack), or by the clear helpers themselves.
// A new path that clears rules or frees a slot by itself fails here.
func TestGiveBackOwnsEveryRuleClearAndRelease(t *testing.T) {
	clears := map[string]bool{"ClearNetworkRules": true, "ClearEgressPolicy": true, "clearAddressRules": true,
		"clearCreateNetRules": true, "ClearAddressRules": true, "wholeAddress": true}
	// The clear helpers call each other; applyAdoptNetworkPolicy undoes a
	// rule it failed to put on a claim's live address, which stays the
	// claim's: no address is given back there.
	helpers := map[string]bool{"ClearNetworkRules": true, "ClearEgressPolicy": true, "clearAddressRules": true,
		"clearCreateNetRules": true, "ClearAddressRules": true, "wholeAddress": true, "applyAdoptNetworkPolicy": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var bad []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			callsGiveBack := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok && calleeName(c) == "giveBack" {
					callsGiveBack = true
				}
				return true
			})
			var lits []*ast.FuncLit
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if l, ok := n.(*ast.FuncLit); ok {
					lits = append(lits, l)
				}
				return true
			})
			inLit := func(p token.Pos) bool {
				for _, l := range lits {
					if p >= l.Pos() && p < l.End() {
						return true
					}
				}
				return false
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := calleeName(c)
				where := fset.Position(c.Pos()).String() + " in " + fn.Name.Name
				if name == "Release" && isNetnsField(c) && fn.Name.Name != "giveBack" {
					bad = append(bad, "netns slot released outside giveBack at "+where)
				}
				if clears[name] && !helpers[fn.Name.Name] && !(callsGiveBack && inLit(c.Pos())) {
					bad = append(bad, name+" clears rules outside a giveBack clear at "+where)
				}
				return true
			})
		}
	}
	if len(bad) > 0 {
		t.Fatalf("paths that give an address back by themselves:\n%s", strings.Join(bad, "\n"))
	}
}

// calleeName is the called function's or method's name.
func calleeName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// isNetnsField reports whether c is a call on d.netns (x.netns.Method).
func isNetnsField(c *ast.CallExpr) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && inner.Sel.Name == "netns"
}
