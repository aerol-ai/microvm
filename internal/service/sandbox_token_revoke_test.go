package service

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/sandboxtoken"
)

// setSandboxTokenClock pins the clock tokens are issued, verified and
// revoked with.
func setSandboxTokenClock(t *testing.T, at time.Time) {
	t.Helper()
	sandboxTokenNow = func() time.Time { return at }
	t.Cleanup(func() { sandboxTokenNow = time.Now })
}

// sandboxTokenCtx is the Access the API edge builds for a verified token.
func sandboxTokenCtx(c sandboxtoken.Claims) context.Context {
	return controlplane.ContextWithAccess(context.Background(), controlplane.Access{
		Identity:     controlplane.Identity{OwnerRef: c.Owner},
		Principal:    controlplane.Principal{Kind: controlplane.PrincipalSandboxToken, ID: c.TokenID, Name: c.TokenID},
		SandboxToken: &c,
	})
}

// issueClaims issues a token through the service and returns its verified
// claims, as the API edge would see them.
func issueClaims(t *testing.T, svc *Service, ctx context.Context, id string, req models.CreateSandboxTokenRequest) sandboxtoken.Claims {
	t.Helper()
	tok, err := svc.IssueSandboxToken(ctx, id, req)
	if err != nil {
		t.Fatalf("IssueSandboxToken: %v", err)
	}
	claims, err := svc.VerifySandboxToken(tok.Token)
	if err != nil {
		t.Fatalf("VerifySandboxToken: %v", err)
	}
	return claims
}

// A revoke on the toolbox route: a token from before it is refused where
// the toolbox request reads the row (EnsureSandboxAwakeForHTTP, the call
// ServeToolboxReverseProxy makes), including one issued earlier in the
// revoke's own second; a token issued after it, even in that same second,
// works. A retry answers the same not-before; a later revoke refuses the
// newer token too. Callers that are not sandbox tokens are untouched.
func TestRevokeSandboxTokensOnTheToolbox(t *testing.T) {
	svc, st, logs := testTokenService(t, time.Hour)
	seedTokenSandbox(t, st, "sb-rv", "team:payments", models.SandboxStatusStarted)
	seedTokenSandbox(t, st, "sb-rv-gone", "team:payments", models.SandboxStatusDestroyed)
	owner := teamCtx("payments")
	base := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) { setSandboxTokenClock(t, base.Add(d)) }
	toolbox := func(c sandboxtoken.Claims) error {
		_, err := svc.EnsureSandboxAwakeForHTTP(sandboxTokenCtx(c), "sb-rv")
		return err
	}

	at(100 * time.Millisecond)
	old := issueClaims(t, svc, owner, "sb-rv", models.CreateSandboxTokenRequest{ExpiresIn: "1h"})
	if err := toolbox(old); err != nil {
		t.Fatalf("before the revoke: %v", err)
	}

	at(400 * time.Millisecond)
	got, err := svc.RevokeSandboxTokens(owner, "sb-rv")
	nb := base.Unix() + 1
	if err != nil || got.SandboxID != "sb-rv" || !got.TokensNotBefore.Equal(time.Unix(nb, 0)) {
		t.Fatalf("revoke = %+v, %v; want not-before %d", got, err, nb)
	}
	if !errors.Is(toolbox(old), ErrSandboxTokenRevoked) {
		t.Fatalf("a token from earlier in the revoke's second still works: %v", toolbox(old))
	}

	// Issued after the revoke, inside the same second: lifted to the
	// not-before, so it works.
	at(700 * time.Millisecond)
	fresh := issueClaims(t, svc, owner, "sb-rv", models.CreateSandboxTokenRequest{ExpiresIn: "1h"})
	if fresh.IssuedAt != nb || fresh.ExpiresAt != nb+3600 {
		t.Fatalf("a token in the revoke's second: iat %d exp %d, want %d and %d", fresh.IssuedAt, fresh.ExpiresAt, nb, nb+3600)
	}
	if err := toolbox(fresh); err != nil {
		t.Fatalf("a token issued after the revoke: %v", err)
	}

	// A retry in the same second is the same revoke.
	at(800 * time.Millisecond)
	if again, err := svc.RevokeSandboxTokens(owner, "sb-rv"); err != nil || !again.TokensNotBefore.Equal(got.TokensNotBefore) {
		t.Fatalf("retry = %+v, %v", again, err)
	}
	if err := toolbox(fresh); err != nil {
		t.Fatalf("a retry refused a token issued after the first call: %v", err)
	}
	// Many at once: all answer, none moves the not-before back.
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := svc.RevokeSandboxTokens(owner, "sb-rv"); err != nil || r.TokensNotBefore.Unix() != nb {
				errs <- errors.Join(err, errors.New("concurrent revoke moved the not-before"))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	// A later revoke refuses the newer token too.
	at(3 * time.Second)
	if _, err := svc.RevokeSandboxTokens(owner, "sb-rv"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(toolbox(fresh), ErrSandboxTokenRevoked) {
		t.Fatal("a later revoke left the earlier token working")
	}
	// Callers that are not sandbox tokens are not affected.
	for name, ctx := range map[string]context.Context{"team runner": owner, "operator": context.Background()} {
		if _, err := svc.EnsureSandboxAwakeForHTTP(ctx, "sb-rv"); err != nil {
			t.Fatalf("%s after a revoke: %v", name, err)
		}
	}
	if out := logs.String(); !strings.Contains(out, "sandbox tokens revoked") || !strings.Contains(out, "sb-rv") {
		t.Fatalf("no log line for the revoke: %s", logs.String())
	}

	for _, tc := range []struct {
		name string
		ctx  context.Context
		id   string
	}{
		{"unknown sandbox", owner, "sb-none"},
		{"another team's sandbox", teamCtx("growth"), "sb-rv"},
		{"deleted sandbox", owner, "sb-rv-gone"},
	} {
		if _, err := svc.RevokeSandboxTokens(tc.ctx, tc.id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: %v, want ErrNotFound", tc.name, err)
		}
	}
}

// A revoke on a token-gated port: PortAccess hands the ingress proxy the
// row's not-before with the gate, from the row or the warm cache, with no
// read of its own. A revoke drops a warm entry, so a not-before cached
// before it never lets an old token in; the entry filled after it carries
// the new value. Checked with the cache empty and with it warm.
func TestRevokeSandboxTokensOnAGatedPort(t *testing.T) {
	for _, warm := range []bool{false, true} {
		name := "cache empty"
		if warm {
			name = "cache warm"
		}
		t.Run(name, func(t *testing.T) {
			base := time.Unix(1_800_000_000, 0)
			setSandboxTokenClock(t, base)
			svc, _, _, id := newGateHarness(t)
			ctx := context.Background()
			if _, err := svc.ExposePortWithVisibility(ctx, id, 3000, "http", models.ExposedPortVisibilityToken); err != nil {
				t.Fatal(err)
			}
			setSandboxTokenClock(t, base.Add(2*time.Second))
			old := issueClaims(t, svc, ctx, id, models.CreateSandboxTokenRequest{ExpiresIn: "1h", Port: 3000})
			if warm {
				a, err := svc.PortAccess(ctx, id, 3000)
				if err != nil || !a.TokenGated || old.CheckNotBefore(a.TokensNotBefore) != nil {
					t.Fatalf("before the revoke: %+v %v", a, err)
				}
				if e, ok := svc.warmEntryFor(id); !ok || e.notBefore != a.TokensNotBefore {
					t.Fatalf("the warm entry does not hold the not-before: %+v %v", e, ok)
				}
			}

			setSandboxTokenClock(t, base.Add(5*time.Second+300*time.Millisecond))
			if _, err := svc.RevokeSandboxTokens(ctx, id); err != nil {
				t.Fatal(err)
			}
			if _, ok := svc.warmEntryFor(id); ok {
				t.Fatal("the revoke left a warm entry with the old not-before")
			}
			nb := base.Unix() + 6
			for _, from := range []string{"row", "warm cache"} {
				a, err := svc.PortAccess(ctx, id, 3000)
				if err != nil || !a.TokenGated || a.TokensNotBefore != nb {
					t.Fatalf("PortAccess from the %s = %+v %v, want not-before %d", from, a, err, nb)
				}
				if !errors.Is(old.CheckNotBefore(a.TokensNotBefore), sandboxtoken.ErrRevoked) {
					t.Fatalf("an old port token passes the %s's not-before", from)
				}
			}

			setSandboxTokenClock(t, base.Add(5*time.Second+600*time.Millisecond))
			fresh := issueClaims(t, svc, ctx, id, models.CreateSandboxTokenRequest{ExpiresIn: "1h", Port: 3000})
			a, _ := svc.PortAccess(ctx, id, 3000)
			if err := fresh.CheckNotBefore(a.TokensNotBefore); err != nil {
				t.Fatalf("a port token issued after the revoke: %v", err)
			}
		})
	}
}

// Failover: the not-before lives only in the owner's row, so the owner
// watcher's recreate on a new node starts the row with a not-before of the
// recreate. A token issued before it (on the old owner, where it may have
// been revoked) is refused; one issued after it works; and a later watcher
// tick that finds the row in place does not move the not-before, so tokens
// issued after the failover keep working.
func TestFailoverRecreateRefusesTokensFromBefore(t *testing.T) {
	base := time.Unix(1_800_000_000, 400_000_000)
	setSandboxTokenClock(t, base)
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	ctx := context.Background()
	const id = "sb-failover-tok"
	spec := models.CreateSandboxRequest{Image: "alpine:3.20"}

	// Signed on the old owner a minute earlier with the shared server key.
	raw, _, err := sandboxtoken.Sign(svc.cipher, sandboxtoken.Claims{
		TokenID: "stk_00000000000000000000000000000001", SandboxID: id,
		IssuedAt: base.Unix() - 60, ExpiresAt: base.Unix() + 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	old, err := svc.VerifySandboxToken(raw)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RecreateSandbox(ctx, id, spec, cluster.PlacementSecrets{}, nil); err != nil {
		t.Fatalf("RecreateSandbox: %v", err)
	}
	row, err := st.Get(ctx, id)
	if err != nil || row.TokensNotBefore != base.Unix()+1 {
		t.Fatalf("recreated row not-before = %d, %v; want %d", row.TokensNotBefore, err, base.Unix()+1)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(sandboxTokenCtx(old), id); !errors.Is(err, ErrSandboxTokenRevoked) {
		t.Fatalf("a token from before the failover: %v, want ErrSandboxTokenRevoked", err)
	}

	setSandboxTokenClock(t, base.Add(300*time.Millisecond))
	fresh := issueClaims(t, svc, ctx, id, models.CreateSandboxTokenRequest{ExpiresIn: "10m"})
	if _, err := svc.EnsureSandboxAwakeForHTTP(sandboxTokenCtx(fresh), id); err != nil {
		t.Fatalf("a token issued after the failover: %v", err)
	}

	setSandboxTokenClock(t, base.Add(30*time.Second))
	if _, err := svc.RecreateSandboxReport(ctx, id, spec, cluster.PlacementSecrets{}, nil); err != nil {
		t.Fatalf("a later watcher tick: %v", err)
	}
	if row, _ := st.Get(ctx, id); row.TokensNotBefore != base.Unix()+1 {
		t.Fatalf("a watcher tick moved the not-before to %d", row.TokensNotBefore)
	}
	if _, err := svc.EnsureSandboxAwakeForHTTP(sandboxTokenCtx(fresh), id); err != nil {
		t.Fatalf("a watcher tick refused a token issued after the failover: %v", err)
	}
}

// A durable WASM sandbox is recreated from its seed row, not through the
// create path, and gets the same not-before.
func TestWasmFailoverRecreateSetsTokensNotBefore(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	setSandboxTokenClock(t, base)
	ctx := context.Background()
	modulesDir := t.TempDir()
	remoteSnap := filepath.Join(t.TempDir(), "remote-mem.snap")
	seedWasmSnapshot(t, remoteSnap, "gen-tok-1")
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rt := &fakeWasmRecreateRuntime{}
	svc := New(config.Config{EnableWasm: true, WasmModulesDir: modulesDir, EnableCluster: true}, slog.Default(), st, rt, nil, nil, nil, nil, nil)
	svc.AttachCluster(newRecreateOwnerCluster("self"))
	svc.SetWasmRuntime(rt)
	svc.AttachWasmCheckpointPusher(&fakeWasmCheckpointStore{pullSrc: remoteSnap})
	spec := models.CreateSandboxRequest{Runtime: models.RuntimeWasm, Durability: models.DurabilityDurable, ModuleRef: "file:///tmp/demo.wasm"}
	if err := svc.RecreateSandbox(ctx, "sb-wasm-tok", spec, cluster.PlacementSecrets{IncarnationID: "inc-sb-wasm-tok"}, nil); err != nil {
		t.Fatalf("RecreateSandbox: %v", err)
	}
	if row, err := st.Get(ctx, "sb-wasm-tok"); err != nil || row.TokensNotBefore != base.Unix()+1 {
		t.Fatalf("recreated WASM row not-before = %v, %v; want %d", row, err, base.Unix()+1)
	}
}
