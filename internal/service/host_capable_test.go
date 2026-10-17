package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

func accessCtx(a controlplane.Access) context.Context {
	return controlplane.ContextWithAccess(context.Background(), a)
}

// boundCtx is a token or OIDC caller holding role on team ("*" = every team).
func boundCtx(kind controlplane.PrincipalKind, role controlplane.Role, team string) context.Context {
	a := controlplane.Access{Role: role, Principal: controlplane.Principal{Kind: kind, ID: string(kind) + ":" + string(role) + ":" + team}}
	if team == controlplane.FleetTeam {
		a.Fleet = true
	} else {
		a.Identity.OwnerRef = controlplane.TeamOwnerRef(team)
	}
	return accessCtx(a)
}

func managedCtx(t *testing.T, role controlplane.Role) context.Context {
	t.Helper()
	a, err := controlplane.ControlPlaneAccess(controlplane.Identity{ExternalID: "u1", OwnerRef: "acct-1", Role: role})
	if err != nil {
		t.Fatal(err)
	}
	return accessCtx(a)
}

type hostCase struct {
	name string
	ctx  context.Context
	host bool
}

// hostCapableCases is every principal kind (and every role binding that
// matters) with whether it may use host powers. Only the operator, a node,
// an internal call (no Access, or a T4 system context) and an admin may.
func hostCapableCases(t *testing.T) []hostCase {
	t.Helper()
	token, oidc := controlplane.PrincipalToken, controlplane.PrincipalOIDC
	return []hostCase{
		{"operator (PAT)", accessCtx(controlplane.OperatorAccess()), true},
		{"node", accessCtx(controlplane.NodeAccess("n2")), true},
		{"internal (no Access)", context.Background(), true},
		{"system loop", accessCtx(controlplane.Access{Fleet: true, Principal: controlplane.Principal{Kind: controlplane.PrincipalSystem, ID: "system:lifecycle"}}), true},
		{"admin (oidc)", boundCtx(oidc, controlplane.RoleAdmin, controlplane.FleetTeam), true},
		{"admin (token)", boundCtx(token, controlplane.RoleAdmin, controlplane.FleetTeam), true},
		{"runner on every team", boundCtx(token, controlplane.RoleRunner, controlplane.FleetTeam), false},
		{"runner on a team", boundCtx(oidc, controlplane.RoleRunner, "payments"), false},
		{"viewer on every team", boundCtx(token, controlplane.RoleViewer, controlplane.FleetTeam), false},
		{"viewer on a team", boundCtx(token, controlplane.RoleViewer, "payments"), false},
		{"auditor", boundCtx(oidc, controlplane.RoleAuditor, controlplane.FleetTeam), false},
		{"managed runner", managedCtx(t, ""), false},
		{"managed viewer", managedCtx(t, controlplane.RoleViewer), false},
		{"sandbox key", accessCtx(controlplane.Access{Principal: controlplane.Principal{Kind: controlplane.PrincipalSandboxKey, ID: "sb-1"}}), false},
	}
}

// TestHostCapableGates is the eng review D3/D7 predicate table: each
// principal kind against each of the four operator-only gates. Fleet scope
// (runner, viewer or auditor on every team) never opens a gate.
func TestHostCapableGates(t *testing.T) {
	raw := []models.MountSpec{{Type: models.MountTypeNFS, Target: "/data", Source: "nfs.internal:/exports/aerolvm"}}
	for _, tc := range hostCapableCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostCapable(tc.ctx); got != tc.host {
				t.Fatalf("hostCapable = %v, want %v", got, tc.host)
			}

			// Gate 1: raw host-side mounts (service.go validateCreateMounts).
			svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			err := svc.validateCreateMounts(tc.ctx, raw, "sb-mount")
			if tc.host != (err == nil) || (!tc.host && !errors.Is(err, models.ErrMountOperatorOnly)) {
				t.Errorf("raw mount: err = %v, host %v", err, tc.host)
			}

			// Gate 2: file:// bundle refs read off the host (isolate.go).
			svc.cfg.EnableIsolate = true
			driver := &recordingRuntime{createErr: errors.New("driver reached")}
			svc.SetIsolateRuntime(driver)
			_, err = svc.CreateSandbox(tc.ctx, models.CreateSandboxRequest{Runtime: models.RuntimeIsolate, ModuleRef: "file:///etc/passwd"})
			refused := err != nil && strings.Contains(err.Error(), "operator-only")
			if refused == tc.host {
				t.Errorf("file:// bundle ref: err = %v, host %v", err, tc.host)
			}

			// Gate 3: a create's custom domains skip the DNS proof only for a
			// host-capable caller (custom_domains.go persistCustomDomainsOnCreate).
			dsvc := newCustomDomainGateService(t)
			dsvc.SetDNSResolver(&mockDNSResolver{})
			err = dsvc.persistCustomDomainsOnCreate(tc.ctx, "sb-dom", []string{"app.example.com"})
			if tc.host != (err == nil) || (!tc.host && !errors.Is(err, models.ErrCustomDomainVerificationFailed)) {
				t.Errorf("custom domain on create without DNS proof: err = %v, host %v", err, tc.host)
			}

			// Gate 4: the owner-less legacy TXT record on attach
			// (dns_verify.go customDomainProofToken).
			want := customDomainOwnerToken("team:payments")
			if tc.host {
				want = ""
			}
			if got := customDomainProofToken(tc.ctx, "team:payments"); got != want {
				t.Errorf("DNS proof token for team payments' sandbox = %q, want %q", got, want)
			}
		})
	}
}

// newCustomDomainGateService is a service with custom domains on and one
// sandbox, sb-dom, owned by the operator namespace.
func newCustomDomainGateService(t *testing.T) *Service {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.test"))
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.test"
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-dom", Image: "alpine", Status: models.SandboxStatusStarted, ContainerID: "ctr-dom",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return svc
}

// A runner bound to every team is not exempt from the DNS proof, but it can
// still attach a domain by proving it: its creates live in the operator
// namespace (""), so the record it shows is that namespace's.
func TestFleetRunnerProvesCustomDomainOwnership(t *testing.T) {
	svc := newCustomDomainGateService(t)
	svc.SetDNSResolver(ownerBoundDNSResolver{owner: ""})
	if err := svc.persistCustomDomainsOnCreate(boundCtx(controlplane.PrincipalToken, controlplane.RoleRunner, controlplane.FleetTeam), "sb-dom", []string{"app.example.com"}); err != nil {
		t.Fatalf("fleet runner with the operator-namespace record: %v", err)
	}
}

// D7: snapshot-alias visibility follows fleet scope, not host power. A runner
// bound to every team sees every team's aliases and may retarget one that
// points at a team's snapshot (it writes across every team by design), while
// a caller fenced to another team gets a 404. A new alias still lands in the
// caller's own namespace, so a fleet runner pointing one at a team's
// snapshot by bare name fails in the store exactly as the operator's does.
func TestFleetRunnerAliasesTeamSnapshots(t *testing.T) {
	svc, st, _ := newSnapshotOwnerService(t)
	fleetRunner := boundCtx(controlplane.PrincipalToken, controlplane.RoleRunner, controlplane.FleetTeam)
	if hostCapable(fleetRunner) {
		t.Fatal("the row is meaningful only for a caller that is not host-capable")
	}

	if err := svc.requireVisibleSnapshot(fleetRunner, "snap-globex"); err != nil {
		t.Fatalf("fleet runner cannot see globex's snapshot: %v", err)
	}
	if got, err := svc.GetSnapshotAlias(fleetRunner, "alias-globex"); err != nil || got.SnapshotName != "snap-globex" {
		t.Fatalf("fleet runner read of globex's alias = %+v, %v", got, err)
	}
	// Another tenant may not take the alias over; the fleet runner may.
	retarget := models.SnapshotAlias{Alias: "alias-globex", SnapshotName: "snap-shared", Facade: models.FacadeRunloop}
	if err := svc.UpsertSnapshotAlias(userCtx("acme"), retarget); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("acme retarget of globex's alias = %v, want ErrNotFound", err)
	}
	if err := svc.UpsertSnapshotAlias(fleetRunner, retarget); err != nil {
		t.Fatalf("fleet runner retarget of globex's alias: %v", err)
	}
	if got, err := st.GetSnapshotAlias(context.Background(), "alias-globex"); err != nil || got.SnapshotName != "snap-shared" || got.OwnerRef != "" {
		t.Fatalf("alias after the fleet runner's upsert = %+v, %v", got, err)
	}

	onto := models.SnapshotAlias{Alias: "new-on-acme", SnapshotName: "snap-acme", Facade: models.FacadeRunloop}
	opErr := svc.UpsertSnapshotAlias(operatorCtx(), onto)
	runnerErr := svc.UpsertSnapshotAlias(fleetRunner, onto)
	t.Logf("new alias by bare name: operator %v, fleet runner %v", opErr, runnerErr)
	if (opErr == nil) != (runnerErr == nil) || errors.Is(runnerErr, store.ErrNotFound) {
		t.Fatalf("new alias by bare name: operator %v, fleet runner %v; want the same store outcome, never a visibility 404", opErr, runnerErr)
	}
}
