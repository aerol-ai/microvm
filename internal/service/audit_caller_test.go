package service

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// gateCluster is a cluster client whose audit caller gate the test flips,
// standing in for a gossip view during a rolling upgrade.
type gateCluster struct {
	*cluster.Noop
	open atomic.Bool
}

func (c *gateCluster) AuditCallerWritesAllowed() bool { return c.open.Load() }

func paymentsToken() controlplane.Access {
	return controlplane.Access{
		Identity:  controlplane.Identity{OwnerRef: controlplane.TeamOwnerRef("payments")},
		Role:      controlplane.RoleRunner,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalToken, ID: "tok_7Hq2", Name: "ci-deploy"},
	}
}

func TestAuditCallerFromContext(t *testing.T) {
	forwarded := paymentsToken()
	forwarded.Via = "edge-1"
	fleetOIDC := controlplane.Access{
		Fleet:     true,
		Role:      controlplane.RoleAuditor,
		Principal: controlplane.Principal{Kind: controlplane.PrincipalOIDC, ID: "oidc:okta:00u1", Name: "ana@acme.com\x1b[2J"},
	}
	managed, err := controlplane.ControlPlaneAccess(controlplane.Identity{OwnerRef: "acct-1", ExternalID: "ext-1"})
	if err != nil {
		t.Fatal(err)
	}
	withVia := func(a controlplane.Access, via string) controlplane.Access { a.Via = via; return a }
	tagged := func(ctx context.Context) context.Context { return withAuditSubsystem(ctx, auditSubsystemReconcile) }
	bridged := func(ctx context.Context) context.Context {
		return auditlog.ContextWithSSHGatewayCall(ctx, auditlog.SSHGatewayCall{SandboxID: "sb-1"})
	}

	cases := []struct {
		name string
		ctx  context.Context
		want *auditlog.Caller
	}{
		{"operator (identity off, the PAT)", controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess()),
			&auditlog.Caller{Kind: "operator", ID: "operator"}},
		{"operator forwarded by a peer", controlplane.ContextWithAccess(context.Background(), withVia(controlplane.OperatorAccess(), "edge-1")),
			&auditlog.Caller{Kind: "operator", ID: "operator", Via: "edge-1"}},
		{"a node acting for itself", controlplane.ContextWithAccess(context.Background(), controlplane.NodeAccess("n3")),
			&auditlog.Caller{Kind: "node", ID: "node:n3"}},
		{"team token forwarded through an edge", controlplane.ContextWithAccess(context.Background(), forwarded),
			&auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}},
		{"fleet OIDC caller, display name sanitized", controlplane.ContextWithAccess(context.Background(), fleetOIDC),
			&auditlog.Caller{Kind: "oidc", ID: "oidc:okta:00u1", Name: "ana@acme.com[2J", Team: "*"}},
		{"managed account: no team", controlplane.ContextWithAccess(context.Background(), managed),
			&auditlog.Caller{Kind: "controlplane", ID: "controlplane:ext-1", Name: "ext-1"}},
		{"an Access with no principal names nobody", controlplane.ContextWithAccess(context.Background(), controlplane.Access{Fleet: true}), nil},
		{"tagged background work", tagged(context.Background()),
			&auditlog.Caller{Kind: "system", ID: "system:reconcile"}},
		{"a request's caller wins over a subsystem tag", tagged(controlplane.ContextWithAccess(context.Background(), forwarded)),
			&auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}},
		{"untagged background work", context.Background(), &auditlog.Caller{Kind: "system", ID: "system:daemon"}},
		// UC-287 on a cluster: the SSH gateway bridges a session with the
		// operator token, but the operator did nothing.
		{"a bridged SSH call on the owner: the sandbox key, via the gateway's node",
			bridged(controlplane.ContextWithAccess(context.Background(), withVia(controlplane.OperatorAccess(), "edge-1"))),
			&auditlog.Caller{Kind: "sandbox_key", ID: "sb-1", Via: "edge-1"}},
		{"a bridged SSH call run on the gateway's own node", bridged(controlplane.ContextWithAccess(context.Background(), controlplane.OperatorAccess())),
			&auditlog.Caller{Kind: "sandbox_key", ID: "sb-1"}},
		{"the marker without an authenticated request names nobody new", bridged(context.Background()),
			&auditlog.Caller{Kind: "system", ID: "system:daemon"}},
		{"nil context", nil, &auditlog.Caller{Kind: "system", ID: "system:daemon"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuditCallerFromContext(tc.ctx); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("caller = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestAuditCallerWriteGate is the service half of the mixed-version gate
// (T4): a single node writes callers at once; a cluster node writes them
// only while its cluster client says every member can read them, and a
// cluster-mode service that has not attached its real client yet (it still
// holds the Noop) writes none.
func TestAuditCallerWriteGate(t *testing.T) {
	ctx := controlplane.ContextWithAccess(context.Background(), paymentsToken())

	single := &Service{cluster: cluster.NewNoop("solo", "", "")}
	if single.auditCaller(ctx) == nil {
		t.Fatal("a single node must write the caller")
	}

	preAttach := &Service{cfg: config.Config{EnableCluster: true}, cluster: cluster.NewNoop("n1", "", "")}
	if preAttach.auditCaller(ctx) != nil {
		t.Fatal("a cluster node holding only the Noop must not write the caller")
	}

	gated := &gateCluster{Noop: cluster.NewNoop("n1", "", "")}
	svc := &Service{cfg: config.Config{EnableCluster: true}, cluster: gated}
	if svc.auditCaller(ctx) != nil {
		t.Fatal("caller written while a member still runs the previous release")
	}
	gated.open.Store(true)
	if got := svc.auditCaller(ctx); got == nil || got.ID != "tok_7Hq2" {
		t.Fatalf("caller after every member upgraded = %+v", got)
	}
	svc.ClearClusterForTest()
	if svc.auditCaller(ctx) != nil {
		t.Fatal("no cluster client must keep the gate closed")
	}
	var nilSvc *Service
	if nilSvc.auditCallerWritesAllowed() {
		t.Fatal("nil service gate must be closed")
	}
}

// TestSecretOpenRecordsTheForwardedCaller is the forwarded attribution test
// at the record: on the owner node, a secret open under the Access the auth
// edge built for a forwarded request names the edge caller, its team and
// the edge node as via, and carries the correlation id the edge sent. The
// same open with the gate closed writes the record exactly as before.
func TestSecretOpenRecordsTheForwardedCaller(t *testing.T) {
	svc, st, audit := testEnvService(t)
	gated := &gateCluster{Noop: cluster.NewNoop("owner-1", "", "")}
	svc.cfg.EnableCluster = true
	svc.cluster = gated
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: "sb-fwd", Image: "alpine:3.19", Status: models.SandboxStatusStarted, CPU: 1, MemoryMB: 256,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
		AuditIncarnationID: "inc-sb-fwd", OwnerRef: controlplane.TeamOwnerRef("payments"),
	}); err != nil {
		t.Fatal(err)
	}
	sealed, err := svc.sealEnv("sb-fwd", "inc-sb-fwd", map[string]string{"TOKEN": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(context.Background(), "sb-fwd", sealed); err != nil {
		t.Fatal(err)
	}
	access := paymentsToken()
	access.Via = "edge-1"
	ctx := controlplane.ContextWithAccess(context.Background(), access)
	ctx = auditlog.ContextWithCorrelationID(ctx, "corr-edge")

	if _, err := svc.loadEnv(ctx, "sb-fwd", "inc-sb-fwd"); err != nil {
		t.Fatalf("loadEnv (gate closed): %v", err)
	}
	gated.open.Store(true)
	if _, err := svc.loadEnv(ctx, "sb-fwd", "inc-sb-fwd"); err != nil {
		t.Fatalf("loadEnv (gate open): %v", err)
	}
	events := audit.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	closed, open := events[0], events[1]
	if closed.Caller != nil {
		t.Fatalf("gate closed wrote a caller: %+v", closed.Caller)
	}
	want := &auditlog.Caller{Kind: "token", ID: "tok_7Hq2", Name: "ci-deploy", Team: "payments", Via: "edge-1"}
	if !reflect.DeepEqual(open.Caller, want) {
		t.Fatalf("owner record caller = %+v, want %+v", open.Caller, want)
	}
	for _, ev := range events {
		if ev.CorrelationID != "corr-edge" || ev.Actor != "owner-1" || ev.NodeID != "owner-1" || ev.Kind != secretAuditKindSecretOpen {
			t.Fatalf("record = %+v: want the edge's correlation id, and actor/node_id still the writing node", ev)
		}
	}
}

// TestSecretOpenSubsystemCallers: opens with no request behind them name
// the subsystem that did them, through each secret-open path.
func TestSecretOpenSubsystemCallers(t *testing.T) {
	svc, st, audit := testEnvService(t)
	svc.cluster = cluster.NewNoop("node-a", "", "")
	seedEnvSandbox(t, st, "sb-sys", nil)
	sealed, err := svc.sealEnv("sb-sys", "inc-sb-sys", map[string]string{"K": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutEnv(context.Background(), "sb-sys", sealed); err != nil {
		t.Fatal(err)
	}
	regSealed, err := svc.sealRegistry(&models.RegistryAuth{Server: "r.example.com", Username: "u", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.loadEnv(withAuditSubsystem(context.Background(), auditSubsystemLifecycle), "sb-sys", "inc-sb-sys"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UnsealRegistry(withAuditSubsystem(context.Background(), auditSubsystemBootRestore), "sb-sys", regSealed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UnsealRegistry(context.Background(), "sb-sys", regSealed); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, ev := range audit.Events() {
		if ev.Caller == nil {
			t.Fatalf("record without a caller on a single node: %+v", ev)
		}
		got = append(got, ev.Caller.ID)
	}
	want := []string{"system:lifecycle", "system:boot-restore", "system:daemon"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("callers = %v, want %v", got, want)
	}
}
