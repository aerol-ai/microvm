package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSecretAuditQueryFiltersWave32(t *testing.T) {
	svc := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(svc.CloseSecretAuditSink)
	if _, _, err := svc.ListSecretAuditLocal(nil, "sb-empty-path", SecretAuditQuery{}); err != nil {
		t.Fatalf("nil ctx local list: %v", err)
	}

	sink := svc.secretAuditSink().(*fileAuditSink)
	now := time.Now().UTC()
	for i, ev := range []SecretAuditEvent{
		{Time: now.Add(-2 * time.Second), EventID: "open-a", SandboxID: "sb-q32", IncarnationID: "inc-a", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess},
		{Time: now.Add(-time.Second), EventID: "open-b", SandboxID: "sb-q32", IncarnationID: "inc-b", Kind: secretAuditKindSecretOpen, Result: secretAuditResultSuccess},
		{Time: now, EventID: "egress-a", SandboxID: "sb-q32", IncarnationID: "inc-a", Kind: secretAuditKindEgress, Result: secretAuditResultSuccess},
		{Time: now.Add(time.Second), EventID: "gap-any", Kind: secretAuditKindGap, Result: secretAuditResultGap},
	} {
		ev.EventID += ""
		if err := sink.EmitDurable(ev); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if _, err := os.OpenFile(sink.path, os.O_APPEND|os.O_WRONLY, 0); err == nil {
		// Blank lines must be skipped so a trailing newline cannot fail integrity.
	}
	if err := os.WriteFile(sink.path, append(wave32ReadFile(t, sink.path), '\n', '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	incA, next, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{
		IncarnationID: "inc-a", Kind: secretAuditKindSecretOpen, Limit: 1,
	})
	if err != nil || len(incA) != 1 || incA[0].EventID != "open-a" || next == "" {
		t.Fatalf("incarnation+kind page = %+v next=%q err=%v", incA, next, err)
	}
	page2, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{
		IncarnationID: "inc-a", Cursor: next, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range page2 {
		if ev.EventID == "open-a" {
			t.Fatal("cursor replayed the first event")
		}
	}
	if _, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{Cursor: now.Format(time.RFC3339Nano)}); err == nil {
		t.Fatal("keyless cursor was accepted")
	}

	gaps, _, err := svc.ListSecretAuditLocal(context.Background(), "other-sandbox", SecretAuditQuery{Kind: secretAuditKindEgress})
	if err != nil || len(gaps) == 0 {
		t.Fatalf("gap events must survive kind/sandbox filters: %+v err=%v", gaps, err)
	}

	if _, _, err := (&Service{}).ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err != nil {
		t.Fatalf("fileless local list: %v", err)
	}
	_ = os.Remove(sink.path)
	if events, _, err := svc.ListSecretAuditLocal(context.Background(), "sb-q32", SecretAuditQuery{}); err != nil || len(events) != 0 {
		t.Fatalf("missing file = %+v err=%v", events, err)
	}

	trunc := &Service{
		cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")},
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
			},
			placement: cluster.Placement{SandboxID: "sb-trunc32", AuditNodesTruncated: true},
		},
	}
	t.Cleanup(trunc.CloseSecretAuditSink)
	if _, err := trunc.ListSecretAudit(context.Background(), "sb-trunc32", SecretAuditQuery{}); !errors.Is(err, ErrSecretAuditIndexIncomplete) {
		t.Fatalf("truncated index = %v", err)
	}

	acl := &Service{
		cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")},
		cluster: &stubMembersCluster{
			Noop: cluster.NewNoop("self", "http://self", ""),
			members: []cluster.Member{
				{NodeID: "self", Alive: true},
				{NodeID: "peer", Alive: true, InternalURL: "https://peer"},
			},
			acl:       cluster.AuditACL{IncarnationID: "inc-acl", AuditNodeIDs: []string{"self", "peer"}},
			aclExists: true,
		},
	}
	t.Cleanup(acl.CloseSecretAuditSink)
	page, err := acl.ListSecretAudit(context.Background(), "sb-acl32", SecretAuditQuery{IncarnationID: "inc-acl", Limit: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !page.Coverage.Partial {
		t.Fatalf("ACL fan-out without fetcher = %+v", page.Coverage)
	}

	bad := &Service{cfg: config.Config{DBPath: filepath.Join(t.TempDir(), "state.db")}}
	t.Cleanup(bad.CloseSecretAuditSink)
	_ = bad.secretAuditSink()
	// A page read parses only records that can belong to it; a malformed
	// record claiming the queried sandbox must still fail the read.
	if err := os.WriteFile(bad.secretAuditFile.path, []byte(`{"sandbox_id":"sb",not-json`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bad.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err == nil {
		t.Fatal("malformed local evidence was accepted")
	}
	if err := os.Chmod(bad.secretAuditFile.path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad.secretAuditFile.path, 0o600) })
	if _, _, err := bad.ListSecretAuditLocal(context.Background(), "sb", SecretAuditQuery{}); err == nil {
		t.Fatal("unreadable audit snapshot succeeded")
	}
}

func wave32ReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPublicTrafficAndEasyGuardsWave32(t *testing.T) {
	ctx := context.Background()
	deny := false
	sb := &models.Sandbox{
		ID: "sb-pub32", AllowPublicTraffic: &deny,
		ExposedPorts:  []models.ExposedPort{{Port: 80, Protocol: models.ExposedPortProtocolHTTP}, {Port: 0}},
		CustomDomains: []models.CustomDomain{{Hostname: "ex.test"}, {Hostname: ""}},
	}
	svc := &Service{caddy: caddy.New(config.Config{EnableCaddy: false}), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := svc.deleteSandboxPublicRoutes(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.deleteSandboxPublicRoutes(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := svc.cleanupPublicTrafficDisabledIngressState(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := svc.cleanupPublicTrafficDisabledIngressState(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := svc.syncExposedPortRoute(ctx, sb, models.ExposedPort{Port: 80, Protocol: models.ExposedPortProtocolHTTP}); err != nil {
		t.Fatal(err)
	}

	if secretAuditKindMatches("", "egress") || !secretAuditKindMatches(secretAuditKindGap, "egress") || !secretAuditKindMatches(secretAuditKindEgress, "egress") {
		t.Fatal("kind matcher")
	}
	if !secretAuditEventMatches(SecretAuditEvent{SandboxID: "sb", Kind: secretAuditKindSecretOpen}, "sb", "", "", time.Time{}, "") {
		t.Fatal("empty after matches")
	}
	after := time.Now().UTC()
	if secretAuditEventMatches(SecretAuditEvent{SandboxID: "sb", Time: after.Add(-time.Second)}, "sb", "", "", after, "k") {
		t.Fatal("before-cursor matched")
	}
	_ = dedupeSecretAuditEvents(nil)
	_ = dedupeSecretAuditEvents([]SecretAuditEvent{{EventID: "a", Time: after}, {EventID: "a", Time: after}})
	_ = formatSecretAuditCursor(SecretAuditEvent{Time: after, EventID: "a"})
	if _, _, err := parseSecretAuditCursor(""); err != nil {
		t.Fatal(err)
	}

	raw, _ := json.Marshal(SecretAuditEvent{EventID: "unused32"})
	_ = raw
}
