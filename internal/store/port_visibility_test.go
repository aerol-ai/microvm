package store

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A2: a port's visibility round-trips through every read path (Get, the
// bulk list attach, ListAllExposedPorts, the host-port lookup), a re-upsert
// changes it, and a row written without one (every row from before the
// column, and the raw-TCP reservation insert) reads as public.
func TestExposedPortVisibilityRoundTrips(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-vis")
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: sb.ID, Port: 3000, PublicURL: "https://a", CreatedAt: now, Visibility: models.ExposedPortVisibilityToken}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: sb.ID, Port: 4000, PublicURL: "https://b", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if res, err := st.TryReserveHostPort(ctx, sb.ID, 5432, 22001, models.ExposedPortProtocolTCP, "tcp://x:22001", now); err != nil || !res.Reserved {
		t.Fatalf("reserve: %+v %v", res, err)
	}

	want := map[int]bool{3000: true, 4000: false, 5432: false}
	check := func(label string, ports []models.ExposedPort) {
		t.Helper()
		if len(ports) != len(want) {
			t.Fatalf("%s: %d ports, want %d: %+v", label, len(ports), len(want), ports)
		}
		for _, p := range ports {
			if p.TokenGated() != want[p.Port] {
				t.Fatalf("%s: port %d gated=%v, want %v", label, p.Port, p.TokenGated(), want[p.Port])
			}
			if !p.TokenGated() && p.Visibility != "" {
				t.Fatalf("%s: a public port reads as %q, want empty", label, p.Visibility)
			}
		}
	}
	got, err := st.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	check("Get", got.ExposedPorts)
	list, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range list {
		if l.ID == sb.ID {
			check("List", l.ExposedPorts)
		}
	}
	all, err := st.ListAllExposedPorts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("ListAllExposedPorts", all)
	if byHost, err := st.GetPortByHostPort(ctx, 22001); err != nil || byHost == nil || byHost.TokenGated() {
		t.Fatalf("GetPortByHostPort = %+v, %v", byHost, err)
	}

	// An explicit re-upsert flips it back to public.
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: sb.ID, Port: 3000, PublicURL: "https://a", CreatedAt: now, Visibility: models.ExposedPortVisibilityPublic}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.Get(ctx, sb.ID)
	for _, p := range got.ExposedPorts {
		if p.Port == 3000 && p.TokenGated() {
			t.Fatal("re-upsert as public kept the token gate")
		}
	}
}
