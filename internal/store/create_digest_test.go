package store

import (
	"context"
	"testing"
)

// A keyed create's request digest lives exactly as long as its sandbox row:
// written in the create's transaction, gone with the row.
func TestCreateRequestDigestLivesWithTheRow(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		digest string
		sealed bool
	}{
		{name: "create", digest: "hmac:0:aaaa"},
		{name: "create with sealed env", digest: "hmac:2:bbbb", sealed: true},
		{name: "a create without a key keeps nothing", digest: ""},
		{name: "sealed create without a key", digest: " ", sealed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := newTestStore(t)
			sb := sampleSandbox("sb-digest")
			sb.CreateRequestDigest = tt.digest
			var err error
			if tt.sealed {
				err = st.CreateWithSealedEnv(ctx, sb, []byte("sealed-env"))
			} else {
				err = st.Create(ctx, sb)
			}
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			want := tt.digest
			if want == " " {
				want = ""
			}
			if got, err := st.GetCreateRequestDigest(ctx, sb.ID); err != nil || got != want {
				t.Fatalf("GetCreateRequestDigest = %q, %v; want %q", got, err, want)
			}
			if err := st.Delete(ctx, sb.ID); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if got, err := st.GetCreateRequestDigest(ctx, sb.ID); err != nil || got != "" {
				t.Fatalf("digest after delete = %q, %v; want none", got, err)
			}
		})
	}
}

// A failed create that rolls its row back takes the digest with it, so a
// retry of the key starts clean.
func TestCreateRequestDigestGoesWithACreateRollback(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	sb := sampleSandbox("sb-rollback")
	sb.CreateRequestDigest = "hmac:0:cccc"
	sb.AuditIncarnationID = "inc-1"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := st.RollbackSandboxCreate(ctx, sb.ID, sb.AuditIncarnationID); err != nil {
		t.Fatal(err)
	}
	if got, err := st.GetCreateRequestDigest(ctx, sb.ID); err != nil || got != "" {
		t.Fatalf("digest after rollback = %q, %v", got, err)
	}
}

func TestCreateRequestDigestErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	// The same id twice: the row insert fails first, and nothing is left
	// half-written.
	sb := sampleSandbox("sb-dup")
	sb.CreateRequestDigest = "hmac:0:dddd"
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	second := sampleSandbox("sb-dup")
	second.CreateRequestDigest = "hmac:0:eeee"
	if err := st.Create(ctx, second); err == nil {
		t.Fatal("a second row under one id was created")
	}
	if got, _ := st.GetCreateRequestDigest(ctx, sb.ID); got != "hmac:0:dddd" {
		t.Fatalf("digest = %q, want the first create's", got)
	}
	// A digest row with no sandbox row cannot exist (foreign key).
	if _, err := st.db.ExecContext(ctx, `INSERT INTO sandbox_create_digests (sandbox_id, digest) VALUES ('sb-none', 'x')`); err == nil {
		t.Fatal("a digest without its sandbox was stored")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetCreateRequestDigest(ctx, sb.ID); err == nil {
		t.Fatal("a read from a closed store succeeded")
	}
}
