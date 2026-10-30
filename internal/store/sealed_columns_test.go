package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

func rotationStore(t *testing.T) (*Store, *secrets.Cipher) {
	t.Helper()
	k0, err := secrets.NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: k0, Current: true}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenWithSecretCipher(filepath.Join(t.TempDir(), "state.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, c
}

func stageAndPromote(t *testing.T, c *secrets.Cipher) {
	t.Helper()
	k1, err := secrets.NewServerKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetRing([]secrets.RingKey{{ID: 0}, {ID: 1, Key: k1, Current: true}}); err != nil {
		t.Fatal(err)
	}
}

// TestResealSealedColumns (eng D26 §13 step 3): every server-key-sealed
// column lists its values with the AAD they were sealed under, pages by
// sandbox id, and a reseal is a compare-and-swap that loses to a write
// that landed after the read.
func TestResealSealedColumns(t *testing.T) {
	ctx := context.Background()
	st, c := rotationStore(t)
	for _, id := range []string{"sb-a", "sb-b", "sb-c"} {
		sb := testSandbox(id, nil)
		sb.AuditIncarnationID = "inc-" + id
		sb.ToolboxEnabled = true
		sb.ToolboxToken = "tok-" + id
		reg, err := c.Encrypt([]byte(`{"server":"r"}`))
		if err != nil {
			t.Fatal(err)
		}
		sb.RegistryAuthSealed = reg
		if err := st.Create(ctx, sb); err != nil {
			t.Fatal(err)
		}
		env, _ := c.EncryptWithAAD([]byte(`{"K":"v"}`), secrets.EnvAAD(id, sb.AuditIncarnationID))
		if err := st.PutEnv(ctx, id, env); err != nil {
			t.Fatal(err)
		}
		mounts, _ := c.Encrypt([]byte(`{"mounts":[]}`))
		if err := st.PutMounts(ctx, id, mounts); err != nil {
			t.Fatal(err)
		}
	}
	stageAndPromote(t, c)

	for _, col := range SealedColumns {
		var all []SealedRow
		after := ""
		for {
			page, err := st.ListSealedRows(ctx, col, after, 2)
			if err != nil {
				t.Fatalf("%s: %v", col, err)
			}
			all = append(all, page...)
			if len(page) < 2 {
				break
			}
			after = page[len(page)-1].SandboxID
		}
		if len(all) != 3 {
			t.Fatalf("%s: %d rows", col, len(all))
		}
		var batch []ResealedRow
		for _, r := range all {
			out, from, changed, err := c.Reseal(r.Sealed, r.AAD)
			if err != nil || !changed || from != 0 {
				t.Fatalf("%s %s: reseal %v %v %d", col, r.SandboxID, err, changed, from)
			}
			batch = append(batch, ResealedRow{SandboxID: r.SandboxID, Old: r.Sealed, New: out})
		}
		// sb-b is written in between: its reseal must lose.
		batch[1].Old = []byte("not what is stored")
		written, err := st.ResealSealedRows(ctx, col, batch)
		if err != nil || !written[0] || written[1] || !written[2] {
			t.Fatalf("%s: written %v %v", col, written, err)
		}
		again, err := st.ResealSealedRows(ctx, col, batch[:1])
		if err != nil || again[0] {
			t.Fatalf("%s: a second reseal of the same bytes = %v %v", col, again, err)
		}
		rows, _ := st.ListSealedRows(ctx, col, "", 10)
		for _, r := range rows {
			_, id, err := c.OpenWithKeyID(r.Sealed, r.AAD)
			want := uint32(1)
			if r.SandboxID == "sb-b" {
				want = 0
			}
			if err != nil || id != want {
				t.Fatalf("%s %s: key %d %v", col, r.SandboxID, id, err)
			}
		}
	}
	got, err := st.Get(ctx, "sb-a")
	if err != nil || got.ToolboxToken != "tok-sb-a" {
		t.Fatalf("toolbox token after reseal = %v", err)
	}
	if col := SealedColumn(99); col.String() != "" {
		t.Fatal("unknown column name")
	}
	if _, err := st.ListSealedRows(ctx, SealedColumn(99), "", 1); err == nil {
		t.Fatal("listed an unknown column")
	}
	if _, err := st.ListSealedRows(ctx, SealedEnv, "", 0); err == nil {
		t.Fatal("listed with no limit")
	}
	if _, err := st.ResealSealedRows(ctx, SealedColumn(99), []ResealedRow{{}}); err == nil {
		t.Fatal("resealed an unknown column")
	}
	if w, err := st.ResealSealedRows(ctx, SealedEnv, nil); err != nil || w != nil {
		t.Fatal("empty reseal")
	}
	st.Close()
	if _, err := st.ListSealedRows(ctx, SealedEnv, "", 1); err == nil {
		t.Fatal("listed from a closed store")
	}
	if _, err := st.ResealSealedRows(ctx, SealedEnv, []ResealedRow{{SandboxID: "x"}}); err == nil {
		t.Fatal("resealed in a closed store")
	}
}

// TestUpsertResealsStaleRegistryAuth: a sandbox read before the reseal pass
// and written after it carries the old key's registry blob; while a
// rotation is in progress the write moves it onto the current key, so the
// pass's work is never undone.
func TestUpsertResealsStaleRegistryAuth(t *testing.T) {
	ctx := context.Background()
	st, c := rotationStore(t)
	sb := testSandbox("sb-r", nil)
	reg, _ := c.Encrypt([]byte(`{"server":"r"}`))
	sb.RegistryAuthSealed = reg
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}
	// No rotation: the blob is stored as given.
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.ListSealedRows(ctx, SealedRegistryAuth, "", 10)
	if !bytes.Equal(rows[0].Sealed, reg) {
		t.Fatal("a write outside a rotation changed the blob")
	}
	stageAndPromote(t, c)
	sb.Status = "stopped"
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ListSealedRows(ctx, SealedRegistryAuth, "", 10)
	if _, id, err := c.OpenWithKeyID(rows[0].Sealed, nil); err != nil || id != 1 {
		t.Fatalf("stale registry blob written back on key %d: %v", id, err)
	}
	// A blob already on the current key is stored as is.
	current := rows[0].Sealed
	sb.RegistryAuthSealed = current
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.ListSealedRows(ctx, SealedRegistryAuth, "", 10); !bytes.Equal(rows[0].Sealed, current) {
		t.Fatal("a current blob was resealed")
	}
	// A blob nothing opens is stored as given, as before.
	sb.RegistryAuthSealed = []byte("garbage-not-sealed")
	if err := st.Upsert(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rows, _ = st.ListSealedRows(ctx, SealedRegistryAuth, "", 10)
	if string(rows[0].Sealed) != "garbage-not-sealed" {
		t.Fatal("an unopenable blob was changed")
	}
}
