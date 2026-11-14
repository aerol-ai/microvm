package service

import (
	"context"
	"sort"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A node that pushed WASM checkpoints, then had its pusher turned off, still
// has those manifests in the registry. Destroy there used to bulk-delete the
// push rows, the only record of the manifests, so they leaked for good. Now a
// row that names a ref stays until a pusher is back and the orphan-ref sweep
// deletes the manifest.
func TestDisabledWasmPusherKeepsCleanupObligation(t *testing.T) {
	const id = "wasm-pusher-off"
	cases := []struct {
		name        string
		rows        []string // registry refs of earlier pushes ("" = no ref)
		registryRef string   // sandbox.WasmRegistryRef
		wantKept    []string
	}{
		{
			name:        "pushed before the pusher was turned off",
			rows:        []string{"aocr://" + id + ":sha256-old", "aocr://" + id + ":sha256-new"},
			registryRef: "aocr://" + id + ":sha256-new",
			wantKept:    []string{"aocr://" + id + ":sha256-new", "aocr://" + id + ":sha256-old"},
		},
		{
			name:        "current ref not in a row yet",
			rows:        []string{"aocr://" + id + ":sha256-old"},
			registryRef: "aocr://" + id + ":sha256-new",
			wantKept:    []string{"aocr://" + id + ":sha256-new", "aocr://" + id + ":sha256-old"},
		},
		{
			name: "a row with no ref carries nothing",
			rows: []string{""},
		},
		{
			name: "never pushed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st, _ := newAOCRCleanupTestService(t)
			svc.wasmCheckpointPusher = nil
			ctx := context.Background()
			for _, ref := range tc.rows {
				if _, err := st.InsertWasmCheckpointPush(ctx, id, "inc-1", ref, "digest-"+ref); err != nil {
					t.Fatal(err)
				}
			}
			if err := st.PutWasmStateKV(ctx, id, "k", []byte("v")); err != nil {
				t.Fatal(err)
			}
			sb := &models.Sandbox{ID: id, Runtime: models.RuntimeWasm, AuditIncarnationID: "inc-1", WasmRegistryRef: tc.registryRef}
			if err := svc.cleanupWasmSandboxArtifacts(ctx, sb); err != nil {
				t.Fatalf("cleanup = %v", err)
			}
			if got := pushRefs(t, svc, id); !equalStrings(got, tc.wantKept) {
				t.Fatalf("push rows after cleanup = %v, want %v", got, tc.wantKept)
			}
			if keys, err := st.ListWasmStateKVKeys(ctx, id); err != nil || len(keys) != 0 {
				t.Fatalf("host KV rows = %v, %v; want none (they are local only)", keys, err)
			}

			// The pusher comes back: the orphan-ref sweep deletes each kept
			// manifest, then its row.
			pusher := &recordingWasmCheckpointStore{}
			svc.wasmCheckpointPusher = pusher
			svc.runWasmOrphanRefSweep(ctx)
			deleted := append([]string(nil), pusher.deleted...)
			sort.Strings(deleted)
			if !equalStrings(deleted, tc.wantKept) {
				t.Fatalf("manifests deleted once a pusher is back = %v, want %v", deleted, tc.wantKept)
			}
			if got := pushRefs(t, svc, id); len(got) != 0 {
				t.Fatalf("push rows after the sweep = %v, want none", got)
			}
		})
	}
}

func pushRefs(t *testing.T, svc *Service, id string) []string {
	t.Helper()
	rows, err := svc.store.ListWasmCheckpointPushes(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.RegistryRef)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
