package netrules

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeBatch records the batch calls the Manager makes; its per-rule methods
// fail the test, so a batch backend is never driven rule by rule.
type fakeBatch struct {
	t         *testing.T
	inputErr  error
	ensureErr error
	deleteErr error
	inserted  []bool
	ensures   [][]RuleInsert
	deletes   [][]RuleRef
}

func (f *fakeBatch) Exists(string, string, ...string) (bool, error) {
	f.t.Fatal("per-rule Exists on a batch backend")
	return false, nil
}
func (f *fakeBatch) Insert(string, string, int, ...string) error {
	f.t.Fatal("per-rule Insert on a batch backend")
	return nil
}
func (f *fakeBatch) Delete(string, string, ...string) error {
	f.t.Fatal("per-rule Delete on a batch backend")
	return nil
}
func (f *fakeBatch) EnsureInputChain(string) error { return f.inputErr }
func (f *fakeBatch) EnsureAll(ins ...RuleInsert) ([]bool, error) {
	f.ensures = append(f.ensures, ins)
	if f.ensureErr != nil {
		return nil, f.ensureErr
	}
	out := make([]bool, len(ins))
	copy(out, f.inserted)
	return out, nil
}
func (f *fakeBatch) DeleteAll(refs ...RuleRef) error {
	f.deletes = append(f.deletes, refs)
	return f.deleteErr
}

func refChains(refs []RuleRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.Chain+" "+strings.Join(r.Spec, " "))
	}
	return out
}

func insertChains(ins []RuleInsert) []string {
	refs := make([]RuleRef, len(ins))
	for i, in := range ins {
		refs[i] = in.RuleRef
	}
	return refChains(refs)
}

// TestBatchBlockAndClearShape: on a batch backend the block-all is one
// EnsureAll (user chain DROP at the top, input drop at position 2) and its
// clear one DeleteAll naming the same two rules, the pair the per-rule path
// installs and sweeps one listing at a time.
func TestBatchBlockAndClearShape(t *testing.T) {
	f := &fakeBatch{t: t, inserted: []bool{false, true}}
	m := &Manager{enabled: true, ipt: f, userChain: ChainAerolvmUser}
	ins, err := m.BlockAllEgressReport("10.0.0.2")
	if err != nil || !ins {
		t.Fatalf("block: inserted=%v err=%v", ins, err)
	}
	want := []string{ChainAerolvmUser + " -s 10.0.0.2 -j DROP", ChainAerolvmInput + " " + strings.Join(inputBlockSpec("10.0.0.2"), " ")}
	if len(f.ensures) != 1 || !slices.Equal(insertChains(f.ensures[0]), want) {
		t.Fatalf("ensure batches = %v, want one with %v", f.ensures, want)
	}
	if f.ensures[0][0].Pos != 1 || f.ensures[0][1].Pos != 2 {
		t.Fatalf("positions = %d, %d; want 1 (top) and 2 (below the established return)", f.ensures[0][0].Pos, f.ensures[0][1].Pos)
	}
	if err := m.ClearBlockAllEgress("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	if len(f.deletes) != 1 || !slices.Equal(refChains(f.deletes[0]), want) {
		t.Fatalf("delete batches = %v, want one with %v", f.deletes, want)
	}
	// Below the floor's jump once a floor is installed.
	m.floorFirst.Store(true)
	if _, err := m.BlockAllEgressReport("10.0.0.3"); err != nil {
		t.Fatal(err)
	}
	if f.ensures[1][0].Pos != 2 {
		t.Fatalf("user DROP position under a floor = %d, want 2", f.ensures[1][0].Pos)
	}
}

// TestBatchBlockAndClearErrors: the error paths keep the per-rule path's
// contract. An input chain that can't be bootstrapped still gets the
// forward DROP installed (the sandbox is shut) and the call reports the
// error; its clear skips the chain that can't hold a rule.
func TestBatchBlockAndClearErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		name      string
		f         fakeBatch
		block     bool
		wantErr   string
		wantRules int
	}{
		{name: "block ensure fails", f: fakeBatch{ensureErr: boom}, block: true, wantErr: "insert egress rules", wantRules: 2},
		{name: "block without input chain", f: fakeBatch{inputErr: boom, inserted: []bool{true}}, block: true, wantErr: "bootstrap", wantRules: 1},
		{name: "block without input chain, ensure fails", f: fakeBatch{inputErr: boom, ensureErr: boom}, block: true, wantErr: "insert egress rule", wantRules: 1},
		{name: "clear fails", f: fakeBatch{deleteErr: boom}, wantErr: "delete egress rules", wantRules: 2},
		{name: "clear without input chain", f: fakeBatch{inputErr: boom}, wantRules: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			f.t = t
			m := &Manager{enabled: true, ipt: &f, userChain: ChainAerolvmUser}
			var err error
			var rules int
			if tc.block {
				var ins bool
				ins, err = m.BlockAllEgressReport("10.0.0.2")
				if tc.f.inputErr != nil && tc.f.ensureErr == nil && !ins {
					t.Fatal("the forward DROP the batch inserted must be reported")
				}
				rules = len(f.ensures[0])
			} else {
				err = m.ClearBlockAllEgress("10.0.0.2")
				rules = len(f.deletes[0])
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if rules != tc.wantRules {
				t.Fatalf("batch named %d rules, want %d", rules, tc.wantRules)
			}
		})
	}
}
