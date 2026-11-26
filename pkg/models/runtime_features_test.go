package models

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// validationAllowedRuntimes is the list ValidRuntime's refusal names
// ("allowed: a, b, c"): every name a create accepts, in ValidRuntime's order.
func validationAllowedRuntimes(t *testing.T) []string {
	t.Helper()
	_, err := ValidRuntime("\x00no-such-runtime")
	if err == nil {
		t.Fatal("ValidRuntime accepted a made-up name")
	}
	_, list, ok := strings.Cut(err.Error(), "allowed: ")
	if !ok {
		t.Fatalf("ValidRuntime's refusal no longer lists the allowed names: %v", err)
	}
	return strings.Split(strings.TrimSuffix(list, ")"), ", ")
}

// acceptedRuntimeConstants is every string constant declared in this
// package that ValidRuntime accepts, read from the source, so a new
// Runtime* constant wired into ValidRuntime is found even if its refusal
// text is not updated.
func acceptedRuntimeConstants(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]string{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, file, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					value, err := strconv.Unquote(lit.Value)
					if err != nil || value == "" {
						continue
					}
					if _, err := ValidRuntime(value); err == nil {
						out[name.Name] = value
					}
				}
			}
		}
	}
	return out
}

// TestRuntimeTableCoversValidRuntimes: every runtime name a create accepts
// has exactly one row, in ValidRuntime's order, and every row is a name a
// create accepts. Adding a runtime to ValidRuntime without a row fails here.
func TestRuntimeTableCoversValidRuntimes(t *testing.T) {
	var names []string
	for _, row := range RuntimeTable() {
		names = append(names, row.Name)
	}
	if allowed := validationAllowedRuntimes(t); !slices.Equal(names, allowed) {
		t.Fatalf("table rows %v, ValidRuntime allows %v: add a row to runtimeTable (runtime_features.go) for each, in the same order", names, allowed)
	}
	consts := acceptedRuntimeConstants(t)
	if len(consts) == 0 {
		t.Fatal("found no runtime constants in the package source")
	}
	for name, value := range consts {
		if _, ok := LookupRuntime(value); !ok {
			t.Errorf("%s = %q is accepted by ValidRuntime but has no row in runtimeTable", name, value)
		}
	}
}

// TestRuntimeTableValues pins each row, so a change to what a runtime can do
// is a change a reviewer sees here as well as in the table.
func TestRuntimeTableValues(t *testing.T) {
	for _, tc := range []struct {
		name      string
		isolation string
		backend   string
		features  RuntimeFeatures
		limits    *RuntimeLimits
		reserved  bool
	}{
		{RuntimeDocker, IsolationContainer, "", RuntimeFeatures{Snapshots: true, Moves: MovesNone, WarmPool: WarmPoolKindParked}, nil, false},
		{RuntimeGvisor, IsolationUserSpaceKernel, "", RuntimeFeatures{Moves: MovesMemory, WarmPool: WarmPoolKindParked}, nil, false},
		{RuntimeKata, IsolationHardwareVM, "", RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindNone}, nil, true},
		{RuntimeFirecracker, IsolationHardwareVM, "kvm", RuntimeFeatures{Snapshots: true, Pause: true, Moves: MovesMemory, WarmPool: WarmPoolKindSnapshot}, nil, false},
		{RuntimeFirecrackerNitro, IsolationHardwareVM, "nitro", RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindNone}, nil, false},
		{RuntimeWasm, IsolationWasm, "", RuntimeFeatures{Moves: MovesMemory, WarmPool: WarmPoolKindParked}, &RuntimeLimits{MaxCheckpointMemoryMB: 1024}, false},
		{RuntimeIsolate, IsolationV8Isolate, "", RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindParked}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row, ok := LookupRuntime(tc.name)
			if !ok {
				t.Fatalf("no row for %q", tc.name)
			}
			if row.Isolation != tc.isolation || row.Backend != tc.backend || row.Features != tc.features || row.Reserved != tc.reserved {
				t.Fatalf("row = %+v, want isolation %q backend %q features %+v reserved %v", row, tc.isolation, tc.backend, tc.features, tc.reserved)
			}
			if (row.Limits == nil) != (tc.limits == nil) || (row.Limits != nil && *row.Limits != *tc.limits) {
				t.Fatalf("limits = %+v, want %+v", row.Limits, tc.limits)
			}
		})
	}
}

// Every value comes from its closed set, and a reserved runtime claims
// nothing it cannot do.
func TestRuntimeTableEnums(t *testing.T) {
	isolations := []string{IsolationContainer, IsolationUserSpaceKernel, IsolationHardwareVM, IsolationWasm, IsolationV8Isolate}
	moves := []string{MovesMemory, MovesDisk, MovesNone}
	warm := []string{WarmPoolKindSnapshot, WarmPoolKindParked, WarmPoolKindNone}
	for _, row := range RuntimeTable() {
		if !slices.Contains(isolations, row.Isolation) || !slices.Contains(moves, row.Features.Moves) || !slices.Contains(warm, row.Features.WarmPool) {
			t.Errorf("%s: value outside its set: %+v", row.Name, row)
		}
		if row.Reserved && (row.Features != RuntimeFeatures{Moves: MovesNone, WarmPool: WarmPoolKindNone} || row.Limits != nil) {
			t.Errorf("%s is reserved but claims features %+v limits %+v", row.Name, row.Features, row.Limits)
		}
	}
}

func TestRuntimeTableReturnsCopies(t *testing.T) {
	rows := RuntimeTable()
	for i := range rows {
		rows[i].Name = "changed"
		if rows[i].Limits != nil {
			rows[i].Limits.MaxCheckpointMemoryMB = 1
		}
	}
	got, ok := LookupRuntime(RuntimeWasm)
	if !ok || got.Limits == nil || got.Limits.MaxCheckpointMemoryMB != 1024 {
		t.Fatalf("a caller changed the table: %+v", got)
	}
	got.Limits.MaxCheckpointMemoryMB = 2
	if again, _ := LookupRuntime(RuntimeWasm); again.Limits.MaxCheckpointMemoryMB != 1024 {
		t.Fatalf("LookupRuntime handed out the table's limits: %+v", again.Limits)
	}
	if _, ok := LookupRuntime("runc"); ok {
		t.Fatal("LookupRuntime found a name ValidRuntime refuses")
	}
}

func TestListRuntimes(t *testing.T) {
	offers := map[string]int{
		RuntimeDocker:           3,
		RuntimeFirecracker:      1,
		RuntimeKata:             2,  // listed in SB_HOST_RUNTIMES, but reserved
		RuntimeFirecrackerNitro: 2,  // a Nitro node pool
		RuntimeWasm:             -1, // never trusted below zero
		"runc":                  4,  // free text no create accepts
	}
	for _, tc := range []struct {
		name      string
		offers    map[string]int
		withNodes bool
		available map[string]bool
		nodes     map[string]int
	}{
		{name: "tenant", offers: offers, available: map[string]bool{RuntimeDocker: true, RuntimeFirecracker: true, RuntimeFirecrackerNitro: true}},
		{name: "fleet admin", offers: offers, withNodes: true,
			available: map[string]bool{RuntimeDocker: true, RuntimeFirecracker: true, RuntimeFirecrackerNitro: true},
			nodes:     map[string]int{RuntimeDocker: 3, RuntimeGvisor: 0, RuntimeKata: 0, RuntimeFirecracker: 1, RuntimeFirecrackerNitro: 2, RuntimeWasm: 0, RuntimeIsolate: 0}},
		{name: "nothing offered", offers: nil, available: map[string]bool{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ListRuntimes(tc.offers, tc.withNodes)
			if len(got.Runtimes) != len(runtimeTable) {
				t.Fatalf("listed %d runtimes, want every row (%d)", len(got.Runtimes), len(runtimeTable))
			}
			for i, entry := range got.Runtimes {
				row := runtimeTable[i]
				if entry.Name != row.Name || entry.Isolation != row.Isolation || entry.Backend != row.Backend || entry.Features != row.Features {
					t.Errorf("entry %d = %+v, want row %+v", i, entry, row)
				}
				if entry.Available != tc.available[entry.Name] {
					t.Errorf("%s available = %v, want %v", entry.Name, entry.Available, tc.available[entry.Name])
				}
				switch {
				case !tc.withNodes && entry.Nodes != nil:
					t.Errorf("%s: a non-admin sees a node count", entry.Name)
				case tc.withNodes && (entry.Nodes == nil || *entry.Nodes != tc.nodes[entry.Name]):
					t.Errorf("%s nodes = %v, want %d", entry.Name, entry.Nodes, tc.nodes[entry.Name])
				}
			}
		})
	}
}

// The wire shape: names, features and availability for everyone; "nodes"
// only for fleet admins; "backend" and "limits" only where a row has them.
func TestListRuntimesJSON(t *testing.T) {
	offers := map[string]int{RuntimeFirecracker: 2}
	for _, tc := range []struct {
		withNodes bool
		want      string
	}{
		{false, `{"name":"firecracker","isolation":"hardware-vm","backend":"kvm","features":{"snapshots":true,"pause":true,"moves":"memory","warm_pool":"snapshot","confidential":false},"available":true}`},
		{true, `{"name":"firecracker","isolation":"hardware-vm","backend":"kvm","features":{"snapshots":true,"pause":true,"moves":"memory","warm_pool":"snapshot","confidential":false},"available":true,"nodes":2}`},
	} {
		body, err := json.Marshal(ListRuntimes(offers, tc.withNodes))
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Runtimes []json.RawMessage `json:"runtimes"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatal(err)
		}
		byName := map[string]string{}
		for _, raw := range decoded.Runtimes {
			var head struct{ Name string }
			_ = json.Unmarshal(raw, &head)
			byName[head.Name] = string(raw)
		}
		if byName[RuntimeFirecracker] != tc.want {
			t.Errorf("withNodes=%v firecracker = %s\nwant %s", tc.withNodes, byName[RuntimeFirecracker], tc.want)
		}
		if want := `"limits":{"max_checkpoint_memory_mb":1024}`; !strings.Contains(byName[RuntimeWasm], want) {
			t.Errorf("wasm = %s, want %s", byName[RuntimeWasm], want)
		}
		if strings.Contains(byName[RuntimeDocker], `"limits"`) || strings.Contains(byName[RuntimeDocker], `"backend"`) {
			t.Errorf("docker carries a field it has no value for: %s", byName[RuntimeDocker])
		}
	}
}

// TestRuntimeBackendAndWarmStartKind: backend and warm come from the table.
// A warm start of a runtime the table gives no pool kind still reads as
// parked, and a name the table does not hold has no backend.
func TestRuntimeBackendAndWarmStartKind(t *testing.T) {
	for _, tc := range []struct {
		runtime    string
		backend    string
		warm, cold string
	}{
		{RuntimeFirecracker, "kvm", WarmPoolKindSnapshot, WarmPoolKindNone},
		{RuntimeFirecrackerNitro, "nitro", WarmPoolKindParked, WarmPoolKindNone},
		{RuntimeDocker, "", WarmPoolKindParked, WarmPoolKindNone},
		{RuntimeWasm, "", WarmPoolKindParked, WarmPoolKindNone},
		{RuntimeKata, "", WarmPoolKindParked, WarmPoolKindNone},
		{"nope", "", WarmPoolKindParked, WarmPoolKindNone},
	} {
		if got := RuntimeBackend(tc.runtime); got != tc.backend {
			t.Errorf("RuntimeBackend(%q) = %q, want %q", tc.runtime, got, tc.backend)
		}
		if got := WarmStartKind(tc.runtime, true); got != tc.warm {
			t.Errorf("WarmStartKind(%q, warm) = %q, want %q", tc.runtime, got, tc.warm)
		}
		if got := WarmStartKind(tc.runtime, false); got != tc.cold {
			t.Errorf("WarmStartKind(%q, cold) = %q, want %q", tc.runtime, got, tc.cold)
		}
	}
}

// TestRuntimeNotOfferedError: the offered list leads the message, the
// cause follows, and the error unwraps to the cause.
func TestRuntimeNotOfferedError(t *testing.T) {
	cause := ErrRuntimeNotImplemented
	err := &RuntimeNotOfferedError{Runtime: RuntimeGvisor, Offered: OfferedRuntimes(map[string]int{RuntimeWasm: 1, RuntimeDocker: 2, RuntimeKata: 1}), Err: cause}
	want := `runtime "gvisor" is not offered here (offered: docker, wasm): ` + cause.Error()
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if err.Unwrap() != cause {
		t.Fatalf("Unwrap() = %v, want the cause", err.Unwrap())
	}
	empty := &RuntimeNotOfferedError{Runtime: RuntimeGvisor}
	if got := empty.Error(); got != `runtime "gvisor" is not offered here (offered: none)` {
		t.Fatalf("no cause, nothing offered: %q", got)
	}
	if got := OfferedRuntimes(nil); len(got) != 0 {
		t.Fatalf("OfferedRuntimes(nil) = %v, want none", got)
	}
}
