package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"gopkg.in/yaml.v3"
)

// A focused scenario (a caps file with a `focus:` block, cluster-chaos today)
// runs only `go test -run <focus.run>`, and the report then marks every use
// case that does not need focus.capability as "skip, not in this focused
// scenario". Both halves fail quietly if they drift apart:
//
//   - a test claiming a focus use case that the regex does not select never
//     runs; its row reads missing only at the end of a paid AWS run;
//   - a test the regex selects that claims some OTHER use case runs on a
//     fleet built for something else (cluster-chaos partitions and kills
//     nodes), and its row is reported where nobody looks for it.
//
// So the regex must select exactly the tests whose primary use case requires
// the focus capability.
func TestFocusedScenarioRunsExactlyItsUseCases(t *testing.T) {
	focused := 0
	for _, f := range capsFiles(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var caps struct {
			Capabilities []harness.Capability `yaml:"capabilities"`
			Focus        *struct {
				Capability harness.Capability `yaml:"capability"`
				Run        string             `yaml:"run"`
			} `yaml:"focus"`
		}
		if err := yaml.Unmarshal(raw, &caps); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		if caps.Focus == nil {
			continue
		}
		focused++
		base := filepath.Base(f)
		t.Run(base, func(t *testing.T) {
			focus := caps.Focus.Capability
			if focus == "" || caps.Focus.Run == "" {
				t.Fatalf("focus needs both capability and run, got %+v", *caps.Focus)
			}
			if !harness.KnownCapabilities[focus] {
				t.Fatalf("focus capability %q is unknown; report/gen.go refuses it", focus)
			}
			if !slices.Contains(caps.Capabilities, focus) {
				t.Fatalf("the scenario does not advertise its own focus capability %q, so every focused case would skip", focus)
			}
			runRE, err := regexp.Compile(caps.Focus.Run)
			if err != nil {
				t.Fatalf("focus.run %q does not compile: %v", caps.Focus.Run, err)
			}

			claims := suiteTestClaims(t)
			var want, selected []string
			for name, ucs := range claims {
				uc, ok := harness.Lookup(ucs[0])
				if ok && slices.Contains(uc.Requires, focus) {
					want = append(want, name)
				}
				if runRE.MatchString(name) {
					selected = append(selected, name)
				}
			}
			sort.Strings(want)
			sort.Strings(selected)
			if len(want) == 0 {
				t.Fatalf("no suite test claims a use case requiring %q; the focused scenario would test nothing", focus)
			}
			var missed, extra []string
			for _, n := range want {
				if !runRE.MatchString(n) {
					missed = append(missed, n)
				}
			}
			for _, n := range selected {
				if !slices.Contains(want, n) {
					extra = append(extra, n+" ("+strings.Join(claims[n], ",")+")")
				}
			}
			if len(missed) > 0 {
				t.Errorf("focus.run %q does not select these %s tests, so they never run on %s: %s",
					caps.Focus.Run, focus, base, strings.Join(missed, ", "))
			}
			if len(extra) > 0 {
				t.Errorf("focus.run %q also selects tests whose use case does not need %s; they would run on a fleet built for faults: %s",
					caps.Focus.Run, focus, strings.Join(extra, ", "))
			}
		})
	}
	if focused == 0 {
		t.Fatal("no scenario has a focus block; this guard would pass having checked nothing")
	}
}

// suiteTestClaims maps every top-level Test function in the suite to the use
// case ids its harness.Require call names, primary first. Tests that claim
// nothing (the suite's own static guards) are left out.
func suiteTestClaims(t *testing.T) map[string][]string {
	t.Helper()
	dir := filepath.Join("..", "suite")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			if ucs, _ := scanTestBody(fn); len(ucs) > 0 {
				out[fn.Name.Name] = ucs
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("found no test claiming a use case; the scan no longer matches the suite")
	}
	return out
}
