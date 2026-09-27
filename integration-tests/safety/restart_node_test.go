package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Restarting the SEED of a SWIM cluster orphans the joiners into their own
// partition, and they do not heal. The live S2 run left node1 seeing only
// itself while nodes 2 and 3 gossiped with each other, and every subsequent
// sandbox create failed "cluster: peer InternalURL required (mTLS
// fail-closed)" — 57 cases, nearly all of them nothing to do with secrets.
//
// harness.PickSSHNode deliberately PREFERS the seed, which is right for
// reading state and exactly wrong for restarting. Any file that restarts a
// node must pick a restartable one instead, and no future case can quietly
// reintroduce the trap.
func TestRestartingCasesDoNotPickTheSeed(t *testing.T) {
	dir := filepath.Join("..", "suite")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Function-scoped, not file-scoped: a file may legitimately contain one
	// case that restarts a node and another that merely reads from the seed.
	// Flagging the file would cry wolf, and a guard that cries wolf trains
	// the reader to skip the one time it is right.
	fset := token.NewFileSet()
	restarts := regexp.MustCompile(`WithNodeEnv\(|RestartSystemdUnit\(|systemctl restart sandboxd`)
	picksSeed := regexp.MustCompile(`PickSSHNode\(`)

	var offenders []string
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, path, b, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			body := string(b[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
			if !restarts.MatchString(body) {
				continue
			}
			scanned++
			if picksSeed.MatchString(body) {
				offenders = append(offenders, e.Name()+":"+fn.Name.Name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no function was found that restarts a node; this guard would pass having checked nothing")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("these functions restart a node but select it with PickSSHNode, which PREFERS THE SEED — restarting the seed orphans the joiners and they do not rejoin: %s\nUse harness.PickRestartableNode instead.",
			strings.Join(offenders, ", "))
	}
}
