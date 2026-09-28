package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A comment line inside a backslash continuation ENDS the command. Every
// line before it becomes a statement of its own — for a block of
// `VAR=value \` prefixes, a set of assignments that apply to nothing — and
// the command after it runs without them. bash -n accepts it: the result is
// valid, just wrong.
//
// It happened: a comment added above run.sh's `go test` line, inside the
// AEROL_* env block, made the whole live suite exit in one second with
// "AEROL_CAPS not set" and threw away a provisioned 8-node T18 cluster.
func TestNoCommentInsideAShellLineContinuation(t *testing.T) {
	root := filepath.Join("..")
	var scripts []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && (info.Name() == ".tf" || info.Name() == ".build" || info.Name() == "reports") {
			return filepath.SkipDir
		}
		if !info.IsDir() && strings.HasSuffix(p, ".sh") {
			scripts = append(scripts, p)
		}
		return nil
	})
	if len(scripts) == 0 {
		t.Fatal("found no shell scripts; this guard would pass having checked nothing")
	}
	for _, p := range scripts {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		inHeredoc := ""
		for i := 1; i < len(lines); i++ {
			prev := lines[i-1]
			if inHeredoc != "" {
				if strings.TrimSpace(prev) == inHeredoc {
					inHeredoc = ""
				}
				continue
			}
			if k := strings.Index(prev, "<<"); k >= 0 && !strings.Contains(prev, "<<<") {
				tag := strings.Trim(strings.Fields(prev[k+2:] + " x")[0], `'"-`)
				if tag != "" && tag != "x" {
					inHeredoc = tag
					continue
				}
			}
			if strings.HasSuffix(strings.TrimRight(prev, " \t"), "\\") &&
				!strings.HasPrefix(strings.TrimSpace(prev), "#") &&
				strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
				t.Errorf("%s:%d: comment inside a line continuation — it ends the command on line %d, and everything continued before it silently stops applying", p, i+1, i)
			}
		}
	}
}
