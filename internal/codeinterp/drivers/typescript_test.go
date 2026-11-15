package drivers

import (
	"bytes"
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// The driver's behaviour is tested against real node in
// internal/codeinterp/proc (javascript_test.go, langs_test.go).
func TestTypeScriptDriver(t *testing.T) {
	checkDriver(t, codeinterp.LangTypeScript, []string{"node", "nodejs"}, "javascript_driver.cjs",
		[]string{"/bin/prog", "--expose-internals", "/d/javascript_driver.cjs", "typescript"}, "stripTypeScriptTypes")
	// One script for both: the launcher writes it once.
	js, _ := Lookup(codeinterp.LangJavaScript)
	ts, _ := Lookup(codeinterp.LangTypeScript)
	if !bytes.Equal(js.Script, ts.Script) {
		t.Fatal("typescript runs a different script")
	}
	checkDriverRefuses(t, codeinterp.LangTypeScript)
}
