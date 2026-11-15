package drivers

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// The driver's behaviour is tested against real node in
// internal/codeinterp/proc (javascript_test.go, langs_test.go).
func TestJavaScriptDriver(t *testing.T) {
	checkDriver(t, codeinterp.LangJavaScript, []string{"node", "nodejs"}, "javascript_driver.cjs",
		[]string{"/bin/prog", "--expose-internals", "/d/javascript_driver.cjs", "javascript"}, "processTopLevelAwait")
	checkDriverRefuses(t, codeinterp.LangJavaScript)
}
