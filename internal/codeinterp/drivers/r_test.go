package drivers

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// The driver's behaviour is tested against real R in
// internal/codeinterp/proc (r_test.go, langs_test.go).
func TestRDriver(t *testing.T) {
	checkDriver(t, codeinterp.LangR, []string{"Rscript"}, "r_driver.R",
		[]string{"/bin/prog", "--no-save", "--no-restore", "/d/r_driver.R"}, "suspendInterrupts")
	checkDriverRefuses(t, codeinterp.LangR)
}
