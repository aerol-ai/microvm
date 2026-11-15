package drivers

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// The driver's behaviour is tested against real bash in
// internal/codeinterp/proc (bash_test.go, langs_test.go).
func TestBashDriver(t *testing.T) {
	checkDriver(t, codeinterp.LangBash, []string{"bash"}, "bash_driver.sh",
		[]string{"/bin/prog", "/d/bash_driver.sh"}, "__aerol_unwind")
	checkDriverRefuses(t, codeinterp.LangBash)
}
