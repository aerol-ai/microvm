package drivers

import (
	_ "embed"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// javascriptDriver also runs typescript (typescript.go): the language is
// its last argument. .cjs keeps it CommonJS whatever package.json is near.
//
//go:embed javascript_driver.cjs
var javascriptDriver []byte

// nodeArgs runs the driver for language. --expose-internals gives the
// driver Node's REPL transform for top-level await (see the script).
func nodeArgs(language string) func(program, scriptPath string) []string {
	return func(program, scriptPath string) []string {
		return []string{program, "--expose-internals", scriptPath, language}
	}
}

func init() {
	register(Driver{
		Language: codeinterp.LangJavaScript,
		// Debian's older packages name the program nodejs.
		Programs: []string{"node", "nodejs"},
		FileName: "javascript_driver.cjs",
		Script:   javascriptDriver,
		Args:     nodeArgs(codeinterp.LangJavaScript),
	})
}
