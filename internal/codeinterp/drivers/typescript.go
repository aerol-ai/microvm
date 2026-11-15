package drivers

import "github.com/aerol-ai/microvm/internal/codeinterp"

func init() {
	// TypeScript is the JavaScript driver with Node's own type stripping
	// (module.stripTypeScriptTypes, Node.js 22.13 or newer); an older node
	// fails the launch with a FATAL that names the version needed.
	register(Driver{
		Language: codeinterp.LangTypeScript,
		Programs: []string{"node", "nodejs"},
		FileName: "javascript_driver.cjs",
		Script:   javascriptDriver,
		Args:     nodeArgs(codeinterp.LangTypeScript),
	})
}
