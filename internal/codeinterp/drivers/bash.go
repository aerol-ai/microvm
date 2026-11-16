package drivers

import (
	_ "embed"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

//go:embed bash_driver.sh
var bashDriver []byte

func init() {
	register(Driver{
		Language: codeinterp.LangBash,
		Programs: []string{"bash"},
		FileName: "bash_driver.sh",
		Script:   bashDriver,
		Args: func(program, scriptPath string) []string {
			return []string{program, scriptPath}
		},
	})
}
