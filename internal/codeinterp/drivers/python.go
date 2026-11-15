package drivers

import (
	_ "embed"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

//go:embed python_driver.py
var pythonDriver []byte

func init() {
	register(Driver{
		Language: codeinterp.LangPython,
		// "python" last: on some images it is Python 2, which cannot run
		// the driver (the launch then fails with its syntax error).
		Programs: []string{"python3", "python"},
		FileName: "python_driver.py",
		Script:   pythonDriver,
		Args: func(program, scriptPath string) []string {
			return []string{program, scriptPath}
		},
	})
}
