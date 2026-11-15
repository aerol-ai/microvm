package drivers

import (
	_ "embed"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

//go:embed r_driver.R
var rDriver []byte

func init() {
	register(Driver{
		Language: codeinterp.LangR,
		Programs: []string{"Rscript"},
		FileName: "r_driver.R",
		Script:   rDriver,
		Args: func(program, scriptPath string) []string {
			// No --vanilla: the image's Rprofile.site (CRAN mirror, library
			// paths) applies, as in an R console.
			return []string{program, "--no-save", "--no-restore", scriptPath}
		},
	})
}
