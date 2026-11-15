// Package drivers holds the interpreter driver scripts, one per language.
// A driver is a small program in the language itself that speaks the
// codeinterp driver protocol (see internal/codeinterp/doc.go). The process
// launcher runs it with the sandbox's interpreter; the WASM launcher runs
// the python one inside python.wasm.
//
// Adding a language is one file: embed the script and register a Driver
// from that file's init (python.go is the model).
package drivers

import (
	"fmt"
	"sort"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// Driver describes how to start one language's driver script.
type Driver struct {
	// Language is one of the codeinterp.Lang constants.
	Language string
	// Programs are tried in order on the sandbox's PATH; the first found
	// runs the script.
	Programs []string
	// FileName is the script's base name. Some interpreters care about the
	// extension (node picks the module type from it).
	FileName string
	// Script is the driver source. Callers must not modify it.
	Script []byte
	// Args returns the full argv, program first, to run the script that
	// was written to scriptPath.
	Args func(program, scriptPath string) []string
	// Env is added to the kernel's environment, after the context's own.
	Env map[string]string
}

var registry = map[string]Driver{}

// register adds a driver. It runs from init functions, so a duplicate or an
// incomplete driver is a programming error caught by any test run.
func register(d Driver) {
	if d.Language == "" || len(d.Programs) == 0 || d.FileName == "" || len(d.Script) == 0 || d.Args == nil {
		panic(fmt.Sprintf("codeinterp/drivers: incomplete driver for %q", d.Language))
	}
	if _, dup := registry[d.Language]; dup {
		panic(fmt.Sprintf("codeinterp/drivers: driver for %q registered twice", d.Language))
	}
	registry[d.Language] = d
}

// Lookup returns the driver for a language (a codeinterp.Lang constant).
func Lookup(language string) (Driver, bool) {
	d, ok := registry[language]
	return d, ok
}

// Languages lists the languages with a driver, in codeinterp.AllLanguages
// order (any language not in that list comes after, sorted).
func Languages() []string {
	out := make([]string, 0, len(registry))
	known := map[string]bool{}
	for _, lang := range codeinterp.AllLanguages {
		known[lang] = true
		if _, ok := registry[lang]; ok {
			out = append(out, lang)
		}
	}
	var extra []string
	for lang := range registry {
		if !known[lang] {
			extra = append(extra, lang)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}
