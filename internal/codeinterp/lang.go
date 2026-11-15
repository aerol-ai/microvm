package codeinterp

import (
	"fmt"
	"strings"
)

// Languages a context can run. Which ones work in a given sandbox depends on
// the interpreters in its image (or, on WASM, on the standard modules).
const (
	LangPython     = "python"
	LangJavaScript = "javascript"
	LangTypeScript = "typescript"
	LangBash       = "bash"
	LangR          = "r"
	LangJava       = "java"
)

// AllLanguages lists every language a launcher may support, in the order
// E2B documents them.
var AllLanguages = []string{LangPython, LangJavaScript, LangTypeScript, LangR, LangJava, LangBash}

// NormalizeLanguage maps a client's language name to one of the constants.
// It follows E2B: an empty name means python, names are trimmed and lower
// cased, and "js"/"ts" are aliases. "py" and "sh" are accepted as well
// because nothing else could mean them.
func NormalizeLanguage(name string) (string, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "", "py", "python3":
		return LangPython, nil
	case "js", "node", "nodejs":
		return LangJavaScript, nil
	case "ts":
		return LangTypeScript, nil
	case "sh", "shell":
		return LangBash, nil
	}
	for _, l := range AllLanguages {
		if n == l {
			return l, nil
		}
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedLanguage, name)
}
