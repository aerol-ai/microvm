package wasm

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Code-run on WASM (issue #535): run a snippet with the language's standard
// module (python.wasm, QuickJS, ruby.wasm) as a streaming run on the
// sandbox's /work. The code reaches the interpreter as an argument, never
// as a file, so code-run adds nothing under /work and nothing on the host.

// CodeRunSpec is one /process/code-run request.
type CodeRunSpec struct {
	Language string
	Code     string
	Argv     []string
	Env      map[string]string
	// Timeout bounds the run; 0 uses the driver's wall timeout.
	Timeout time.Duration
	// MaxOutputBytes caps each of stdout and stderr (sandboxd buffers them).
	MaxOutputBytes int64
}

// CodeRunLanguageError is a code-run in a language this node cannot run.
type CodeRunLanguageError struct {
	Language string
	// Configured lists the languages this node can run.
	Configured []string
}

func (e *CodeRunLanguageError) Error() string {
	if len(e.Configured) == 0 {
		return fmt.Sprintf("code-run language %q: no code-run languages are configured for wasm sandboxes on this node (SB_WASM_CODERUN_MODULES)", e.Language)
	}
	return fmt.Sprintf("code-run language %q is not supported on wasm sandboxes here; supported: %s", e.Language, strings.Join(e.Configured, ", "))
}

// codeRunFamily is how one interpreter takes code on its command line.
type codeRunFamily struct {
	program string
	// evalFlag runs the next argument as the program.
	evalFlag string
	// separator puts "--" before the caller's argv, so an argument that
	// starts with "-" reaches the program instead of the interpreter.
	// CPython needs none: -c already ends its option list, and a "--"
	// would reach sys.argv.
	separator bool
}

// The flags were checked against the modules the integration suite stages
// (integration-tests/fixtures/wasm/modules.yml): python-3.12.0.wasm,
// qjs-wasi.wasm (quickjs-ng) and ruby-3.2.2.wasm.
var codeRunFamilies = map[string]codeRunFamily{
	"python":     {program: "python", evalFlag: "-c"},
	"javascript": {program: "qjs", evalFlag: "-e", separator: true},
	"ruby":       {program: "ruby", evalFlag: "-e", separator: true},
}

// codeRunLanguageFamily maps request languages to a family. A language in
// SB_WASM_CODERUN_MODULES outside this table cannot run: there is no way to
// know how its interpreter takes code.
var codeRunLanguageFamily = map[string]string{
	"python": "python", "python3": "python", "py": "python",
	"javascript": "javascript", "js": "javascript", "node": "javascript",
	"ruby": "ruby", "rb": "ruby",
}

func codeRunArgs(family codeRunFamily, code string, argv []string) []string {
	args := []string{family.program, family.evalFlag, code}
	if family.separator && len(argv) > 0 {
		args = append(args, "--")
	}
	return append(args, argv...)
}

// codeRunLanguages lists the configured languages this driver can run.
func (d *Driver) codeRunLanguages() []string {
	out := make([]string, 0, len(d.cfg.CodeRunModules))
	for lang, ref := range d.cfg.CodeRunModules {
		if _, ok := codeRunLanguageFamily[lang]; ok && strings.TrimSpace(ref) != "" {
			out = append(out, lang)
		}
	}
	sort.Strings(out)
	return out
}

// codeRunModulePath resolves a language's module once and caches the path.
// The refs come from operator config, not from the request, so they resolve
// with the daemon's own context: a tenant's host-path restrictions do not
// apply to them, and a cancelled request does not abort a pull another
// request is about to need.
func (d *Driver) codeRunModulePath(lang, ref string) (string, error) {
	d.codeRunMu.Lock()
	path := d.codeRunPaths[lang]
	d.codeRunMu.Unlock()
	if path != "" {
		return path, nil
	}
	if d.resolver == nil {
		return "", fmt.Errorf("wasm runtime: module resolver not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resolved, err := d.resolver.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve code-run module %q for %s: %w", ref, lang, err)
	}
	d.codeRunMu.Lock()
	if d.codeRunPaths == nil {
		d.codeRunPaths = make(map[string]string)
	}
	d.codeRunPaths[lang] = resolved.Path
	d.codeRunMu.Unlock()
	return resolved.Path, nil
}

// forgetCodeRunModule drops a cached path whose file is gone (a cache
// eviction or a restaged module), so the next code-run resolves again.
func (d *Driver) forgetCodeRunModule(lang, path string) {
	if _, err := os.Stat(path); err == nil {
		return
	}
	d.codeRunMu.Lock()
	if d.codeRunPaths[lang] == path {
		delete(d.codeRunPaths, lang)
	}
	d.codeRunMu.Unlock()
}

// StartCodeRun runs spec.Code with its language's module as a streaming run
// in the sandbox. A language that is not configured returns a
// *CodeRunLanguageError.
func (d *Driver) StartCodeRun(ctx context.Context, sandboxID string, spec CodeRunSpec) (*Stream, error) {
	lang := strings.ToLower(strings.TrimSpace(spec.Language))
	familyName, known := codeRunLanguageFamily[lang]
	ref := strings.TrimSpace(d.cfg.CodeRunModules[lang])
	if !known || ref == "" {
		return nil, &CodeRunLanguageError{Language: spec.Language, Configured: d.codeRunLanguages()}
	}
	path, err := d.codeRunModulePath(lang, ref)
	if err != nil {
		return nil, err
	}
	st, err := d.StartStream(ctx, sandboxID, StreamSpec{
		ModulePath:     path,
		Args:           codeRunArgs(codeRunFamilies[familyName], spec.Code, spec.Argv),
		Env:            spec.Env,
		Timeout:        spec.Timeout,
		MaxOutputBytes: spec.MaxOutputBytes,
	})
	if err != nil {
		d.forgetCodeRunModule(lang, path)
		return nil, err
	}
	return st, nil
}
