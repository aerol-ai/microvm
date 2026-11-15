package e2b

import (
	"os"

	"github.com/aerol-ai/microvm/internal/codeinterp"
)

// DefaultCwd is where E2B starts contexts that name no cwd. E2B's template
// runs as "user" with this home, and code written for E2B (and E2B's own
// tests) expects os.getcwd() to say so.
const DefaultCwd = "/home/user"

// ManagerOptions are the Manager options for E2B's protocol: defaults get
// random ids, are listed and can be deleted (a new one is made on next use).
//
// Most images have no /home/user, so it is created here. When that fails
// (a read-only root, no permission) contexts start in the agent's own
// working directory instead, and that directory is what they report: a
// context must never claim a cwd its kernel could not enter.
func ManagerOptions(l codeinterp.Launcher, lim *codeinterp.Limit) codeinterp.Options {
	return managerOptions(l, lim, DefaultCwd, os.MkdirAll, os.Getwd)
}

// ManagerOptionsAt is ManagerOptions for a launcher whose kernels see a file
// system of their own, such as a WASM sandbox's /work: contexts that name
// no cwd start in cwd as given, since the agent can neither make nor check
// a folder there. When the launcher can say which languages it has
// drivers for (a Languages method), the others are refused up front, so
// E2B's javascript default is never registered where it cannot run.
func ManagerOptionsAt(l codeinterp.Launcher, lim *codeinterp.Limit, cwd string) codeinterp.Options {
	opts := codeinterp.Options{
		Launcher:     l,
		Limit:        lim,
		DefaultCwd:   cwd,
		ListDefaults: true,
	}
	if ls, ok := l.(interface{ Languages() []string }); ok {
		opts.Languages = ls.Languages()
	}
	return opts
}

func managerOptions(l codeinterp.Launcher, lim *codeinterp.Limit, cwd string,
	mkdirAll func(string, os.FileMode) error, getwd func() (string, error)) codeinterp.Options {
	return codeinterp.Options{
		Launcher:     l,
		Limit:        lim,
		DefaultCwd:   usableCwd(cwd, mkdirAll, getwd),
		ListDefaults: true,
	}
}

func usableCwd(cwd string, mkdirAll func(string, os.FileMode) error, getwd func() (string, error)) string {
	if err := mkdirAll(cwd, 0o755); err == nil {
		return cwd
	}
	if wd, err := getwd(); err == nil && wd != "" {
		return wd
	}
	// The root always exists, so a kernel can always start there.
	return "/"
}
