package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
)

// Exec with argv (plan E2): a command given as a list runs with no shell
// parsing in between, so arguments with spaces, quotes, $ or ; reach the
// program as written. It must still find the same programs a command string
// finds on the same route, including what the login profile adds to PATH
// (conda, nix, sdkman from /etc/profile.d).
//
//	image has a shell ─► <shell> -lc '<PATH restore>; exec "$@"' sh argv...   (buffered exec)
//	                 └─► <shell> -c 'exec "$@"' sh argv...                     (exec stream)
//	no shell ──────────► argv[0] looked up on the image PATH, then exec'd directly
//
// The shell only expands "$@", which is each argument whole, and exec
// replaces it with the program, so the program is the process toolboxd
// waits on: its exit status and a signal that ends it are its own. A
// missing program gets the shell's own answer, exit 127 and a "not found"
// line; the direct path gives the same.

// argvScript is the script a shell runs for argv: nothing but exec.
const argvScript = `exec "$@"`

// validateArgvRequest checks command and argv together. hasCommand is the
// route's own test for a command (buffered exec ignores a blank one, the
// stream only an empty one, as before argv). It returns "" when the request
// is valid.
func validateArgvRequest(hasCommand bool, argv []string) string {
	switch {
	case hasCommand && len(argv) > 0:
		return "set command or argv, not both"
	case !hasCommand && len(argv) == 0:
		return "command is required"
	case len(argv) > 0 && strings.TrimSpace(argv[0]) == "":
		return "argv[0] must name the program to run"
	case len(argv) > 0 && strings.HasPrefix(argv[0], "-"):
		// A shell's exec would read it as one of its own options.
		return "argv[0] must name the program to run, not an option"
	}
	return ""
}

// shellArgv is the shell command line that runs argv without parsing it.
// login selects a login shell with the PATH restore, as buffered exec runs
// a command string; the exec stream runs a plain -c, as it does for one.
func shellArgv(shell string, login bool, argv []string) []string {
	flag, script := "-c", argvScript
	if login {
		flag, script = "-lc", loginshell.Prefix(argvScript)
	}
	return append([]string{shell, flag, script, "sh"}, argv...)
}

// argvSearchPath is the PATH a program named in argv is looked up on when
// there is no shell: the one the request sets, else the image's
// (AEROLVM_IMAGE_PATH, which the runtime or toolboxd's start records), else
// the child's PATH. Never toolboxd's own, which exec.Command would use and
// which on a Firecracker guest is init's, not the image's.
func argvSearchPath(env []string, reqEnv map[string]string) string {
	if p := reqEnv["PATH"]; p != "" {
		return p
	}
	if p := lastEnv(env, loginshell.Env); p != "" {
		return p
	}
	return lastEnv(env, "PATH")
}

// lastEnv is key's value in env as a child would see it: the last entry
// wins, as exec.Cmd dedupes it.
func lastEnv(env []string, key string) string {
	value := ""
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			value = v
		}
	}
	return value
}

// resolveArgvProgram finds the program argv[0] names, the way a shell
// does, for a sandbox with no shell: a name with a slash is used as given
// (relative to workdir), otherwise the first executable regular file in a
// PATH directory. Empty and relative PATH entries are skipped, as Go's
// exec.LookPath refuses them, so the working folder is never searched. When
// it cannot run, code and stderr are a shell's answer: 127 and "not found",
// or 126 for a file that is not executable.
func resolveArgvProgram(name, pathList, workdir string) (path string, code int, stderr string) {
	if strings.Contains(name, "/") {
		at := name
		if !filepath.IsAbs(name) && workdir != "" {
			at = filepath.Join(workdir, name)
		}
		info, err := os.Stat(at)
		switch {
		case err != nil:
			return "", 127, name + ": not found\n"
		case info.IsDir():
			return "", 126, name + ": is a directory\n"
		case info.Mode()&0o111 == 0:
			return "", 126, name + ": permission denied\n"
		}
		return name, 0, ""
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, 0, ""
		}
	}
	return "", 127, name + ": not found\n"
}

// argvStartFailure turns a failed direct start into a shell's answer: 127
// and "not found" for a missing file (or a script whose interpreter is
// missing), 126 for one that cannot run. ok is false when the cause is the
// working folder, which keeps its own error, as for a command string.
func argvStartFailure(name, workdir string, err error) (code int, stderr string, ok bool) {
	if workdir != "" {
		if info, statErr := os.Stat(workdir); statErr != nil || !info.IsDir() {
			return 0, "", false
		}
	}
	if errors.Is(err, fs.ErrNotExist) {
		return 127, name + ": not found\n", true
	}
	reason := err.Error()
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		reason = pathErr.Err.Error()
	}
	return 126, name + ": " + reason + "\n", true
}
