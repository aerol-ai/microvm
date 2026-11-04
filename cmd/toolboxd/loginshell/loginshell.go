// Package loginshell keeps an image's PATH in the login shells toolboxd
// runs.
//
// Images put their tools on PATH with ENV (the golang image adds
// /usr/local/go/bin, rust /usr/local/cargo/bin), and toolboxd starts with
// that PATH. A login shell reads /etc/profile first, and on Alpine and
// Debian alike that file overwrites PATH with a fixed default, so the
// image's own directories vanish and `go` or `cargo` is "not found". Login
// shells stay, because some images set tools up through the profile
// (conda, nix, sdkman in /etc/profile.d); what changes is that the image's
// PATH is put back in front once the profile has run.
//
// toolboxd records the PATH it started with in Env, inherited by every
// child, and runs Restore after the profile: prefixed to every command it
// hands a login shell (Prefix, Argv), written first to a stdin-fed login
// session, and installed as an /etc/profile.d script (InstallProfileHook)
// for the interactive terminals no command reaches.
package loginshell

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

// Env names the variable holding the PATH login shells put back: the one
// toolboxd started with, or the one a request set.
const Env = "AEROLVM_IMAGE_PATH"

// Restore is POSIX shell that puts $AEROLVM_IMAGE_PATH back at the front of
// PATH unless it is already there, keeping whatever the profile added
// after it. It does nothing when the variable is unset, so it is harmless
// outside aerolvm.
const Restore = `if [ -n "${AEROLVM_IMAGE_PATH:-}" ]; then case ":${PATH}:" in ":${AEROLVM_IMAGE_PATH}:"*) ;; *) PATH="${AEROLVM_IMAGE_PATH}:${PATH}"; export PATH ;; esac; fi`

// ProfileDir is where login shells on Alpine and Debian source drop-in
// scripts, after /etc/profile has set PATH.
const ProfileDir = "/etc/profile.d"

// profileHookName sorts first, so later profile.d scripts still add their
// directories after the image's.
const profileHookName = "00-aerolvm-image-path.sh"

const profileHook = `# Written by aerolvm's toolboxd. /etc/profile resets PATH and drops the
# directories this image put on it (ENV PATH); put them back in front.
# Without AEROLVM_IMAGE_PATH (outside aerolvm) it does nothing.
` + Restore + "\n"

// Record notes the PATH toolboxd started with, for every child to inherit.
// A value already set (by the runtime) is kept.
func Record() {
	if os.Getenv(Env) != "" {
		return
	}
	if p := os.Getenv("PATH"); p != "" {
		_ = os.Setenv(Env, p)
	}
}

// EnvFor is the extra environment for a child started with a request's
// env: a PATH the request sets is the one its login shells keep.
func EnvFor(env map[string]string) []string {
	if p, ok := env["PATH"]; ok && p != "" {
		return []string{Env + "=" + p}
	}
	return nil
}

// Prefix returns a command for a login shell's -c that restores the PATH
// first. It is a separate line, so the command is unchanged.
func Prefix(command string) string {
	return Restore + "\n" + command
}

// Argv returns argv with the PATH restore prefixed to its command when argv
// runs a login shell with -c (an E2B command is /bin/bash -l -c ...).
// Anything else is returned unchanged.
func Argv(argv []string) []string {
	p := parse(argv)
	if !p.login || p.cmd < 0 {
		return argv
	}
	out := append([]string(nil), argv...)
	out[p.cmd] = Prefix(out[p.cmd])
	return out
}

// LoginWithoutCommand reports whether argv starts a login shell that reads
// its commands from stdin (or a terminal) rather than -c.
func LoginWithoutCommand(argv []string) bool {
	p := parse(argv)
	return p.login && !p.dashC
}

type parsed struct {
	login bool
	dashC bool
	cmd   int // index of -c's command string, or -1
}

var shells = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true}

// parse reads a shell's options the way sh and bash do: options until the
// first non-option argument, which is -c's command when -c was given. -o
// and +o take the next argument as an option name.
func parse(argv []string) parsed {
	p := parsed{cmd: -1}
	if len(argv) == 0 || !shells[filepath.Base(argv[0])] {
		return p
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			if p.dashC && i+1 < len(argv) {
				p.cmd = i + 1
			}
			return p
		case a == "--login":
			p.login = true
		case strings.HasPrefix(a, "--"):
			// Other long options (--norc, --noprofile) take no argument.
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			flags := a[1:]
			if a[0] == '-' {
				p.login = p.login || strings.ContainsRune(flags, 'l')
				p.dashC = p.dashC || strings.ContainsRune(flags, 'c')
			}
			if last := flags[len(flags)-1]; last == 'o' || last == 'O' {
				i++
			}
		default:
			if p.dashC {
				p.cmd = i
			}
			return p
		}
	}
	return p
}

// profileFile is the temp file the hook is written through. *os.File is
// what production uses. Tests substitute a file whose write, chmod, or
// close fails: a real temp file will not, and those are the failures a
// full disk or a read-only root produces. The caller logs them.
type profileFile interface {
	WriteString(string) (int, error)
	Chmod(os.FileMode) error
	Close() error
	Name() string
}

// createProfileFile is os.CreateTemp. Tests replace it to reach the error
// returns in InstallProfileHook.
var createProfileFile = func(dir, pattern string) (profileFile, error) {
	return os.CreateTemp(dir, pattern)
}

// InstallProfileHook writes the PATH restore as a profile.d script in dir,
// for the interactive login shells no command reaches (terminals). It
// reports whether the hook is in place. A missing dir means no profile
// sources drop-ins, and nothing is written; an unwritable one (a non-root
// image, a read-only root) is an error the caller logs.
func InstallProfileHook(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false, nil
	}
	path := filepath.Join(dir, profileHookName)
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, []byte(profileHook)) {
		return true, nil
	}
	tmp, err := createProfileFile(dir, "."+profileHookName+".*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(profileHook); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	return true, nil
}
