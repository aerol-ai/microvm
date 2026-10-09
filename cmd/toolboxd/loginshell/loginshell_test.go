package loginshell

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// runSh runs script under /bin/sh with env and returns its trimmed stdout.
func runSh(t *testing.T, script string, env ...string) string {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sh -c %q: %v\n%s", script, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestRestoreAfterAProfileReset: what /etc/profile does on Alpine and
// Debian (a fixed PATH) is undone, the profile's own entries are kept
// after the image's, a PATH already led by the image's is left alone, and
// without the variable nothing changes.
func TestRestoreAfterAProfileReset(t *testing.T) {
	const image = "/go/bin:/usr/local/go/bin:/usr/bin:/bin"
	const reset = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	cases := []struct {
		name, script, env, want string
	}{
		{"profile reset", reset + "\n" + Restore + "\necho \"$PATH\"", Env + "=" + image,
			image + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		{"no reset", "PATH=" + image + ":/opt/extra\n" + Restore + "\necho \"$PATH\"", Env + "=" + image,
			image + ":/opt/extra"},
		{"unset", reset + "\n" + Restore + "\necho \"$PATH\"", "",
			"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		{"exported", reset + "\n" + Restore + "\nsh -c 'echo \"$PATH\"'", Env + "=" + image,
			image + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
		// A directory that only shares a prefix with the image's first entry
		// is not "already there": /usr must not count as /usr/bin.
		{"prefix is not a whole entry", "PATH=/usr/bin:/bin\n" + Restore + "\necho \"$PATH\"", Env + "=/usr",
			"/usr:/usr/bin:/bin"},
		{"image path in the middle", "PATH=/usr/bin:" + image + ":/bin\n" + Restore + "\necho \"$PATH\"", Env + "=" + image,
			image + ":/usr/bin:" + image + ":/bin"},
		{"already exact", "PATH=" + image + "\n" + Restore + "\necho \"$PATH\"", Env + "=" + image, image},
		// An empty value is the same as unset: ${AEROLVM_IMAGE_PATH:-} drops it.
		{"empty value", reset + "\n" + Restore + "\necho \"$PATH\"", Env + "=",
			"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var env []string
			if c.env != "" {
				env = append(env, c.env)
			}
			if got := runSh(t, c.script, env...); got != c.want {
				t.Fatalf("PATH = %q, want %q", got, c.want)
			}
		})
	}
}

// TestPrefixKeepsTheCommand: the restore is its own line, so the command's
// exit status and output are its own.
func TestPrefixKeepsTheCommand(t *testing.T) {
	if got := runSh(t, Prefix("echo ok; exit 0"), Env+"=/x"); got != "ok" {
		t.Fatalf("output = %q", got)
	}
	cmd := exec.Command("/bin/sh", "-c", Prefix("exit 7"))
	cmd.Env = []string{Env + "=/x"}
	if err := cmd.Run(); err == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatalf("exit = %v, want 7", err)
	}
}

func TestArgv(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		rewrite int // index whose command gets the prefix, -1 for none
		noCmd   bool
	}{
		{"e2b bash -l -c", []string{"/bin/bash", "-l", "-c", "go version"}, 3, false},
		{"combined -lc", []string{"/bin/sh", "-lc", "go version"}, 2, false},
		{"--login -c", []string{"bash", "--login", "-c", "go version"}, 3, false},
		{"-c before -l", []string{"/bin/bash", "-c", "-l", "go version"}, 3, false},
		{"-o takes an argument", []string{"/bin/bash", "-o", "pipefail", "-lc", "go version"}, 4, false},
		{"-- ends options", []string{"/bin/sh", "-lc", "--", "go version"}, 3, false},
		{"not a login shell", []string{"/bin/sh", "-c", "go version"}, -1, false},
		{"login, no command", []string{"/bin/bash", "-l"}, -1, true},
		{"--login, no command", []string{"/bin/sh", "--login"}, -1, true},
		{"not a shell", []string{"/usr/bin/env", "-l", "-c", "x"}, -1, false},
		{"empty", nil, -1, false},
		{"-c with no command", []string{"/bin/sh", "-lc"}, -1, false},
		// Long options other than --login take no argument and do not end parsing.
		{"--noprofile is ignored", []string{"/bin/bash", "--noprofile", "-lc", "go version"}, 3, false},
		{"--norc then --login", []string{"/bin/zsh", "--norc", "--login", "-c", "go version"}, 4, false},
		// +o and -O both consume the next argument; a leading + does not set login.
		{"+o consumes the next argument", []string{"/bin/bash", "+o", "histexpand", "-lc", "go version"}, 4, false},
		{"-O consumes the next argument", []string{"/bin/bash", "-O", "extglob", "-lc", "go version"}, 4, false},
		{"-lo consumes the next argument", []string{"/bin/bash", "-lo", "pipefail", "-c", "go version"}, 4, false},
		{"-c then -- with nothing after", []string{"/bin/sh", "-c", "--"}, -1, false},
		{"login then --", []string{"/bin/sh", "-l", "--"}, -1, true},
		// -- stops option parsing, so a command that itself starts with a dash is kept.
		{"command after -- may start with a dash", []string{"/bin/sh", "-lc", "--", "-n"}, 3, false},
		// A script operand is not -c's command string. Parsing stops, and the
		// shell is still treated as one that reads stdin (no -c was given).
		{"script operand ends option parsing", []string{"/bin/bash", "-l", "script.sh"}, -1, true},
		{"+l is not a login shell", []string{"/bin/sh", "+l"}, -1, false},
		{"a lone dash is stdin, not an option", []string{"/bin/sh", "-l", "-"}, -1, true},
		{"ash", []string{"/bin/ash", "-lc", "go version"}, 2, false},
		{"dash", []string{"dash", "--login", "-c", "go version"}, 3, false},
		{"ksh", []string{"/usr/bin/ksh", "-lc", "go version"}, 2, false},
		{"mksh", []string{"mksh", "-ilc", "go version"}, 2, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Argv(c.argv)
			for i := range c.argv {
				want := c.argv[i]
				if i == c.rewrite {
					want = Prefix(c.argv[i])
				}
				if got[i] != want {
					t.Fatalf("argv[%d] = %q, want %q", i, got[i], want)
				}
			}
			if c.rewrite >= 0 && slices.Equal(got, c.argv) {
				t.Fatal("argv was rewritten in place")
			}
			if LoginWithoutCommand(c.argv) != c.noCmd {
				t.Fatalf("LoginWithoutCommand = %v, want %v", !c.noCmd, c.noCmd)
			}
		})
	}
}

func TestEnvFor(t *testing.T) {
	if got := EnvFor(map[string]string{"PATH": "/req/bin:/bin", "X": "1"}); !slices.Equal(got, []string{Env + "=/req/bin:/bin"}) {
		t.Fatalf("EnvFor = %v", got)
	}
	if got := EnvFor(map[string]string{"X": "1"}); got != nil {
		t.Fatalf("EnvFor without PATH = %v", got)
	}
	if got := EnvFor(map[string]string{"PATH": ""}); got != nil {
		t.Fatalf("EnvFor with an empty PATH = %v", got)
	}
}

func TestRecord(t *testing.T) {
	t.Setenv("PATH", "/image/bin:/bin")
	t.Setenv(Env, "")
	os.Unsetenv(Env)
	Record()
	if got := os.Getenv(Env); got != "/image/bin:/bin" {
		t.Fatalf("recorded %q", got)
	}
	// A value the runtime set is kept.
	t.Setenv(Env, "/runtime/bin")
	Record()
	if got := os.Getenv(Env); got != "/runtime/bin" {
		t.Fatalf("kept %q", got)
	}

	// An empty PATH is not a search path to put back.
	t.Setenv(Env, "")
	os.Unsetenv(Env)
	t.Setenv("PATH", "")
	Record()
	if _, ok := os.LookupEnv(Env); ok {
		t.Fatal("empty PATH was recorded")
	}
}

// TestInstallProfileHook: written once (idempotent), restores the PATH when
// a login shell sources it after a reset, skips a system without
// profile.d, and reports an unwritable one.
func TestInstallProfileHook(t *testing.T) {
	dir := t.TempDir()
	for range 2 {
		ok, err := InstallProfileHook(dir)
		if err != nil || !ok {
			t.Fatalf("install: %v %v", ok, err)
		}
	}
	hook := filepath.Join(dir, profileHookName)
	info, err := os.Stat(hook)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("hook: %v %v", info, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
	got := runSh(t, "PATH=/usr/bin:/bin\n. "+hook+"\necho \"$PATH\"", Env+"=/image/bin")
	if got != "/image/bin:/usr/bin:/bin" {
		t.Fatalf("PATH after the hook = %q", got)
	}

	if ok, err := InstallProfileHook(filepath.Join(dir, "missing")); ok || err != nil {
		t.Fatalf("missing dir: %v %v", ok, err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, err := InstallProfileHook(file); ok || err != nil {
		t.Fatalf("not a dir: %v %v", ok, err)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o555); err != nil {
			t.Fatal(err)
		}
		if ok, err := InstallProfileHook(ro); ok || err == nil {
			t.Fatalf("unwritable dir: %v %v", ok, err)
		}
	}
}

// TestInstallProfileHookRewritesAStaleFile: a hook left by an older
// toolboxd (different bytes) is replaced, so terminals pick up the current
// restore. The matching-bytes path is the one TestInstallProfileHook covers.
func TestInstallProfileHookRewritesAStaleFile(t *testing.T) {
	dir := t.TempDir()
	hook := filepath.Join(dir, profileHookName)
	if err := os.WriteFile(hook, []byte("echo stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, err := InstallProfileHook(dir)
	if err != nil || !ok {
		t.Fatalf("rewrite: %v %v", ok, err)
	}
	got, err := os.ReadFile(hook)
	if err != nil || string(got) != profileHook {
		t.Fatalf("hook = %q, %v", got, err)
	}
}

// TestInstallProfileHookRenameOntoADirectory: the destination is not a
// file we can replace (a directory where the hook name should be). Rename
// fails and the error is returned, rather than reported as installed.
func TestInstallProfileHookRenameOntoADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, profileHookName), 0o755); err != nil {
		t.Fatal(err)
	}
	ok, err := InstallProfileHook(dir)
	if ok || err == nil {
		t.Fatalf("rename onto a directory: %v %v", ok, err)
	}
}

// failProfile is a temp file that fails one step. A real *os.File does not
// fail write, chmod, or close, so those returns stay dark without this.
type failProfile struct {
	name string
	fail string
}

func (f *failProfile) Name() string { return f.name }
func (f *failProfile) WriteString(string) (int, error) {
	if f.fail == "write" {
		return 0, os.ErrInvalid
	}
	return len(profileHook), nil
}
func (f *failProfile) Chmod(os.FileMode) error {
	if f.fail == "chmod" {
		return os.ErrInvalid
	}
	return nil
}
func (f *failProfile) Close() error {
	if f.fail == "close" {
		return os.ErrInvalid
	}
	return nil
}

func TestInstallProfileHookFileErrors(t *testing.T) {
	orig := createProfileFile
	t.Cleanup(func() { createProfileFile = orig })
	dir := t.TempDir()
	for _, step := range []string{"write", "chmod", "close"} {
		t.Run(step, func(t *testing.T) {
			createProfileFile = func(dir, pattern string) (profileFile, error) {
				return &failProfile{name: filepath.Join(dir, "tmp"), fail: step}, nil
			}
			ok, err := InstallProfileHook(dir)
			if ok || err == nil {
				t.Fatalf("%s: got ok=%v err=%v", step, ok, err)
			}
		})
	}
}
