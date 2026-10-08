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
