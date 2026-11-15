package proc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/codeinterp"
	"github.com/aerol-ai/microvm/internal/codeinterp/drivers"
)

func TestLaunchErrors(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		lang    string
		cwd     func(t *testing.T) string
		ctx     func() (context.Context, context.CancelFunc)
		wantErr string
		is      error
	}{
		{name: "unsupported language", lang: "cobol", wantErr: "unsupported language", is: codeinterp.ErrUnsupportedLanguage},
		{name: "missing cwd", cwd: func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope") }, wantErr: "does not exist"},
		{name: "cwd is a file", cwd: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return f
		}, wantErr: "is not a directory"},
		{name: "fatal", mode: "fatal", wantErr: "failed to start: cannot set up"},
		{name: "exit with stderr", mode: "exit", wantErr: "exited before it was ready: driver broke: bad interpreter"},
		{name: "silent exit", mode: "silent-exit", wantErr: "exited before it was ready: exit status 7"},
		{name: "frame before ready", mode: "early", wantErr: "sent COUNT before READY"},
		{name: "context ends", mode: "hang", ctx: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 300*time.Millisecond)
		}, wantErr: "deadline exceeded", is: context.DeadlineExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useFakeDriver(t, tc.mode)
			lang := tc.lang
			if lang == "" {
				lang = codeinterp.LangPython
			}
			cwd := t.TempDir()
			if tc.cwd != nil {
				cwd = tc.cwd(t)
			}
			ctx, cancel := context.Background(), func() {}
			if tc.ctx != nil {
				ctx, cancel = tc.ctx()
			}
			defer cancel()
			k, err := New(Config{DriverDir: t.TempDir()}).Launch(ctx, codeinterp.Spec{Language: lang, Cwd: cwd})
			if err == nil {
				_ = k.Close()
				t.Fatalf("Launch succeeded, want %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("error = %v, want errors.Is %v", err, tc.is)
			}
		})
	}
}

func TestLaunchMissingInterpreter(t *testing.T) {
	d := fakeDriver(t, "")
	d.Programs = []string{"definitely-not-an-interpreter", "/nonexistent/also-not"}
	prev := lookupDriver
	lookupDriver = func(string) (drivers.Driver, bool) { return d, true }
	t.Cleanup(func() { lookupDriver = prev })

	l := New(Config{Env: func() []string { return []string{"PATH=" + t.TempDir()} }})
	_, err := l.Launch(context.Background(), codeinterp.Spec{Language: codeinterp.LangPython})
	var missing *codeinterp.MissingInterpreterError
	if !errors.As(err, &missing) {
		t.Fatalf("error = %v, want MissingInterpreterError", err)
	}
	if !strings.Contains(err.Error(), "definitely-not-an-interpreter") {
		t.Fatalf("error = %v, want it to name the programs", err)
	}
}

func TestLaunchStartFailure(t *testing.T) {
	useFakeDriver(t, "")
	l := New(Config{
		DriverDir: t.TempDir(),
		Start: func(cmd *exec.Cmd) (func() error, error) {
			return nil, errors.New("no more processes")
		},
	})
	_, err := l.Launch(context.Background(), codeinterp.Spec{Language: codeinterp.LangPython})
	if err == nil || !strings.Contains(err.Error(), "no more processes") {
		t.Fatalf("error = %v", err)
	}
}

func TestLaunchUsesStartFuncAndEnv(t *testing.T) {
	useFakeDriver(t, "env")
	started := 0
	cwd := t.TempDir()
	l := New(Config{
		DriverDir: t.TempDir(),
		Env:       func() []string { return append(os.Environ(), "MPLBACKEND=") },
		Start: func(cmd *exec.Cmd) (func() error, error) {
			started++
			if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid {
				t.Errorf("kernel not in its own process group")
			}
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			return cmd.Wait, nil
		},
	})
	spec := codeinterp.Spec{Language: codeinterp.LangPython, Cwd: cwd, Env: map[string]string{"CTX_VAR": "ctx"}}
	k, err := l.Launch(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if started != 1 {
		t.Fatalf("Start called %d times", started)
	}
	// The fake prints its env to stderr at once; an idle kernel keeps the
	// stderr tail.
	kk := k.(*kernel)
	var got string
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(got, "\n") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		kk.mu.Lock()
		got = string(kk.tail)
		kk.mu.Unlock()
	}
	real, _ := filepath.EvalSymlinks(cwd)
	for _, want := range []string{"mode=fd", "mpl= ", "unbuf=1", "ctx=ctx", "nonce=32"} {
		if !strings.Contains(got+" ", want) {
			t.Errorf("driver env %q lacks %q", got, want)
		}
	}
	if !strings.Contains(got, "cwd="+cwd) && !strings.Contains(got, "cwd="+real) {
		t.Errorf("driver env %q, want cwd %s", got, cwd)
	}
}

func TestKernelEnv(t *testing.T) {
	got := kernelEnv(
		[]string{"PATH=/bin", "HOME=/root", "MPLBACKEND=svg", "BROKEN", "=x", "A=base"},
		map[string]string{"A": "ctx", "Z": "z"},
		map[string]string{"A": "driver"},
		"n0nce",
	)
	want := []string{"PATH=/bin", "HOME=/root", "MPLBACKEND=svg", "A=driver", "Z=z",
		"AEROL_INTERP_MODE=fd", "AEROL_INTERP_NONCE=n0nce", "PYTHONUNBUFFERED=1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kernelEnv = %q, want %q", got, want)
	}
	if got := envValue(kernelEnv(nil, nil, nil, "n"), "MPLBACKEND"); got != "Agg" {
		t.Fatalf("MPLBACKEND default = %q, want Agg", got)
	}
}

func TestFindProgram(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "py3")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExe := filepath.Join(dir, "py2")
	if err := os.WriteFile(notExe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "pydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := drivers.Driver{Language: "python", Programs: []string{"pydir", "py2", "py3"}}
	if got, err := findProgram(d, "relative:"+dir); err != nil || got != exe {
		t.Fatalf("findProgram = %q, %v; want %q", got, err, exe)
	}
	d.Programs = []string{exe}
	if got, err := findProgram(d, ""); err != nil || got != exe {
		t.Fatalf("absolute program = %q, %v", got, err)
	}
	d.Programs = []string{notExe, "py3"}
	if _, err := findProgram(d, "relative"); err == nil {
		t.Fatal("found a program through a relative PATH entry")
	}
	// No PATH at all falls back to the shell's default search path.
	d.Programs = []string{"sh"}
	if got, err := findProgram(d, ""); err != nil || !filepath.IsAbs(got) {
		t.Fatalf("default PATH lookup = %q, %v", got, err)
	}
}

func TestDriverScriptWrittenOnce(t *testing.T) {
	root := filepath.Join(t.TempDir(), "drivers")
	l := New(Config{DriverDir: root})
	d := drivers.Driver{FileName: "x.py", Script: []byte("print(1)\n")}
	path, err := l.script(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, "-x.py") || filepath.Dir(path) != root {
		t.Fatalf("path = %s", path)
	}
	for p, want := range map[string]os.FileMode{root: 0o700, path: 0o600} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %v", p, info.Mode().Perm(), want)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != "print(1)\n" {
		t.Fatalf("content = %q", b)
	}
	again, err := l.script(d)
	if err != nil || again != path {
		t.Fatalf("second write = %s, %v", again, err)
	}
	// A /tmp cleaner removed it: written again.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if again, err = l.script(d); err != nil || again != path {
		t.Fatalf("rewrite = %s, %v", again, err)
	}
	// Other content, other name: an upgraded toolboxd never runs the old one.
	other, err := l.script(drivers.Driver{FileName: "x.py", Script: []byte("print(2)\n")})
	if err != nil || other == path {
		t.Fatalf("new content path = %s, %v", other, err)
	}

	// The default folder is a fresh private temp folder.
	tmp := New(Config{})
	p, err := tmp.script(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(p)) })
	if !strings.Contains(filepath.Base(filepath.Dir(p)), "aerolvm-codeinterp-") {
		t.Fatalf("default dir = %s", filepath.Dir(p))
	}

	// A folder that cannot be made is an error.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{DriverDir: filepath.Join(blocker, "sub")}).script(d); err == nil {
		t.Fatal("script in an impossible folder succeeded")
	}
}

func TestLanguages(t *testing.T) {
	if got := New(Config{}).Languages(); !reflect.DeepEqual(got, drivers.Languages()) || len(got) == 0 {
		t.Fatalf("Languages = %v", got)
	}
}
