package runscwrap

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestArgs(t *testing.T) {
	spec := []byte(`{"annotations":{"` + RestoreAnnotation + `":"/var/lib/sandboxd/containerd/moves/in/sb-1"}}`)
	flags := []string{"--root=/run/containerd/runsc/aerolvm", "--log=/b/log.json", "--log-format=json", "--host-uds=open"}
	with := func(tail ...string) []string { return append(slices.Clone(flags), tail...) }
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	for _, tc := range []struct {
		name  string
		args  []string
		spec  []byte
		check func(string) bool
		want  []string
	}{
		{"start with a checkpoint restores", with("start", "sb-1"), spec, yes,
			with("restore", "--image-path=/var/lib/sandboxd/containerd/moves/in/sb-1", "--detach", "sb-1")},
		{"start after the checkpoint is gone starts", with("start", "sb-1"), spec, no, with("start", "sb-1")},
		{"start of a container without the annotation", with("start", "sb-1"), []byte(`{"annotations":{}}`), yes, with("start", "sb-1")},
		{"no spec", with("start", "sb-1"), nil, yes, with("start", "sb-1")},
		{"a spec that is not JSON", with("start", "sb-1"), []byte("{"), yes, with("start", "sb-1")},
		{"a relative directory is refused", with("start", "sb-1"),
			[]byte(`{"annotations":{"` + RestoreAnnotation + `":"moves/in/sb-1"}}`), yes, with("start", "sb-1")},
		{"a directory with .. is refused", with("start", "sb-1"),
			[]byte(`{"annotations":{"` + RestoreAnnotation + `":"/var/lib/x/../../etc"}}`), yes, with("start", "sb-1")},
		{"create passes through", with("create", "--bundle", "/b", "sb-1"), spec, yes, with("create", "--bundle", "/b", "sb-1")},
		{"wait passes through", with("wait", "sb-1"), spec, yes, with("wait", "sb-1")},
		{"exec of a command named start passes through", with("exec", "--detach", "sb-1", "start", "x"), spec, yes,
			with("exec", "--detach", "sb-1", "start", "x")},
		{"a flag after start is not an id", with("start", "--x"), spec, yes, with("start", "--x")},
		{"too short", []string{"start"}, spec, yes, []string{"start"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Args(tc.args, tc.spec, tc.check); !slices.Equal(got, tc.want) {
				t.Fatalf("Args =\n %q\nwant\n %q", got, tc.want)
			}
		})
	}
}

func TestHasCheckpoint(t *testing.T) {
	dir := t.TempDir()
	if HasCheckpoint(dir) {
		t.Fatal("an empty directory holds a checkpoint")
	}
	if err := os.Mkdir(filepath.Join(dir, CheckpointFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if HasCheckpoint(dir) {
		t.Fatal("a directory named like the checkpoint counts")
	}
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, CheckpointFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !HasCheckpoint(other) {
		t.Fatal("a checkpoint was missed")
	}
}

// Main runs from the bundle (the shim's working directory) and replaces
// itself with the runsc beside it, with the rewritten arguments.
func TestMain_ExecsTheRunscBesideIt(t *testing.T) {
	bin := t.TempDir()
	runsc := filepath.Join(bin, "runsc")
	if err := os.WriteFile(runsc, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ckpt := t.TempDir()
	if err := os.WriteFile(filepath.Join(ckpt, CheckpointFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle := t.TempDir()
	spec := `{"annotations":{"` + RestoreAnnotation + `":"` + ckpt + `"}}`
	if err := os.WriteFile(filepath.Join(bundle, specFile), []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(bundle)
	var gotBin string
	var gotArgs []string
	execFn = func(b string, a []string, _ []string) error {
		gotBin, gotArgs = b, a
		return errors.New("stub")
	}
	t.Cleanup(func() { execFn = syscallExec })
	if code := Main([]string{filepath.Join(bin, CommandName), "--root=/r", "start", "sb-1"}); code != 126 {
		t.Fatalf("exit %d", code)
	}
	want := []string{runsc, "--root=/r", "restore", "--image-path=" + ckpt, "--detach", "sb-1"}
	if gotBin != runsc || !slices.Equal(gotArgs, want) {
		t.Fatalf("exec %s %q, want %s %q", gotBin, gotArgs, runsc, want)
	}
}

// Without a runsc beside it, the wrapper uses the one on PATH, and says so
// when there is none.
func TestMain_FindsRunscOnPath(t *testing.T) {
	t.Chdir(t.TempDir())
	var gotBin string
	execFn = func(b string, _ []string, _ []string) error { gotBin = b; return errors.New("stub") }
	lookPath = func(string) (string, error) { return "/usr/bin/runsc", nil }
	t.Cleanup(func() { execFn, lookPath = syscallExec, pathLookup })
	if Main([]string{CommandName, "state", "sb-1"}); gotBin != "/usr/bin/runsc" {
		t.Fatalf("exec %q", gotBin)
	}
	lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	if code := Main([]string{CommandName, "state", "sb-1"}); code != 127 {
		t.Fatalf("no runsc: exit %d", code)
	}
	if code := Main(nil); code != 2 {
		t.Fatalf("no argv: exit %d", code)
	}
}

var (
	syscallExec = execFn
	pathLookup  = lookPath
)
