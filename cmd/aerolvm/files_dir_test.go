package main

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// tarStream builds what `tar -cf - .` prints: entries under "./". A body
// starting with "->" is a symlink to the rest; "" with a trailing-slash
// name is a folder; a name starting with "!" is a hard link.
func tarStream(t *testing.T, pairs ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755})
	for i := 0; i+1 < len(pairs); i += 2 {
		name, body := pairs[i], pairs[i+1]
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}
		switch {
		case strings.HasSuffix(name, "/"):
			hdr = &tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}
		case strings.HasPrefix(body, "->"):
			hdr = &tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: body[2:]}
		case strings.HasPrefix(name, "!"):
			hdr = &tar.Header{Name: name[1:], Typeflag: tar.TypeLink, Linkname: body}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			_, _ = tw.Write([]byte(body))
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

// scriptTar makes the fake sandbox answer the cp -r download command with
// archive on stdout, then exit with code (and stderr).
func scriptTar(h *harness, archive []byte, code int, stderr string) {
	h.fake.ExecFunc = func(cmd string, _ io.Reader, out func(byte, []byte), _ <-chan struct{}) (int, string) {
		if !strings.Contains(cmd, "tar -C") {
			return 1, ""
		}
		for rest := archive; len(rest) > 0; {
			n := min(len(rest), 1000)
			out(1, rest[:n])
			rest = rest[n:]
		}
		if stderr != "" {
			out(2, []byte(stderr))
		}
		return code, ""
	}
}

func TestCpRecursiveUpload(t *testing.T) {
	h := newHarness(t)
	box := h.fake.AddSandbox(models.Sandbox{Name: "box"})
	local := filepath.Join(t.TempDir(), "project")
	for name, body := range map[string]string{"main.go": "package main", "pkg/util.go": "package pkg"} {
		path := filepath.Join(local, name)
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A trailing slash puts the folder inside the destination, as cp -r.
	if code := h.run("cp", "-r", local, "box:/work/"); code != 0 {
		t.Fatalf("cp -r up = %d %s", code, h.stderr.String())
	}
	if got, _ := h.fake.File(box.ID, "/work/project/pkg/util.go"); string(got) != "package pkg" {
		t.Fatalf("uploaded %q", got)
	}
	if code := h.run("cp", "--recursive", local, "box:/srv/app", "--json"); code != 0 || !strings.Contains(h.stdout.String(), `"recursive": true`) {
		t.Fatalf("cp --recursive = %d %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if got, _ := h.fake.File(box.ID, "/srv/app/main.go"); string(got) != "package main" {
		t.Fatalf("uploaded %q", got)
	}

	file := filepath.Join(local, "main.go")
	if code := h.run("cp", "-r", file, "box:/x"); code != exitError || !strings.Contains(h.stderr.String(), "drop -r") {
		t.Fatalf("cp -r of a file = %d %s", code, h.stderr.String())
	}
	if code := h.run("cp", "-r", filepath.Join(local, "missing"), "box:/x"); code != exitError {
		t.Fatalf("cp -r of a missing folder = %d", code)
	}
	if code := h.run("cp", "-r", local, "box:"); code != exitUsage {
		t.Fatalf("cp -r with no destination = %d", code)
	}
	for _, args := range [][]string{{"cp", "-r", "-", "box:/x"}, {"cp", "-r", "box:/x", "-"}} {
		if code := h.run(args...); code != exitUsage {
			t.Fatalf("%v = %d, want usage", args, code)
		}
	}
	// An agent that cannot unpack an archive is refused before sending.
	h.fake.ToolboxFeatures = []string{}
	if code := h.run("cp", "-r", local, "box:/old"); code != exitError || !strings.Contains(h.stderr.String(), "files.extract") {
		t.Fatalf("cp -r to an older agent = %d %s", code, h.stderr.String())
	}
}

func TestCpRecursiveDownload(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	scriptTar(h, tarStream(t, "./src/", "", "./src/a.txt", "alpha", "./link", "->src/a.txt"), 0, "")

	parent := t.TempDir()
	// Into an existing folder: the remote folder's name is kept.
	if code := h.run("cp", "-r", "box:/work/out", parent, "--json"); code != 0 {
		t.Fatalf("cp -r down = %d %s", code, h.stderr.String())
	}
	if got, err := os.ReadFile(filepath.Join(parent, "out", "src", "a.txt")); err != nil || string(got) != "alpha" {
		t.Fatalf("downloaded %q, %v", got, err)
	}
	if !strings.Contains(h.stdout.String(), `"entries": 3`) {
		t.Fatalf("report = %s", h.stdout.String())
	}
	if cmd := h.fake.ExecCommands[len(h.fake.ExecCommands)-1]; !strings.Contains(cmd, "tar -C /work/out -cf - .") {
		t.Fatalf("command = %q", cmd)
	}
	// To a new name: that is the folder.
	fresh := filepath.Join(parent, "fresh")
	if code := h.run("cp", "-r", "box:/work/out", fresh); code != 0 {
		t.Fatalf("cp -r to a new folder = %d %s", code, h.stderr.String())
	}
	if target, err := os.Readlink(filepath.Join(fresh, "link")); err != nil || target != "src/a.txt" {
		t.Fatalf("symlink = %q, %v", target, err)
	}
	if code := h.run("cp", "-r", "box:/work/out", filepath.Join(parent, "no", "such", "parent")); code != exitError {
		t.Fatalf("cp -r under a missing parent = %d", code)
	}
}

// CEO review R9: the archive comes from an untrusted sandbox and lands on
// this machine. Each hostile one is refused with nothing written outside
// the target folder; the entries before the refused one are kept.
func TestCpRecursiveDownloadRefusesHostileArchives(t *testing.T) {
	cases := map[string][]byte{}
	h := newHarness(t)
	cases["dot-dot"] = tarStream(t, "./ok.txt", "1", "./../victim", "pwned")
	cases["absolute"] = tarStream(t, "/tmp/victim", "pwned")
	cases["symlink out"] = tarStream(t, "./up", "->../outside")
	cases["two-step chain"] = tarStream(t, "./d/", "", "./d/l1", "->..", "./d/l1/l2", "->../outside", "./d/l1/l2/victim", "pwned")
	cases["hard link"] = tarStream(t, "./a", "x", "!./b", "./a")
	for name, archive := range cases {
		t.Run(name, func(t *testing.T) {
			h.fake.AddSandbox(models.Sandbox{Name: "box-" + strings.ReplaceAll(name, " ", "-")})
			scriptTar(h, archive, 0, "")
			base := t.TempDir()
			outside := filepath.Join(base, "outside")
			if err := os.Mkdir(outside, 0o755); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(base, "dest")
			code := h.run("cp", "-r", "box-"+strings.ReplaceAll(name, " ", "-")+":/work", dest)
			if code != exitError || !strings.Contains(h.stderr.String(), "refused the archive") {
				t.Fatalf("hostile archive = %d %s", code, h.stderr.String())
			}
			if entries, _ := os.ReadDir(outside); len(entries) != 0 {
				t.Fatalf("written outside the target: %v", entries)
			}
			if entries, _ := os.ReadDir(base); len(entries) != 2 {
				t.Fatalf("written next to the target: %v", entries)
			}
			if name == "dot-dot" {
				if got, _ := os.ReadFile(filepath.Join(dest, "ok.txt")); string(got) != "1" {
					t.Fatal("the entry before the refused one was not kept")
				}
			}
		})
	}
	if _, err := os.Stat("/tmp/victim"); err == nil {
		t.Fatal("an absolute entry was written")
	}
}

func TestCpRecursiveDownloadFailures(t *testing.T) {
	h := newHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	h.fake.AddSandbox(models.Sandbox{Name: "wasm-box", Runtime: models.RuntimeWasm})
	h.fake.AddSandbox(models.Sandbox{Name: "iso", Runtime: models.RuntimeIsolate})
	out := filepath.Join(t.TempDir(), "out")

	scriptTar(h, nil, 127, "aerolvm: no tar in this sandbox image\n")
	if code := h.run("cp", "-r", "box:/work", out); code != exitError || !strings.Contains(h.stderr.String(), "has no tar") {
		t.Fatalf("no tar = %d %s", code, h.stderr.String())
	}
	scriptTar(h, nil, 2, "tar: /work: Cannot open: No such file or directory\n")
	if code := h.run("cp", "-r", "box:/work", out); code != exitError || !strings.Contains(h.stderr.String(), "Cannot open") {
		t.Fatalf("tar failure = %d %s", code, h.stderr.String())
	}
	scriptTar(h, nil, 2, "")
	if code := h.run("cp", "-r", "box:/work", out); code != exitError || !strings.Contains(h.stderr.String(), "code 2") {
		t.Fatalf("silent tar failure = %d %s", code, h.stderr.String())
	}
	h.fake.ExecFunc = func(string, io.Reader, func(byte, []byte), <-chan struct{}) (int, string) {
		return 0, agenttoolstest.DropStream
	}
	if code := h.run("cp", "-r", "box:/work", out); code != exitError {
		t.Fatalf("dropped stream = %d", code)
	}
	// Each runtime without tar is refused with a reason that names it.
	for ref, reason := range map[string]string{"wasm-box": "WASM sandbox has no tar", "iso": "isolate"} {
		if code := h.run("cp", "-r", ref+":/work", out); code != exitError || !strings.Contains(h.stderr.String(), reason) {
			t.Fatalf("cp -r down from %s = %d %s", ref, code, h.stderr.String())
		}
		if code := h.run("cp", "-r", t.TempDir(), ref+":/work"); code != exitError || !strings.Contains(h.stderr.String(), reason) {
			t.Fatalf("cp -r up to %s = %d %s", ref, code, h.stderr.String())
		}
	}
	if code := h.run("cp", "-r", "box:", out); code != exitUsage {
		t.Fatalf("empty remote = %d", code)
	}
	if code := h.run("cp", "-r", "missing:/work", out); code != exitError {
		t.Fatalf("missing sandbox = %d", code)
	}
	h.fake.ExecStartError = "exec: tar: not found"
	if code := h.run("cp", "-r", "box:/work", out); code != exitError {
		t.Fatalf("exec start error = %d", code)
	}
}

// The CLI's sandbox lookup already turns an isolate away; the check is kept
// for any caller that reaches cp -r with one.
func TestRequireTarSandbox(t *testing.T) {
	for runtime, want := range map[string]string{models.RuntimeIsolate: "V8 isolate", models.RuntimeWasm: "WASM", "docker": ""} {
		err := requireTarSandbox(&microvm.Sandbox{Sandbox: models.Sandbox{Runtime: runtime}})
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Fatalf("%s: %v", runtime, err)
		}
	}
}
