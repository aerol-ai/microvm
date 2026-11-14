package images

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// instruction is one Dockerfile instruction with its continuation lines
// joined, so a check sees "RUN a && b" as one RUN.
type instruction struct {
	keyword string
	args    string
}

func parseDockerfile(t *testing.T, path string) []instruction {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []instruction
	var cur strings.Builder
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if cur.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		full := strings.TrimSpace(cur.String())
		cur.Reset()
		keyword, args, _ := strings.Cut(full, " ")
		out = append(out, instruction{keyword: strings.ToUpper(keyword), args: strings.TrimSpace(args)})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// pinnedImage accepts a tag with at least major.minor plus a digest. The
// digest is the pin: a registry can point any tag at a new image, and
// OpenSSF Scorecard's Pinned-Dependencies check flags a tag alone. The
// versioned tag says which release the digest is, and Dependabot needs it
// to move both together. A tag like "python:3" moves with every minor
// release, so it does not say which release the digest is.
var pinnedImage = regexp.MustCompile(`^[^:@\s]+:[^@\s]*\d+\.\d+[^@\s]*@sha256:[0-9a-f]{64}$`)

// unhashedPipInstall returns the first pip install in a RUN line that
// Scorecard would call unpinned. Scorecard reads the arguments after
// "install" in order and stops at --require-hashes, so that flag must come
// before the first argument that is not a flag (a package, or the file
// after -r). A later --require-hashes still makes pip check hashes, but
// Scorecard has already counted the package as unpinned.
func unhashedPipInstall(run string) (string, bool) {
	fields := strings.Fields(run)
	for i := 0; i+1 < len(fields); i++ {
		if base := filepath.Base(fields[i]); (base != "pip" && base != "pip3") || fields[i+1] != "install" {
			continue
		}
		cmd := fields[i : i+2]
		pinned := false
		for _, arg := range fields[i+2:] {
			if arg == "&&" || arg == "||" || arg == "|" || arg == ";" {
				break
			}
			cmd = append(cmd, arg)
			if arg == "--require-hashes" {
				pinned = true
				break
			}
			if !strings.HasPrefix(arg, "-") {
				break
			}
		}
		if !pinned {
			return strings.Join(cmd, " "), true
		}
	}
	return "", false
}

// TestImagesBuildFromTheDockerfileAlone holds every ready-made image to
// what its docs promise: the SDK image builder sends only the Dockerfile,
// so nothing may come from a build context (COPY or ADD); the base image
// is pinned by digest, and every pip install by hash; the image ends as a
// numeric non-root user, which a create policy's require_non_root
// accepts; and it says what to run.
func TestImagesBuildFromTheDockerfileAlone(t *testing.T) {
	dockerfiles, err := filepath.Glob(filepath.Join("*", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dockerfiles) == 0 {
		t.Fatal("no images/*/Dockerfile found")
	}
	for _, path := range dockerfiles {
		t.Run(filepath.Dir(path), func(t *testing.T) {
			var from, user string
			starts := false
			for _, in := range parseDockerfile(t, path) {
				switch in.keyword {
				case "COPY", "ADD":
					t.Errorf("%s %s: the SDK image builder sends no build context", in.keyword, in.args)
				case "FROM":
					from = strings.Fields(in.args)[0]
				case "RUN":
					if cmd, bad := unhashedPipInstall(in.args); bad {
						t.Errorf("RUN %s: pip install needs --require-hashes before its first package or -r file", cmd)
					}
				case "USER":
					user = in.args
				case "ENTRYPOINT", "CMD":
					starts = true
				}
			}
			if !pinnedImage.MatchString(from) {
				t.Errorf("FROM %q is not a versioned tag pinned by digest (name:1.2@sha256:...)", from)
			}
			uid, err := strconv.Atoi(strings.SplitN(user, ":", 2)[0])
			if err != nil || uid == 0 {
				t.Errorf("last USER %q is not a numeric non-root user", user)
			}
			if !starts {
				t.Error("no ENTRYPOINT or CMD: a sandbox from the image would start nothing")
			}
		})
	}
}

func TestParseDockerfileJoinsContinuations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	content := "# comment\nFROM debian:12.7\n\nRUN a \\\n  && b\nUSER 1000\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := parseDockerfile(t, path)
	want := []instruction{{"FROM", "debian:12.7"}, {"RUN", "a    && b"}, {"USER", "1000"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("instruction %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestPinnedImage(t *testing.T) {
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		ref  string
		want bool
	}{
		{"python:3.12.16-slim-bookworm" + digest, true},
		{"codercom/code-server:4.105.1" + digest, true},
		{"ubuntu:24.04" + digest, true},
		// A tag alone is not a pin: the registry can move it.
		{"python:3.12.16-slim-bookworm", false},
		{"ubuntu:24.04", false},
		// A digest with no versioned tag does not say which release it is.
		{"debian" + digest, false},
		{"python:3" + digest, false},
		{"node:22-bookworm" + digest, false},
		{"python:latest" + digest, false},
		{"python:3.12" + "@sha256:" + strings.Repeat("a", 63), false},
		{"python:latest", false},
		{"ubuntu", false},
	} {
		if got := pinnedImage.MatchString(tc.ref); got != tc.want {
			t.Errorf("pinnedImage(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestUnhashedPipInstall(t *testing.T) {
	for _, tc := range []struct {
		run     string
		wantCmd string
		bad     bool
	}{
		{run: "pip install --require-hashes -r /tmp/r.txt", bad: false},
		{run: "printf x > /tmp/r.txt && pip install --require-hashes --only-binary=:all: -r /tmp/r.txt && rm /tmp/r.txt", bad: false},
		{run: "python -m pip install --require-hashes -r r.txt", bad: false},
		{run: "apt-get update && apt-get install -y curl", bad: false},
		{run: "pip --version", bad: false},
		{run: "pip install playwright==1.64.1", wantCmd: "pip install playwright==1.64.1", bad: true},
		{run: "/usr/local/bin/pip3 install -q requests", wantCmd: "/usr/local/bin/pip3 install -q requests", bad: true},
		// Scorecard counts the -r file before it reaches the flag.
		{run: "pip install -r r.txt --require-hashes", wantCmd: "pip install -r r.txt", bad: true},
		{run: "pip install --upgrade && echo done", wantCmd: "pip install --upgrade", bad: true},
		// The second install is checked on its own.
		{run: "pip install --require-hashes -r a.txt && pip install b", wantCmd: "pip install b", bad: true},
	} {
		cmd, bad := unhashedPipInstall(tc.run)
		if bad != tc.bad || cmd != tc.wantCmd {
			t.Errorf("unhashedPipInstall(%q) = (%q, %v), want (%q, %v)", tc.run, cmd, bad, tc.wantCmd, tc.bad)
		}
	}
}
