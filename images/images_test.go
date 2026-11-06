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

// versionedTag accepts a digest, or a tag with at least major.minor: a tag
// like "python:3" or "debian:12" moves with every minor release, so it is
// not a pin.
var versionedTag = regexp.MustCompile(`^[^:@\s]+(:[^\s]*\d+\.\d+[^\s]*|@sha256:[0-9a-f]{64})$`)

// TestImagesBuildFromTheDockerfileAlone holds every ready-made image to
// what its docs promise: the SDK image builder sends only the Dockerfile,
// so nothing may come from a build context (COPY or ADD); the base image
// is pinned to a versioned tag or a digest; the image ends as a numeric
// non-root user, which a create policy's require_non_root accepts; and it
// says what to run.
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
				case "USER":
					user = in.args
				case "ENTRYPOINT", "CMD":
					starts = true
				}
			}
			if !versionedTag.MatchString(from) {
				t.Errorf("FROM %q is not pinned to a versioned tag or a digest", from)
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
	for _, tc := range []struct {
		ref  string
		want bool
	}{
		{"python:3.12.16-slim-bookworm", true},
		{"codercom/code-server:4.105.1", true},
		{"debian@sha256:" + strings.Repeat("a", 64), true},
		{"python:latest", false},
		{"ubuntu", false},
		{"python:3", false},
		{"debian:12", false},
		{"node:22-bookworm", false},
		{"ubuntu:24.04", true},
	} {
		if got := versionedTag.MatchString(tc.ref); got != tc.want {
			t.Errorf("versionedTag(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}
