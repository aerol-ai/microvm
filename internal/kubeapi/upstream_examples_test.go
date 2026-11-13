//go:build agentsandbox_examples

package kubeapi

// The golden-example gate (plan §16.1): every Sandbox, SandboxTemplate,
// SandboxWarmPool and SandboxClaim in the pinned upstream release's
// examples, answered the way this API answers it, must match
// testdata/upstream-examples.txt: accepted, or refused naming the fields.
// So a change to the field tables, or a new pin, shows exactly which
// upstream examples it lets in or shuts out. It fetches from GitHub, so it
// runs behind a tag, never in make test:
//
//	go test -tags agentsandbox_examples -run TestUpstreamExamples ./internal/kubeapi/
//	# after moving UpstreamRelease and UpstreamCommit:
//	go test -tags agentsandbox_examples -run TestUpstreamExamples ./internal/kubeapi/ -update
//
// The file holds paths, names and our verdicts only; no upstream content.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var updateExamples = flag.Bool("update", false, "rewrite testdata/upstream-examples.txt from the pinned release")

const examplesFile = "testdata/upstream-examples.txt"

var exampleClient = &http.Client{Timeout: 30 * time.Second}

func fetchUpstream(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := exampleClient.Get(url)
	if err != nil {
		t.Fatalf("fetch %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch %s: %d %v", url, resp.StatusCode, err)
	}
	return body
}

// examplePaths lists the release's example manifests (the tree, on -update)
// or the ones the expectations name.
func examplePaths(t *testing.T, want []string) []string {
	if !*updateExamples {
		seen := map[string]bool{}
		var out []string
		for _, line := range want {
			path, _, _ := strings.Cut(line, "#")
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
		return out
	}
	var tree struct {
		Tree []struct{ Path string } `json:"tree"`
	}
	raw := fetchUpstream(t, "https://api.github.com/repos/kubernetes-sigs/agent-sandbox/git/trees/"+UpstreamCommit+"?recursive=1")
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range tree.Tree {
		if strings.HasPrefix(e.Path, "examples/") && (strings.HasSuffix(e.Path, ".yaml") || strings.HasSuffix(e.Path, ".yml")) {
			out = append(out, e.Path)
		}
	}
	sort.Strings(out)
	return out
}

// jsonable turns yaml.v3's decoded document into what encoding/json takes.
func jsonable(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = jsonable(x)
		}
	case []any:
		for i, x := range t {
			t[i] = jsonable(x)
		}
	}
	return v
}

// exampleVerdict answers one document as the API would: "ok", or the
// fields refused.
func exampleVerdict(kind string, body []byte) string {
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	var err error
	switch kind {
	case SandboxKind:
		// A fixed clock, so a shutdownTime in an example reads the same
		// on every run.
		_, _, err = CreateFrom(body, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), func() string { return "x7k2p" })
	case SandboxTemplateKind:
		err = validateStored(SandboxTemplatesResource, doc)
	case SandboxWarmPoolKind:
		err = validateStored(SandboxWarmPoolsResource, doc)
	case SandboxClaimKind:
		var refused []string
		refusedFields(doc, claimTable, "", &refused)
		if len(refused) > 0 {
			err = &FieldError{Fields: refused}
		}
	}
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	if _, after, found := strings.Cut(msg, "not supported by AerolVM: "); found {
		msg = after
	}
	return strings.ReplaceAll(msg, "\n", " ")
}

func readExpectations(t *testing.T) (commit string, lines []string) {
	f, err := os.Open(examplesFile)
	if err != nil {
		if *updateExamples {
			return "", nil
		}
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if c, ok := strings.CutPrefix(line, "# commit "); ok {
			commit = strings.TrimSpace(c)
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return commit, lines
}

func TestUpstreamExamples(t *testing.T) {
	commit, want := readExpectations(t)
	if !*updateExamples && commit != UpstreamCommit {
		t.Fatalf("%s is for commit %s, but the pin is %s: rerun with -update", examplesFile, commit, UpstreamCommit)
	}
	var got []string
	accepted := 0
	for _, path := range examplePaths(t, want) {
		raw := fetchUpstream(t, "https://raw.githubusercontent.com/kubernetes-sigs/agent-sandbox/"+UpstreamCommit+"/"+path)
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		for i := 0; ; i++ {
			var doc map[string]any
			err := dec.Decode(&doc)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				got = append(got, fmt.Sprintf("%s#%d - - => not YAML", path, i))
				break
			}
			kind, _ := doc["kind"].(string)
			switch kind {
			case SandboxKind, SandboxTemplateKind, SandboxWarmPoolKind, SandboxClaimKind:
			default:
				continue
			}
			body, _ := json.Marshal(jsonable(doc))
			name := "-"
			if md, ok := doc["metadata"].(map[string]any); ok {
				if n, ok := md["name"].(string); ok && n != "" {
					name = n
				}
			}
			v := exampleVerdict(kind, body)
			if v == "ok" {
				accepted++
			}
			got = append(got, fmt.Sprintf("%s#%d %s %s => %s", path, i, kind, name, v))
		}
	}
	if *updateExamples {
		var b strings.Builder
		fmt.Fprintf(&b, "# agent-sandbox %s examples, as the AerolVM agent-sandbox API answers them.\n", UpstreamRelease)
		fmt.Fprintf(&b, "# commit %s\n", UpstreamCommit)
		fmt.Fprintf(&b, "# %d documents, %d accepted. Regenerate: see upstream_examples_test.go.\n", len(got), accepted)
		for _, line := range got {
			b.WriteString(line + "\n")
		}
		if err := os.WriteFile(examplesFile, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d documents, %d accepted", examplesFile, len(got), accepted)
		return
	}
	wantSet := map[string]bool{}
	for _, l := range want {
		wantSet[l] = true
	}
	gotSet := map[string]bool{}
	for _, l := range got {
		gotSet[l] = true
		if !wantSet[l] {
			t.Errorf("now:      %s", l)
		}
	}
	for _, l := range want {
		if !gotSet[l] {
			t.Errorf("expected: %s", l)
		}
	}
	t.Logf("%d documents, %d accepted", len(got), accepted)
}
