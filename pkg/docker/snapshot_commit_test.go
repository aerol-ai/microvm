package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	snapTestToken  = "tok-source-sandbox-0123456789"
	snapTestSecret = "sk-live-source-secret-9f8e7d"
	snapTestNonce  = "nonce-source-sandbox-42"
)

// snapshotDaemon fakes the Docker endpoints CreateSnapshot calls and records
// every request it makes, so a test can check both what was committed and
// that nothing it sent carries the source sandbox's credentials.
type snapshotDaemon struct {
	t *testing.T

	containerConfig map[string]any
	containerImage  string
	baseEnv         []string

	// fail maps a step to the HTTP status it answers with.
	fail map[string]int
	// emptyID makes a commit step answer with no image id.
	emptyID map[string]bool

	mu            sync.Mutex
	steps         []string
	commitQueries []url.Values
	commitBodies  []map[string]json.RawMessage
	helperName    string
	helperBody    map[string]any
	removed       []string
	sent          strings.Builder
}

func newSnapshotDaemon(t *testing.T) *snapshotDaemon {
	return &snapshotDaemon{
		t: t,
		containerConfig: map[string]any{
			"Hostname":   "sb-source",
			"Image":      "python:3.12",
			"Entrypoint": []string{"/opt/aerolvm/toolboxd"},
			"Cmd":        []string{"sleep", "infinity"},
			"WorkingDir": "/work",
			"Labels":     map[string]string{managedLabelKey: "true"},
			"Env": []string{
				"SB_SANDBOX_ID=sb-source",
				"SB_TOOLBOX_PORT=2280",
				"SB_TOOLBOX_TOKEN=" + snapTestToken,
				poolParkedEnv + "=",
				readySocketEnv + "=" + GuestReadySocketPath,
				readyNonceEnv + "=" + snapTestNonce,
				"OPENAI_API_KEY=" + snapTestSecret,
				"PATH=/custom/bin:/usr/bin",
				"LANG=C.UTF-8",
			},
		},
		containerImage: "sha256:base",
		baseEnv:        []string{"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"},
	}
}

func (d *snapshotDaemon) client() *Client {
	return &Client{httpClient: &http.Client{Transport: roundTripFunc(d.roundTrip)}}
}

func (d *snapshotDaemon) step(name string) (*http.Response, bool) {
	d.steps = append(d.steps, name)
	if status, ok := d.fail[name]; ok {
		return textResponse(status, name+" failed"), true
	}
	return nil, false
}

func (d *snapshotDaemon) roundTrip(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	d.sent.WriteString(r.URL.String())
	d.sent.Write(body)

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/containers/cid/json":
		if resp, failed := d.step("inspect-container"); failed {
			return resp, nil
		}
		return jsonResponse(http.StatusOK, map[string]any{"Id": "cid", "Image": d.containerImage, "Config": d.containerConfig}), nil
	case r.Method == http.MethodGet && r.URL.Path == "/images/"+d.containerImage+"/json":
		if resp, failed := d.step("inspect-image"); failed {
			return resp, nil
		}
		return jsonResponse(http.StatusOK, map[string]any{"Config": map[string]any{"Env": d.baseEnv}}), nil
	case r.Method == http.MethodPost && r.URL.Path == "/commit":
		name := "commit-source"
		id := "sha256:intermediate"
		if r.URL.Query().Get("container") != "cid" {
			name, id = "commit-helper", "sha256:final"
		}
		d.commitQueries = append(d.commitQueries, r.URL.Query())
		var config map[string]json.RawMessage
		if len(body) > 0 {
			if err := json.Unmarshal(body, &config); err != nil {
				d.t.Fatalf("%s body is not a config: %v", name, err)
			}
		}
		d.commitBodies = append(d.commitBodies, config)
		if resp, failed := d.step(name); failed {
			return resp, nil
		}
		if d.emptyID[name] {
			id = ""
		}
		return jsonResponse(http.StatusCreated, map[string]string{"Id": id}), nil
	case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
		d.helperName = r.URL.Query().Get("name")
		_ = json.Unmarshal(body, &d.helperBody)
		if resp, failed := d.step("create-helper"); failed {
			return resp, nil
		}
		return jsonResponse(http.StatusCreated, map[string]string{"Id": "helper-id"}), nil
	case r.Method == http.MethodDelete && d.helperName != "" && r.URL.Path == "/containers/"+d.helperName:
		if r.URL.Query().Get("force") != "1" {
			d.t.Fatalf("helper removed without force: %s", r.URL)
		}
		d.removed = append(d.removed, "container:helper")
		if resp, failed := d.step("remove-helper"); failed {
			return resp, nil
		}
		return textResponse(http.StatusNoContent, ""), nil
	case r.Method == http.MethodDelete && r.URL.Path == "/images/sha256:intermediate":
		d.removed = append(d.removed, "image:intermediate")
		if resp, failed := d.step("remove-intermediate"); failed {
			return resp, nil
		}
		return jsonResponse(http.StatusOK, []map[string]string{{"Deleted": "sha256:intermediate"}}), nil
	}
	d.t.Fatalf("unexpected docker call %s %s", r.Method, r.URL)
	return nil, nil
}

// requestsCarry reports whether anything CreateSnapshot sent to Docker (paths,
// queries, bodies) contains s. The inspect responses hold the secrets; the
// requests must not.
func (d *snapshotDaemon) requestsCarry(s string) bool {
	return strings.Contains(d.sent.String(), s)
}

func rawStrings(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func TestSnapshotEnv(t *testing.T) {
	tests := []struct {
		name      string
		container []string
		base      []string
		want      []string
	}{
		{
			name:      "the image's own variables are kept",
			container: []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"},
			base:      []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"},
			want:      []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"},
		},
		{
			name:      "a variable the create added is cleared",
			container: []string{"OPENAI_API_KEY=" + snapTestSecret, "PATH=/bin"},
			base:      []string{"PATH=/bin"},
			want:      []string{"OPENAI_API_KEY=", "PATH=/bin"},
		},
		{
			name:      "an image variable the create overrode goes back to the image's value",
			container: []string{"PATH=/custom/bin:/usr/bin", "HOME=/root"},
			base:      []string{"HOME=/root", "PATH=/usr/local/bin:/usr/bin"},
			want:      []string{"PATH=/usr/local/bin:/usr/bin", "HOME=/root"},
		},
		{
			name: "every driver variable is cleared",
			container: []string{
				"SB_TOOLBOX_TOKEN=" + snapTestToken, "SB_TOOLBOX_PORT=2280", "SB_SANDBOX_ID=sb-1",
				poolParkedEnv + "=1", readySocketEnv + "=" + GuestReadySocketPath, readyNonceEnv + "=" + snapTestNonce,
				gvisorpids.EnvVar + "=512",
			},
			want: []string{
				"SB_TOOLBOX_TOKEN=", "SB_TOOLBOX_PORT=", "SB_SANDBOX_ID=",
				poolParkedEnv + "=", readySocketEnv + "=", readyNonceEnv + "=",
				gvisorpids.EnvVar + "=",
			},
		},
		{
			// A snapshot taken before this change carries the old token in its
			// config; a snapshot of a sandbox made from it must not keep it.
			name:      "a driver variable is cleared even when the base image holds a value",
			container: []string{"SB_TOOLBOX_TOKEN=fresh-token"},
			base:      []string{"SB_TOOLBOX_TOKEN=" + snapTestToken},
			want:      []string{"SB_TOOLBOX_TOKEN="},
		},
		{
			name:      "a snapshot of a snapshot keeps the cleared keys cleared",
			container: []string{"SB_TOOLBOX_TOKEN=fresh-token", "OPENAI_API_KEY=", "PATH=/bin"},
			base:      []string{"SB_TOOLBOX_TOKEN=", "OPENAI_API_KEY=", "PATH=/bin"},
			want:      []string{"SB_TOOLBOX_TOKEN=", "OPENAI_API_KEY=", "PATH=/bin"},
		},
		{
			name:      "the first of a duplicated key wins, as in the env Docker hands the process",
			container: []string{"A=1", "A=2", "B=x"},
			base:      []string{"B=y", "B=z"},
			want:      []string{"A=", "B=y"},
		},
		{
			name:      "an entry with no value and one with an empty key",
			container: []string{"BARE", "=orphan", "KEEP="},
			base:      []string{"KEEP="},
			want:      []string{"BARE=", "KEEP="},
		},
		{
			name: "no env",
			want: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := snapshotEnv(tt.container, tt.base)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("snapshotEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCreateSnapshotCommitsWithoutTheSandboxsSecrets(t *testing.T) {
	d := newSnapshotDaemon(t)
	id, err := d.client().CreateSnapshot(context.Background(), " cid ", "aerolvm-snapshot/owner/py:v1")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if id != "sha256:final" {
		t.Fatalf("CreateSnapshot id = %q, want the tagged image's", id)
	}
	wantSteps := []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "commit-helper", "remove-helper", "remove-intermediate"}
	if !slices.Equal(d.steps, wantSteps) {
		t.Fatalf("docker calls = %v, want %v", d.steps, wantSteps)
	}

	// The source commit is untagged and carries a config whose env holds the
	// image's own variables and cleared keys for everything the create added.
	source := d.commitQueries[0]
	if source.Get("container") != "cid" || source.Has("repo") || source.Has("tag") || source.Has("changes") {
		t.Fatalf("source commit query = %v, want an untagged commit of cid", source)
	}
	config := d.commitBodies[0]
	wantEnv := []string{
		"SB_SANDBOX_ID=", "SB_TOOLBOX_PORT=", "SB_TOOLBOX_TOKEN=", poolParkedEnv + "=",
		readySocketEnv + "=", readyNonceEnv + "=", "OPENAI_API_KEY=",
		"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8",
	}
	if got := rawStrings(t, config["Env"]); !slices.Equal(got, wantEnv) {
		t.Fatalf("committed Env = %q, want %q", got, wantEnv)
	}
	// Everything else in the container's config goes back unchanged.
	for key, want := range map[string]string{
		"Cmd":        `["sleep","infinity"]`,
		"Entrypoint": `["/opt/aerolvm/toolboxd"]`,
		"WorkingDir": `"/work"`,
		"Labels":     `{"aerolvm.managed":"true"}`,
		"Hostname":   `"sb-source"`,
	} {
		if got := string(config[key]); got != want {
			t.Fatalf("committed %s = %s, want %s", key, got, want)
		}
	}

	// The helper is made from the intermediate, never started, and has no
	// network; the tagged commit is the helper's, with no config of its own.
	if !strings.HasPrefix(d.helperName, snapshotHelperPrefix) {
		t.Fatalf("helper name = %q, want the %q prefix", d.helperName, snapshotHelperPrefix)
	}
	if d.helperBody["Image"] != "sha256:intermediate" {
		t.Fatalf("helper image = %v, want the intermediate", d.helperBody["Image"])
	}
	if hc, _ := d.helperBody["HostConfig"].(map[string]any); hc["NetworkMode"] != "none" {
		t.Fatalf("helper HostConfig = %v, want NetworkMode none", d.helperBody["HostConfig"])
	}
	tagged := d.commitQueries[1]
	if tagged.Get("container") != d.helperName || tagged.Get("repo") != "aerolvm-snapshot/owner/py" || tagged.Get("tag") != "v1" || tagged.Get("pause") != "false" {
		t.Fatalf("tagged commit query = %v", tagged)
	}
	if d.commitBodies[1] != nil {
		t.Fatalf("tagged commit sent a config %v; it must take the helper's", d.commitBodies[1])
	}
	if want := []string{"container:helper", "image:intermediate"}; !slices.Equal(d.removed, want) {
		t.Fatalf("removed = %v, want %v (helper before the image it uses)", d.removed, want)
	}

	for name, value := range map[string]string{"toolbox token": snapTestToken, "user secret": snapTestSecret, "ready nonce": snapTestNonce} {
		if d.requestsCarry(value) {
			t.Fatalf("a request to Docker carried the source sandbox's %s", name)
		}
	}
}

// A snapshot whose name has no tag commits the repository alone.
func TestCreateSnapshotUntaggedName(t *testing.T) {
	d := newSnapshotDaemon(t)
	if _, err := d.client().CreateSnapshot(context.Background(), "cid", "snap-alpha"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if q := d.commitQueries[1]; q.Get("repo") != "snap-alpha" || q.Has("tag") {
		t.Fatalf("tagged commit query = %v, want repo snap-alpha and no tag", q)
	}
}

func TestCreateSnapshotFailurePaths(t *testing.T) {
	tests := []struct {
		name      string
		fail      map[string]int
		emptyID   map[string]bool
		mutate    func(*snapshotDaemon)
		logged    bool
		wantErr   string
		wantSteps []string
		removed   []string
	}{
		{
			name:      "container inspect fails",
			fail:      map[string]int{"inspect-container": http.StatusNotFound},
			wantErr:   "inspect container",
			wantSteps: []string{"inspect-container"},
		},
		{
			name:      "the container reports no config",
			mutate:    func(d *snapshotDaemon) { d.containerConfig = nil },
			wantErr:   "reports no config",
			wantSteps: []string{"inspect-container"},
		},
		{
			name:      "the container env is not a list",
			mutate:    func(d *snapshotDaemon) { d.containerConfig["Env"] = "PATH=/bin" },
			wantErr:   "container env",
			wantSteps: []string{"inspect-container"},
		},
		{
			name:      "the container reports no image",
			mutate:    func(d *snapshotDaemon) { d.containerImage = " " },
			wantErr:   "reports no image",
			wantSteps: []string{"inspect-container"},
		},
		{
			// Without the base env the commit cannot tell the image's own
			// variables from the create's, so it does not commit at all.
			name:      "base image inspect fails",
			fail:      map[string]int{"inspect-image": http.StatusNotFound},
			wantErr:   "inspect base image",
			wantSteps: []string{"inspect-container", "inspect-image"},
		},
		{
			name:      "the source commit fails",
			fail:      map[string]int{"commit-source": http.StatusInternalServerError},
			wantErr:   "commit snapshot",
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source"},
		},
		{
			name:      "the source commit returns no id",
			emptyID:   map[string]bool{"commit-source": true},
			wantErr:   "no image id",
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source"},
		},
		{
			name:      "the helper cannot be created",
			fail:      map[string]int{"create-helper": http.StatusInternalServerError},
			wantErr:   "create helper",
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "remove-intermediate"},
			removed:   []string{"image:intermediate"},
		},
		{
			name:      "the tagged commit fails",
			fail:      map[string]int{"commit-helper": http.StatusInternalServerError},
			wantErr:   "commit snapshot",
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "commit-helper", "remove-helper", "remove-intermediate"},
			removed:   []string{"container:helper", "image:intermediate"},
		},
		{
			name:      "the tagged commit returns no id",
			emptyID:   map[string]bool{"commit-helper": true},
			wantErr:   "no image id",
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "commit-helper", "remove-helper", "remove-intermediate"},
			removed:   []string{"container:helper", "image:intermediate"},
		},
		{
			// The orphan sweep reclaims a helper left behind; the snapshot
			// itself is good.
			name:      "the helper cannot be removed",
			fail:      map[string]int{"remove-helper": http.StatusInternalServerError},
			logged:    true,
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "commit-helper", "remove-helper", "remove-intermediate"},
			removed:   []string{"container:helper", "image:intermediate"},
		},
		{
			// What the graphdriver store answers: the intermediate is the
			// tagged image's parent and goes when the snapshot image goes.
			name:      "the intermediate is the tagged image's parent",
			fail:      map[string]int{"remove-intermediate": http.StatusConflict},
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "commit-helper", "remove-helper", "remove-intermediate"},
			removed:   []string{"container:helper", "image:intermediate"},
		},
		{
			name:      "the intermediate cannot be removed for another reason",
			fail:      map[string]int{"remove-intermediate": http.StatusInternalServerError},
			wantSteps: []string{"inspect-container", "inspect-image", "commit-source", "create-helper", "commit-helper", "remove-helper", "remove-intermediate"},
			removed:   []string{"container:helper", "image:intermediate"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newSnapshotDaemon(t)
			d.fail, d.emptyID = tt.fail, tt.emptyID
			if tt.mutate != nil {
				tt.mutate(d)
			}
			c := d.client()
			var logs strings.Builder
			if tt.logged {
				c.logger = slog.New(slog.NewTextHandler(&logs, nil))
			}
			id, err := c.CreateSnapshot(context.Background(), "cid", "snap:v1")
			if tt.logged && !strings.Contains(logs.String(), "snapshot helper container not removed") {
				t.Fatalf("the leftover helper was not logged: %q", logs.String())
			}
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("CreateSnapshot = %v, want success", err)
			case tt.wantErr == "" && id != "sha256:final":
				t.Fatalf("CreateSnapshot id = %q", id)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("CreateSnapshot = %q, %v; want an error containing %q", id, err, tt.wantErr)
			}
			if !slices.Equal(d.steps, tt.wantSteps) {
				t.Fatalf("docker calls = %v, want %v", d.steps, tt.wantSteps)
			}
			if !slices.Equal(d.removed, tt.removed) {
				t.Fatalf("removed = %v, want %v", d.removed, tt.removed)
			}
		})
	}
}

func TestCreateSnapshotRefusesABadNameBeforeCallingDocker(t *testing.T) {
	d := newSnapshotDaemon(t)
	for _, ref := range []string{"", "bad@sha256:x", "repo:"} {
		if _, err := d.client().CreateSnapshot(context.Background(), "cid", ref); err == nil {
			t.Fatalf("CreateSnapshot(%q) succeeded", ref)
		}
	}
	if len(d.steps) != 0 {
		t.Fatalf("docker was called for a bad name: %v", d.steps)
	}
}

// A cancelled snapshot still removes what it made: the cleanups run on a
// context the caller's cancellation cannot reach.
func TestCreateSnapshotCleansUpAfterCancellation(t *testing.T) {
	d := newSnapshotDaemon(t)
	ctx, cancel := context.WithCancel(context.Background())
	inner := d.roundTrip
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if err := r.Context().Err(); err != nil {
			return nil, err // what a real transport does with a dead context
		}
		resp, err := inner(r)
		if r.URL.Path == "/containers/create" {
			cancel() // the caller gives up mid-snapshot
		}
		return resp, err
	})}}
	if _, err := c.CreateSnapshot(ctx, "cid", "snap:v1"); err == nil {
		t.Fatal("CreateSnapshot succeeded after its context was cancelled")
	}
	if want := []string{"container:helper", "image:intermediate"}; !slices.Equal(d.removed, want) {
		t.Fatalf("removed = %v, want %v", d.removed, want)
	}
}

// dockerMergeEnv is the rule dockerd applies when it creates a container from
// an image (moby daemon/commit.go merge, which create and commit share): the
// container's env, plus each image variable whose key the container's env
// does not have.
func dockerMergeEnv(containerEnv, imageEnv []string) []string {
	out := slices.Clone(containerEnv)
	for _, imageKV := range imageEnv {
		imageKey, _, _ := strings.Cut(imageKV, "=")
		if !slices.ContainsFunc(containerEnv, func(kv string) bool {
			key, _, _ := strings.Cut(kv, "=")
			return key == imageKey
		}) {
			out = append(out, imageKV)
		}
	}
	return out
}

func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v, true
		}
	}
	return "", false
}

// A sandbox created from a snapshot gets its own toolbox token and only the
// env its own create passed. The create's env wins over the image's, so the
// snapshot's cleared token never reaches toolboxd; run outside AerolVM, the
// image starts toolboxd with an empty token, and a token-less toolboxd
// refuses everything (cmd/toolboxd TestTokenlessAgentFailsClosed).
func TestSandboxFromASnapshotGetsItsOwnTokenAndEnv(t *testing.T) {
	d := newSnapshotDaemon(t)
	if _, err := d.client().CreateSnapshot(context.Background(), "cid", "snap:v1"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	imageEnv := rawStrings(t, d.commitBodies[0]["Env"])

	createEnv := captureCreateEnv(t, func(c *Client) { c.readyEnabled = false },
		models.CreateSandboxRequest{Image: "snap:v1", Env: map[string]string{"MY_VAR": "mine"}}, "sb-restored")
	seen := dockerMergeEnv(createEnv, imageEnv)

	for key, want := range map[string]string{
		"SB_TOOLBOX_TOKEN": "tok", // captureCreateEnv's create token
		"SB_SANDBOX_ID":    "sb-restored",
		poolParkedEnv:      "",
		"MY_VAR":           "mine",
		"OPENAI_API_KEY":   "", // the source's secret is not inherited
		"PATH":             "/usr/local/bin:/usr/bin:/bin",
	} {
		if got, ok := envValue(seen, key); !ok || got != want {
			t.Fatalf("restored sandbox %s = %q (set=%v), want %q; env %q", key, got, ok, want, seen)
		}
	}
	for _, kv := range seen {
		if strings.Contains(kv, snapTestToken) || strings.Contains(kv, snapTestSecret) || strings.Contains(kv, snapTestNonce) {
			t.Fatalf("restored sandbox inherited a source credential: %q", kv)
		}
	}

	// Started outside AerolVM's create, the image hands toolboxd an empty token.
	if got, ok := envValue(dockerMergeEnv(nil, imageEnv), "SB_TOOLBOX_TOKEN"); !ok || got != "" {
		t.Fatalf("bare run of the snapshot: SB_TOOLBOX_TOKEN = %q (set=%v), want empty", got, ok)
	}
}

func TestDockerMergeEnvMatchesDockerd(t *testing.T) {
	got := dockerMergeEnv([]string{"A=create", "B="}, []string{"A=image", "B=image", "C=image"})
	if want := []string{"A=create", "B=", "C=image"}; !slices.Equal(got, want) {
		t.Fatalf("dockerMergeEnv = %q, want %q", got, want)
	}
	if fmt.Sprint(dockerMergeEnv(nil, nil)) != "[]" {
		t.Fatal("dockerMergeEnv(nil, nil) is not empty")
	}
}

func TestIsLiveSnapshotHelper(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	age := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	cases := []struct {
		name    string
		summary containerSummary
		want    bool
	}{
		{"fresh helper", containerSummary{Names: []string{"/snapcommit-0011"}, Created: age(time.Second)}, true},
		{"helper just under the limit", containerSummary{Names: []string{"/snapcommit-0011"}, Created: age(snapshotHelperMaxAge - time.Second)}, true},
		{"helper at the limit", containerSummary{Names: []string{"/snapcommit-0011"}, Created: age(snapshotHelperMaxAge)}, false},
		{"helper with no creation time", containerSummary{Names: []string{"/snapcommit-0011"}}, false},
		{"sandbox", containerSummary{Names: []string{"/sb-0011"}, Created: age(time.Second)}, false},
		{"no name", containerSummary{Created: age(time.Second)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLiveSnapshotHelper(tc.summary, now); got != tc.want {
				t.Fatalf("isLiveSnapshotHelper(%+v) = %v, want %v", tc.summary, got, tc.want)
			}
		})
	}
}
