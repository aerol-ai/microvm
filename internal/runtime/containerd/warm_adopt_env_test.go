package containerd

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"

	"github.com/aerol-ai/microvm/internal/pool/containerdpool"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/gvisorpids"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// adoptEnvCanary stands in for a secret in a create's env: it must reach the
// toolbox through the adopt frame and nowhere else on the host.
const adoptEnvCanary = "canary-adopt-env-4d2c"

func TestPoolEligibleEnvTable(t *testing.T) {
	oversize := map[string]string{"BIG": strings.Repeat("v", readyproto.MaxAdoptEnvBytes)}
	for _, tc := range []struct {
		name  string
		env   map[string]string
		binds []mounts.ContainerBind
		want  bool
	}{
		{"no env", nil, nil, true},
		{"empty env", map[string]string{}, nil, true},
		{"plain env", map[string]string{"API_KEY": adoptEnvCanary, "MODE": "prod"}, nil, true},
		{"PATH and HOME", map[string]string{"PATH": "/opt/bin:/usr/bin", "HOME": "/work"}, nil, true},
		// The service's own additions that carry no mount: cloud identity
		// env (its token is pushed over the toolbox API later) and a
		// withheld key's placeholder, a value like any other.
		{"cloud identity env", map[string]string{"AEROLVM_IDENTITY_TOKEN_FILE": "/run/aerolvm/identity/token", "AWS_ROLE_ARN": "arn:aws:iam::1:role/r"}, nil, true},
		{"withheld placeholder", map[string]string{"OPENAI_API_KEY": egresspolicy.InjectPlaceholder("OPENAI_API_KEY")}, nil, true},
		{"lower-case user is not USER", map[string]string{"user": "x"}, nil, true},
		{"SB without underscore", map[string]string{"SBX": "x"}, nil, true},
		// Keys toolboxd reads for itself at boot: honoured cold, ignored
		// warm, so they keep the create cold.
		{"SB_ toolbox setting", map[string]string{"SB_RECORDING_DIR": "/x"}, nil, false},
		{"SB_TOOLBOX_PORT", map[string]string{"SB_TOOLBOX_PORT": "1"}, nil, false},
		{"gVisor pids key", map[string]string{gvisorpids.EnvVar: "5"}, nil, false},
		{"egress CA", map[string]string{"AEROLVM_EGRESS_CA": "/x"}, nil, false},
		{"egress CA bundle", map[string]string{"AEROLVM_EGRESS_CA_BUNDLE": "/x"}, nil, false},
		{"USER", map[string]string{"USER": "app"}, nil, false},
		{"LOGNAME", map[string]string{"LOGNAME": "app"}, nil, false},
		// What the frame cannot carry goes cold before a slot is spent.
		{"oversize", oversize, nil, false},
		{"empty key", map[string]string{"": "v"}, nil, false},
		{"NUL in value", map[string]string{"K": "a\x00b"}, nil, false},
		{"bytes JSON would rewrite", map[string]string{"K": "\xff"}, nil, false},
		// Egress inspect rules bring env with binds (the CA file and the
		// bundle's tmpfs): the binds keep the create cold.
		{"env with inspect binds", map[string]string{"SSL_CERT_FILE": "/run/aerolvm/egress/bundle.pem"}, []mounts.ContainerBind{
			{HostPath: "/var/lib/aerolvm/egress-ca.pem", ContainerPath: "/run/aerolvm/egress/ca.pem", ReadOnly: true},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := models.CreateSandboxRequest{Image: "alpine:3.20", Env: tc.env}
			if got := poolEligible(req, tc.binds); got != tc.want {
				t.Fatalf("poolEligible = %v, want %v", got, tc.want)
			}
		})
	}
}

// recordingPool is the containerd warm pool, noting each slot it releases.
type recordingPool struct {
	*containerdpool.Pool
	released []string
}

func (p *recordingPool) ReleasePark(slotID string) {
	p.released = append(p.released, slotID)
	p.Pool.ReleasePark(slotID)
}

// adoptWithEnv parks slotID and creates sandboxID from it with env,
// returning the create's state and error and the pool it drew on.
func (r *restartRig) adoptWithEnv(slotID, sandboxID, token string, env map[string]string) (*models.SandboxRuntimeState, *recordingPool, error) {
	r.t.Helper()
	slot := r.park(slotID)
	pool := &recordingPool{Pool: containerdpool.New(nil)}
	pool.RecordLoaded(slot)
	r.d.SetWarmPool(pool)
	defer r.d.SetWarmPool(nil)
	state, err := r.d.Create(context.Background(), models.CreateSandboxRequest{Image: "cfg:test", Runtime: models.RuntimeDocker, Env: env}, sandboxID, token, nil)
	return state, pool, err
}

// filesHolding lists every file under dirs whose content holds needle.
func filesHolding(t *testing.T, needle string, dirs ...string) []string {
	t.Helper()
	var hits []string
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || e.Type()&fs.ModeSocket != 0 {
				return nil
			}
			if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), needle) {
				hits = append(hits, p)
			}
			return nil
		})
	}
	return hits
}

// The env reaches the toolbox in the adopt frame and nowhere else: not the
// container's spec (what `ctr containers info` shows), not its labels, not
// a host file, and not a snapshot committed from the container.
func TestWarmAdoptCarriesEnvInTheFrameOnly(t *testing.T) {
	r := newRestartRig(t)
	env := map[string]string{"API_KEY": adoptEnvCanary, "MODE": "prod"}
	state, _, err := r.adoptWithEnv("park-e1", "sb-e1", "tok", env)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if state.AdoptedParkID != "park-e1" {
		t.Fatalf("create went cold: %+v", state)
	}
	if got := r.lastAdopt(); !maps.Equal(got.Env, env) || got.SandboxID != "sb-e1" {
		t.Fatalf("the toolbox was adopted with %d keys for %q, want the create's env", len(got.Env), got.SandboxID)
	}

	c := r.tr.containers["park-e1"]
	if c.labels[adoptEnvLabelKey] != adoptEnvLabelValue {
		t.Fatalf("labels %v lack the adopted-with-env mark", c.labels)
	}
	labels, _ := json.Marshal(c.labels)
	spec, _ := json.Marshal(c.specOverride)
	for what, blob := range map[string][]byte{"labels": labels, "spec": spec} {
		if strings.Contains(string(blob), adoptEnvCanary) || strings.Contains(string(blob), "API_KEY") {
			t.Fatalf("the container's %s carry the env: %s", what, blob)
		}
	}
	if hits := filesHolding(t, adoptEnvCanary, r.cfg.RunDir, r.cfg.LogDir, r.cfg.ReadyDir); len(hits) > 0 {
		t.Fatalf("the env reached host files: %v", hits)
	}

	backend := baseFixture(&fakeTask{status: cntr.Running})
	backend.container = c
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })
	if _, err := r.d.commitContainerSnapshotLive(context.Background(), r.d.client, "park-e1", "snap:env"); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	for dgst, data := range backend.blobData {
		if strings.Contains(string(data), adoptEnvCanary) {
			t.Fatalf("snapshot blob %s carries the env", dgst)
		}
	}
	if img, _ := json.Marshal(backend.createdArg); strings.Contains(string(img), adoptEnvCanary) {
		t.Fatalf("snapshot image record carries the env: %s", img)
	}
}

// A toolbox that acks without proving it applied the env (one built before
// adopt frames carried env drops the field) fails the adopt: the slot is
// destroyed, its pool slot released, and the create goes cold with its env.
func TestWarmAdoptWithEnvFallsBackColdWithoutTheDigest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digest func(readyproto.AdoptFrame) string
	}{
		{"older agent: no digest", func(readyproto.AdoptFrame) string { return "" }},
		{"wrong digest", func(f readyproto.AdoptFrame) string { return readyproto.EnvDigest(f.Nonce, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRestartRig(t)
			r.ackDigest = tc.digest
			env := map[string]string{"API_KEY": adoptEnvCanary}
			state, pool, err := r.adoptWithEnv("park-f1", "sb-f1", "tok", env)
			if err != nil {
				t.Fatalf("create must fall back cold, got %v", err)
			}
			if state.AdoptedParkID != "" || state.ContainerID != "sb-f1" {
				t.Fatalf("create served from the slot: %+v", state)
			}
			if _, left := r.tr.containers["park-f1"]; left {
				t.Fatal("the slot whose toolbox ignored the env was not destroyed")
			}
			if len(pool.released) != 1 || pool.released[0] != "park-f1" {
				t.Fatalf("pool released %v, want the slot once", pool.released)
			}
			if _, err := os.Stat(filepath.Join(r.cfg.ReadyDir, "park-f1.sock")); !os.IsNotExist(err) {
				t.Fatal("the destroyed slot's park socket is still on disk")
			}
			if _, err := os.Stat(filepath.Join(r.cfg.RunDir, "hosts", "park-f1")); !os.IsNotExist(err) {
				t.Fatal("the destroyed slot left its host files")
			}
		})
	}
}

// A slot handle that cannot carry env is never adopted without it.
func TestWarmAdoptRefusesAHandleThatCannotCarryEnv(t *testing.T) {
	stubToolboxProbe(t)
	key := containerdpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	pool := &recordingPool{Pool: containerdpool.New(nil)}
	pool.NoteTarget(key)
	tr := newFakeTransport()
	tr.containers["park-1"] = &fakeContainer{id: "park-1", labels: map[string]string{poolParkLabelKey: poolParkLabelValue}}
	d := newTestDriver(t)
	d.cfg.ReadyEnabled = true
	d.SetClient(NewTestClient("aerolvm", tr))
	d.SetWarmPool(pool)
	pool.RecordLoaded(&containerdpool.ParkedSlot{
		ID: "park-1", ContainerID: "park-1", ContainerIP: "10.88.0.9", ImageID: "sha256:img", Key: key, Handle: &fakeHandle{alive: true},
	})
	_, err := d.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Env: map[string]string{"K": adoptEnvCanary}}, "sb-h", "tok", nil, models.RuntimeDocker)
	if err == nil || !strings.Contains(err.Error(), "cannot carry the sandbox env") || strings.Contains(err.Error(), adoptEnvCanary) {
		t.Fatalf("tryWarmAdopt = %v", err)
	}
	if len(pool.released) != 1 {
		t.Fatalf("pool released %v, want the slot", pool.released)
	}
	if err := adoptHandle(context.Background(), struct{}{}, "sb", "t", "n", nil); err == nil || !strings.Contains(err.Error(), "type mismatch") {
		t.Fatalf("adoptHandle on a non-handle = %v", err)
	}
}

// envLoader counts its calls and returns env or err.
type envLoader struct {
	env   map[string]string
	err   error
	calls int
}

func (l *envLoader) load(context.Context) (map[string]string, error) {
	l.calls++
	return l.env, l.err
}

// A pool container adopted with env has that env in no spec, so each start
// re-adopts it with the env the sealed row holds now (here: a key removed),
// after a sandboxd restart too.
func TestWarmAdoptedWithEnvRestartResendsEnv(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	if _, _, err := r.adoptWithEnv("park-s1", "sb-s1", "tok", map[string]string{"API_KEY": adoptEnvCanary, "MODE": "prod"}); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Stop(ctx, "park-s1"); err != nil {
		t.Fatal(err)
	}
	now := map[string]string{"API_KEY": adoptEnvCanary}
	loader := &envLoader{env: now}
	if _, err := r.d.StartWithIdentityEnv(ctx, "park-s1", "sb-s1", "tok", loader.load); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := r.lastAdopt(); !maps.Equal(got.Env, now) || got.SandboxID != "sb-s1" {
		t.Fatalf("restart adopted with %d keys, want the sealed row's %d", len(got.Env), len(now))
	}
	if loader.calls != 1 {
		t.Fatalf("env loaded %d times, want once", loader.calls)
	}

	// A new sandboxd: the mark is on the container, not in memory.
	if err := r.d.Stop(ctx, "park-s1"); err != nil {
		t.Fatal(err)
	}
	d2 := r.newDriver()
	if _, err := d2.StartWithIdentityEnv(ctx, "park-s1", "sb-s1", "tok", loader.load); err != nil {
		t.Fatalf("start after a sandboxd restart: %v", err)
	}
	if got := r.lastAdopt(); !maps.Equal(got.Env, now) {
		t.Fatalf("restart after a sandboxd restart adopted with %d keys", len(got.Env))
	}
	// A running sandbox is left alone: no load, no adopt.
	if _, err := d2.StartWithIdentityEnv(ctx, "park-s1", "sb-s1", "tok", loader.load); err != nil || loader.calls != 2 {
		t.Fatalf("start of a running sandbox: err %v, loads %d", err, loader.calls)
	}
}

// A start that can't hand the env back starts nothing: no task, no adopt.
func TestWarmAdoptedWithEnvRestartRefusesWithoutTheEnv(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start func(d *Driver) error
		want  string
	}{
		{"no loader", func(d *Driver) error {
			_, err := d.StartWithIdentity(context.Background(), "park-s2", "sb-s2", "tok")
			return err
		}, "needs the sandbox's env"},
		{"loader fails", func(d *Driver) error {
			_, err := d.StartWithIdentityEnv(context.Background(), "park-s2", "sb-s2", "tok", (&envLoader{err: errors.New("sealed row unreadable")}).load)
			return err
		}, "sealed row unreadable"},
		{"env loads empty", func(d *Driver) error {
			_, err := d.StartWithIdentityEnv(context.Background(), "park-s2", "sb-s2", "tok", (&envLoader{env: map[string]string{}}).load)
			return err
		}, "loaded empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRestartRig(t)
			ctx := context.Background()
			if _, _, err := r.adoptWithEnv("park-s2", "sb-s2", "tok", map[string]string{"API_KEY": adoptEnvCanary}); err != nil {
				t.Fatal(err)
			}
			if err := r.d.Stop(ctx, "park-s2"); err != nil {
				t.Fatal(err)
			}
			r.mu.Lock()
			before := len(r.adopted)
			r.mu.Unlock()
			err := tc.start(r.d)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), adoptEnvCanary) {
				t.Fatalf("start = %v, want %q", err, tc.want)
			}
			r.mu.Lock()
			after := len(r.adopted)
			r.mu.Unlock()
			if after != before {
				t.Fatal("the toolbox was adopted by a start that refused")
			}
			if c := r.tr.containers["park-s2"]; c.task != nil && c.task.status == cntr.Running {
				t.Fatal("a task runs behind a refused start")
			}
			if _, err := os.Stat(filepath.Join(r.cfg.ReadyDir, "park-s2.sock")); !os.IsNotExist(err) {
				t.Fatal("the refused start's park listener outlived it")
			}
		})
	}
}

// A re-adopt the toolbox doesn't prove it applied fails the start and kills
// the task, as any failed re-adopt does.
func TestWarmAdoptedWithEnvRestartFailsClosedOnABadDigest(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	if _, _, err := r.adoptWithEnv("park-s3", "sb-s3", "tok", map[string]string{"API_KEY": adoptEnvCanary}); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Stop(ctx, "park-s3"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.ackDigest = func(readyproto.AdoptFrame) string { return "" }
	r.mu.Unlock()
	_, err := r.d.StartWithIdentityEnv(ctx, "park-s3", "sb-s3", "tok", (&envLoader{env: map[string]string{"API_KEY": adoptEnvCanary}}).load)
	if err == nil || !strings.Contains(err.Error(), "re-adopt warm-pool container") || strings.Contains(err.Error(), adoptEnvCanary) {
		t.Fatalf("start = %v", err)
	}
	if c := r.tr.containers["park-s3"]; c.task.status == cntr.Running || c.task.killed == 0 {
		t.Fatalf("task after the failed start: status %v, kills %d", c.task.status, c.task.killed)
	}
}

// The env is loaded only for a container adopted with env: a pool
// container adopted without env and a cold container read nothing more.
func TestStartWithIdentityEnvLoadsOnlyWhenNeeded(t *testing.T) {
	r := newRestartRig(t)
	ctx := context.Background()
	r.adopt("park-s4", "sb-s4", "tok")
	if err := r.d.Stop(ctx, "park-s4"); err != nil {
		t.Fatal(err)
	}
	loader := &envLoader{env: map[string]string{"API_KEY": adoptEnvCanary}}
	if _, err := r.d.StartWithIdentityEnv(ctx, "park-s4", "sb-s4", "tok", loader.load); err != nil {
		t.Fatal(err)
	}
	if got := r.lastAdopt(); len(got.Env) != 0 {
		t.Fatalf("an env-less pool sandbox was re-adopted with %d keys", len(got.Env))
	}

	if _, err := r.d.Create(ctx, models.CreateSandboxRequest{Image: "cfg:test", ContainerCommand: []string{"sleep"}, Env: map[string]string{"K": "v"}}, "sb-cold4", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Stop(ctx, "sb-cold4"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.d.StartWithIdentityEnv(ctx, "sb-cold4", "sb-cold4", "tok", loader.load); err != nil {
		t.Fatal(err)
	}
	if loader.calls != 0 {
		t.Fatalf("env loaded %d times for starts that need none", loader.calls)
	}
	var _ sbruntime.EnvIdentityStarter = r.d
}

func TestReadoptEnvLabelsError(t *testing.T) {
	c := &fakeContainer{id: "park-l", labelsErr: errors.New("engine busy")}
	if _, err := readoptEnv(context.Background(), c, nil); err == nil || !strings.Contains(err.Error(), "engine busy") {
		t.Fatalf("readoptEnv = %v", err)
	}
}
