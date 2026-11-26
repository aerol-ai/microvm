package kubepod

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func testConfig(t *testing.T) Config {
	return Config{
		Namespace:      "aerolvm-sandboxes",
		WorkerID:       "worker-0",
		RuntimeClasses: map[string]string{models.RuntimeGvisor: "gvisor", models.RuntimeDocker: "runc"},
		DefaultRuntime: models.RuntimeGvisor,
		ToolboxImage:   "ghcr.io/aerol-ai/aerolvm:test",
		SpecDir:        t.TempDir(),
		StartTimeout:   2 * time.Second,
		StopTimeout:    2 * time.Second,
	}
}

func newTestDriver(t *testing.T, f *fakeAPI, edit func(*Config)) *Driver {
	t.Helper()
	cfg := testConfig(t)
	if edit != nil {
		edit(&cfg)
	}
	d, err := New(cfg, f.client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.pollMin, d.pollMax = time.Millisecond, 5*time.Millisecond
	return d
}

func TestNewChecksConfig(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"no namespace", func(c *Config) { c.Namespace = "" }, "namespace"},
		{"bad namespace", func(c *Config) { c.Namespace = "Sandboxes" }, "namespace"},
		{"no worker", func(c *Config) { c.WorkerID = " " }, "worker ID"},
		{"worker too long", func(c *Config) { c.WorkerID = strings.Repeat("w", 64) }, "worker ID"},
		{"worker bad char", func(c *Config) { c.WorkerID = "node:1" }, "worker ID"},
		{"no runtimes", func(c *Config) { c.RuntimeClasses = nil }, "no runtime is offered"},
		{"empty runtime name", func(c *Config) { c.RuntimeClasses = map[string]string{" ": "gvisor"} }, "empty"},
		{"bad class", func(c *Config) { c.RuntimeClasses = map[string]string{"gvisor": "G_visor"} }, "not a RuntimeClass name"},
		{"empty class", func(c *Config) { c.RuntimeClasses = map[string]string{"gvisor": ""} }, "not a RuntimeClass name"},
		{"default not offered", func(c *Config) { c.DefaultRuntime = "kata" }, "default runtime \"kata\""},
		{"no default of two", func(c *Config) { c.DefaultRuntime = "" }, "default runtime \"\""},
		{"no toolbox image", func(c *Config) { c.ToolboxImage = " " }, "toolbox image"},
		{"relative toolbox path", func(c *Config) { c.ToolboxPath = "toolboxd" }, "absolute"},
		{"bad port", func(c *Config) { c.ToolboxPort = 70000 }, "out of range"},
		{"relative spec dir", func(c *Config) { c.SpecDir = "specs" }, "absolute"},
		{"spec dir under a file", func(c *Config) { c.SpecDir = filepath.Join(notADir, "specs") }, "spec folder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.edit(&cfg)
			_, err := New(cfg, NewClient("https://example.invalid", nil, nil), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error with %q", err, tc.want)
			}
		})
	}
	if _, err := New(testConfig(t), nil, nil); err == nil {
		t.Fatal("New without a client: want an error")
	}
}

func TestNewDefaults(t *testing.T) {
	cfg := testConfig(t)
	cfg.RuntimeClasses = map[string]string{" gvisor ": " gvisor "}
	cfg.DefaultRuntime = ""
	cfg.StartTimeout, cfg.StopTimeout = 0, 0
	cfg.StopGrace = 100 * time.Millisecond
	d, err := New(cfg, NewClient("https://example.invalid", nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := d.cfg
	if got.DefaultRuntime != "gvisor" || got.RuntimeClasses["gvisor"] != "gvisor" {
		t.Errorf("one runtime offered: default = %q, classes = %v", got.DefaultRuntime, got.RuntimeClasses)
	}
	if got.ToolboxPath != defaultToolboxPath || got.ToolboxPort != defaultToolboxPort {
		t.Errorf("toolbox = %s:%d", got.ToolboxPath, got.ToolboxPort)
	}
	if got.StartTimeout != defaultStartTimeout || got.StopTimeout != defaultStopTimeout {
		t.Errorf("timeouts = %v, %v", got.StartTimeout, got.StopTimeout)
	}
	if got.StopGrace != time.Second {
		t.Errorf("grace under a second = %v, want raised to 1s", got.StopGrace)
	}
	cfg.StopGrace = 0
	d, _ = New(cfg, NewClient("https://example.invalid", nil, nil), nil)
	if d.cfg.StopGrace != defaultStopGrace {
		t.Errorf("default grace = %v", d.cfg.StopGrace)
	}
}

func TestRenderPodShape(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	p, err := d.renderPod(models.CreateSandboxRequest{
		Image: " python:3.12 ", CPU: 1.5, MemoryMB: 512, DiskGB: 4,
		ContainerCommand: []string{"sleep", "infinity"},
	}, "sb-0011223344556677")
	if err != nil {
		t.Fatal(err)
	}
	m := p.Metadata
	if m.Name != "sb-0011223344556677" || m.Namespace != "aerolvm-sandboxes" {
		t.Errorf("name = %s/%s", m.Namespace, m.Name)
	}
	wantLabels := map[string]string{
		LabelName: "aerolvm", LabelComponent: "sandbox", LabelManagedBy: "aerolvm-worker", LabelWorker: "worker-0",
	}
	if !reflect.DeepEqual(m.Labels, wantLabels) {
		t.Errorf("labels = %v", m.Labels)
	}
	if m.Annotations[AnnotationSandboxID] != "sb-0011223344556677" || m.Annotations[AnnotationRuntime] != "gvisor" {
		t.Errorf("annotations = %v", m.Annotations)
	}
	s := p.Spec
	if s.RuntimeClassName != "gvisor" || s.RestartPolicy != "Never" {
		t.Errorf("class = %q, restart = %q", s.RuntimeClassName, s.RestartPolicy)
	}
	if s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken {
		t.Error("service account token must be off")
	}
	if s.EnableServiceLinks == nil || *s.EnableServiceLinks {
		t.Error("service links must be off")
	}
	if s.TerminationGracePeriodSeconds == nil || *s.TerminationGracePeriodSeconds != 10 {
		t.Errorf("grace = %v", s.TerminationGracePeriodSeconds)
	}
	if s.SecurityContext == nil || s.SecurityContext.SeccompProfile.Type != "RuntimeDefault" {
		t.Error("seccomp must be RuntimeDefault")
	}
	if len(s.Volumes) != 1 || s.Volumes[0].EmptyDir == nil || s.Volumes[0].EmptyDir.SizeLimit != toolboxVolumeLimit {
		t.Errorf("volumes = %+v: want only the toolbox emptyDir", s.Volumes)
	}

	if len(s.InitContainers) != 1 {
		t.Fatalf("init containers = %d", len(s.InitContainers))
	}
	ic := s.InitContainers[0]
	if ic.Image != "ghcr.io/aerol-ai/aerolvm:test" || !reflect.DeepEqual(ic.Command, []string{defaultToolboxPath, "--install-to", toolboxBinary}) {
		t.Errorf("init = %s %v", ic.Image, ic.Command)
	}
	isc := ic.SecurityContext
	if *isc.RunAsNonRoot != true || *isc.RunAsUser != nobodyUID || *isc.ReadOnlyRootFilesystem != true ||
		*isc.AllowPrivilegeEscalation || *isc.Privileged || !reflect.DeepEqual(isc.Capabilities.Drop, []string{"ALL"}) {
		t.Errorf("init security = %+v", isc)
	}
	if !reflect.DeepEqual(ic.Resources.Requests, ic.Resources.Limits) {
		t.Errorf("init requests %v != limits %v", ic.Resources.Requests, ic.Resources.Limits)
	}

	if len(s.Containers) != 1 {
		t.Fatalf("containers = %d", len(s.Containers))
	}
	c := s.Containers[0]
	if c.Image != "python:3.12" || !reflect.DeepEqual(c.Command, []string{toolboxBinary}) || !reflect.DeepEqual(c.Args, []string{"sleep", "infinity"}) {
		t.Errorf("sandbox = %s %v %v", c.Image, c.Command, c.Args)
	}
	if !reflect.DeepEqual(c.Env, []EnvVar{{Name: "SB_SANDBOX_ID", Value: "sb-0011223344556677"}}) {
		t.Errorf("env = %v: want only the sandbox ID", c.Env)
	}
	want := map[string]string{"cpu": "1500m", "memory": "512Mi", "ephemeral-storage": "4Gi"}
	if !reflect.DeepEqual(c.Resources.Limits, want) || !reflect.DeepEqual(c.Resources.Requests, want) {
		t.Errorf("resources = %+v, want requests = limits = %v", c.Resources, want)
	}
	if len(c.VolumeMounts) != 1 || !c.VolumeMounts[0].ReadOnly || c.VolumeMounts[0].MountPath != toolboxMountDir {
		t.Errorf("sandbox mounts = %+v: want the toolbox volume read-only", c.VolumeMounts)
	}
	sc := c.SecurityContext
	if *sc.Privileged || *sc.AllowPrivilegeEscalation || !reflect.DeepEqual(sc.Capabilities.Drop, []string{"ALL"}) || sc.RunAsNonRoot != nil {
		t.Errorf("sandbox security = %+v", sc)
	}
	// An allow-list: the default install's sandbox set, every entry of
	// which Pod Security "baseline" allows a pod to add.
	baselineAllowed := map[string]bool{
		"AUDIT_WRITE": true, "CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true, "KILL": true, "MKNOD": true,
		"NET_BIND_SERVICE": true, "SETFCAP": true, "SETGID": true, "SETPCAP": true, "SETUID": true, "SYS_CHROOT": true,
	}
	if len(sc.Capabilities.Add) != len(rootpolicy.SandboxCapabilities()) {
		t.Errorf("added %v, want the sandbox set %v", sc.Capabilities.Add, rootpolicy.SandboxCapabilities())
	}
	for _, capName := range sc.Capabilities.Add {
		if !baselineAllowed[capName] {
			t.Errorf("adds %s, which Pod Security baseline refuses", capName)
		}
		if capName == "NET_RAW" {
			t.Error("adds NET_RAW")
		}
	}

	raw, _ := json.Marshal(p)
	for _, banned := range []string{"hostPath", "hostNetwork", "hostPID", "hostIPC", "serviceAccountName", `"privileged":true`} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("pod JSON has %s", banned)
		}
	}
}

func TestRenderPodChoices(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), func(c *Config) {
		c.ToolboxPort = 3390
		c.ToolboxPath = "/toolboxd"
	})
	p, err := d.renderPod(models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeDocker, CPU: 0.0001}, "Sb_Custom")
	if err != nil {
		t.Fatal(err)
	}
	if p.Spec.RuntimeClassName != "runc" || p.Metadata.Annotations[AnnotationRuntime] != models.RuntimeDocker {
		t.Errorf("class = %q", p.Spec.RuntimeClassName)
	}
	if p.Metadata.Name != podName("Sb_Custom") || p.Metadata.Annotations[AnnotationSandboxID] != "Sb_Custom" {
		t.Errorf("name = %q, id = %q", p.Metadata.Name, p.Metadata.Annotations[AnnotationSandboxID])
	}
	c := p.Spec.Containers[0]
	if c.Resources.Limits["cpu"] != "1m" || c.Resources.Limits["memory"] != "1024Mi" {
		t.Errorf("limits = %v: want the smallest CPU and the default memory", c.Resources.Limits)
	}
	if _, ok := c.Resources.Limits["ephemeral-storage"]; ok {
		t.Error("no disk size asked: no ephemeral-storage limit")
	}
	if c.Args != nil {
		t.Errorf("args = %v, want none", c.Args)
	}
	if !reflect.DeepEqual(c.Env[1], EnvVar{Name: "SB_TOOLBOX_PORT", Value: "3390"}) {
		t.Errorf("env = %v", c.Env)
	}
	if p.Spec.InitContainers[0].Command[0] != "/toolboxd" {
		t.Errorf("init command = %v", p.Spec.InitContainers[0].Command)
	}
	if got := cpuQuantity(0); got != "1000m" {
		t.Errorf("cpuQuantity(0) = %s, want the default", got)
	}
}

func TestRenderPodRefuses(t *testing.T) {
	d := newTestDriver(t, newFakeAPI(t), nil)
	cases := []struct {
		name string
		req  models.CreateSandboxRequest
		want error
		text string
	}{
		{"env", models.CreateSandboxRequest{Image: "alpine", Env: map[string]string{"K": "v"}}, ErrEnvNotSupported, ""},
		{"gpus", models.CreateSandboxRequest{Image: "alpine", GPUs: &models.GPURequest{}}, ErrGPUsNotSupported, ""},
		{"registry", models.CreateSandboxRequest{Image: "alpine", Registry: &models.RegistryAuth{}}, ErrRegistryAuthNotSupported, ""},
		{"no image", models.CreateSandboxRequest{Image: " "}, nil, "image is required"},
		{"not offered", models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeKata}, ErrRuntimeNotOffered, "offered: docker, gvisor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.renderPod(tc.req, "sb-0011223344556677")
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("renderPod = %v, want %v with %q", err, tc.want, tc.text)
			}
		})
	}
}

func TestPodName(t *testing.T) {
	if got := podName("sb-0011223344556677"); got != "sb-0011223344556677" {
		t.Errorf("a generated ID is its own pod name, got %q", got)
	}
	odd := []string{"Sb-Upper", "sb_under", strings.Repeat("a", 64), "-lead", "trail-"}
	seen := map[string]bool{}
	for _, id := range odd {
		name := podName(id)
		if !strings.HasPrefix(name, hashedNamePrefix) || len(name) > 63 || !dnsLabel.MatchString(name) {
			t.Errorf("podName(%q) = %q: want a hashed DNS label", id, name)
		}
		if podName(id) != name {
			t.Errorf("podName(%q) is not stable", id)
		}
		if seen[name] {
			t.Errorf("podName(%q) = %q collides", id, name)
		}
		seen[name] = true
	}
}
