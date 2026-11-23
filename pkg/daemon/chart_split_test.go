package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The Helm chart's privilegeMode (charts/aerolvm/templates/_privilegemode.tpl,
// plans/security-gaps-m1-m4.md M1 PR 11) and checkPrivilegeMode agree. A
// value that turns on something split cannot run yet must fail at helm
// install, not as a worker that restarts forever; and a split worker the
// chart renders must be one sandboxd starts.
//
// chartGapRows are the chart's refusals. A daemon row names the setting the
// chart value renders into the agent and what checkPrivilegeMode then says:
// the test renders the value in single, reads that setting back, and checks
// split refuses it. A Kubernetes row is worker pod wiring the chart does
// not have yet; only the chart's refusal is checked.

type chartGapRow struct {
	name  string
	flags []string
	// chart is what the chart's refusal names.
	chart string
	// env and set: the setting the value renders, and how it reaches
	// sandboxd's config. Empty env: a Kubernetes row.
	env string
	set func(c *config.Config, value string)
	// step or want: the gap checkPrivilegeMode names, or a lasting need's
	// words.
	step privmode.Step
	want string
}

var chartClusterFlags = []string{"--set", "mode=cluster", "--set", "cluster.zones={z-a,z-b,z-c}",
	"--set", "cluster.workerPools[0].name=general", "--set", "cluster.workerPools[0].machine.cpu=8",
	"--set", "cluster.workerPools[0].machine.memoryGiB=32", "--set", "cluster.workerPools[0].minWorkers=3",
	"--set", "cluster.workerPools[0].maxWorkers=9"}

func isTrue(v string) bool {
	return slices.Contains([]string{"1", "t", "T", "TRUE", "true", "True"}, v)
}

func chartGapRows() []chartGapRow {
	set := func(f func(*config.Config, bool)) func(*config.Config, string) {
		return func(c *config.Config, v string) { f(c, isTrue(v)) }
	}
	moves := set(func(c *config.Config, on bool) { c.GvisorCheckpointMoves = on })
	pool := set(func(c *config.Config, on bool) { c.ContainerdPoolEnabled = on })
	return append(firecrackerGapRows(), []chartGapRow{
		{name: "gVisor moves", flags: []string{"--set", "worker.gvisor.checkpointMoves=true"}, chart: "worker.gvisor.checkpointMoves",
			env: "SB_GVISOR_CHECKPOINT_MOVES", set: moves, step: privmode.StepMoves},
		{name: "the agent-sandbox API's warm pools", flags: append(slices.Clone(chartClusterFlags), "--set", "cluster.agentSandboxAPI.enabled=true"),
			chart: "cluster.agentSandboxAPI.enabled", env: "SB_CONTAINERD_POOL_ENABLED", set: pool, step: privmode.StepWarmPool},
		{name: "the warm pool in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_CONTAINERD_POOL_ENABLED=true"},
			chart: "worker.extraEnv.SB_CONTAINERD_POOL_ENABLED", env: "SB_CONTAINERD_POOL_ENABLED", set: pool, step: privmode.StepWarmPool},
		{name: "gVisor moves in extraEnv", flags: []string{"--set", "worker.gvisor.checkpointMoves=false", "--set", "worker.extraEnv.SB_GVISOR_CHECKPOINT_MOVES=true"},
			chart: "worker.extraEnv.SB_GVISOR_CHECKPOINT_MOVES", env: "SB_GVISOR_CHECKPOINT_MOVES", set: moves, step: privmode.StepMoves},
		// WASM is refused whole on a split worker pod (a Kubernetes row
		// below), which covers its warm pool without the resident host.
		{name: "the WASM warm pool", flags: []string{"--set", "worker.wasm.enabled=true",
			"--set", "worker.extraEnv.SB_WASM_POOL_ENABLED=true", "--set", "worker.extraEnv.SB_WASM_RESIDENT_HOST_ENABLED=false"},
			chart: "worker.wasm.enabled", env: "SB_WASM_RESIDENT_HOST_ENABLED",
			set: func(c *config.Config, v string) {
				wasmSplit(c)
				c.WasmPoolEnabled, c.WasmResidentHostEnabled = true, isTrue(v)
			},
			step: privmode.StepWasmWarmPool},
		{name: "the Docker engine", flags: []string{"--set", "worker.extraEnv.SB_CONTAINER_ENGINE=docker"},
			chart: "worker.extraEnv.SB_CONTAINER_ENGINE", env: "SB_CONTAINER_ENGINE",
			set: func(c *config.Config, v string) { c.ContainerEngine = v }, want: "SB_CONTAINER_ENGINE=containerd"},
		{name: "no netns pool", flags: []string{"--set", "worker.extraEnv.SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=false"},
			chart: "worker.extraEnv.SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", env: "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED",
			set: func(c *config.Config, v string) { c.ContainerdNativeNetnsPoolEnabled = isTrue(v) }, want: "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED"},
		// Kubernetes rows: split on the daemon, not yet in the worker pod.
		{name: "WASM", flags: []string{"--set", "worker.wasm.enabled=true"}, chart: "worker.wasm.enabled"},
		{name: "V8 isolates", flags: []string{"--set", "worker.isolate.enabled=true"}, chart: "worker.isolate.enabled"},
		{name: "a helper setting in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_ROOTD_AGENT_UID=1"}, chart: "worker.extraEnv.SB_ROOTD_AGENT_UID"},
	}...)
}

// firecrackerGapRows are the chart's Firecracker refusals. The chart refuses
// worker.firecracker.enabled whole in split: it does not wire Firecracker
// into a split worker pod, and no live run has proven it, so the first two
// rows are the chart's alone. sandboxd's own refusals are narrower (M1 PRs
// 9b, #1425, #1426): a worker with the VM pool waits for the helper's warm
// pool step, and one without the jailer is never split. When a privmode
// step is renamed again, change only the step name here.
func firecrackerGapRows() []chartGapRow {
	const fcOn = "worker.firecracker.enabled=true"
	// fc is a split worker with Firecracker on as the chart renders it:
	// through the jailer, with the host firewall on.
	fc := func(more func(*config.Config, string)) func(*config.Config, string) {
		return func(c *config.Config, v string) {
			c.EnableFirecracker, c.UseJailer, c.EnableNetworkRules = true, true, true
			if more != nil {
				more(c, v)
			}
		}
	}
	vmPool := privmode.StepFirecrackerWarmPool
	return []chartGapRow{
		{name: "Firecracker", flags: []string{"--set", fcOn}, chart: "worker.firecracker.enabled"},
		{name: "Firecracker in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_ENABLE_FIRECRACKER=true"},
			chart: "worker.extraEnv.SB_ENABLE_FIRECRACKER"},
		{name: "Firecracker's VM pool", flags: []string{"--set", fcOn, "--set", "worker.extraEnv.SB_FIRECRACKER_VMM_POOL_ENABLED=true"},
			chart: "worker.firecracker.enabled", env: "SB_FIRECRACKER_VMM_POOL_ENABLED",
			set: fc(func(c *config.Config, v string) { c.FirecrackerVMMPoolEnabled = isTrue(v) }), step: vmPool},
		{name: "Firecracker without the jailer", flags: []string{"--set", fcOn, "--set", "worker.extraEnv.SB_FIRECRACKER_USE_JAILER=false"},
			chart: "worker.firecracker.enabled", env: "SB_FIRECRACKER_USE_JAILER",
			set: fc(func(c *config.Config, v string) { c.UseJailer = isTrue(v) }), want: "SB_FIRECRACKER_USE_JAILER=true"},
	}
}

// Every gap checkPrivilegeMode can name has a chart row, read from its
// source: a new gap fails here until the chart refuses it too. No Helm.
func TestChartRefusalsCoverEveryDaemonGap(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "privilege_mode.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	byName := privmodeSteps(t)
	var steps []privmode.Step
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "checkPrivilegeMode" && fn.Name.Name != "checkSplitWasm") {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// privmode.Step* constants; privmode.Step alone is the type.
			if x, isIdent := sel.X.(*ast.Ident); isIdent && x.Name == "privmode" && strings.HasPrefix(sel.Sel.Name, "Step") && sel.Sel.Name != "Step" {
				s, ok := byName[sel.Sel.Name]
				if !ok {
					t.Fatalf("privmode.%s is not a Step constant in internal/privmode/privmode.go", sel.Sel.Name)
				}
				steps = append(steps, s)
			}
			return true
		})
	}
	if len(steps) == 0 {
		t.Fatal("found no privmode step in checkPrivilegeMode")
	}
	covered := map[privmode.Step]bool{}
	for _, r := range chartGapRows() {
		covered[r.step] = true
	}
	for _, s := range steps {
		if !covered[s] {
			t.Errorf("checkPrivilegeMode refuses %s in split, and no chart value is refused for it: add it to aerolvm.splitGaps "+
				"(charts/aerolvm/templates/_privilegemode.tpl) and a row here", s)
		}
	}
}

// privmodeSteps maps each privmode Step constant's name to its value, read
// from internal/privmode/privmode.go, so a step added or renamed there
// needs no change here.
func privmodeSteps(t *testing.T) map[string]privmode.Step {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "internal", "privmode", "privmode.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]privmode.Step{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if typ, isIdent := vs.Type.(*ast.Ident); !ok || !isIdent || typ.Name != "Step" {
				continue
			}
			for i, name := range vs.Names {
				if lit, isLit := vs.Values[i].(*ast.BasicLit); isLit && lit.Kind == token.STRING {
					out[name.Name] = privmode.Step(strings.Trim(lit.Value, `"`))
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("read no Step constant from internal/privmode/privmode.go")
	}
	return out
}

// Each row's value fails `helm template` with privilegeMode split, naming
// the value; rendered in single, the setting it makes is one split refuses
// as the row says.
func TestChartRefusesWhatSplitRefuses(t *testing.T) {
	helm := chartHelm(t)
	// sandboxd in the WASM worker group, as checkSplitWasm needs.
	old := agentGroups
	agentGroups = func() ([]int, error) { return []int{61000}, nil }
	t.Cleanup(func() { agentGroups = old })
	for _, r := range chartGapRows() {
		t.Run(r.name, func(t *testing.T) {
			_, err := renderChart(helm, append([]string{"--set", "privilegeMode=split"}, r.flags...)...)
			if err == nil || !strings.Contains(err.Error(), "privilegeMode split cannot run") || !strings.Contains(err.Error(), r.chart) {
				t.Fatalf("split with %v: err = %v, want a refusal naming %s", r.flags, err, r.chart)
			}
			if r.env == "" {
				return
			}
			out, err := renderChart(helm, r.flags...)
			if err != nil {
				t.Fatalf("single with %v: %v", r.flags, err)
			}
			env := workerEnv(t, out, "agent")
			v, ok := env[r.env]
			if !ok {
				t.Fatalf("single with %v renders no %s", r.flags, r.env)
			}
			cfg := splitConfig()
			r.set(&cfg, v)
			err = checkPrivilegeMode(cfg)
			var g *privmode.Gap
			switch {
			case r.step != "" && (!errors.As(err, &g) || !slices.Contains(g.Steps, r.step)):
				t.Fatalf("%s=%s in split: err = %v, want the gap %s", r.env, v, err, r.step)
			case r.want != "" && (err == nil || !strings.Contains(err.Error(), r.want)):
				t.Fatalf("%s=%s in split: err = %v, want %q", r.env, v, err, r.want)
			}
		})
	}
}

// What a split worker gets is what sandboxd starts with: the settings
// checkPrivilegeMode reads, as the chart renders them for split, in single
// and cluster mode, with and without the edge.
func TestChartSplitWorkerStarts(t *testing.T) {
	helm := chartHelm(t)
	edge := []string{"--set", "edge.enabled=true", "--set", "edge.domain=aerolvm.test", "--set", "edge.certManager.issuerRef.name=ci"}
	enterprise := append(slices.Clone(chartClusterFlags), "--set", "identity.enabled=true", "--set", "enterprise.enabled=true",
		"--set", "audit.witness.bucket=w", "--set", "audit.export.backend=s3", "--set", "audit.export.s3.bucket=a")
	for name, flags := range map[string][]string{
		"single": nil, "single edge": edge, "cluster": chartClusterFlags, "cluster edge": append(slices.Clone(chartClusterFlags), edge...),
		"enterprise": enterprise, "enterprise edge": append(slices.Clone(enterprise), edge...),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, append([]string{"--set", "privilegeMode=split"}, flags...)...)
			if err != nil {
				t.Fatal(err)
			}
			env := workerEnv(t, out, "agent")
			cfg := config.Config{PrivilegeMode: privmode.Split, ContainerEngine: env["SB_CONTAINER_ENGINE"],
				ContainerdNativeNetnsPoolEnabled: isTrue(env["SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED"]),
				ContainerdPoolEnabled:            isTrue(env["SB_CONTAINERD_POOL_ENABLED"]),
				GvisorCheckpointMoves:            isTrue(env["SB_GVISOR_CHECKPOINT_MOVES"]),
				EnableFirecracker:                isTrue(env["SB_ENABLE_FIRECRACKER"]),
				EnableWasm:                       isTrue(env["SB_ENABLE_WASM"]),
				EnableIsolate:                    isTrue(env["SB_ENABLE_ISOLATE"])}
			if env["SB_PRIVILEGE_MODE"] != "split" || cfg.ContainerEngine != models.ContainerEngineContainerd {
				t.Fatalf("split worker env: SB_PRIVILEGE_MODE=%q SB_CONTAINER_ENGINE=%q", env["SB_PRIVILEGE_MODE"], cfg.ContainerEngine)
			}
			if err := checkPrivilegeMode(cfg); err != nil {
				t.Fatalf("sandboxd refuses the split worker the chart renders: %v", err)
			}
			// The helper reads the settings it shares with sandboxd from its
			// own environment: each one the agent sets, the runtime
			// container sets to the same value. The toolbox path is the
			// helper's own copy (SB_ROOTD_TOOLBOX_SOURCE instead).
			runtime := workerEnv(t, out, "runtime")
			for _, k := range rootdSettings(t) {
				if v, ok := env[k]; ok && k != "SB_TOOLBOX_BINARY_PATH" && runtime[k] != v {
					t.Errorf("%s: the agent has %q, the root helper %q", k, v, runtime[k])
				}
			}
			if runtime["SB_ROOTD_AGENT_UID"] != "65531" || runtime["SB_ROOTD_SOCKET"] != env["SB_ROOTD_SOCKET"] {
				t.Errorf("the helper serves uid %q on %q; the agent dials %q", runtime["SB_ROOTD_AGENT_UID"], runtime["SB_ROOTD_SOCKET"], env["SB_ROOTD_SOCKET"])
			}
			// Enterprise mode's public API socket goes to the edge's group,
			// which a split agent, not root, can give a file only when it is
			// in that group.
			if g := env["SB_PUBLIC_API_SOCKET_GROUP"]; g != "" {
				groups, _ := dig(workerSpec(t, out), "securityContext")["supplementalGroups"].([]any)
				if !slices.ContainsFunc(groups, func(v any) bool { return fmt.Sprint(v) == g }) {
					t.Errorf("SB_PUBLIC_API_SOCKET_GROUP=%s, but the pod's supplementalGroups are %v", g, groups)
				}
			}
		})
	}
}

// In a split worker no root process writes in a folder the agent can write
// (plan §3.3, "root-read paths live in root's folders"). Every container
// that starts as root (the runtime container, the egress container before
// it drops to 65532, split-folders, and any other) mounts each volume the
// agent writes read only, or not at all. Two pairs are allowed, each for
// its reason below. The set of root containers is pinned, so a new one, or
// an edge made root, fails here until someone looks at its folders. The
// one machine folder is the agent's read-only cgroup tree.
func TestChartSplitRootWritesNoAgentFolder(t *testing.T) {
	helm := chartHelm(t)
	// Root container and volume pairs that may share a volume the agent
	// writes.
	allowed := map[string]bool{
		// The shared folder's top is root's (split-folders makes it 0750
		// root:65531), and the agent writes only in its own folder there,
		// where root never writes.
		"runtime/rootd-shared": true,
		// split-folders runs before every other container. In these two it
		// sets the volume's own top folder, its mount point, which no
		// container can swap for another file; and it makes the agent's
		// folder in the shared folder only after that folder's top is
		// root's.
		"split-folders/state":        true,
		"split-folders/rootd-shared": true,
	}
	edge := []string{"--set", "edge.enabled=true", "--set", "edge.domain=aerolvm.test", "--set", "edge.certManager.issuerRef.name=ci"}
	for name, flags := range map[string][]string{"single": edge, "cluster": append(slices.Clone(chartClusterFlags), edge...)} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, append([]string{"--set", "privilegeMode=split"}, flags...)...)
			if err != nil {
				t.Fatal(err)
			}
			spec := workerSpec(t, out)
			type mount struct {
				path string
				rw   bool
			}
			type container struct {
				mounts map[string]mount
				env    map[string]string
				root   bool
			}
			all := map[string]container{}
			for _, list := range []string{"initContainers", "containers"} {
				cs, _ := spec[list].([]any)
				for _, c := range cs {
					m, _ := c.(map[string]any)
					sc, _ := m["securityContext"].(map[string]any)
					// No user of its own means the image's user, root in
					// every image here.
					user := fmt.Sprint(sc["runAsUser"])
					privileged, _ := sc["privileged"].(bool)
					ctr := container{mounts: map[string]mount{}, env: map[string]string{}, root: privileged || user == "0" || user == "<nil>"}
					vms, _ := m["volumeMounts"].([]any)
					for _, v := range vms {
						vm, _ := v.(map[string]any)
						ro, _ := vm["readOnly"].(bool)
						ctr.mounts[fmt.Sprint(vm["name"])] = mount{path: fmt.Sprint(vm["mountPath"]), rw: !ro}
					}
					env, _ := m["env"].([]any)
					for _, e := range env {
						kv, _ := e.(map[string]any)
						ctr.env[fmt.Sprint(kv["name"])] = fmt.Sprint(kv["value"])
					}
					all[fmt.Sprint(m["name"])] = ctr
				}
			}
			agent := all["agent"]
			var roots []string
			for name, c := range all {
				if !c.root {
					continue
				}
				roots = append(roots, name)
				for vol, m := range c.mounts {
					if m.rw && agent.mounts[vol].rw && !allowed[name+"/"+vol] {
						t.Errorf("%s starts as root and writes volume %s, which the agent writes", name, vol)
					}
				}
			}
			slices.Sort(roots)
			if want := []string{"egress", "runtime", "split-folders"}; !slices.Equal(roots, want) {
				t.Errorf("containers that start as root: %v, want %v", roots, want)
			}
			if _, ok := all["runtime"].mounts["state"]; ok {
				t.Error("the runtime container mounts sandboxd's state volume")
			}
			if init := all["split-folders"].mounts; !init["rootd-shared"].rw || !init["state"].rw || !init["cni-state"].rw || !init["run-egress"].rw {
				t.Errorf("split-folders mounts %v", init)
			}
			// The egress gateway's control socket: the agent dials it in a
			// folder the egress container writes and the agent reads only.
			sock := agent.env["SB_EGRESS_GATEWAY_SOCKET"]
			if sock == "" || all["egress"].env["SB_EGRESS_GATEWAY_SOCKET"] != sock {
				t.Errorf("gateway socket: agent %q, egress %q", sock, all["egress"].env["SB_EGRESS_GATEWAY_SOCKET"])
			}
			placed := false
			for vol, m := range all["egress"].mounts {
				if m.rw && filepath.Dir(sock) == m.path {
					a, ok := agent.mounts[vol]
					placed = ok && !a.rw && a.path == m.path
				}
			}
			if !placed {
				t.Errorf("the gateway socket %s is not in a folder the egress container writes and the agent reads only", sock)
			}
			vols, _ := spec["volumes"].([]any)
			for _, v := range vols {
				vm, _ := v.(map[string]any)
				if hp := dig(vm, "hostPath"); hp != nil && (vm["name"] != "host-cgroup" || agent.mounts["host-cgroup"].rw || hp["path"] != "/sys/fs/cgroup") {
					t.Errorf("machine folder %v", vm)
				}
			}
		})
	}
}

// Single renders none of split: no setting, no helper, a privileged agent.
func TestChartSingleHasNoSplit(t *testing.T) {
	helm := chartHelm(t)
	for name, flags := range map[string][]string{"single": nil, "cluster": chartClusterFlags} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, flags...)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{"SB_PRIVILEGE_MODE", "SB_ROOTD_", "rootd-shared", "host-cgroup", "runAsUser: 65531", "split-folders", "run-runtime", "run-egress", "SB_EGRESS_GATEWAY_SOCKET"} {
				if strings.Contains(out, bad) {
					t.Errorf("single renders %q", bad)
				}
			}
			if !strings.Contains(out, "privileged: true") {
				t.Error("single renders no privileged agent")
			}
		})
	}
}

// rootdSettings are the SB_ names the root helper reads, from its config's
// source.
func rootdSettings(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "rootd", "config.go"))
	if err != nil {
		t.Fatal(err)
	}
	names := regexp.MustCompile(`"(SB_[A-Z0-9_]+)"`).FindAllStringSubmatch(string(raw), -1)
	var out []string
	for _, m := range names {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	if len(out) < 20 {
		t.Fatalf("read %d settings from the helper's config; its source changed shape", len(out))
	}
	return out
}

// chartHelm is Helm (HELM, or on PATH). Without it the chart tests skip,
// unless AEROLVM_CHART_TOOLS=require (the kubernetes CI job).
func chartHelm(t *testing.T) string {
	t.Helper()
	path := os.Getenv("HELM")
	if path == "" {
		path, _ = exec.LookPath("helm")
	}
	if path == "" {
		if os.Getenv("AEROLVM_CHART_TOOLS") == "require" {
			t.Fatal("helm not found (set HELM or put it on PATH)")
		}
		t.Skip("helm not found; set HELM or AEROLVM_CHART_TOOLS=require")
	}
	// The chart needs Helm 3.8 or later (scripts/k8s-dev.sh).
	out, err := exec.Command(path, "version", "--template", "{{.Version}}").Output()
	var major, minor int
	if _, serr := fmt.Sscanf(strings.TrimSpace(string(out)), "v%d.%d", &major, &minor); err != nil || serr != nil || major != 3 || minor < 8 {
		if os.Getenv("AEROLVM_CHART_TOOLS") == "require" {
			t.Fatalf("helm %q is not 3.8 or later", strings.TrimSpace(string(out)))
		}
		t.Skipf("helm %q is not 3.8 or later; set HELM", strings.TrimSpace(string(out)))
	}
	return path
}

// renderChart is `helm template` of charts/aerolvm with args.
func renderChart(helm string, args ...string) (string, error) {
	cmd := exec.Command(helm, append([]string{"template", "t", filepath.Join("..", "..", "charts", "aerolvm"), "--namespace", "aerolvm-system"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// workerEnv is one container's plain env values in the rendered worker
// pod: the single-mode StatefulSet's, or cluster mode's worker template.
func workerEnv(t *testing.T, rendered, container string) map[string]string {
	t.Helper()
	spec := workerSpec(t, rendered)
	cs, _ := spec["containers"].([]any)
	for _, c := range cs {
		m, _ := c.(map[string]any)
		if m["name"] != container {
			continue
		}
		env := map[string]string{}
		list, _ := m["env"].([]any)
		for _, e := range list {
			kv, _ := e.(map[string]any)
			if name, ok := kv["name"].(string); ok {
				if v, ok := kv["value"]; ok {
					env[name] = fmt.Sprint(v)
				}
			}
		}
		return env
	}
	t.Fatalf("the worker pod has no %s container", container)
	return nil
}

// workerSpec is the rendered worker pod's spec.
func workerSpec(t *testing.T, rendered string) map[string]any {
	t.Helper()
	var spec map[string]any
	dec := yaml.NewDecoder(strings.NewReader(rendered))
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		switch doc["kind"] {
		case "StatefulSet":
			spec = dig(doc, "spec", "template", "spec")
		case "ConfigMap":
			name, _ := dig(doc, "metadata")["name"].(string)
			worker, _ := dig(doc, "data")["worker"].(string)
			if strings.HasSuffix(name, "-pod-templates") {
				var tmpl map[string]any
				if err := yaml.Unmarshal([]byte(worker), &tmpl); err != nil {
					t.Fatal(err)
				}
				spec = dig(tmpl, "spec")
			}
		}
	}
	if spec == nil {
		t.Fatal("rendered no worker pod")
	}
	return spec
}

func dig(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		next, _ := m[k].(map[string]any)
		if next == nil {
			return nil
		}
		m = next
	}
	return m
}
