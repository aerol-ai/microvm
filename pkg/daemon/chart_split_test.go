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
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/privmode"
	"github.com/aerol-ai/microvm/internal/rootd"
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
	return append(firecrackerGapRows(), []chartGapRow{
		{name: "the Docker engine", flags: []string{"--set", "worker.extraEnv.SB_CONTAINER_ENGINE=docker"},
			chart: "worker.extraEnv.SB_CONTAINER_ENGINE", env: "SB_CONTAINER_ENGINE",
			set: func(c *config.Config, v string) { c.ContainerEngine = v }, want: "SB_CONTAINER_ENGINE=containerd"},
		{name: "no netns pool", flags: []string{"--set", "worker.extraEnv.SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=false"},
			chart: "worker.extraEnv.SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED", env: "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED",
			set: func(c *config.Config, v string) { c.ContainerdNativeNetnsPoolEnabled = isTrue(v) }, want: "SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED"},
		// Kubernetes rows: worker pod wiring. WASM and V8 isolates run in a
		// split worker pod through worker.wasm.enabled and
		// worker.isolate.enabled (TestChartSplitHosts); turned on in
		// extraEnv they would get none of the pod's wiring for them.
		{name: "WASM in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_ENABLE_WASM=true"}, chart: "worker.extraEnv.SB_ENABLE_WASM"},
		{name: "V8 isolates in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_ENABLE_ISOLATE=true"}, chart: "worker.extraEnv.SB_ENABLE_ISOLATE"},
		{name: "a helper setting in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_ROOTD_AGENT_UID=1"}, chart: "worker.extraEnv.SB_ROOTD_AGENT_UID"},
	}...)
}

// firecrackerGapRows are the chart's Firecracker refusals. The chart refuses
// worker.firecracker.enabled whole in split: it does not wire Firecracker
// into a split worker pod, and no live run has proven it, so the first two
// rows are the chart's alone. sandboxd's own refusal is narrower (M1 PRs
// 9b, #1425, #1426, PR 18): one without the jailer is never split; the VM
// pool and disk images run in split since PR 18.
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
	return []chartGapRow{
		{name: "Firecracker", flags: []string{"--set", fcOn}, chart: "worker.firecracker.enabled"},
		{name: "Firecracker in extraEnv", flags: []string{"--set", "worker.extraEnv.SB_ENABLE_FIRECRACKER=true"},
			chart: "worker.extraEnv.SB_ENABLE_FIRECRACKER"},
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
	found := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || (fn.Name.Name != "checkPrivilegeMode" && fn.Name.Name != "checkSplitWasm") {
			continue
		}
		found++
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
	// Since M1 PR 18 checkPrivilegeMode names no step; the two functions
	// must still be there, or this test reads nothing.
	if found != 2 {
		t.Fatalf("found %d of checkPrivilegeMode and checkSplitWasm in privilege_mode.go", found)
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
	// M1 PR 13: gVisor moves, the containerd warm pool, the agent-sandbox
	// API's warm pools that park in it, and the helper's move limits.
	moves := []string{"--set", "worker.gvisor.checkpointMoves=true", "--set", "worker.extraEnv.SB_CONTAINERD_POOL_ENABLED=true",
		"--set", "worker.extraEnv.SB_ROOTD_MOVE_MAX_BYTES=1073741824", "--set", "worker.extraEnv.SB_ROOTD_MOVE_MAX_STAGED=2"}
	hosts := []string{"--set", "worker.wasm.enabled=true", "--set", "worker.isolate.enabled=true"}
	for name, flags := range map[string][]string{
		"single": nil, "single edge": edge, "cluster": chartClusterFlags, "cluster edge": append(slices.Clone(chartClusterFlags), edge...),
		"enterprise": enterprise, "enterprise edge": append(slices.Clone(enterprise), edge...),
		"moves and warm pool": moves,
		"cluster agent-sandbox API": append(slices.Clone(chartClusterFlags), "--set", "cluster.agentSandboxAPI.enabled=true",
			"--set", "worker.gvisor.checkpointMoves=true"),
		"WASM and V8 isolates": hosts, "cluster WASM and V8 isolates": append(slices.Clone(chartClusterFlags), hosts...),
		"enterprise WASM and V8 isolates": append(append(slices.Clone(enterprise), edge...), hosts...),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, append([]string{"--set", "privilegeMode=split"}, flags...)...)
			if err != nil {
				t.Fatal(err)
			}
			env := workerEnv(t, out, "agent")
			// sandboxd's own defaults (config.Load) where the chart sets
			// nothing.
			boolOr := func(k string, def bool) bool {
				if v, ok := env[k]; ok {
					return isTrue(v)
				}
				return def
			}
			cfg := config.Config{PrivilegeMode: privmode.Split, ContainerEngine: env["SB_CONTAINER_ENGINE"],
				ContainerdNativeNetnsPoolEnabled: isTrue(env["SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED"]),
				ContainerdPoolEnabled:            isTrue(env["SB_CONTAINERD_POOL_ENABLED"]),
				GvisorCheckpointMoves:            isTrue(env["SB_GVISOR_CHECKPOINT_MOVES"]),
				EnableFirecracker:                isTrue(env["SB_ENABLE_FIRECRACKER"]),
				EnableWasm:                       isTrue(env["SB_ENABLE_WASM"]),
				EnableIsolate:                    isTrue(env["SB_ENABLE_ISOLATE"]),
				IsolateUseJail:                   boolOr("SB_ISOLATE_USE_JAIL", true),
				WasmWorkerDropPrivs:              boolOr("SB_WASM_WORKER_DROP_PRIVS", true),
				WasmWorkerUID:                    config.DefaultWasmWorkerID, WasmWorkerGID: config.DefaultWasmWorkerID}
			// sandboxd's groups are the ones the container runtime gives
			// the agent: its own, the groups its image lists for its user,
			// and the pod's supplemental groups. A WASM worker needs it in
			// the workers' group (checkSplitWasm).
			spec := workerSpec(t, out)
			groups := append([]int{65531}, agentImageGroups(t, 65531)...)
			sup, _ := dig(spec, "securityContext")["supplementalGroups"].([]any)
			for _, g := range sup {
				if n, ok := g.(int); ok {
					groups = append(groups, n)
				}
			}
			old := agentGroups
			agentGroups = func() ([]int, error) { return groups, nil }
			t.Cleanup(func() { agentGroups = old })
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

// agentImageGroups are the groups the agent image's /etc/group lists for
// the user its /etc/passwd names uid: the groups a container running the
// image as uid gets besides its own (containerd and CRI-O read them from
// the image). Read from the lines packaging/images/aerolvm.Dockerfile
// writes.
func agentImageGroups(t *testing.T, uid int) []int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "images", "aerolvm.Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	name := ""
	for _, m := range regexp.MustCompile(`'([a-z][a-z0-9-]*):x:(\d+):\d+:[^':]*:[^':]*:[^':]*'`).FindAllStringSubmatch(string(raw), -1) {
		if m[2] == strconv.Itoa(uid) {
			name = m[1]
		}
	}
	if name == "" {
		return nil
	}
	var out []int
	for _, m := range regexp.MustCompile(`'[a-z][a-z0-9-]*:x:(\d+):([a-z0-9,-]*)'`).FindAllStringSubmatch(string(raw), -1) {
		if slices.Contains(strings.Split(m[2], ","), name) {
			n, _ := strconv.Atoi(m[1])
			out = append(out, n)
		}
	}
	return out
}

// The WASM workers' group reaches the split agent alone (review of PR
// 1441): the agent image lists the agent's uid in it, and the pod gives it
// to no container. No other container runs the agent's uid, so none gets
// the image's groups for it.
func TestChartSplitWasmGroupIsTheAgentsAlone(t *testing.T) {
	helm := chartHelm(t)
	if g := agentImageGroups(t, 65531); !slices.Contains(g, config.DefaultWasmWorkerID) {
		t.Fatalf("the agent image lists uid 65531 in groups %v, want the WASM workers' %d", g, config.DefaultWasmWorkerID)
	}
	for _, uid := range []int{0, 65532} {
		if g := agentImageGroups(t, uid); len(g) != 0 {
			t.Errorf("the agent image lists uid %d in groups %v", uid, g)
		}
	}
	wasm := []string{"--set", "privilegeMode=split", "--set", "worker.wasm.enabled=true"}
	for name, flags := range map[string][]string{"single": wasm, "cluster": append(slices.Clone(chartClusterFlags), wasm...)} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, flags...)
			if err != nil {
				t.Fatal(err)
			}
			spec := workerSpec(t, out)
			if sup, ok := dig(spec, "securityContext")["supplementalGroups"]; ok {
				t.Errorf("the pod gives every container groups %v", sup)
			}
			for _, list := range []string{"initContainers", "containers"} {
				cs, _ := spec[list].([]any)
				for _, c := range cs {
					m, _ := c.(map[string]any)
					sc, _ := m["securityContext"].(map[string]any)
					if uid := fmt.Sprint(sc["runAsUser"]); (uid == "65531") != (m["name"] == "agent") {
						t.Errorf("container %s runs as uid %s; only the agent runs as 65531", m["name"], uid)
					}
					if _, ok := sc["supplementalGroups"]; ok {
						t.Errorf("container %s sets its own groups", m["name"])
					}
				}
			}
		})
	}
}

// gVisor moves in split (M1 PR 13): the helper reads the switch from its own
// environment, off by default in split as before and on when set, and its
// moves folder is a folder of containerd's volume, which split-folders makes
// root's alone before the helper checks it. A helper setting other than the
// move limits stays refused in worker.extraEnv.
func TestChartSplitMoves(t *testing.T) {
	helm := chartHelm(t)
	movesDir := filepath.Join(rootd.DefaultStateDir, "moves")
	for _, tc := range []struct {
		name  string
		flags []string
		want  string
	}{
		{"default", nil, "false"},
		{"on", []string{"--set", "worker.gvisor.checkpointMoves=true"}, "true"},
		{"cluster, on", append(slices.Clone(chartClusterFlags), "--set", "worker.gvisor.checkpointMoves=true"), "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderChart(helm, append([]string{"--set", "privilegeMode=split"}, tc.flags...)...)
			if err != nil {
				t.Fatal(err)
			}
			agent, runtime := workerEnv(t, out, "agent"), workerEnv(t, out, "runtime")
			if agent["SB_GVISOR_CHECKPOINT_MOVES"] != tc.want || runtime["SB_GVISOR_CHECKPOINT_MOVES"] != tc.want {
				t.Fatalf("SB_GVISOR_CHECKPOINT_MOVES: agent %q, helper %q, want %q", agent["SB_GVISOR_CHECKPOINT_MOVES"],
					runtime["SB_GVISOR_CHECKPOINT_MOVES"], tc.want)
			}
			spec := workerSpec(t, out)
			mount := func(list, name, path string) map[string]any {
				cs, _ := spec[list].([]any)
				for _, c := range cs {
					m, _ := c.(map[string]any)
					if m["name"] != name {
						continue
					}
					vms, _ := m["volumeMounts"].([]any)
					for _, v := range vms {
						if vm, _ := v.(map[string]any); vm["mountPath"] == path {
							return vm
						}
					}
				}
				return nil
			}
			helper := mount("containers", "runtime", movesDir)
			if helper == nil || helper["name"] != "containerd" || helper["subPath"] == nil || helper["readOnly"] == true {
				t.Fatalf("the helper's moves folder %s is mounted as %v, want a writable folder of containerd's volume", movesDir, helper)
			}
			init := mount("initContainers", "split-folders", "/var/lib/aerolvm-rootd-moves")
			if init == nil || init["name"] != "containerd" || init["subPath"] != helper["subPath"] {
				t.Fatalf("split-folders mounts the moves folder as %v, the helper as %v", init, helper)
			}
			if !strings.Contains(out, "chown 0:0 /var/lib/aerolvm-rootd-moves") || !strings.Contains(out, "chmod 0700 /var/lib/aerolvm-rootd-moves") {
				t.Error("split-folders does not make the moves folder root's alone")
			}
			if mount("containers", "agent", movesDir) != nil {
				t.Error("the agent mounts the helper's moves folder")
			}
		})
	}
	_, err := renderChart(helm, "--set", "privilegeMode=split", "--set", "worker.extraEnv.SB_ROOTD_RUNSC=/tmp/runsc")
	if err == nil || !strings.Contains(err.Error(), "worker.extraEnv.SB_ROOTD_RUNSC") {
		t.Fatalf("split with SB_ROOTD_RUNSC in extraEnv: err = %v, want a refusal naming it", err)
	}
}

// WASM and V8 isolates in a split worker pod: the root helper starts their
// hosts in the runtime container, so the pod shares no process namespace,
// and the two containers meet only where the helper's rules allow, as on a
// VM (scripts/install.sh isolate_environment, split_environment):
//
//   - the WASM hosts' sockets are in a folder of the helper's on the
//     shared folder, at one path in both containers, outside the agent's
//     own folder; the compile cache is in the agent's own folder there;
//   - the V8 jail's base is outside every folder the agent writes, root's
//     (split-folders), two-way from the runtime container only, and read
//     only in the agent, which takes the helper's mounts in;
//   - workerd comes from a volume only a root init container with no
//     capability writes, read only in the runtime container, never in the
//     agent.
//
// The root helper then loads the runtime container's settings as they are,
// with both host kinds on.
func TestChartSplitHosts(t *testing.T) {
	helm := chartHelm(t)
	hosts := []string{"--set", "privilegeMode=split", "--set", "worker.wasm.enabled=true", "--set", "worker.isolate.enabled=true"}
	for name, flags := range map[string][]string{"single": hosts, "cluster": append(slices.Clone(chartClusterFlags), hosts...)} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, flags...)
			if err != nil {
				t.Fatal(err)
			}
			spec := workerSpec(t, out)
			if v, _ := spec["shareProcessNamespace"].(bool); v {
				t.Error("a split worker shares one process namespace")
			}
			type mount struct {
				vol, path, propagation string
				ro                     bool
			}
			containers := map[string][]mount{}
			scripts := map[string]string{}
			for _, list := range []string{"initContainers", "containers"} {
				cs, _ := spec[list].([]any)
				for _, c := range cs {
					m, _ := c.(map[string]any)
					name := fmt.Sprint(m["name"])
					vms, _ := m["volumeMounts"].([]any)
					for _, v := range vms {
						vm, _ := v.(map[string]any)
						ro, _ := vm["readOnly"].(bool)
						p, _ := vm["mountPropagation"].(string)
						containers[name] = append(containers[name], mount{vol: fmt.Sprint(vm["name"]), path: fmt.Sprint(vm["mountPath"]), propagation: p, ro: ro})
					}
					args, _ := m["args"].([]any)
					for _, a := range args {
						scripts[name] += fmt.Sprint(a)
					}
				}
			}
			// mountOf is the container's mount whose folder holds path.
			mountOf := func(c, path string) (mount, bool) {
				var best mount
				for _, m := range containers[c] {
					if (path == m.path || strings.HasPrefix(path, m.path+"/")) && len(m.path) > len(best.path) {
						best = m
					}
				}
				return best, best.path != ""
			}
			agent, runtime := workerEnv(t, out, "agent"), workerEnv(t, out, "runtime")

			sockets, cache, own := runtime["SB_ROOTD_WASM_SOCKET_DIR"], runtime["SB_WASM_COMPILE_CACHE_DIR"], agent["SB_MOUNTS_CRED_DIR"]
			if sockets == "" || agent["SB_ROOTD_WASM_SOCKET_DIR"] != sockets || cache == "" || agent["SB_WASM_COMPILE_CACHE_DIR"] != cache {
				t.Fatalf("WASM: sockets %q / %q, cache %q / %q (helper / agent)", sockets, agent["SB_ROOTD_WASM_SOCKET_DIR"], cache, agent["SB_WASM_COMPILE_CACHE_DIR"])
			}
			for _, p := range []string{sockets, cache} {
				a, okA := mountOf("agent", p)
				r, okR := mountOf("runtime", p)
				if !okA || !okR || a.vol != "rootd-shared" || r.vol != "rootd-shared" || a.path != r.path {
					t.Errorf("%s: the agent sees it on %+v, the helper on %+v; want the shared folder at one path", p, a, r)
				}
			}
			if strings.HasPrefix(sockets+"/", own+"/") || !strings.HasPrefix(cache, own+"/") {
				t.Errorf("WASM sockets %s must be outside the agent's own folder %s, its compile cache %s inside", sockets, own, cache)
			}

			base := runtime["SB_ISOLATE_JAIL_CHROOT_BASE"]
			if base == "" || agent["SB_ISOLATE_JAIL_CHROOT_BASE"] != base || runtime["SB_ISOLATE_JAIL_DIR"] != base {
				t.Fatalf("V8 jail base: helper %q, agent %q, supervisor's unmount %q", base, agent["SB_ISOLATE_JAIL_CHROOT_BASE"], runtime["SB_ISOLATE_JAIL_DIR"])
			}
			if agent["SB_ISOLATE_USE_JAIL"] != "true" || runtime["SB_ISOLATE_USE_JAIL"] != "true" {
				t.Error("split writes SB_ISOLATE_USE_JAIL=true for both, as install.sh does")
			}
			r, _ := mountOf("runtime", base)
			a, _ := mountOf("agent", base)
			f, _ := mountOf("split-folders", base)
			if r.path != base || r.vol != "isolate-jail" || r.ro || r.propagation != "Bidirectional" {
				t.Errorf("the helper mounts the jail base as %+v, want its own volume, writable and two-way", r)
			}
			if a.path != base || a.vol != "isolate-jail" || !a.ro || a.propagation != "HostToContainer" {
				t.Errorf("the agent mounts the jail base as %+v, want the same volume, read only, HostToContainer", a)
			}
			for _, m := range containers["agent"] {
				if !m.ro && (base == m.path || strings.HasPrefix(base, m.path+"/")) {
					t.Errorf("the jail base %s is inside %s, which the agent writes", base, m.path)
				}
			}
			if f.path != base || !strings.Contains(scripts["split-folders"], "chown 0:0 "+base+"\n") || !strings.Contains(scripts["split-folders"], "chmod 0755 "+base+"\n") {
				t.Errorf("split-folders does not make the jail base %s root's, closed to others (mount %+v)", base, f)
			}

			workerd := runtime["SB_ISOLATE_WORKERD_PATH"]
			w, _ := mountOf("runtime", workerd)
			c, _ := mountOf("workerd", workerd)
			if workerd == "" || w.vol != "workerd" || !w.ro || c.vol != "workerd" || c.path != w.path || c.ro {
				t.Errorf("workerd %q: the helper reads it from %+v, the init container writes it to %+v", workerd, w, c)
			}
			for _, m := range containers["agent"] {
				if m.vol == "workerd" {
					t.Error("the agent mounts workerd's volume")
				}
			}
			if !strings.Contains(scripts["workerd"], "/usr/local/bin/workerd") {
				t.Error("the workerd init container copies no workerd")
			}
			// The helper runs no program from a folder anyone else can write
			// (rootd checkRootBinaries). The kubelet makes an emptyDir root's
			// and open to everyone, so the init container closes it.
			if dir := filepath.Dir(workerd); w.path != dir || !strings.Contains(scripts["workerd"], "chmod 0755 "+dir+"\n") {
				t.Errorf("the workerd init container leaves workerd's folder %s open to others (mount %+v)", dir, w)
			}

			// The helper's environment is the runtime container's, plus the
			// cgroup parent the supervisor works out (internal/supervisor
			// helperEnv). The node's memory stands in for /proc/meminfo,
			// which this test may not have; the mount tools' user is made by
			// the runtime container's start command, so this machine has
			// none, and external storage is left out.
			cfg, err := rootd.ConfigFromEnv(func(k string) string {
				switch k {
				case "SB_CONTAINERD_CGROUP_PARENT":
					return "/kubepods/pod1/runtime/sandboxes"
				case "SB_HOST_MEMORY_MB":
					return "8192"
				case "SB_ROOTD_MOUNT_USER":
					return ""
				}
				return runtime[k]
			})
			if err != nil {
				t.Fatalf("the root helper refuses the runtime container's settings: %v", err)
			}
			if cfg.Hosts.Wasm == nil || cfg.Hosts.Wasm.SocketDir != sockets || cfg.Hosts.Wasm.CacheRoot != cache || cfg.Hosts.Wasm.GID != config.DefaultWasmWorkerID {
				t.Errorf("helper's WASM hosts = %+v", cfg.Hosts.Wasm)
			}
			if cfg.Hosts.Workerd == nil || cfg.Hosts.Workerd.Jail.ChrootBase != base || cfg.Hosts.Workerd.Jail.WorkerdPath != workerd {
				t.Errorf("helper's V8 hosts = %+v", cfg.Hosts.Workerd)
			}
		})
	}
	// The helper's V8 jail limit is one the operator may set, as its move
	// limits: worker.extraEnv reaches the runtime container.
	out, err := renderChart(helm, append(slices.Clone(hosts), "--set-string", "worker.extraEnv.SB_ROOTD_ISOLATE_MAX_JAILS=100")...)
	if err != nil {
		t.Fatalf("split with SB_ROOTD_ISOLATE_MAX_JAILS in extraEnv: %v", err)
	}
	if v := workerEnv(t, out, "runtime")["SB_ROOTD_ISOLATE_MAX_JAILS"]; v != "100" {
		t.Fatalf("the helper's SB_ROOTD_ISOLATE_MAX_JAILS = %q, want 100", v)
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
	// WASM and V8 isolates add one root container, workerd, which copies
	// workerd into a volume of its own that the agent never mounts.
	hosts := append(slices.Clone(edge), "--set", "worker.wasm.enabled=true", "--set", "worker.isolate.enabled=true")
	for name, flags := range map[string][]string{"single": edge, "cluster": append(slices.Clone(chartClusterFlags), edge...),
		"WASM and V8 isolates": hosts, "cluster WASM and V8 isolates": append(slices.Clone(chartClusterFlags), hosts...)} {
		t.Run(name, func(t *testing.T) {
			wantRoots := []string{"egress", "runtime", "split-folders"}
			if slices.Contains(flags, "worker.isolate.enabled=true") {
				wantRoots = []string{"egress", "runtime", "split-folders", "workerd"}
			}
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
			if !slices.Equal(roots, wantRoots) {
				t.Errorf("containers that start as root: %v, want %v", roots, wantRoots)
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

// A split worker pod sets no fsGroup (it would regroup the folders
// split-folders closes), and its containers run as different users, so
// the kubelet makes every Secret, ConfigMap and projected file root's, in
// root's group. A container that is not root reads such a file only
// through the bit for others: each file the chart gives one must have it.
// (The operator's stamped volumes, the join token and an external-CA
// certificate, are checked in operator/internal/controller, EKS drill
// m1d-1.)
func TestChartSplitNonRootReadsItsFiles(t *testing.T) {
	helm := chartHelm(t)
	edge := []string{"--set", "edge.enabled=true", "--set", "edge.domain=aerolvm.test", "--set", "edge.certManager.issuerRef.name=ci"}
	files := []string{"--set", "worker.registryCA.existingConfigMap=ca", "--set", "identity.enabled=true",
		"--set", "identity.file.content=issuers: []", "--set", "audit.credentials.caBundle.existingConfigMap=aws-ca"}
	enterprise := append(slices.Clone(chartClusterFlags), "--set", "enterprise.enabled=true",
		"--set", "audit.witness.bucket=w", "--set", "audit.export.backend=s3", "--set", "audit.export.s3.bucket=a")
	for name, flags := range map[string][]string{
		"single":     append(slices.Clone(edge), files...),
		"enterprise": append(append(slices.Clone(enterprise), edge...), files...),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, append([]string{"--set", "privilegeMode=split"}, flags...)...)
			if err != nil {
				t.Fatal(err)
			}
			spec := workerSpec(t, out)
			if dig(spec, "securityContext")["fsGroup"] != nil {
				t.Fatal("a split worker pod sets fsGroup")
			}
			// Each file's mode: its item's, else the volume's default,
			// else 0644.
			modes := map[string][]int{}
			vols, _ := spec["volumes"].([]any)
			for _, v := range vols {
				vm, _ := v.(map[string]any)
				for _, kind := range []string{"secret", "configMap", "projected"} {
					src := dig(vm, kind)
					if src == nil {
						continue
					}
					def := 0o644
					if m, ok := src["defaultMode"].(int); ok {
						def = m
					}
					items, _ := src["items"].([]any)
					if kind == "projected" {
						items, _ = src["sources"].([]any)
					}
					fileModes := []int{def}
					for _, it := range items {
						if m, ok := it.(map[string]any)["mode"].(int); ok {
							fileModes = append(fileModes, m)
						}
					}
					modes[fmt.Sprint(vm["name"])] = fileModes
				}
			}
			if len(modes) == 0 {
				t.Fatal("no Secret, ConfigMap or projected volume rendered")
			}
			checked := 0
			for _, list := range []string{"initContainers", "containers"} {
				cs, _ := spec[list].([]any)
				for _, c := range cs {
					m, _ := c.(map[string]any)
					sc, _ := m["securityContext"].(map[string]any)
					if user := fmt.Sprint(sc["runAsUser"]); user == "0" || user == "<nil>" {
						continue
					}
					vms, _ := m["volumeMounts"].([]any)
					for _, x := range vms {
						vol := fmt.Sprint(x.(map[string]any)["name"])
						for _, mode := range modes[vol] {
							checked++
							if mode&0o004 == 0 {
								t.Errorf("%s (uid %v) mounts %s, whose file mode %#o it cannot read", m["name"], sc["runAsUser"], vol, mode)
							}
						}
					}
				}
			}
			if checked == 0 {
				t.Fatal("no non-root container mounts a Secret, ConfigMap or projected volume: the check checked nothing")
			}
		})
	}
}

// Single renders none of split: no setting, no helper, a privileged agent.
// It shares one process namespace exactly when WASM or V8 isolates are on:
// sandboxd starts their hosts in the runtime container's group, and they
// outlive an agent restart only with the namespace shared (C14); without
// them it stays off, so no container reads another's command lines.
func TestChartSingleHasNoSplit(t *testing.T) {
	helm := chartHelm(t)
	wasm, v8 := []string{"--set", "worker.wasm.enabled=true"}, []string{"--set", "worker.isolate.enabled=true"}
	hosts := append(slices.Clone(wasm), v8...)
	cluster := func(flags []string) []string { return append(slices.Clone(chartClusterFlags), flags...) }
	for name, tc := range map[string]struct {
		flags  []string
		shared bool
	}{
		"single": {nil, false}, "cluster": {chartClusterFlags, false},
		"single WASM and V8 isolates": {hosts, true}, "cluster WASM and V8 isolates": {cluster(hosts), true},
		"single WASM": {wasm, true}, "cluster WASM": {cluster(wasm), true},
		"single V8 isolates": {v8, true}, "cluster V8 isolates": {cluster(v8), true},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := renderChart(helm, tc.flags...)
			if err != nil {
				t.Fatal(err)
			}
			if shared, _ := workerSpec(t, out)["shareProcessNamespace"].(bool); shared != tc.shared {
				t.Errorf("the worker pod shares one process namespace: %v, want %v", shared, tc.shared)
			}
			for _, bad := range []string{"SB_PRIVILEGE_MODE", "SB_ROOTD_", "rootd-shared", "host-cgroup", "runAsUser: 65531", "split-folders", "run-runtime", "run-egress", "SB_EGRESS_GATEWAY_SOCKET",
				"/srv/isolate-jail", "HostToContainer", "aerolvm-workerd", "supplementalGroups"} {
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
