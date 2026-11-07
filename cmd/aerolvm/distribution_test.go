package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/aerol-ai/microvm/internal/agenttools/agenttoolstest"
)

// These tests keep what ships around the binary honest about the binary
// (plans/mcp-server-and-agent-cli.md §5.8, CEO review C2/C3): the Claude Code
// plugin and its skill, the npm package and launcher, and the MCP Registry
// server.json. Each names verbs, flags, env vars or packages that must exist.

const repoRoot = "../.."

// releaseTargets are the GOOS/GOARCH pairs release.yml builds aerolvm for,
// with npm's name for each. The npm launcher, its optionalDependencies and
// npm/stage.mjs all have to agree with this list.
var releaseTargets = []struct{ goos, goarch, npmOS, npmCPU string }{
	{"darwin", "amd64", "darwin", "x64"},
	{"darwin", "arm64", "darwin", "arm64"},
	{"linux", "amd64", "linux", "x64"},
	{"linux", "arm64", "linux", "arm64"},
	{"windows", "amd64", "win32", "x64"},
	{"windows", "arm64", "win32", "arm64"},
}

func readRepoJSON(t *testing.T, rel string, v any) {
	t.Helper()
	readJSONFile(t, filepath.Join(repoRoot, rel), v)
}

// readJSONFile decodes strictly: a field the test's struct doesn't know is
// an error, so a new manifest key gets looked at here.
func readJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// allHelp is every help text the CLI prints, where a documented flag or
// env var must appear.
func allHelp() string {
	a := &app{}
	var b strings.Builder
	b.WriteString(a.overview())
	for _, v := range a.verbs() {
		b.WriteString(v.help)
	}
	return b.String()
}

type pluginManifest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Author      struct{ Name, URL string }
	Homepage    string   `json:"homepage"`
	Repository  string   `json:"repository"`
	License     string   `json:"license"`
	Keywords    []string `json:"keywords"`
	MCPServers  map[string]struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
	} `json:"mcpServers"`
	UserConfig map[string]struct {
		Type        string `json:"type"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Required    bool   `json:"required"`
		Sensitive   bool   `json:"sensitive"`
	} `json:"userConfig"`
}

func TestClaudeCodePluginManifests(t *testing.T) {
	var market struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Owner       struct{ Name, URL string }
		Plugins     []struct {
			Name        string   `json:"name"`
			Source      string   `json:"source"`
			Description string   `json:"description"`
			Category    string   `json:"category"`
			Tags        []string `json:"tags"`
		} `json:"plugins"`
	}
	readRepoJSON(t, ".claude-plugin/marketplace.json", &market)
	if market.Name == "" || market.Owner.Name == "" || len(market.Plugins) != 1 {
		t.Fatalf("marketplace = %+v", market)
	}
	entry := market.Plugins[0]
	if entry.Name != "aerolvm" || !strings.HasPrefix(entry.Source, "./") {
		t.Fatalf("plugin entry = %+v", entry)
	}

	var plugin pluginManifest
	readRepoJSON(t, filepath.Join(entry.Source, ".claude-plugin/plugin.json"), &plugin)
	if plugin.Name != entry.Name {
		t.Fatalf("plugin.json name %q, marketplace entry %q", plugin.Name, entry.Name)
	}
	server, ok := plugin.MCPServers["aerolvm"]
	if !ok || server.Command != "aerolvm" || !slices.Equal(server.Args, []string{"mcp"}) {
		t.Fatalf("mcpServers = %+v", plugin.MCPServers)
	}
	help := allHelp()
	ref := regexp.MustCompile(`\$\{user_config\.([A-Za-z_][A-Za-z0-9_]*)\}`)
	for name, value := range server.Env {
		if !strings.Contains(help, name) {
			t.Errorf("env %s is not a variable aerolvm documents", name)
		}
		for _, m := range ref.FindAllStringSubmatch(value, -1) {
			if _, ok := plugin.UserConfig[m[1]]; !ok {
				t.Errorf("env %s references undeclared user_config.%s", name, m[1])
			}
		}
	}
	if tok, ok := plugin.UserConfig["api_token"]; !ok || !tok.Sensitive {
		t.Fatalf("api_token must be a sensitive userConfig option: %+v", plugin.UserConfig)
	}
	for key, opt := range plugin.UserConfig {
		if opt.Type == "" || opt.Title == "" || opt.Description == "" {
			t.Errorf("userConfig %s needs type, title and description", key)
		}
	}
}

// TestPluginSkillNamesRealVerbs is the CEO review C2 check: the skill may
// only teach verbs, flags and MCP tools that exist.
func TestPluginSkillNamesRealVerbs(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "plugins/aerolvm/skills/aerolvm/SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	skill := string(b)
	if !strings.HasPrefix(skill, "---\nname: aerolvm\ndescription: ") {
		t.Fatal("SKILL.md must open with name and description frontmatter")
	}

	var verbs []string
	for _, v := range (&app{}).verbs() {
		verbs = append(verbs, v.name)
	}
	help := allHelp()
	command := regexp.MustCompile(`\baerolvm ([a-z][a-z-]*)`)
	flag := regexp.MustCompile(`(?:^|\s)(--[a-z][a-z-]*)`)
	commands := 0
	for _, code := range codeIn(skill) {
		for _, line := range strings.Split(code, "\n") {
			i := strings.Index(line, "aerolvm ")
			if i < 0 {
				continue
			}
			cmd := line[i:]
			// Flags after a bare "--" belong to the command run in the
			// sandbox, not to aerolvm.
			if j := strings.Index(cmd, " -- "); j >= 0 {
				cmd = cmd[:j]
			}
			for _, m := range command.FindAllStringSubmatch(cmd, -1) {
				commands++
				if !slices.Contains(verbs, m[1]) {
					t.Errorf("SKILL.md runs %q, but aerolvm has no %q verb", m[0], m[1])
				}
			}
			for _, m := range flag.FindAllStringSubmatch(cmd, -1) {
				if !strings.Contains(help, m[1]) {
					t.Errorf("SKILL.md uses %s, which no aerolvm help text mentions", m[1])
				}
			}
		}
	}
	if commands < 5 {
		t.Fatalf("found only %d aerolvm commands in SKILL.md code; is the parser broken?", commands)
	}

	var tools []struct {
		Name string `json:"name"`
	}
	golden, err := os.ReadFile(filepath.Join(repoRoot, "internal/agentmcp/testdata/tools_unpinned_all.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(golden, &tools); err != nil {
		t.Fatal(err)
	}
	var toolNames []string
	for _, tool := range tools {
		toolNames = append(toolNames, tool.Name)
	}
	for _, name := range regexp.MustCompile(`\b[a-z]+_[a-z_]+\b`).FindAllString(skill, -1) {
		if !slices.Contains(toolNames, name) {
			t.Errorf("SKILL.md names MCP tool %q, which aerolvm mcp does not offer", name)
		}
	}
}

// codeIn returns the fenced blocks and inline code spans of a Markdown text.
func codeIn(md string) []string {
	var out []string
	parts := strings.Split(md, "```")
	for i, part := range parts {
		if i%2 == 1 {
			out = append(out, part)
			continue
		}
		spans := strings.Split(part, "`")
		for j := 1; j < len(spans); j += 2 {
			out = append(out, spans[j])
		}
	}
	return out
}

type npmPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Description          string            `json:"description"`
	License              string            `json:"license"`
	Repository           map[string]string `json:"repository"`
	Homepage             string            `json:"homepage"`
	Keywords             []string          `json:"keywords"`
	MCPName              string            `json:"mcpName"`
	Bin                  map[string]string `json:"bin"`
	Files                []string          `json:"files"`
	Engines              map[string]string `json:"engines"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PublishConfig        map[string]string `json:"publishConfig"`
}

func TestNPMPackageMatchesReleaseTargets(t *testing.T) {
	var pkg npmPackage
	readRepoJSON(t, "npm/aerolvm/package.json", &pkg)
	if pkg.Bin["aerolvm"] != "aerolvm.js" || !slices.Contains(pkg.Files, "aerolvm.js") {
		t.Fatalf("bin = %v, files = %v", pkg.Bin, pkg.Files)
	}
	for _, f := range pkg.Files {
		if _, err := os.Stat(filepath.Join(repoRoot, "npm/aerolvm", f)); err != nil {
			t.Errorf("files lists %s: %v", f, err)
		}
	}
	// The repo holds placeholders; the release stamps the tag into all of
	// them (npm/stage.mjs, and the registry job for server.json).
	if pkg.Version != "0.0.0" {
		t.Errorf("npm/aerolvm/package.json version = %q, want the 0.0.0 placeholder", pkg.Version)
	}
	var want []string
	for _, target := range releaseTargets {
		want = append(want, pkg.Name+"-"+target.npmOS+"-"+target.npmCPU)
	}
	var got []string
	for name, version := range pkg.OptionalDependencies {
		got = append(got, name)
		if version != pkg.Version {
			t.Errorf("optionalDependencies %s = %q, want %q", name, version, pkg.Version)
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("optionalDependencies = %v, want %v", got, want)
	}

	release, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	loop := regexp.MustCompile(`for target in ([a-z0-9/ ]+); do`).FindSubmatch(release)
	if loop == nil {
		t.Fatal("release.yml has no `for target in ...; do` loop building aerolvm")
	}
	var built []string
	for _, target := range releaseTargets {
		built = append(built, target.goos+"/"+target.goarch)
	}
	gotBuilt := strings.Fields(string(loop[1]))
	slices.Sort(built)
	slices.Sort(gotBuilt)
	if !slices.Equal(gotBuilt, built) {
		t.Fatalf("release.yml builds %v, npm expects %v", gotBuilt, built)
	}
}

func TestMCPRegistryServerJSON(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	// testdata/mcp-server.schema.json is the 2025-12-11 registry schema,
	// vendored so this stays offline; the release job also runs
	// `mcp-publisher validate` against the live registry rules.
	schemaJSON, err := os.ReadFile("testdata/mcp-server.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	var instance map[string]any
	if err := json.Unmarshal(raw, &instance); err != nil {
		t.Fatal(err)
	}
	if err := resolved.Validate(instance); err != nil {
		t.Fatalf("server.json does not match the registry schema: %v", err)
	}
	if instance["$schema"] != schema.ID {
		t.Fatalf("server.json $schema = %v, want %s", instance["$schema"], schema.ID)
	}

	var server struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Packages []struct {
			RegistryType     string `json:"registryType"`
			Identifier       string `json:"identifier"`
			Version          string `json:"version"`
			Transport        struct{ Type string }
			PackageArguments []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"packageArguments"`
			EnvironmentVariables []struct {
				Name     string `json:"name"`
				IsSecret bool   `json:"isSecret"`
			} `json:"environmentVariables"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	var pkg npmPackage
	readRepoJSON(t, "npm/aerolvm/package.json", &pkg)
	if len(server.Packages) != 1 {
		t.Fatalf("packages = %+v", server.Packages)
	}
	p := server.Packages[0]
	// The registry accepts the npm package only if its mcpName is the
	// server name.
	if server.Name != pkg.MCPName || p.RegistryType != "npm" || p.Identifier != pkg.Name {
		t.Fatalf("server.json %s → %s %s; package.json %s has mcpName %q", server.Name, p.RegistryType, p.Identifier, pkg.Name, pkg.MCPName)
	}
	if server.Version != "0.0.0" || p.Version != "0.0.0" {
		t.Fatalf("server.json versions = %q/%q, want the 0.0.0 placeholders", server.Version, p.Version)
	}
	if p.Transport.Type != "stdio" || len(p.PackageArguments) != 1 || p.PackageArguments[0].Value != "mcp" {
		t.Fatalf("package runs as %+v %+v, want stdio `aerolvm mcp`", p.Transport, p.PackageArguments)
	}
	help := allHelp()
	for _, env := range p.EnvironmentVariables {
		if !strings.Contains(help, env.Name) {
			t.Errorf("env %s is not a variable aerolvm documents", env.Name)
		}
		if env.Name == "SB_PAT_TOKEN" && !env.IsSecret {
			t.Error("SB_PAT_TOKEN must be isSecret")
		}
	}
}

// TestNPMLauncher stages the npm packages with npm/stage.mjs, installs the
// launcher and this platform's binary package into a node_modules tree, and
// runs the real binary through node: stdout, exit codes and a SIGTERM sent
// to the launcher alone all pass through.
func TestNPMLauncher(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary and runs node")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	var host *struct{ goos, goarch, npmOS, npmCPU string }
	for i := range releaseTargets {
		if releaseTargets[i].goos == runtime.GOOS && releaseTargets[i].goarch == runtime.GOARCH {
			host = &releaseTargets[i]
		}
	}
	if host == nil || runtime.GOOS == "windows" {
		t.Skipf("no npm package for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	dist := t.TempDir()
	for _, target := range releaseTargets {
		name := "aerolvm_" + target.goos + "_" + target.goarch
		if target.goos == "windows" {
			name += ".exe"
		}
		if target != *host {
			// Only this platform's binary runs; the others must just exist.
			if err := os.WriteFile(filepath.Join(dist, name), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		build := exec.Command("go", "build", "-ldflags", "-X github.com/aerol-ai/microvm/internal/version.Version=v1.2.3", "-o", filepath.Join(dist, name), ".")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
	}
	staged := t.TempDir()
	if out, err := exec.Command(node, filepath.Join(repoRoot, "npm/stage.mjs"), "v1.2.3", dist, staged).CombinedOutput(); err != nil {
		t.Fatalf("stage: %v\n%s", err, out)
	}
	order, err := os.ReadFile(filepath.Join(staged, "order.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Fields(string(order)); len(lines) != len(releaseTargets)+1 || lines[len(lines)-1] != "aerolvm" {
		t.Fatalf("publish order = %v, want every platform package before the launcher", lines)
	}
	var launcherPkg npmPackage
	readJSONFile(t, filepath.Join(staged, "aerolvm/package.json"), &launcherPkg)
	if launcherPkg.Version != "1.2.3" || launcherPkg.OptionalDependencies["@aerol-ai/"+"aerolvm-"+host.npmOS+"-"+host.npmCPU] != "1.2.3" {
		t.Fatalf("staged launcher = %+v, want version 1.2.3 everywhere", launcherPkg)
	}

	modules := filepath.Join(t.TempDir(), "node_modules", "@aerol-ai")
	platformPkg := "aerolvm-" + host.npmOS + "-" + host.npmCPU
	for _, dir := range []string{"aerolvm", platformPkg} {
		if err := os.CopyFS(filepath.Join(modules, dir), os.DirFS(filepath.Join(staged, dir))); err != nil {
			t.Fatal(err)
		}
	}
	launcher := filepath.Join(modules, "aerolvm", "aerolvm.js")

	run := func(args ...string) (stdout, stderr string, code int) {
		t.Helper()
		cmd := exec.Command(node, append([]string{launcher}, args...)...)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); ok {
			return out.String(), errb.String(), exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return out.String(), errb.String(), 0
	}
	if out, _, code := run("version"); code != 0 || strings.TrimSpace(out) != "v1.2.3" {
		t.Fatalf("version through the launcher = %q, exit %d", out, code)
	}
	if out, _, code := run("no-such-verb"); code != exitUsage || out != "" {
		t.Fatalf("usage error through the launcher: stdout %q, exit %d; want nothing and %d", out, code, exitUsage)
	}

	t.Run("sigterm-to-launcher", func(t *testing.T) {
		fake := agenttoolstest.New(t)
		cmd := exec.Command(node, launcher, "mcp", "--sandbox", "my-agent", "--create-if-missing", "--ephemeral")
		checkEphemeralShutdown(t, cmd, fake, "sigterm")
	})

	if err := os.RemoveAll(filepath.Join(modules, platformPkg)); err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := run("version"); code != 1 || out != "" || !strings.Contains(stderr, "@aerol-ai/"+platformPkg) {
		t.Fatalf("missing platform package: stdout %q, stderr %q, exit %d", out, stderr, code)
	}
}
