package main

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// `aerolvm upgrade plan` (plans/kubectl-style-cluster-ops.md §6.1): what
// apply would do, from the members list and the target's release.json. It
// changes nothing. The order and batches it prints are the rules the leader
// follows (§6.2); the leader still decides at run time (a node that goes
// down later is skipped then).

// planStepEstimate is the time one node step (or one worker batch) takes:
// stop, swap, start and the leader's health check. [estimated: the Phase 3a
// gate measured 4 s for the swap itself; the health wait dominates.]
const planStepEstimate = time.Minute

// planRuntimes is §6.4: what a running sandbox sees while sandboxd restarts.
var planRuntimes = [][2]string{
	{"containerd, docker, gVisor sandboxes", "keep running; sandboxd adopts them again"},
	{"Firecracker VMs", "keep running (moved out of sandboxd's cgroup first)"},
	{"external-storage mounts", "keep serving (their helpers run in their own cgroup)"},
	// Measured live (T14, single-node-wasm-isolate): neither survives.
	{"WASM sandboxes", "STOP: marked stopped; `aerolvm start` keeps their files but may not run them again; passivatable ones fail their checkpoint"},
	{"V8-isolate sandboxes", "are LOST: sandboxd deletes them when it starts again"},
	{"toolboxd in running sandboxes", "the old one keeps running; new sandboxes get the new one"},
	{"the node's sandboxd API", "down for a few seconds while sandboxd restarts"},
	{"Caddy", "restarts only when its file changes"},
}

type upgradePlan struct {
	Target                string            `json:"target_version"`
	Mode                  string            `json:"mode"`
	Source                string            `json:"source"`
	Files                 []string          `json:"files"`
	Release               *release.Metadata `json:"release,omitempty"`
	Nodes                 []planNode        `json:"nodes"`
	Allowed               bool              `json:"allowed"`
	Refusals              []string          `json:"refusals,omitempty"`
	Warnings              []string          `json:"warnings,omitempty"`
	Skew                  planSkew          `json:"skew"`
	OneWayMigrations      []int             `json:"one_way_migrations"`
	RollbackAfterFinalize bool              `json:"rollback_after_finalize"`
	HostSetup             string            `json:"host_setup"`
	EgressGateway         string            `json:"egress_gateway"`
	Batch                 string            `json:"batch,omitempty"`
	BatchSize             int               `json:"batch_size,omitempty"`
	Tiers                 []planTier        `json:"tiers"`
	RestartLosers         planLosers        `json:"restart_losers"`
}

// planLosers counts the sandboxes a node restart stops or loses (WASM and
// V8 isolate, planRuntimes), so plan can say how many before anything runs.
type planLosers struct {
	WASM    int  `json:"wasm"`
	Isolate int  `json:"isolate"`
	Counted bool `json:"counted"`
	// Capped is set when the count stopped at maxLoserPages pages: the
	// numbers are then a lower bound.
	Capped bool `json:"capped,omitempty"`
}

type planNode struct {
	NodeID  string `json:"node_id"`
	Role    string `json:"role"`
	Version string `json:"version"`
	Alive   bool   `json:"alive"`
	Voter   bool   `json:"voter,omitempty"`
	Leader  bool   `json:"leader,omitempty"`
	Tier    string `json:"tier"`
	Order   int    `json:"order,omitempty"`
	Batch   int    `json:"batch,omitempty"`
	Action  string `json:"action"`
}

type planSkew struct {
	UpgradeFromMin string `json:"upgrade_from_min,omitempty"`
	// Below are node versions the target does not accept straight; Steps
	// are the releases to go through first, oldest first.
	Below []string `json:"below,omitempty"`
	Steps []string `json:"steps,omitempty"`
	// Unordered are node versions that are not release tags (dev builds).
	Unordered []string `json:"unordered,omitempty"`
}

type planTier struct {
	Name     string `json:"name"`
	Nodes    int    `json:"nodes"`
	Steps    int    `json:"steps"`
	Estimate string `json:"estimate"`
}

const (
	tierServers = "servers"
	tierIngress = "ingress"
	tierWorkers = "workers"
	tierNode    = "node"

	actionUpgrade  = "upgrade"
	actionOnTarget = "skip: already on the target"
	actionDown     = "skip: down (upgraded when it is back)"
)

func runUpgradePlan(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("upgrade plan")
	var from, releaseURL, archFlag, batch, output string
	var pauseAfter int
	var unversioned bool
	fs.StringVar(&from, "from", "", "")
	fs.StringVar(&releaseURL, "release-url", "", "")
	fs.StringVar(&archFlag, "arch", "", "")
	fs.StringVar(&batch, "batch", "", "")
	fs.IntVar(&pauseAfter, "pause-after", 0, "")
	fs.BoolVar(&unversioned, "allow-unversioned", false, "")
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "upgrade", err)
	}
	if len(pos) != 1 {
		return a.usageError(c, "upgrade", "plan needs one version, such as `aerolvm upgrade plan v0.6.12`")
	}
	version := pos[0]
	if code := a.checkUpgradeVersion(c, version, unversioned); code >= 0 {
		return code
	}
	format, ok := outputFormat(c, output, "json", "yaml")
	if !ok {
		return a.usageError(c, "upgrade", "-o must be json or yaml, got %q", format)
	}
	if batch != "" {
		if err := checkBatch(batch); err != nil {
			return a.usageError(c, "upgrade", "%v", err)
		}
	}
	if pauseAfter < 0 {
		return a.usageError(c, "upgrade", "--pause-after must not be negative")
	}
	arches, err := parseArches(archFlag)
	if err != nil {
		return a.usageError(c, "upgrade", "%v", err)
	}
	set, err := a.loadSource(ctx, c, from, releaseURL, version, arches)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	defer set.cleanup()
	t, err := a.upgradeTarget(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	p := upgradePlan{Target: version, Release: set.meta, Files: set.sortedFiles(), Mode: "single-node"}
	if set.offline() {
		p.Source = "files from " + set.origin + " (uploaded by apply)"
	} else {
		p.Source = "release " + set.origin + " (each node downloads it)"
	}
	if t.cluster {
		p.Mode = "cluster"
		nodes, err := a.listNodes(ctx, c)
		if err != nil {
			return a.fail(c, err, exitError)
		}
		p.planCluster(nodes, batch, pauseAfter)
	} else {
		p.planSingle(t.version)
	}
	fetch := a.releaseFetcher(c, releaseURL)
	p.judge(ctx, fetch, set)
	p.countLosers(countRestartLosers(ctx, a, c))
	if format != "" {
		a.printValue(format, p)
	} else {
		a.printPlan(p)
	}
	if !p.Allowed {
		return exitError
	}
	return exitOK
}

func (p *upgradePlan) planSingle(running string) {
	n := planNode{NodeID: "this node", Role: "single node", Version: running, Alive: true, Tier: tierNode, Order: 1, Action: actionUpgrade}
	steps := 1
	if running == p.Target {
		n.Action, n.Order, steps = actionOnTarget, 0, 0
	}
	p.Nodes = []planNode{n}
	p.Tiers = []planTier{{Name: tierNode, Nodes: 1, Steps: steps, Estimate: estimate(steps)}}
	p.Warnings = append(p.Warnings, "a single node's API is down while sandboxd restarts; its sandboxes keep running")
}

// tierOf maps a role to its tier. A node with no role is an older build,
// which sandboxd reads as mixed: a Raft server that also runs sandboxes.
func tierOf(role string) string {
	switch role {
	case "ingress":
		return tierIngress
	case "worker":
		return tierWorkers
	}
	return tierServers
}

func (p *upgradePlan) planCluster(nodes []nodeRaw, batch string, pauseAfter int) {
	byTier := map[string][]planNode{}
	voters, votersDown := 0, 0
	var down []string
	for _, nr := range nodes {
		r := nr.rec
		n := planNode{NodeID: r.NodeID, Role: r.role(), Version: r.Version, Alive: r.Alive, Voter: r.Voter, Leader: r.Leader, Tier: tierOf(r.Role)}
		switch {
		case !r.Alive:
			n.Action = actionDown
			down = append(down, r.NodeID)
		case r.Version == p.Target:
			n.Action = actionOnTarget
		default:
			n.Action = actionUpgrade
		}
		if r.Voter {
			voters++
			if !r.Alive {
				votersDown++
			}
		}
		byTier[n.Tier] = append(byTier[n.Tier], n)
	}
	// Servers: the leader goes last, after handing off leadership (§6.2).
	servers := byTier[tierServers]
	sort.SliceStable(servers, func(i, j int) bool {
		if servers[i].Leader != servers[j].Leader {
			return !servers[i].Leader
		}
		return servers[i].NodeID < servers[j].NodeID
	})
	ingress := byTier[tierIngress]
	sort.Slice(ingress, func(i, j int) bool { return ingress[i].NodeID < ingress[j].NodeID })
	workers := byTier[tierWorkers]
	sort.Slice(workers, func(i, j int) bool { return workers[i].NodeID < workers[j].NodeID })

	order := 0
	steps := map[string]int{}
	for _, list := range [][]planNode{servers, ingress} {
		for i := range list {
			if list[i].Action == actionUpgrade {
				order++
				list[i].Order = order
				steps[list[i].Tier]++
			}
		}
	}
	p.Batch = batch
	if p.Batch == "" {
		p.Batch = "10%"
	}
	p.BatchSize = batchSize(p.Batch, len(workers))
	batchNo, inBatch, size := 0, 0, p.BatchSize
	if pauseAfter > 0 {
		size = min(size, pauseAfter)
	}
	for i := range workers {
		if workers[i].Action != actionUpgrade {
			continue
		}
		if batchNo == 0 || inBatch == size {
			batchNo++
			inBatch = 0
			if batchNo > 1 {
				size = p.BatchSize
			}
		}
		inBatch++
		order++
		workers[i].Order = order
		workers[i].Batch = batchNo
	}
	steps[tierWorkers] = batchNo
	p.Nodes = append(append(append([]planNode{}, servers...), ingress...), workers...)
	for _, tier := range []string{tierServers, tierIngress, tierWorkers} {
		list := byTier[tier]
		if len(list) == 0 {
			continue
		}
		p.Tiers = append(p.Tiers, planTier{Name: tier, Nodes: len(list), Steps: steps[tier], Estimate: estimate(steps[tier])})
	}
	if pauseAfter > 0 && batchNo > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("the rollout pauses after the first %d worker(s); go on with: aerolvm upgrade resume", min(pauseAfter, p.BatchSize)))
	}
	switch {
	case voters == 1:
		p.Warnings = append(p.Warnings, "this cluster has one Raft server: the API is down while it restarts (sandboxes keep running); apply needs --allow-downtime")
	case voters == 2 && votersDown == 0:
		p.Warnings = append(p.Warnings, "this cluster has two Raft servers: while either one restarts, one of two is up, which is no majority, so the API is down during each server restart (sandboxes keep running); apply needs --allow-downtime")
	}
	if votersDown > 0 && voters-votersDown-1 <= voters/2 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("%d of %d Raft servers are down: restarting another would lose the majority, so the rollout will fail at the servers; bring them back or delete them first", votersDown, voters))
	}
	if len(down) > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("down nodes are skipped and upgraded when they come back; finalize waits for them: %s", strings.Join(down, ", ")))
	}
}

func estimate(steps int) string {
	if steps == 0 {
		return "nothing to do"
	}
	return "about " + minutes(time.Duration(steps)*planStepEstimate)
}

func minutes(d time.Duration) string {
	return fmt.Sprintf("%d min", int((d+time.Minute-1)/time.Minute))
}

// metaFetcher reads a published release's release.json; nil, nil when it
// has none.
type metaFetcher interface {
	meta(ctx context.Context, version, sum string) (*release.Metadata, error)
}

// judge fills in the checks that need release.json: skew, downgrades,
// one-way migrations, host setup and the egress gateway.
func (p *upgradePlan) judge(ctx context.Context, fetch metaFetcher, set *releaseSet) {
	p.HostSetup, p.EgressGateway = "unknown", "unknown"
	p.OneWayMigrations = []int{}
	p.RollbackAfterFinalize = true
	target, targetErr := release.ParseVersion(p.Target)
	var versions []string
	seen := map[string]bool{}
	for _, n := range p.Nodes {
		if !n.Alive || n.Version == "" || seen[n.Version] {
			continue
		}
		seen[n.Version] = true
		versions = append(versions, n.Version)
		v, err := release.ParseVersion(n.Version)
		if err != nil || targetErr != nil {
			p.Skew.Unordered = append(p.Skew.Unordered, n.Version)
			continue
		}
		if v.Compare(target) > 0 {
			p.Refusals = append(p.Refusals, fmt.Sprintf("%s is older than %s, which runs on a node; going back is: aerolvm upgrade rollback", p.Target, n.Version))
		}
	}
	sort.Strings(versions)
	if len(p.Skew.Unordered) > 0 {
		sort.Strings(p.Skew.Unordered)
		p.Warnings = append(p.Warnings, fmt.Sprintf("the version order can't be checked for %s (not a release tag); apply needs --allow-unversioned",
			strings.Join(p.Skew.Unordered, ", ")))
	}
	m := set.meta
	if m == nil {
		p.Warnings = append(p.Warnings, p.Target+" has no release.json: the skew, migration, host-setup and gateway checks are skipped")
		p.Allowed = len(p.Refusals) == 0
		return
	}
	p.Skew.UpgradeFromMin = m.UpgradeFromMin
	p.Skew.Below = belowFloor(m, versions)
	if len(p.Skew.Below) > 0 {
		p.Skew.Steps = stepChain(ctx, fetch, m, lowest(p.Skew.Below))
		p.Refusals = append(p.Refusals, fmt.Sprintf("%s can't be reached straight from %s (it needs %s or later); step through %s",
			p.Target, strings.Join(p.Skew.Below, ", "), m.UpgradeFromMin, strings.Join(append(append([]string{}, p.Skew.Steps...), p.Target), ", then ")))
	}
	if len(m.OneWayMigrations) > 0 {
		p.OneWayMigrations = m.OneWayMigrations
		p.RollbackAfterFinalize = false
	}
	if m.HostSetupNeedsNetwork && set.offline() {
		p.Refusals = append(p.Refusals, p.Target+"'s host setup needs packages or network access, so it can't be applied from --from or a bundle")
	}
	// What the nodes run now, from their own release.json files.
	var current []*release.Metadata
	known := true
	for _, v := range versions {
		if _, err := release.ParseVersion(v); err != nil || v == p.Target {
			continue
		}
		cm, err := fetch.meta(ctx, v, "")
		if err != nil || cm == nil {
			known = false
			continue
		}
		current = append(current, cm)
	}
	if known && len(current) > 0 {
		p.HostSetup, p.EgressGateway = "unchanged", "stays up"
	}
	for _, cm := range current {
		if cm.HostSetupSHA256 != m.HostSetupSHA256 {
			p.HostSetup = "changes"
		}
		if speaks := slices.Max(cm.EgressGatewayProtocol); !slices.Contains(m.EgressGatewayProtocol, speaks) {
			p.EgressGateway = "restarts"
		}
	}
	p.Allowed = len(p.Refusals) == 0
}

func lowest(versions []string) string {
	out := versions[0]
	for _, v := range versions[1:] {
		if c, err := release.CompareVersions(v, out); err == nil && c < 0 {
			out = v
		}
	}
	return out
}

// stepChain walks back from the target through each release's
// upgrade_from_min until one accepts from, and returns those releases,
// oldest first. It stops where a release.json can't be read (a release
// older than release.json itself): that release is the first hop.
func stepChain(ctx context.Context, fetch metaFetcher, m *release.Metadata, from string) []string {
	var steps []string
	for i := 0; i < 16 && m != nil; i++ {
		floor := m.UpgradeFromMin
		if slices.Contains(steps, floor) {
			break
		}
		steps = append([]string{floor}, steps...)
		next, err := fetch.meta(ctx, floor, "")
		if err != nil || next == nil || next.UpgradeAllowedFrom(from) == nil {
			break
		}
		m = next
	}
	return steps
}

func (a *app) printPlan(p upgradePlan) {
	alive := 0
	for _, n := range p.Nodes {
		if n.Alive {
			alive++
		}
	}
	fmt.Fprintf(a.stdout, "Upgrade plan: %s (%s, %d node(s), %d up)\n", p.Target, p.Mode, len(p.Nodes), alive)
	fmt.Fprintf(a.stdout, "Source: %s; %d file(s) checked against checksums.txt\n\n", p.Source, len(p.Files))

	tw := tabwriter.NewWriter(a.stdout, 0, 4, 3, ' ', 0)
	fmt.Fprintln(tw, "ORDER\tNODE\tROLE\tVERSION\tSTATUS\tBATCH\tACTION")
	for _, n := range p.Nodes {
		status := "NotReady"
		if n.Alive {
			status = "Ready"
		}
		if n.Leader {
			status += ",Leader"
		}
		order, batch := "-", "-"
		if n.Order > 0 {
			order = strconv.Itoa(n.Order)
		}
		if n.Batch > 0 {
			batch = strconv.Itoa(n.Batch)
		}
		action := n.Action
		if n.Leader && n.Action == actionUpgrade {
			action += " (last server: it hands off leadership first)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", order, n.NodeID, n.Role, dash(n.Version), status, batch, action)
	}
	_ = tw.Flush()

	fmt.Fprintln(a.stdout)
	tw = tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	skew := "not checked (no release.json)"
	switch {
	case len(p.Skew.Below) > 0:
		skew = fmt.Sprintf("REFUSED: needs %s or later; step through %s", p.Skew.UpgradeFromMin,
			strings.Join(append(append([]string{}, p.Skew.Steps...), p.Target), ", then "))
	case p.Skew.UpgradeFromMin != "":
		skew = "allowed (upgrade_from_min " + p.Skew.UpgradeFromMin + ")"
	}
	migrations := "none: rollback works until finalize"
	if len(p.OneWayMigrations) > 0 {
		nums := make([]string, len(p.OneWayMigrations))
		for i, n := range p.OneWayMigrations {
			nums[i] = strconv.Itoa(n)
		}
		migrations = "finalize runs " + strings.Join(nums, ", ") + ": after finalize there is no rollback"
		if p.Mode == "single-node" {
			migrations = "the new sandboxd runs " + strings.Join(nums, ", ") + " when it starts: after that only the database backup takes it back"
		}
	} else if p.Release == nil {
		migrations = "unknown (no release.json)"
	}
	host := p.HostSetup
	switch p.HostSetup {
	case "changes":
		host = "changes: each node runs the new install.sh in config-only mode"
	case "unknown":
		host = "unknown (the running release's release.json can't be read)"
	}
	if p.Release != nil && p.Release.HostSetupNeedsNetwork {
		host += "; needs packages or network access"
	}
	gateway := p.EgressGateway
	switch p.EgressGateway {
	case "restarts":
		gateway = "restarts on each node: hostname-filtered sandboxes pause briefly"
	case "unknown":
		gateway = "unknown (each node decides when it upgrades)"
	}
	rows := [][2]string{
		{"Version skew:", skew},
		{"One-way migrations:", migrations},
		{"Host setup:", host},
		{"Egress gateway:", gateway},
	}
	if p.Mode == "cluster" {
		rows = append(rows, [2]string{"Worker batches:", fmt.Sprintf("%s, %d worker(s) per batch", p.Batch, p.BatchSize)})
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r[0], r[1])
	}
	_ = tw.Flush()

	fmt.Fprintf(a.stdout, "\nEstimated time (about %s per step):\n", minutes(planStepEstimate))
	tw = tabwriter.NewWriter(a.stdout, 0, 4, 3, ' ', 0)
	for _, t := range p.Tiers {
		steps := fmt.Sprintf("%d step(s), one node at a time", t.Steps)
		if t.Name == tierWorkers {
			steps = fmt.Sprintf("%d batch(es)", t.Steps)
		}
		fmt.Fprintf(tw, "  %s\t%d node(s)\t%s\t%s\n", t.Name, t.Nodes, steps, t.Estimate)
	}
	_ = tw.Flush()

	fmt.Fprintln(a.stdout, "\nWhat a running sandbox sees while sandboxd restarts, on every node:")
	tw = tabwriter.NewWriter(a.stdout, 0, 4, 3, ' ', 0)
	for _, r := range planRuntimes {
		fmt.Fprintf(tw, "  %s\t%s\n", r[0], r[1])
	}
	_ = tw.Flush()

	if len(p.Warnings) > 0 {
		fmt.Fprintln(a.stdout, "\nWarnings:")
		for _, w := range p.Warnings {
			fmt.Fprintf(a.stdout, "  - %s\n", w)
		}
	}
	if len(p.Refusals) > 0 {
		fmt.Fprintln(a.stdout, "\nRefused:")
		for _, r := range p.Refusals {
			fmt.Fprintf(a.stdout, "  - %s\n", r)
		}
		fmt.Fprintln(a.stdout, "\napply would be refused.")
		return
	}
	fmt.Fprintf(a.stdout, "\nTo go ahead: aerolvm upgrade apply %s\n", p.Target)
}

// maxLoserPages bounds countRestartLosers' list pass: plan is a read-only
// look, and a fleet of 100k sandboxes should not make it slow.
const maxLoserPages = 40

// countRestartLosers lists sandboxes once and counts the WASM and isolate
// ones. Tests replace it.
var countRestartLosers = func(ctx context.Context, a *app, c *commonFlags) (planLosers, error) {
	tools, err := a.tools(ctx, c)
	if err != nil {
		return planLosers{}, err
	}
	var out planLosers
	token := ""
	seen := map[string]bool{}
	for page := 0; ; page++ {
		if page == maxLoserPages {
			out.Capped = true
			break
		}
		items, next, err := tools.Client().ListPage(ctx, token, microvm.WithLimit(sandboxListPage))
		if err != nil {
			return planLosers{}, err
		}
		for _, sb := range items {
			switch sb.Runtime {
			case models.RuntimeWasm:
				out.WASM++
			case models.RuntimeIsolate:
				out.Isolate++
			}
		}
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		token = next
	}
	out.Counted = true
	return out, nil
}

// countLosers records the count and warns when a restart would stop or lose
// any sandbox. A failed count is a warning too: plan never hides it.
func (p *upgradePlan) countLosers(l planLosers, err error) {
	if err != nil {
		p.Warnings = append(p.Warnings, "could not count WASM and V8-isolate sandboxes ("+err.Error()+"); a node restart stops or loses them")
		return
	}
	p.RestartLosers = l
	if l.WASM+l.Isolate == 0 {
		return
	}
	atLeast := ""
	if l.Capped {
		atLeast = "at least "
	}
	p.Warnings = append(p.Warnings, fmt.Sprintf("%s%d WASM and %d V8-isolate sandbox(es) run now: each node's restart stops its WASM sandboxes and deletes its isolate sandboxes", atLeast, l.WASM, l.Isolate))
}
