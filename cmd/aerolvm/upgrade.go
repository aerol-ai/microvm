package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aerol-ai/microvm/internal/agenttools"
	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

// `aerolvm upgrade` (plans/kubectl-style-cluster-ops.md §6.1). On a cluster
// it writes a rollout to Raft (POST /v1/cluster/upgrade) and the leader
// runs it; on a single node it calls that node's own route (POST
// /v1/node/upgrade), which starts `sandboxd upgrade node` there. The CLI
// tells the two apart from /health: a node in cluster mode always reports
// cluster_topology there, and a single node never does.

const upgradeHelp = `Upgrade sandboxd on every node of a cluster, or on a single node.

Usage: aerolvm upgrade plan <version> [--from <dir>|<bundle.tgz>] [--batch <n|n%>] [--pause-after N]
       aerolvm upgrade apply <version> [--hold] [--batch <n|n%>] [--pause-after N]
                             [--node-timeout 10m] [--from <dir>|<bundle.tgz>]
                             [--allow-downtime] [--wait]
       aerolvm upgrade status
       aerolvm upgrade stop
       aerolvm upgrade resume
       aerolvm upgrade finalize
       aerolvm upgrade rollback [--wait]

plan prints what apply would do, and changes nothing: each node's role and
version, whether the jump is allowed (and the releases to step through when
it is not), the order the nodes go in, what restarts, whether host setup
changes, whether finalize runs one-way schema migrations (no rollback after
that), whether the egress gateway restarts, and a time estimate per tier.
It exits 1 when apply would be refused.

apply checks every file against the release's checksums.txt (or the
bundle's) before anything is sent. On a cluster it hands the rollout to the
leader and returns; the rollout goes on if aerolvm exits. With --wait it
follows the rollout and prints each node's progress, and the command to run
on a node that takes no remote upgrade. On a single node it starts the
upgrade there; --batch, --pause-after and --hold are cluster-only. Running
apply again for the same version is safe: it returns the same rollout, or
does nothing when the node already runs it.

status prints the current rollout (cluster) or the latest node upgrade.
stop finishes the nodes in progress and starts no new one. resume continues
a paused rollout. finalize turns on the new cluster version after a --hold
rollout. rollback puts every node back on the previous version (only before
finalize). Each one succeeds again when repeated.

Flags (plan, apply):
  --from <dir|tgz>     take the files from a directory (with its
                       checksums.txt) or an offline bundle from
                       "aerolvm release pull", and upload them; without it
                       the nodes download the release themselves
  --arch a,b           only these CPU types (default: every one in the
                       source; the nodes pick their own)
  --release-url URL    where releases are published (default GitHub;
                       AEROLVM_RELEASE_URL)
  --batch n|n%         workers per batch, a number or a percentage of the
                       workers rounded up (default 10%, at least 1)
  --pause-after N      cut the first worker batch to N and pause after it
                       (a canary); "aerolvm upgrade resume" goes on
Flags (apply):
  --hold               stop at "done" and wait for "aerolvm upgrade finalize"
  --node-timeout D     how long each node may take (default 10m)
  --allow-downtime     needed when the cluster has one or two Raft servers:
                       the API is down while each restarts (sandboxes keep
                       running)
  --allow-unversioned  allow a dev or test build whose version is not vX.Y.Z
  --wait               follow the rollout until it ends (rollback: too)
  -o json|yaml         print the rollout or operation (also --json)

Needs an admin. A node with SB_REMOTE_UPGRADE=false takes no upgrade over
the API: run "sudo sandboxd upgrade node" on it (status prints the command).

Examples:
  aerolvm upgrade plan v0.7.0
  aerolvm upgrade apply v0.7.0 --wait
  aerolvm upgrade apply v0.7.0 --from aerolvm-v0.7.0.tgz --pause-after 2 --wait
  aerolvm upgrade resume
`

const (
	// upgradeCallTimeout bounds one JSON call to an upgrade route.
	upgradeCallTimeout = 60 * time.Second
	// maxUpgradeResponseBytes bounds a response: a rollout record of a
	// 2,000-node fleet is well under 2 MiB.
	maxUpgradeResponseBytes = 16 << 20
)

func runUpgrade(ctx context.Context, a *app, args []string) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "plan":
		return runUpgradePlan(ctx, a, args)
	case "apply":
		return runUpgradeApply(ctx, a, args)
	case "status":
		return runUpgradeStatus(ctx, a, args)
	case "stop":
		return a.rolloutCommand(ctx, args, "stop", upgradewire.ClusterUpgradeStopPath)
	case "resume":
		return a.rolloutCommand(ctx, args, "resume", upgradewire.ClusterUpgradeResumePath)
	case "finalize":
		return a.rolloutCommand(ctx, args, "finalize", upgradewire.ClusterUpgradeFinalizePath)
	case "rollback":
		return runUpgradeRollback(ctx, a, args)
	case "":
		return a.usageError(nil, "upgrade", "expected a subcommand: plan, apply, status, stop, resume, finalize or rollback")
	}
	return a.usageError(nil, "upgrade", "unknown subcommand %q: expected plan, apply, status, stop, resume, finalize or rollback", sub)
}

// upgradeTarget is the sandboxd the command talks to.
type upgradeTarget struct {
	conn    connection
	cluster bool
	// version is the answering sandboxd's build.
	version string
}

func (a *app) upgradeTarget(ctx context.Context, c *commonFlags) (upgradeTarget, error) {
	conn, err := a.resolve(ctx, c)
	if err != nil {
		return upgradeTarget{}, err
	}
	var health struct {
		Version         string `json:"version"`
		ClusterTopology string `json:"cluster_topology"`
		ClusterNodes    int    `json:"cluster_nodes"`
	}
	if err := a.upgradeGet(ctx, c, conn, "/health", &health); err != nil {
		return upgradeTarget{}, err
	}
	return upgradeTarget{conn: conn, version: health.Version, cluster: health.ClusterTopology != "" || health.ClusterNodes > 0}, nil
}

// upgradeCall is one request to an upgrade route.
type upgradeCall struct {
	method, path string
	in           any       // a JSON body
	body         io.Reader // a raw body (an upload)
	size         int64
	out          any
	timeout      time.Duration
}

var errCodeRe = regexp.MustCompile(`^[a-z][a-z_]*$`)

// upgradeDo sends call and returns the status. A HEAD's 404 is an answer,
// not an error. Any other non-2xx answer is an *agenttools.Error built from
// the upgradewire.ErrorResponse body: its code, its reason as the message,
// its hint.
func (a *app) upgradeDo(ctx context.Context, c *commonFlags, conn connection, call upgradeCall) (int, error) {
	if call.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, call.timeout)
		defer cancel()
	}
	body := call.body
	if call.in != nil {
		raw, err := json.Marshal(call.in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, call.method, strings.TrimRight(conn.apiURL, "/")+call.path, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+conn.token)
	req.Header.Set("Accept", "application/json")
	switch {
	case call.in != nil:
		req.Header.Set("Content-Type", "application/json")
	case call.body != nil:
		req.Header.Set("Content-Type", "application/octet-stream")
		req.ContentLength = call.size
	}
	client := a.apiHTTPClient(c, conn)
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUpgradeResponseBytes))
	if err != nil {
		return resp.StatusCode, err
	}
	if call.method == http.MethodHead && resp.StatusCode == http.StatusNotFound {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, upgradeRefusal(resp.StatusCode, raw)
	}
	if call.out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, call.out); err != nil {
			return resp.StatusCode, fmt.Errorf("sandboxd sent an unreadable response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// upgradeRefusal turns a refusal body into the CLI's error.
func upgradeRefusal(status int, raw []byte) error {
	var e upgradewire.ErrorResponse
	jsonErr := json.Unmarshal(raw, &e)
	if (jsonErr != nil || e.Error == "") && (status == http.StatusNotFound || status == http.StatusMethodNotAllowed) {
		// The route itself is missing: sandboxd predates it.
		return &agenttools.Error{Code: agenttools.CodeServerUnsupported, HTTPStatus: status,
			Message: "this sandboxd has no upgrade API: it is older than the release that added `aerolvm upgrade`",
			Hint:    "upgrade it once with install.sh (docs: \"Upgrade without the repo\"); later upgrades use aerolvm upgrade"}
	}
	code := ""
	if errCodeRe.MatchString(e.Error) {
		code = e.Error
	}
	msg := strings.TrimSpace(e.Reason)
	if msg == "" {
		msg = strings.TrimSpace(e.Error)
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	if len(e.Nodes) > 0 {
		msg += " (nodes: " + strings.Join(e.Nodes, ", ") + ")"
	}
	out := &agenttools.Error{Code: code, Message: msg, HTTPStatus: status, Hint: e.Hint}
	if out.Code == "" {
		out.Code = statusCode(status)
	}
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests:
		out.Retryable = true
	}
	return out
}

// statusCode is the agenttools code for an HTTP status with no code of its
// own in the body.
func statusCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return agenttools.CodeInvalidArgument
	case http.StatusUnauthorized:
		return agenttools.CodeUnauthorized
	case http.StatusForbidden:
		return agenttools.CodeForbidden
	case http.StatusNotFound:
		return agenttools.CodeNotFound
	case http.StatusConflict:
		return agenttools.CodeConflict
	case http.StatusRequestEntityTooLarge:
		return agenttools.CodeTooLarge
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests:
		return agenttools.CodeUnavailable
	}
	return agenttools.CodeInternal
}

// transient is an error worth waiting out while a node restarts: no HTTP
// answer at all, or a gateway or overload status.
func transient(err error) bool {
	var e *agenttools.Error
	if errors.As(err, &e) {
		return e.Retryable
	}
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

// upgradeGet is a GET retried on a dropped connection or a 502/503/504, as
// clusterCall retries reads.
func (a *app) upgradeGet(ctx context.Context, c *commonFlags, conn connection, path string, out any) error {
	for attempt := 0; ; attempt++ {
		_, err := a.upgradeDo(ctx, c, conn, upgradeCall{method: http.MethodGet, path: path, out: out, timeout: upgradeCallTimeout})
		if err == nil || attempt >= len(clusterReadRetryDelays) || !transient(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(clusterReadRetryDelays[attempt]):
		}
	}
}

func isCode(err error, code string) bool {
	var e *agenttools.Error
	return errors.As(err, &e) && e.Code == code
}

// batchRe accepts "3" or "10%".
var batchRe = regexp.MustCompile(`^([0-9]{1,6})(%?)$`)

// checkBatch validates --batch as the server does (CEO D10): a number of
// workers, at least 1, or a percentage from 1% to 100%.
func checkBatch(s string) error {
	m := batchRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return fmt.Errorf("--batch %q is not a number of workers (3) or a percentage (10%%)", s)
	}
	n, _ := strconv.Atoi(m[1])
	switch {
	case n == 0:
		return fmt.Errorf("--batch %s would never upgrade a worker; give at least 1 or 1%%", s)
	case m[2] == "%" && n > 100:
		return fmt.Errorf("--batch %s is more than every worker; give at most 100%%", s)
	}
	return nil
}

// batchSize is how many of workers one batch takes (rounded up, at least 1).
func batchSize(spec string, workers int) int {
	if spec == "" {
		spec = "10%"
	}
	m := batchRe.FindStringSubmatch(spec)
	if m == nil {
		return 1
	}
	n, _ := strconv.Atoi(m[1])
	if m[2] == "%" {
		n = (workers*n + 99) / 100
	}
	return max(n, 1)
}

// applyOpts are apply's flags.
type applyOpts struct {
	version                                 string
	hold, wait, allowDowntime, unversioned  bool
	batch                                   string
	pauseAfter                              int
	nodeTimeout                             time.Duration
	nodeTimeoutSet, batchSet, pauseAfterSet bool
	from, releaseURL, archFlag              string
	output                                  string
}

func runUpgradeApply(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("upgrade apply")
	o := applyOpts{nodeTimeout: upgradewire.DefaultNodeTimeout}
	fs.BoolVar(&o.hold, "hold", false, "")
	fs.BoolVar(&o.wait, "wait", false, "")
	fs.BoolVar(&o.allowDowntime, "allow-downtime", false, "")
	fs.BoolVar(&o.unversioned, "allow-unversioned", false, "")
	fs.StringVar(&o.batch, "batch", "", "")
	fs.IntVar(&o.pauseAfter, "pause-after", 0, "")
	fs.DurationVar(&o.nodeTimeout, "node-timeout", o.nodeTimeout, "")
	fs.StringVar(&o.from, "from", "", "")
	fs.StringVar(&o.releaseURL, "release-url", "", "")
	fs.StringVar(&o.archFlag, "arch", "", "")
	fs.StringVar(&o.output, "o", "", "")
	fs.StringVar(&o.output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "upgrade", err)
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "node-timeout":
			o.nodeTimeoutSet = true
		case "batch":
			o.batchSet = true
		case "pause-after":
			o.pauseAfterSet = true
		}
	})
	if len(pos) != 1 {
		return a.usageError(c, "upgrade", "apply needs one version, such as `aerolvm upgrade apply v0.7.0`")
	}
	o.version = pos[0]
	if code := a.checkUpgradeVersion(c, o.version, o.unversioned); code >= 0 {
		return code
	}
	format, ok := outputFormat(c, o.output, "json", "yaml")
	if !ok {
		return a.usageError(c, "upgrade", "-o must be json or yaml, got %q", format)
	}
	o.output = format
	if o.batchSet {
		if err := checkBatch(o.batch); err != nil {
			return a.usageError(c, "upgrade", "%v", err)
		}
	}
	if o.pauseAfter < 0 {
		return a.usageError(c, "upgrade", "--pause-after must not be negative")
	}
	if o.nodeTimeout <= 0 {
		return a.usageError(c, "upgrade", "--node-timeout must be a positive duration such as 10m")
	}
	arches, err := parseArches(o.archFlag)
	if err != nil {
		return a.usageError(c, "upgrade", "%v", err)
	}
	set, err := a.loadSource(ctx, c, o.from, o.releaseURL, o.version, arches)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	defer set.cleanup()
	if set.offline() && set.meta != nil && set.meta.HostSetupNeedsNetwork {
		return a.fail(c, needsNetworkError(o.version), exitError)
	}
	if set.offline() {
		a.progress(c, "aerolvm: %d files of %s match checksums.txt (%s)", len(set.files), o.version, set.origin)
	}
	t, err := a.upgradeTarget(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if t.cluster {
		return a.applyCluster(ctx, c, t, o, set)
	}
	return a.applySingle(ctx, c, t, o, set)
}

// checkUpgradeVersion refuses a version argument that is not a release tag
// unless --allow-unversioned says it is a dev build; -1 means fine.
func (a *app) checkUpgradeVersion(c *commonFlags, version string, unversioned bool) int {
	if !releaseVersionRe.MatchString(version) {
		return a.usageError(c, "upgrade", "%q is not a version", version)
	}
	if _, err := release.ParseVersion(version); err != nil && !unversioned {
		return a.usageError(c, "upgrade", "%s is not a release tag such as v0.7.0; pass --allow-unversioned for a dev or test build", version)
	}
	return -1
}

func needsNetworkError(version string) error {
	return &agenttools.Error{Code: "host_setup_needs_network",
		Message: version + "'s host setup needs packages or network access on every node, so it can't be applied from --from or a bundle",
		Hint:    "apply it without --from, from a site where the nodes reach the release URL or a mirror (SB_RELEASE_URL)"}
}

// skewError is a node below the target's upgrade_from_min.
func skewError(version string, meta *release.Metadata, below []string) error {
	return &agenttools.Error{Code: upgradewire.ErrCodeSkew,
		Message: fmt.Sprintf("%s can't be reached straight from %s: it needs %s or later", version, strings.Join(below, ", "), meta.UpgradeFromMin),
		Hint:    "aerolvm upgrade plan " + version + " lists the releases to step through"}
}

// belowFloor lists the versions in have that meta does not accept straight.
// A version that is not a release tag can't be ordered and is left out.
func belowFloor(meta *release.Metadata, have []string) []string {
	if meta == nil {
		return nil
	}
	seen := map[string]bool{}
	var below []string
	for _, v := range have {
		if seen[v] {
			continue
		}
		seen[v] = true
		if _, err := release.ParseVersion(v); err != nil {
			continue
		}
		if meta.UpgradeAllowedFrom(v) != nil {
			below = append(below, v)
		}
	}
	sort.Strings(below)
	return below
}

// uploadFiles sends every file the server lacks: HEAD first, then a
// streamed PUT, so a retry after a dropped upload sends only what is left.
func (a *app) uploadFiles(ctx context.Context, c *commonFlags, conn connection, filesPath string, set *releaseSet) error {
	for _, name := range set.sortedFiles() {
		sum := set.files[name]
		status, err := a.upgradeDo(ctx, c, conn, upgradeCall{method: http.MethodHead, path: filesPath + "/" + sum, timeout: upgradeCallTimeout})
		if err != nil {
			return err
		}
		if status == http.StatusOK {
			a.progress(c, "aerolvm: %s is already there", name)
			continue
		}
		f, err := os.Open(set.paths[name])
		if err != nil {
			return err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		a.progress(c, "aerolvm: uploading %s (%s)", name, humanBytes(fi.Size()))
		_, err = a.upgradeDo(ctx, c, conn, upgradeCall{method: http.MethodPut, path: filesPath + "/" + sum, body: f, size: fi.Size()})
		f.Close()
		if err != nil {
			e := *agenttools.Classify(err)
			e.Message = "upload " + name + ": " + e.Message
			return &e
		}
	}
	return nil
}

func (a *app) applySingle(ctx context.Context, c *commonFlags, t upgradeTarget, o applyOpts, set *releaseSet) int {
	switch {
	case o.hold:
		return a.usageError(c, "upgrade", "--hold is for a cluster; this sandboxd is a single node, which has no rollout to hold")
	case o.batchSet, o.pauseAfterSet:
		return a.usageError(c, "upgrade", "--batch and --pause-after are for a cluster; this sandboxd is a single node")
	}
	if below := belowFloor(set.meta, []string{t.version}); len(below) > 0 {
		return a.fail(c, skewError(o.version, set.meta, below), exitError)
	}
	source := upgradewire.SourceRelease
	if set.offline() {
		if err := a.uploadFiles(ctx, c, t.conn, upgradewire.NodeUpgradeFilesPath, set); err != nil {
			return a.fail(c, err, exitError)
		}
		source = upgradewire.SourceUpload
	}
	req := upgradewire.NodeUpgradeRequest{Version: o.version, Files: set.files, Source: source, AllowUnversioned: o.unversioned}
	if o.nodeTimeoutSet {
		req.HealthTimeout = o.nodeTimeout.String()
	}
	var op upgradewire.NodeUpgradeResponse
	status, err := a.upgradeDo(ctx, c, t.conn, upgradeCall{method: http.MethodPost, path: upgradewire.NodeUpgradePath, in: req, out: &op, timeout: upgradeCallTimeout})
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if status == http.StatusOK {
		if o.output != "" {
			a.printValue(o.output, op)
			return exitOK
		}
		fmt.Fprintf(a.stdout, "node already runs %s; nothing to do\n", o.version)
		return exitOK
	}
	if !o.wait {
		if o.output != "" {
			a.printValue(o.output, op)
			return exitOK
		}
		fmt.Fprintf(a.stdout, "upgrade %s started: %s -> %s\n", op.Op, dash(op.From), op.Version)
		a.note("aerolvm: follow it with: aerolvm upgrade status")
		return exitOK
	}
	a.progress(c, "aerolvm: upgrade %s started: %s -> %s", op.Op, dash(op.From), op.Version)
	return a.waitNode(ctx, c, t.conn, op, o.nodeTimeout, o.output)
}

// waitNode follows a node operation until it ends. sandboxd restarts in the
// middle of it, so a dropped connection or a 502 is waited out.
func (a *app) waitNode(ctx context.Context, c *commonFlags, conn connection, op upgradewire.NodeUpgradeResponse, limit time.Duration, output string) int {
	waitCtx, cancel := context.WithTimeout(ctx, limit+time.Minute)
	defer cancel()
	last, restarting := op.State, false
	for {
		select {
		case <-waitCtx.Done():
			return a.fail(c, &agenttools.Error{Code: agenttools.CodeTimeout,
				Message: fmt.Sprintf("upgrade %s is still %s after %s", op.Op, last, limit+time.Minute),
				Hint:    "it goes on without aerolvm; check it with: aerolvm upgrade status"}, exitError)
		case <-time.After(a.pollInterval()):
		}
		var cur upgradewire.NodeUpgradeResponse
		_, err := a.upgradeDo(waitCtx, c, conn, upgradeCall{method: http.MethodGet, path: upgradewire.NodeUpgradePath, out: &cur, timeout: 15 * time.Second})
		if err != nil {
			if transient(err) && waitCtx.Err() == nil {
				if !restarting {
					a.progress(c, "aerolvm: sandboxd is restarting; waiting for it")
					restarting = true
				}
				continue
			}
			if waitCtx.Err() != nil {
				continue
			}
			return a.fail(c, err, exitError)
		}
		if cur.Op != op.Op {
			continue
		}
		if cur.State != last {
			a.progress(c, "aerolvm: %s: %s", op.Op, cur.State)
			last = cur.State
		}
		switch cur.State {
		case upgradewire.NodeOpDone:
			if output != "" {
				a.printValue(output, cur)
				return exitOK
			}
			fmt.Fprintf(a.stdout, "node now runs %s (upgrade %s)\n", cur.Version, cur.Op)
			return exitOK
		case upgradewire.NodeOpFailed:
			if output != "" {
				a.printValue(output, cur)
			}
			return a.fail(c, &agenttools.Error{Code: "upgrade_failed",
				Message: fmt.Sprintf("upgrade %s failed: %s", cur.Op, dash(cur.Error)),
				Hint:    "the previous files are back; on the node: journalctl -u aerolvm-upgrade-" + cur.Op}, exitError)
		}
	}
}

func (a *app) pollInterval() time.Duration {
	if a.pollEvery > 0 {
		return a.pollEvery
	}
	return 2 * time.Second
}

func (a *app) applyCluster(ctx context.Context, c *commonFlags, t upgradeTarget, o applyOpts, set *releaseSet) int {
	if set.meta != nil {
		if nodes, err := a.listNodes(ctx, c); err == nil {
			var versions []string
			for _, n := range nodes {
				if n.rec.Alive && n.rec.Version != "" {
					versions = append(versions, n.rec.Version)
				}
			}
			if below := belowFloor(set.meta, versions); len(below) > 0 {
				return a.fail(c, skewError(o.version, set.meta, below), exitError)
			}
		}
	}
	source := upgradewire.SourceRelease
	if set.offline() {
		if err := a.uploadFiles(ctx, c, t.conn, upgradewire.ClusterUpgradeFilesPath, set); err != nil {
			return a.fail(c, err, exitError)
		}
		source = upgradewire.SourceUpload
	}
	req := upgradewire.ApplyRequest{Version: o.version, Files: set.files, Source: source, Hold: o.hold, Batch: o.batch,
		PauseAfter: o.pauseAfter, NodeTimeout: o.nodeTimeout.String(), AllowDowntime: o.allowDowntime, AllowUnversioned: o.unversioned}
	var ro upgradewire.Rollout
	status, err := a.upgradeDo(ctx, c, t.conn, upgradeCall{method: http.MethodPost, path: upgradewire.ClusterUpgradePath, in: req, out: &ro, timeout: upgradeCallTimeout})
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if !o.wait {
		if o.output != "" {
			a.printValue(o.output, ro)
			return exitOK
		}
		if status == http.StatusCreated {
			fmt.Fprintf(a.stdout, "rollout %s started: %s -> %s on %d nodes\n", ro.ID, dash(ro.PreviousVersion), ro.TargetVersion, len(ro.Nodes))
		} else {
			fmt.Fprintf(a.stdout, "rollout %s to %s is already %s\n", ro.ID, ro.TargetVersion, ro.State)
		}
		a.note("aerolvm: the leader runs it; follow it with: aerolvm upgrade status")
		return exitOK
	}
	if status == http.StatusCreated {
		a.progress(c, "aerolvm: rollout %s started: %s -> %s on %d nodes", ro.ID, dash(ro.PreviousVersion), ro.TargetVersion, len(ro.Nodes))
	} else {
		a.progress(c, "aerolvm: rollout %s to %s is already %s", ro.ID, ro.TargetVersion, ro.State)
	}
	return a.waitRollout(ctx, c, t.conn, ro, false, o.output)
}

// rolloutEnd says whether a rollout followed by --wait has ended, and how.
func rolloutEnd(ro upgradewire.Rollout, rollback bool) (ended bool, ok bool, msg, hint string) {
	switch ro.State {
	case upgradewire.StateFinalized:
		return true, !rollback, fmt.Sprintf("rollout %s finalized: every node runs %s", ro.ID, ro.TargetVersion), ""
	case upgradewire.StateDone:
		if ro.Hold && !rollback {
			return true, true, fmt.Sprintf("rollout %s is done and held: every node runs %s", ro.ID, ro.TargetVersion),
				"turn on the new version with: aerolvm upgrade finalize (or go back: aerolvm upgrade rollback)"
		}
	case upgradewire.StatePaused:
		return true, true, fmt.Sprintf("rollout %s paused after its canary workers", ro.ID),
			"check them, then: aerolvm upgrade resume (or aerolvm upgrade rollback)"
	case upgradewire.StateFailed:
		return true, false, fmt.Sprintf("rollout %s failed: %s", ro.ID, dash(ro.Error)),
			"fix the node, then run the same apply again, or: aerolvm upgrade rollback"
	case upgradewire.StateStopped:
		return true, false, fmt.Sprintf("rollout %s was stopped", ro.ID), "run the same apply again to go on, or: aerolvm upgrade rollback"
	case upgradewire.StateRolledBack:
		return true, rollback, fmt.Sprintf("rollout %s rolled back: every node runs %s again", ro.ID, dash(ro.TargetVersion)), ""
	case upgradewire.StateFinalizing:
		for _, n := range ro.Nodes {
			if n.State == upgradewire.NodeFailed {
				return true, false, fmt.Sprintf("rollout %s: node %s failed its one-way migrations: %s", ro.ID, n.NodeID, dash(n.Error)),
					"the node stays cordoned; see aerolvm upgrade status"
			}
		}
	}
	return false, false, "", ""
}

// waitRollout follows a rollout until it ends, printing each node's moves.
func (a *app) waitRollout(ctx context.Context, c *commonFlags, conn connection, ro upgradewire.Rollout, rollback bool, output string) int {
	seen := map[string]string{}
	state := ""
	first := true
	report := func(ro upgradewire.Rollout) {
		for _, n := range ro.Nodes {
			if seen[n.NodeID] == n.State {
				continue
			}
			seen[n.NodeID] = n.State
			if first && n.State == upgradewire.NodePending {
				continue // a fleet's worth of "pending" says nothing yet
			}
			line := fmt.Sprintf("aerolvm:   node %s (%s): %s", n.NodeID, n.Role, n.State)
			if n.Version != "" && n.State == upgradewire.NodeDone {
				line += ", runs " + n.Version
			}
			if n.Error != "" {
				line += ": " + n.Error
			}
			a.progress(c, "%s", line)
			if n.State == upgradewire.NodeManual && n.ManualCommand != "" {
				a.progress(c, "aerolvm:     run on it, as root: %s", n.ManualCommand)
			}
		}
		first = false
		if ro.State != state {
			a.progress(c, "aerolvm: rollout %s: %s", ro.ID, ro.State)
			state = ro.State
		}
	}
	quiet := false
	for {
		report(ro)
		if ended, ok, msg, hint := rolloutEnd(ro, rollback); ended {
			if output != "" {
				a.printValue(output, ro)
			}
			if !ok {
				return a.fail(c, &agenttools.Error{Code: "rollout_" + strings.ReplaceAll(ro.State, "-", "_"), Message: msg, Hint: hint}, exitError)
			}
			if output == "" {
				fmt.Fprintln(a.stdout, msg)
				if hint != "" {
					a.note("aerolvm: %s", hint)
				}
			}
			return exitOK
		}
		select {
		case <-ctx.Done():
			return a.fail(c, &agenttools.Error{Code: agenttools.CodeCanceled, Message: "stopped following the rollout",
				Hint: "the rollout goes on; check it with: aerolvm upgrade status"}, exitError)
		case <-time.After(a.pollInterval()):
		}
		var next upgradewire.Rollout
		if err := a.upgradeGet(ctx, c, conn, upgradewire.ClusterUpgradePath, &next); err != nil {
			if transient(err) && ctx.Err() == nil {
				if !quiet {
					a.progress(c, "aerolvm: the API is not answering (a server may be restarting); waiting")
					quiet = true
				}
				continue
			}
			return a.fail(c, err, exitError)
		}
		quiet = false
		ro = next
	}
}

// printValue prints v as JSON or YAML.
func (a *app) printValue(format string, v any) {
	raw, _ := json.Marshal(v)
	a.printObjects(format, "", rawItems([]json.RawMessage{raw}), true)
}

func runUpgradeStatus(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("upgrade status")
	var output string
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "upgrade", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "upgrade", "status takes no argument, got %q", pos[0])
	}
	format, ok := outputFormat(c, output, "json", "yaml")
	if !ok {
		return a.usageError(c, "upgrade", "-o must be json or yaml, got %q", format)
	}
	t, err := a.upgradeTarget(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	path := upgradewire.NodeUpgradePath
	if t.cluster {
		path = upgradewire.ClusterUpgradePath
	}
	var raw json.RawMessage
	if err := a.upgradeGet(ctx, c, t.conn, path, &raw); err != nil {
		if !isCode(err, agenttools.CodeNotFound) && !isCode(err, "not_found") {
			return a.fail(c, err, exitError)
		}
		if format != "" {
			fmt.Fprintln(a.stdout, "null")
			return exitOK
		}
		if t.cluster {
			fmt.Fprintln(a.stdout, "No rollout has run on this cluster.")
		} else {
			fmt.Fprintf(a.stdout, "No upgrade has run on this node. It runs %s.\n", dash(t.version))
		}
		return exitOK
	}
	if format != "" {
		a.printObjects(format, "", rawItems([]json.RawMessage{raw}), true)
		return exitOK
	}
	if t.cluster {
		var ro upgradewire.Rollout
		if err := json.Unmarshal(raw, &ro); err != nil {
			return a.fail(c, fmt.Errorf("sandboxd sent an unreadable rollout: %w", err), exitError)
		}
		a.printRollout(ro)
		return exitOK
	}
	var op upgradewire.NodeUpgradeResponse
	if err := json.Unmarshal(raw, &op); err != nil {
		return a.fail(c, fmt.Errorf("sandboxd sent an unreadable operation: %w", err), exitError)
	}
	a.printNodeOp(op, t.version)
	return exitOK
}

func rfcTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (a *app) printNodeOp(op upgradewire.NodeUpgradeResponse, running string) {
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	rows := [][2]string{
		{"Node upgrade:", dash(op.Op)},
		{"State:", op.State},
		{"Version:", fmt.Sprintf("%s, from %s", op.Version, dash(op.From))},
		{"Rollback:", yesNo(op.Rollback)},
		{"Node runs:", dash(running)},
		{"Started:", rfcTime(op.StartedAt)},
		{"Updated:", rfcTime(op.UpdatedAt)},
	}
	if op.Error != "" {
		rows = append(rows, [2]string{"Error:", op.Error})
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r[0], r[1])
	}
	_ = tw.Flush()
}

func (a *app) printRollout(ro upgradewire.Rollout) {
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	settings := []string{"batch " + dash(ro.Batch)}
	if ro.PauseAfter > 0 {
		settings = append(settings, fmt.Sprintf("pause after %d", ro.PauseAfter))
	}
	settings = append(settings, "node timeout "+dash(ro.NodeTimeout))
	if ro.Hold {
		settings = append(settings, "hold")
	}
	if ro.AllowDowntime {
		settings = append(settings, "allow downtime")
	}
	rows := [][2]string{
		{"Rollout:", fmt.Sprintf("%s (%s)", ro.ID, dash(ro.Direction))},
		{"State:", ro.State},
		{"Target:", fmt.Sprintf("%s, from %s", ro.TargetVersion, dash(ro.PreviousVersion))},
		{"Source:", dash(ro.Source)},
		{"Started by:", dash(ro.Caller)},
		{"Settings:", strings.Join(settings, ", ")},
		{"Active version:", dash(ro.ActiveVersion)},
		{"Created:", rfcTime(ro.CreatedAt)},
		{"Updated:", rfcTime(ro.UpdatedAt)},
	}
	if ro.Error != "" {
		rows = append(rows, [2]string{"Error:", ro.Error})
	}
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\n", r[0], r[1])
	}
	_ = tw.Flush()
	if len(ro.Nodes) == 0 {
		return
	}
	nodes := append([]upgradewire.RolloutNode(nil), ro.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Order != nodes[j].Order {
			return nodes[i].Order < nodes[j].Order
		}
		return nodes[i].NodeID < nodes[j].NodeID
	})
	fmt.Fprintln(a.stdout)
	tw = tabwriter.NewWriter(a.stdout, 0, 4, 3, ' ', 0)
	fmt.Fprintln(tw, "ORDER\tNODE\tROLE\tARCH\tBATCH\tSTATE\tVERSION\tNOTE")
	var skipped, manual []upgradewire.RolloutNode
	for _, n := range nodes {
		batch := "-"
		if n.Batch > 0 {
			batch = strconv.Itoa(n.Batch)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n.Order, n.NodeID, dash(n.Role), dash(n.Arch), batch, n.State, dash(n.Version), dash(n.Error))
		switch n.State {
		case upgradewire.NodeSkipped:
			skipped = append(skipped, n)
		case upgradewire.NodeManual:
			manual = append(manual, n)
		}
	}
	_ = tw.Flush()
	if len(skipped) > 0 {
		fmt.Fprintln(a.stdout, "\nSkipped nodes were down when their turn came, and finalize waits for them. For each one:")
		fmt.Fprintln(a.stdout, "  start it again: it stays cordoned, the leader upgrades it, then uncordons it; or")
		for _, n := range skipped {
			fmt.Fprintf(a.stdout, "  delete it: aerolvm delete node %s\n", n.NodeID)
		}
	}
	if len(manual) > 0 {
		fmt.Fprintln(a.stdout, "\nThese nodes take no upgrade over the API (SB_REMOTE_UPGRADE=false). Run this on each, as root:")
		for _, n := range manual {
			fmt.Fprintf(a.stdout, "  %s: %s\n", n.NodeID, dash(n.ManualCommand))
		}
	}
}

// rolloutCommand is stop, resume and finalize: cluster only.
func (a *app) rolloutCommand(ctx context.Context, args []string, name, path string) int {
	fs, c := a.newFlagSet("upgrade " + name)
	var output string
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "upgrade", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "upgrade", "%s takes no argument, got %q", name, pos[0])
	}
	format, ok := outputFormat(c, output, "json", "yaml")
	if !ok {
		return a.usageError(c, "upgrade", "-o must be json or yaml, got %q", format)
	}
	t, err := a.upgradeTarget(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if !t.cluster {
		return a.fail(c, &agenttools.Error{Code: upgradewire.ErrCodeNotClusterMode,
			Message: "this sandboxd is a single node: there is no rollout to " + name,
			Hint:    "a single node's upgrade runs to the end by itself; see it with: aerolvm upgrade status"}, exitError)
	}
	var ro upgradewire.Rollout
	if _, err := a.upgradeDo(ctx, c, t.conn, upgradeCall{method: http.MethodPost, path: path, out: &ro, timeout: upgradeCallTimeout}); err != nil {
		return a.fail(c, err, exitError)
	}
	if format != "" {
		a.printValue(format, ro)
		return exitOK
	}
	fmt.Fprintf(a.stdout, "rollout %s: %s\n", ro.ID, ro.State)
	return exitOK
}

func runUpgradeRollback(ctx context.Context, a *app, args []string) int {
	fs, c := a.newFlagSet("upgrade rollback")
	var wait bool
	var output string
	timeout := upgradewire.DefaultNodeTimeout
	fs.BoolVar(&wait, "wait", false, "")
	fs.DurationVar(&timeout, "node-timeout", timeout, "")
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&output, "output", "", "")
	pos, _, err := parseArgs(fs, args)
	if err != nil {
		return a.flagError(c, "upgrade", err)
	}
	if len(pos) > 0 {
		return a.usageError(c, "upgrade", "rollback takes no argument, got %q; it goes back to the version before the last upgrade", pos[0])
	}
	format, ok := outputFormat(c, output, "json", "yaml")
	if !ok {
		return a.usageError(c, "upgrade", "-o must be json or yaml, got %q", format)
	}
	if timeout <= 0 {
		return a.usageError(c, "upgrade", "--node-timeout must be a positive duration such as 10m")
	}
	t, err := a.upgradeTarget(ctx, c)
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if t.cluster {
		var ro upgradewire.Rollout
		if _, err := a.upgradeDo(ctx, c, t.conn, upgradeCall{method: http.MethodPost, path: upgradewire.ClusterUpgradeRollbackPath, out: &ro, timeout: upgradeCallTimeout}); err != nil {
			return a.fail(c, err, exitError)
		}
		if wait {
			return a.waitRollout(ctx, c, t.conn, ro, true, format)
		}
		if format != "" {
			a.printValue(format, ro)
			return exitOK
		}
		fmt.Fprintf(a.stdout, "rollout %s: %s, back to %s\n", ro.ID, ro.State, dash(ro.TargetVersion))
		return exitOK
	}
	return a.rollbackSingle(ctx, c, t, wait, timeout, format)
}

// rollbackSingle puts back the files the node's last upgrade replaced. It
// reads the latest operation to learn where to go back to, so running it
// twice does not undo its own rollback.
func (a *app) rollbackSingle(ctx context.Context, c *commonFlags, t upgradeTarget, wait bool, timeout time.Duration, format string) int {
	var last upgradewire.NodeUpgradeResponse
	if err := a.upgradeGet(ctx, c, t.conn, upgradewire.NodeUpgradePath, &last); err != nil {
		if isCode(err, "not_found") {
			return a.fail(c, &agenttools.Error{Code: agenttools.CodeNotFound, Message: "no upgrade has run on this node, so there is nothing to roll back"}, exitError)
		}
		return a.fail(c, err, exitError)
	}
	done := func(msg string) int {
		if format != "" {
			a.printValue(format, last)
			return exitOK
		}
		fmt.Fprintln(a.stdout, msg)
		return exitOK
	}
	switch {
	case last.State != upgradewire.NodeOpDone && last.State != upgradewire.NodeOpFailed:
		return a.fail(c, &agenttools.Error{Code: upgradewire.ErrCodeUpgradeRunning,
			Message: fmt.Sprintf("upgrade %s is still %s", last.Op, last.State), Hint: "wait for it: aerolvm upgrade status"}, exitError)
	case last.Rollback && last.State == upgradewire.NodeOpDone:
		return done(fmt.Sprintf("node already rolled back to %s (upgrade %s); nothing to do", last.Version, last.Op))
	case last.From == "":
		return a.fail(c, &agenttools.Error{Code: "no_previous_version",
			Message: fmt.Sprintf("upgrade %s recorded no previous version", dash(last.Op)),
			Hint:    "on the node: sudo sandboxd upgrade node <version> --rollback"}, exitError)
	case last.From == t.version:
		return done(fmt.Sprintf("node already runs %s, the version before upgrade %s; nothing to do", t.version, last.Op))
	}
	req := upgradewire.NodeUpgradeRequest{Version: last.From, Rollback: true, Source: upgradewire.SourceRelease}
	var op upgradewire.NodeUpgradeResponse
	status, err := a.upgradeDo(ctx, c, t.conn, upgradeCall{method: http.MethodPost, path: upgradewire.NodeUpgradePath, in: req, out: &op, timeout: upgradeCallTimeout})
	if err != nil {
		return a.fail(c, err, exitError)
	}
	if status == http.StatusOK {
		last = op
		return done(fmt.Sprintf("node already runs %s; nothing to do", last.From))
	}
	if !wait {
		if format != "" {
			a.printValue(format, op)
			return exitOK
		}
		fmt.Fprintf(a.stdout, "rollback %s started: %s -> %s\n", op.Op, dash(op.From), op.Version)
		a.note("aerolvm: follow it with: aerolvm upgrade status")
		return exitOK
	}
	a.progress(c, "aerolvm: rollback %s started: %s -> %s", op.Op, dash(op.From), op.Version)
	return a.waitNode(ctx, c, t.conn, op, timeout, format)
}
