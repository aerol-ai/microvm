package cluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/release"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	"github.com/hashicorp/raft"
)

// The public rollout commands (plans/kubectl-style-cluster-ops.md §6.1,
// §6.6; CEO D6, D10, D11; eng D6, D8). They run on the leader: the API
// forwards every write there. Each one asks decideRollout first, so a
// refusal or a repeat costs no Raft write, and the FSM asks it again when
// the entry applies.

// RolloutError is a refused rollout command: the HTTP status and the body.
type RolloutError struct {
	Status int
	Body   upgradewire.ErrorResponse
}

func (e *RolloutError) Error() string {
	if e.Body.Reason != "" {
		return e.Body.Error + ": " + e.Body.Reason
	}
	return e.Body.Error
}

func rolloutErr(status int, code, reason, hint string, nodes ...string) error {
	return &RolloutError{Status: status, Body: upgradewire.ErrorResponse{Error: code, Reason: reason, Hint: hint, Nodes: nodes}}
}

func verdictErr(v rolloutVerdict) error {
	return rolloutErr(http.StatusConflict, v.Code, v.Reason, v.Hint, v.Nodes...)
}

// Rollouts is the rollout capability of a server (pkg/api/v1). Workers and
// ingress nodes forward to the leader before they get here.
type Rollouts interface {
	GetRollout(ctx context.Context) (*upgradewire.Rollout, error)
	ApplyRollout(ctx context.Context, caller string, req upgradewire.ApplyRequest) (*upgradewire.Rollout, bool, error)
	RolloutCommand(ctx context.Context, caller, command string) (*upgradewire.Rollout, error)
	TransferLeadership(ctx context.Context, to string) (upgradewire.LeaderTransferResponse, error)
}

// Rollout commands RolloutCommand takes.
const (
	RolloutStop     = evStop
	RolloutResume   = evResume
	RolloutFinalize = evFinalize
	RolloutRollback = evRollback
)

// IsLeader reports whether this server leads Raft.
func (c *Cluster) IsLeader() bool {
	return c != nil && c.raft != nil && c.raft.raft != nil && c.raft.raft.State() == raft.Leader
}

// GetRollout reads the rollout from this server's FSM. A server that is
// still catching up after a restart answers ErrNotCaughtUp.
func (c *Cluster) GetRollout(_ context.Context) (*upgradewire.Rollout, error) {
	if !c.PlacementViewCaughtUp() {
		return nil, ErrNotCaughtUp
	}
	r, active := c.fsm.rolloutView()
	if r == nil {
		return nil, rolloutErr(http.StatusNotFound, "not_found", "this cluster never had a rollout", "")
	}
	return RolloutAPIView(r, active), nil
}

// ApplyRollout starts a rollout, or answers the current one (§6.6 table).
// created is true for a new rollout (201).
func (c *Cluster) ApplyRollout(ctx context.Context, caller string, req upgradewire.ApplyRequest) (*upgradewire.Rollout, bool, error) {
	if !c.IsLeader() {
		return nil, false, ErrNotLeader
	}
	if err := c.refuseUnlessOperator(ctx); err != nil {
		return nil, false, err
	}
	if err := c.raftServersRunAtLeast(rolloutFSMOpsVersion, "rollouts"); err != nil {
		return nil, false, rolloutErr(http.StatusConflict, "cluster_version", err.Error(), "upgrade every server to a release with rollouts first (install.sh, once per node)")
	}
	spec, err := c.validateApply(req)
	if err != nil {
		return nil, false, err
	}
	cur, active := c.fsm.rolloutView()
	v := decideRollout(cur, rolloutEvent{Kind: evApply, Target: spec.TargetVersion})
	switch v.Outcome {
	case outcomeRefused:
		return nil, false, verdictErr(v)
	case outcomeExisting, outcomeNoop:
		if !sameFiles(cur.Files, spec.Files) {
			return nil, false, rolloutErr(http.StatusConflict, upgradewire.ErrCodeRolloutConflict,
				fmt.Sprintf("a rollout to %s with other file hashes is %s", cur.TargetVersion, cur.State), "check the release's checksums; roll back or finalize the current rollout first")
		}
		return RolloutAPIView(cur, active), false, nil
	case outcomeRestage:
		if !sameFiles(cur.Files, spec.Files) {
			return nil, false, rolloutErr(http.StatusConflict, upgradewire.ErrCodeRolloutConflict,
				fmt.Sprintf("the %s rollout to %s used other file hashes", cur.State, cur.TargetVersion), "roll it back first, then apply the new files")
		}
	}
	if req.Source == upgradewire.SourceUpload {
		if missing := c.missingUploads(spec.Files); len(missing) > 0 {
			return nil, false, rolloutErr(http.StatusConflict, upgradewire.ErrCodeFilesMissing,
				"the leader does not hold every uploaded file", "upload them with PUT "+upgradewire.ClusterUpgradeFilesPath+"/{sha256} (aerolvm upgrade apply --from does), then apply again", missing...)
		}
	}
	if v.Outcome == outcomeNew {
		rec, err := c.buildRollout(caller, spec, req)
		if err != nil {
			return nil, false, err
		}
		if err := c.checkSkew(rec); err != nil {
			return nil, false, err
		}
		spec = rec
	}
	res, err := c.proposeRolloutCommand(ctx, RolloutCommand{Event: evApply, New: spec, Target: spec.TargetVersion})
	if err != nil {
		return nil, false, err
	}
	if res.Verdict.Outcome == outcomeRefused {
		return nil, false, verdictErr(res.Verdict)
	}
	if c.logger != nil {
		c.logger.Info("cluster: rollout applied", "rollout_id", res.Rollout.ID, "target", res.Rollout.TargetVersion,
			"outcome", res.Verdict.Outcome, "caller", caller, "nodes", len(res.Rollout.Nodes))
	}
	c.wakeRollout()
	return RolloutAPIView(res.Rollout, active), res.Verdict.Outcome == outcomeNew, nil
}

// RolloutCommand runs stop, resume, finalize or rollback.
func (c *Cluster) RolloutCommand(ctx context.Context, caller, command string) (*upgradewire.Rollout, error) {
	if !c.IsLeader() {
		return nil, ErrNotLeader
	}
	switch command {
	case evStop, evResume, evFinalize, evRollback:
	default:
		return nil, rolloutErr(http.StatusBadRequest, "bad_request", "unknown rollout command "+command, "")
	}
	if command == evRollback {
		if err := c.refuseUnlessOperator(ctx); err != nil {
			return nil, err
		}
	}
	cur, active := c.fsm.rolloutView()
	v := decideRollout(cur, rolloutEvent{Kind: command})
	switch v.Outcome {
	case outcomeRefused:
		if cur == nil {
			return nil, rolloutErr(http.StatusNotFound, "not_found", "there is no rollout", "")
		}
		return nil, verdictErr(v)
	case outcomeNoop:
		return RolloutAPIView(cur, active), nil
	}
	cmd := RolloutCommand{Event: command, RolloutID: cur.ID}
	switch command {
	case evStop:
		cmd.Error = "stopped by " + caller
	case evFinalize:
		a, err := c.finalizeTarget(cur)
		if err != nil {
			return nil, err
		}
		cmd.Active = &a
	}
	res, err := c.proposeRolloutCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	if res.Verdict.Outcome == outcomeRefused {
		return nil, verdictErr(res.Verdict)
	}
	if c.logger != nil {
		c.logger.Info("cluster: rollout command", "rollout_id", cur.ID, "command", command, "caller", caller, "state", res.Rollout.State)
	}
	c.wakeRollout()
	_, active = c.fsm.rolloutView()
	return RolloutAPIView(res.Rollout, active), nil
}

// finalizeTarget is the active version finalize commits: the lowest fv the
// rollout's nodes report (they all run the target now), never below the
// current one, and the target's release.
func (c *Cluster) finalizeTarget(r *RolloutRecord) (ActiveVersion, error) {
	cur := c.fsm.activeFVValue()
	low := 0
	for _, n := range r.sortedNodes() {
		fv := 0
		if n.NodeID == c.nodeID {
			fv = fsmOpsVersion
		} else if m, ok := c.LookupMember(n.NodeID); ok && m.Alive {
			fv = m.FSMOpsVersion
		}
		if fv == 0 {
			return ActiveVersion{}, rolloutErr(http.StatusConflict, upgradewire.ErrCodeRolloutConflict,
				fmt.Sprintf("node %s does not report its FSM op version (is it up?)", n.NodeID), "wait for it to come back, or delete it", n.NodeID)
		}
		if low == 0 || fv < low {
			low = fv
		}
	}
	if low < cur {
		low = cur
	}
	return ActiveVersion{FV: low, Release: r.TargetVersion}, nil
}

// proposeRolloutCommand writes one opRolloutCommand on this leader.
func (c *Cluster) proposeRolloutCommand(ctx context.Context, rc RolloutCommand) (rolloutApplyResult, error) {
	payload, err := encodeCommand(command{Op: opRolloutCommand, StampUnixNano: time.Now().UnixNano(), RolloutCmd: &rc})
	if err != nil {
		return rolloutApplyResult{}, err
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return rolloutApplyResult{}, err
	}
	res, _ := result.(rolloutApplyResult)
	return res, nil
}

// proposeRolloutNode writes one opRolloutNode on this leader.
func (c *Cluster) proposeRolloutNode(ctx context.Context, u RolloutNodeUpdate) (rolloutApplyResult, error) {
	payload, err := encodeCommand(command{Op: opRolloutNode, StampUnixNano: time.Now().UnixNano(), RolloutNode: &u})
	if err != nil {
		return rolloutApplyResult{}, err
	}
	result, err := c.applyEncodedLocalResult(ctx, payload)
	if err != nil {
		return rolloutApplyResult{}, err
	}
	res, _ := result.(rolloutApplyResult)
	return res, nil
}

// TransferLeadership hands Raft leadership to another voter (to, or the
// most up-to-date one when empty) and waits for the new leader.
func (c *Cluster) TransferLeadership(ctx context.Context, to string) (upgradewire.LeaderTransferResponse, error) {
	if !c.IsLeader() {
		return upgradewire.LeaderTransferResponse{}, ErrNotLeader
	}
	to = strings.TrimSpace(to)
	var f raft.Future
	if to == "" {
		f = c.raft.raft.LeadershipTransfer()
	} else {
		if to == c.nodeID {
			return upgradewire.LeaderTransferResponse{Leader: c.nodeID, Term: c.raft.raft.CurrentTerm()}, nil
		}
		srv, ok := c.configuredServer(to)
		if !ok || srv.Suffrage != raft.Voter {
			return upgradewire.LeaderTransferResponse{}, rolloutErr(http.StatusBadRequest, "bad_request", to+" is not a Raft voter", "")
		}
		f = c.raft.raft.LeadershipTransferToServer(srv.ID, srv.Address)
	}
	if err := f.Error(); err != nil {
		return upgradewire.LeaderTransferResponse{}, rolloutErr(http.StatusConflict, "transfer_failed", err.Error(), "")
	}
	deadline := time.Now().Add(c.commitTimeout + 5*time.Second)
	for {
		_, id := c.raft.raft.LeaderWithID()
		if leader := string(id); leader != "" && leader != c.nodeID {
			if c.logger != nil {
				c.logger.Info("cluster: leadership transferred", "from", c.nodeID, "to", leader)
			}
			return upgradewire.LeaderTransferResponse{Leader: leader, Term: c.raft.raft.CurrentTerm()}, nil
		}
		if time.Now().After(deadline) {
			return upgradewire.LeaderTransferResponse{}, rolloutErr(http.StatusServiceUnavailable, "transfer_failed", "no new leader was elected in time", "")
		}
		select {
		case <-ctx.Done():
			return upgradewire.LeaderTransferResponse{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

var (
	rolloutVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	rolloutAssetRe   = regexp.MustCompile(`^(?:v[0-9][A-Za-z0-9.+-]*_)?(sandboxd|toolboxd|caddy)(?:_(linux)_([a-z0-9]+))?$`)
)

// validateApply checks an apply request's inputs and returns the rollout
// header it describes.
func (c *Cluster) validateApply(req upgradewire.ApplyRequest) (*RolloutRecord, error) {
	bad := func(reason string) error { return rolloutErr(http.StatusBadRequest, "bad_request", reason, "") }
	target := strings.TrimSpace(req.Version)
	if !rolloutVersionRe.MatchString(target) {
		return nil, bad(fmt.Sprintf("version %q is not a release tag", req.Version))
	}
	if !req.AllowUnversioned {
		if _, err := release.ParseVersion(target); err != nil {
			return nil, rolloutErr(http.StatusBadRequest, upgradewire.ErrCodeSkew,
				fmt.Sprintf("%s is not a release tag, so it cannot be ordered against the running versions", target), "pass allow_unversioned for a dev or test build")
		}
	}
	switch req.Source {
	case upgradewire.SourceRelease, upgradewire.SourceUpload:
	default:
		return nil, bad(fmt.Sprintf("source must be %q or %q", upgradewire.SourceRelease, upgradewire.SourceUpload))
	}
	if len(req.Files) == 0 {
		return nil, bad("files is empty: give every release file's SHA-256")
	}
	for name, sum := range req.Files {
		if !upgradewire.SHA256Re.MatchString(sum) {
			return nil, bad(fmt.Sprintf("files[%s]: %q is not 64 lower-case hex digits", name, sum))
		}
		if name != release.FileName && !rolloutAssetRe.MatchString(name) {
			return nil, bad(fmt.Sprintf("files: %q is not a release file (sandboxd, toolboxd, caddy or release.json, optionally _linux_<arch>)", name))
		}
	}
	if _, err := ParseRolloutBatch(req.Batch, 1); err != nil {
		return nil, bad(err.Error())
	}
	if req.PauseAfter < 0 {
		return nil, bad("pause_after must not be negative")
	}
	timeout := upgradewire.DefaultNodeTimeout
	if strings.TrimSpace(req.NodeTimeout) != "" {
		d, err := time.ParseDuration(req.NodeTimeout)
		if err != nil || d <= 0 {
			return nil, bad(fmt.Sprintf("node_timeout %q is not a positive duration", req.NodeTimeout))
		}
		timeout = d
	}
	batch := strings.TrimSpace(req.Batch)
	if batch == "" {
		batch = "10%"
	}
	return &RolloutRecord{
		TargetVersion: target, Source: req.Source, Hold: req.Hold, Batch: batch, PauseAfter: req.PauseAfter,
		NodeTimeoutNanos: int64(timeout), AllowDowntime: req.AllowDowntime, AllowUnversioned: req.AllowUnversioned,
		Files: cloneStringMap(req.Files),
	}, nil
}

// ParseRolloutBatch turns --batch into a batch size for workers workers:
// "3" is three, "10%" is 10% rounded up; at least 1 (CEO D10). "0", "0%",
// and anything over 100% are refused. Empty is 10%.
func ParseRolloutBatch(batch string, workers int) (int, error) {
	b := strings.TrimSpace(batch)
	if b == "" {
		b = "10%"
	}
	if pct, ok := strings.CutSuffix(b, "%"); ok {
		p, err := strconv.ParseFloat(pct, 64)
		if err != nil || p <= 0 || p > 100 || math.IsNaN(p) {
			return 0, fmt.Errorf("batch %q: a percentage must be above 0%% and at most 100%%", batch)
		}
		n := int(math.Ceil(float64(workers) * p / 100))
		if n < 1 {
			n = 1
		}
		return n, nil
	}
	n, err := strconv.Atoi(b)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("batch %q: give a count of at least 1 or a percentage such as 10%%", batch)
	}
	return n, nil
}

func sameFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// missingUploads lists the files the leader's store lacks.
func (c *Cluster) missingUploads(files map[string]string) []string {
	var missing []string
	for _, name := range sortedKeys(files) {
		if ok, _ := c.HasUpgradeFile(files[name]); !ok {
			missing = append(missing, name+"="+files[name])
		}
	}
	return missing
}

// newRolloutID makes a rollout ID: the UTC time and four random bytes.
func newRolloutID(now time.Time) string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "r" + now.UTC().Format("20060102t150405") + "-" + hex.EncodeToString(b[:])
}

// rolloutMember is one node a new rollout covers.
type rolloutMember struct {
	Member
	tier string
}

// buildRollout fills a new rollout: every member that is not deleted, its
// tier, CPU type, order and batch (§6.2), and its own cordon mark.
func (c *Cluster) buildRollout(caller string, spec *RolloutRecord, req upgradewire.ApplyRequest) (*RolloutRecord, error) {
	voters, err := c.raftVoters()
	if err != nil {
		return nil, rolloutErr(http.StatusServiceUnavailable, "retry", err.Error(), "")
	}
	// With one or two voters, restarting any one leaves no majority up, so
	// the driver restarts no server without allow_downtime (quorumRefusal).
	// Say so now, before anything is staged.
	if len(voters) < 3 && !req.AllowDowntime {
		reason := "this cluster has one Raft voter: no majority stays up and leadership cannot move while it restarts, so the API is down for that restart (sandboxes keep running)"
		if len(voters) == 2 {
			reason = "this cluster has two Raft voters: while either one restarts, one of two is up, which is no majority, so the API is down for each server restart (sandboxes keep running)"
		}
		return nil, rolloutErr(http.StatusConflict, upgradewire.ErrCodeNeedsDowntime, reason,
			"apply again with allow_downtime (aerolvm upgrade apply --allow-downtime)")
	}
	denied := c.fsm.deniedNodeSet()
	drained := c.fsm.drainedNodesSnapshot()
	isVoter := map[string]bool{}
	for _, v := range voters {
		isVoter[v] = true
	}
	configured, _ := c.raftServerIDs()
	seen := map[string]bool{}
	var members []rolloutMember
	add := func(m Member) {
		if m.NodeID == "" || seen[m.NodeID] || denied[m.NodeID] {
			return
		}
		seen[m.NodeID] = true
		members = append(members, rolloutMember{Member: m, tier: rolloutTierOf(m, configured[m.NodeID])})
	}
	for _, m := range c.LocalMembers() {
		add(m)
	}
	for id := range configured {
		if !seen[id] {
			add(Member{NodeID: id, Role: "server"})
		}
	}
	spec.ID = newRolloutID(time.Now())
	spec.Caller = caller
	spec.PreviousVersion = previousVersion(members, spec.TargetVersion)
	spec.Nodes = map[string]*RolloutNodeRecord{}
	if err := orderRolloutNodes(spec, members, c.nodeID, len(voters) == 1); err != nil {
		return nil, err
	}
	for _, id := range sortedNodeIDs(spec.Nodes) {
		n := spec.Nodes[id]
		n.WasCordoned = drained[id]
		if err := checkNodeFiles(spec.Files, n.Arch); err != nil {
			return nil, rolloutErr(http.StatusBadRequest, "bad_request",
				fmt.Sprintf("%v (node %s runs linux/%s)", err, id, n.Arch), "give the files for every CPU type the cluster runs, one of each binary")
		}
	}
	return spec, nil
}

const (
	nodeupgradeRoleSandboxd = "sandboxd"
	nodeupgradeRoleToolboxd = "toolboxd"
)

// rolloutTierOf puts a member in a tier: a Raft server is a server; then
// an ingress-only node; everything else that owns sandboxes is a worker.
func rolloutTierOf(m Member, raftServer bool) string {
	if raftServer {
		return rolloutTierServer
	}
	if !CanOwnSandboxRole(m.Role) && CanServeControlPlaneRole(m.Role) {
		return rolloutTierServer
	}
	if !CanOwnSandboxRole(m.Role) {
		return rolloutTierIngress
	}
	return rolloutTierWorker
}

// previousVersion is the version most nodes not on the target run: the
// version a rollback goes back to.
func previousVersion(members []rolloutMember, target string) string {
	counts := map[string]int{}
	for _, m := range members {
		if v := strings.TrimSpace(m.Version); v != "" && v != target {
			counts[v]++
		}
	}
	best, bestN := "", 0
	for v, n := range counts {
		if n > bestN || (n == bestN && v < best) {
			best, bestN = v, n
		}
	}
	if best == "" && version.Version != target {
		best = version.Version
	}
	return best
}

// orderRolloutNodes numbers the nodes in §6.2 order: servers one at a time
// with this leader last, then ingress nodes one at a time, then workers in
// batches. With one voter (eng D8) the server goes last of all, after the
// workers. --pause-after cuts the first worker batch (§6.7).
func orderRolloutNodes(r *RolloutRecord, members []rolloutMember, leader string, singleVoter bool) error {
	byTier := map[string][]rolloutMember{}
	for _, m := range members {
		byTier[m.tier] = append(byTier[m.tier], m)
	}
	for tier := range byTier {
		list := byTier[tier]
		sort.Slice(list, func(i, j int) bool {
			if (list[i].NodeID == leader) != (list[j].NodeID == leader) {
				return list[j].NodeID == leader
			}
			return list[i].NodeID < list[j].NodeID
		})
	}
	workers := byTier[rolloutTierWorker]
	size, err := ParseRolloutBatch(r.Batch, len(workers))
	if err != nil {
		return rolloutErr(http.StatusBadRequest, "bad_request", err.Error(), "")
	}
	tiers := []string{rolloutTierServer, rolloutTierIngress, rolloutTierWorker}
	if singleVoter {
		tiers = []string{rolloutTierIngress, rolloutTierWorker, rolloutTierServer}
	}
	order := 0
	for _, tier := range tiers {
		batch, inBatch := 1, 0
		first := size
		if r.PauseAfter > 0 && r.PauseAfter < first {
			first = r.PauseAfter
		}
		for _, m := range byTier[tier] {
			order++
			arch := m.Arch
			if arch == "" {
				arch = "amd64"
			}
			n := &RolloutNodeRecord{
				NodeID: m.NodeID, Role: m.Role, Tier: tier, Arch: arch, State: upgradewire.NodePending,
				Version: m.Version, Order: order,
			}
			if tier == rolloutTierWorker {
				limit := size
				if batch == 1 {
					limit = first
				}
				if inBatch >= limit {
					batch++
					inBatch = 0
				}
				n.Batch = batch
				inBatch++
			}
			if m.Version == r.TargetVersion {
				// Already on the target: nothing to do for it (§6.6).
				n.State = upgradewire.NodeDone
			}
			r.Nodes[m.NodeID] = n
		}
	}
	return nil
}

// nodeFiles is the subset of files a node of arch installs: release.json
// and every binary built for arch. An asset without a CPU type fits every
// node.
func nodeFiles(files map[string]string, arch string) map[string]string {
	out := map[string]string{}
	for name, sum := range files {
		if name == release.FileName {
			out[name] = sum
			continue
		}
		m := rolloutAssetRe.FindStringSubmatch(name)
		if m == nil || (m[3] != "" && m[3] != arch) {
			continue
		}
		out[name] = sum
	}
	return out
}

// checkNodeFiles reports why a node of arch could not install files: no
// sandboxd or toolboxd for it, or two files for one binary.
func checkNodeFiles(files map[string]string, arch string) error {
	roles := map[string]string{}
	for name := range nodeFiles(files, arch) {
		m := rolloutAssetRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		if prev, dup := roles[m[1]]; dup {
			return fmt.Errorf("files name two %s files for %s: %s and %s", m[1], arch, prev, name)
		}
		roles[m[1]] = name
	}
	for _, need := range []string{nodeupgradeRoleSandboxd, nodeupgradeRoleToolboxd} {
		if roles[need] == "" {
			return fmt.Errorf("files has no %s for linux/%s", need, arch)
		}
	}
	return nil
}

// checkSkew refuses a downgrade (§6.3 step 3) and, when the leader holds
// the target's release.json, a jump from below its upgrade_from_min (§6.5).
func (c *Cluster) checkSkew(r *RolloutRecord) error {
	if r.AllowUnversioned {
		return nil
	}
	tgt, err := release.ParseVersion(r.TargetVersion)
	if err != nil {
		return rolloutErr(http.StatusBadRequest, upgradewire.ErrCodeSkew, err.Error(), "")
	}
	meta := c.leaderReleaseMeta(r.Files)
	for _, n := range r.sortedNodes() {
		cur, err := release.ParseVersion(n.Version)
		if err != nil {
			continue
		}
		if tgt.Compare(cur) < 0 {
			return rolloutErr(http.StatusConflict, upgradewire.ErrCodeSkew,
				fmt.Sprintf("%s is older than %s, which node %s runs: a downgrade is a rollback", r.TargetVersion, n.Version, n.NodeID), "aerolvm upgrade rollback", n.NodeID)
		}
		if meta != nil {
			if err := meta.UpgradeAllowedFrom(n.Version); err != nil {
				return rolloutErr(http.StatusConflict, upgradewire.ErrCodeSkew, err.Error(), "upgrade through the releases in between first", n.NodeID)
			}
		}
	}
	return nil
}

// leaderReleaseMeta reads the target's release.json from the leader's
// store, when an upload put it there.
func (c *Cluster) leaderReleaseMeta(files map[string]string) *release.Metadata {
	sum := files[release.FileName]
	if sum == "" || c.upgrade == nil {
		return nil
	}
	p, err := c.upgrade.paths()
	if err != nil {
		return nil
	}
	path, err := nodeupgrade.FileStore{Dir: nodeupgrade.FileStoreDir(p.StateDir)}.Path(sum)
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	meta, err := release.Parse(raw)
	if err != nil {
		return nil
	}
	return &meta
}

// raftVoters lists the voters' IDs; raftServerIDs every configured server.
func (c *Cluster) raftVoters() ([]string, error) {
	f := c.raft.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	var out []string
	for _, s := range f.Configuration().Servers {
		if s.Suffrage == raft.Voter {
			out = append(out, string(s.ID))
		}
	}
	return out, nil
}

func (c *Cluster) raftServerIDs() (map[string]bool, error) {
	f := c.raft.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, s := range f.Configuration().Servers {
		out[string(s.ID)] = true
	}
	return out, nil
}

func sortedNodeIDs(m map[string]*RolloutNodeRecord) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
