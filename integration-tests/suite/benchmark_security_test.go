//go:build integration

package suite

// Group L — non-regression on the boot path (§7 group L). UC-165, UC-166.
//
// These live beside benchmark_test.go and reuse its summarize/artifact
// machinery rather than re-deriving percentiles, so a change to how the
// suite computes p99 moves both at once.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// The bands the plan fixes. p99 gets a wider one because a tail on spot t3 is
// mostly the instance, not the code.
const (
	securityP50Band = 1.10
	securityP99Band = 1.20
)

// mainBaselineEnv points at the artifact produced by the same benchmark run
// against main-built binaries. Without it there is nothing to compare to and
// UC-165 says so rather than passing.
const mainBaselineEnv = "AEROL_BENCH_MAIN_BASELINE"

// UC-165 — the default create path did not get slower.
//
// The comparison is main-built binaries vs branch-built binaries, NOT
// security-profile-on vs security-profile-off. Those are different questions:
// the second measures what the feature costs when you turn it on, which is
// expected to be non-zero and is not a regression. This one asks whether the
// code that everyone runs — with the feature off — still costs what it did.
func TestSecurityBranchDidNotSlowTheDefaultCreatePath(t *testing.T) {
	harness.Require(t, sc, "UC-165")
	requireBenchEnabled(t)

	baselinePath := os.Getenv(mainBaselineEnv)
	if baselinePath == "" {
		t.Skipf("%s not set: UC-165 needs the same benchmark run against main-built binaries to compare against. Produce it with `integration-tests/run.sh cluster-3-mixed-bench --ref main` and point %s at its JSON.",
			mainBaselineEnv, mainBaselineEnv)
	}
	baseline, err := loadBenchBaseline(baselinePath)
	if err != nil {
		t.Fatalf("read the main baseline at %s: %v", baselinePath, err)
	}
	if len(baseline.Latency) == 0 {
		t.Fatalf("the main baseline at %s has no latency rows; there is nothing to compare against", baselinePath)
	}

	currentPath := os.Getenv("AEROL_BENCH_OUT")
	if currentPath == "" {
		t.Skip("AEROL_BENCH_OUT not set; this run produced no artifact to compare")
	}
	current, err := loadBenchBaseline(currentPath)
	if err != nil {
		t.Fatalf("read this run's artifact at %s: %v", currentPath, err)
	}

	// 25 samples, per the plan: at 10, spot-instance noise is wider than the
	// 10% band and the comparison decides nothing.
	if n := benchEnvInt("AEROL_BENCH_SAMPLES", 10); n < 25 {
		t.Logf("WARNING: AEROL_BENCH_SAMPLES=%d. The +10%% p50 band is narrower than t3 spot noise below 25 samples, so a pass here is weak evidence.", n)
	}
	// Identical hardware, or the comparison measures the instance type rather
	// than the branch. The plan says "both arms on identical instance types";
	// this is where that is enforced instead of assumed.
	if baseline.Machine != nil && current.Machine != nil {
		if b, cu := baseline.Machine.DefaultInstance, current.Machine.DefaultInstance; b != cu {
			t.Fatalf("the baseline ran with default_instance_type %q and this run with %q: comparing create latency across instance types measures the hardware, not the branch", b, cu)
		}
		if b, cu := instanceShape(baseline.Machine), instanceShape(current.Machine); b != cu {
			t.Fatalf("the two arms declare different node shapes (%s vs %s): the comparison is not like for like", b, cu)
		}
	}

	byRuntime := map[string]latencyStats{}
	for _, ls := range baseline.Latency {
		byRuntime[ls.Runtime] = ls
	}

	compared := 0
	for _, cur := range current.Latency {
		base, ok := byRuntime[cur.Runtime]
		if !ok {
			t.Logf("runtime %q is not in the baseline; skipping it", cur.Runtime)
			continue
		}
		// Server-side, not API: the api-server gap is the WAN hop to the
		// cluster and varies with where the run was launched from.
		if base.Serverp50MS == 0 || cur.Serverp50MS == 0 {
			t.Logf("runtime %q has no server-side timing on one side (baseline=%dms current=%dms); falling back to the API round-trip",
				cur.Runtime, base.Serverp50MS, cur.Serverp50MS)
			assertWithinBand(t, cur.Runtime, "api p50", base.APIp50MS, cur.APIp50MS, securityP50Band)
			assertWithinBand(t, cur.Runtime, "api p99", base.APIp99MS, cur.APIp99MS, securityP99Band)
		} else {
			assertWithinBand(t, cur.Runtime, "server p50", base.Serverp50MS, cur.Serverp50MS, securityP50Band)
			assertWithinBand(t, cur.Runtime, "server p99", base.Serverp99MS, cur.Serverp99MS, securityP99Band)
		}
		compared++
	}
	if compared == 0 {
		t.Fatalf("no runtime appeared in both the baseline and this run; UC-165 compared nothing and would have passed regardless")
	}
}

func assertWithinBand(t *testing.T, runtime, metric string, baseMS, curMS int64, band float64) {
	t.Helper()
	if baseMS <= 0 {
		t.Logf("%s %s: baseline is %dms, nothing to compare", runtime, metric, baseMS)
		return
	}
	limit := float64(baseMS) * band
	pct := (float64(curMS)/float64(baseMS) - 1) * 100
	if float64(curMS) > limit {
		t.Errorf("%s %s regressed: main=%dms branch=%dms (%+.1f%%, band +%.0f%%)",
			runtime, metric, baseMS, curMS, pct, (band-1)*100)
		return
	}
	t.Logf("%s %s: main=%dms branch=%dms (%+.1f%%)", runtime, metric, baseMS, curMS, pct)
}

func loadBenchBaseline(path string) (benchReport, error) {
	var rep benchReport
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return rep, err
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return rep, fmt.Errorf("decode %s: %w", path, err)
	}
	return rep, nil
}

// UC-166 — HA create latency, reported SEPARATELY, with the first call
// visible rather than averaged away.
//
// Separately, because an HA create pays the min-ACK wait and a plain create
// does not: folding them into one number hides the cost of the feature in the
// noise of the creates that do not use it. First-call visible, because
// SealAndDistribute runs synchronously on the cluster create path under a 5s
// commitCtx and pkg/secrets mints a fresh DEK and calls wrap() ONCE PER SEAL
// with no cache — so on a KMS profile every HA create pays a live AWS KMS
// round trip, and the first one also pays whatever setup precedes it. A
// median over 25 samples would report that as ~0.
func TestHACreateLatencyReportedSeparately(t *testing.T) {
	harness.Require(t, sc, "UC-166")
	requireBenchEnabled(t)
	c := client(t)

	samples := benchEnvInt("AEROL_BENCH_SAMPLES", 10)
	if samples < 2 {
		t.Skip("UC-166 needs at least 2 samples to separate the first call from the rest")
	}

	var apiD []time.Duration
	var serverD []time.Duration
	var firstCall time.Duration
	failures := 0

	for i := 0; i < samples; i++ {
		public := true
		opts := sdktypes.CreateSandboxOptions{
			Name:               harness.UniqueName(sc, t) + fmt.Sprintf("-%d", i),
			Image:              harness.DefaultImage,
			AllowPublicTraffic: &public,
			Env:                map[string]string{"UC166_TOKEN": secretValue(t, "166")},
			Failover:           &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
		}
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		sb, err := c.SDK().Create(ctx, opts)
		elapsed := time.Since(start)
		cancel()
		if err != nil {
			failures++
			t.Logf("HA bench sample %d failed: %v", i, err)
			continue
		}
		id := sb.ID
		if i == 0 {
			firstCall = elapsed
		}
		apiD = append(apiD, elapsed)
		if ms, ok := c.LastServerCreateMS(); ok {
			serverD = append(serverD, time.Duration(ms*float64(time.Millisecond)))
		}
		destroyBest(c, id)
	}

	if len(apiD) == 0 {
		t.Fatalf("every HA create sample failed (%d attempts); there is no latency to report", samples)
	}

	label := "ha-create"
	if sc.Has(harness.CapSecretsKMS) {
		// The KMS row is the one that matters: it is the only profile that
		// pays a live AWS KMS wrap per seal, and without it S3/S6's real cost
		// is never measured.
		label = "ha-create-kms"
	}
	ls := summarize(label, samples, failures, apiD, nil, serverD)
	ls.APISamplesMS = durationsToMS(apiD)
	ls.ServerSamplesMS = durationsToMS(serverD)

	t.Logf("UC-166 %s: FIRST CALL %dms | api p50=%dms p90=%dms p99=%dms | server p50=%dms p99=%dms (%d ok, %d fail)",
		label, firstCall.Milliseconds(), ls.APIp50MS, ls.APIp90MS, ls.APIp99MS,
		ls.Serverp50MS, ls.Serverp99MS, len(apiD), failures)

	if !sc.Has(harness.CapSecretsKMS) {
		t.Logf("NOTE: this scenario has no KMS provider, so this row does NOT include the per-seal AWS KMS round trip that S3/S6 pay. UC-166's KMS row is unmeasured until this runs on a secrets-kms scenario.")
	}

	writeBenchArtifact(t, benchReport{
		Latency:      []latencyStats{ls},
		HeadlineNote: fmt.Sprintf("UC-166 HA create (failover.policy=recreate). First call %dms, reported separately because SealAndDistribute runs synchronously on the create path and pkg/secrets wraps a fresh DEK per seal with no cache.", firstCall.Milliseconds()),
	})
}

// instanceShape renders a machineConfig's per-node instance types in a stable
// order, so two arms can be compared without caring about map ordering.
func instanceShape(m *machineConfig) string {
	if m == nil {
		return ""
	}
	parts := make([]string, 0, len(m.Nodes))
	for _, n := range m.Nodes {
		it := n.InstanceType
		if it == "" {
			it = m.DefaultInstance
		}
		parts = append(parts, n.Role+"="+it)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
