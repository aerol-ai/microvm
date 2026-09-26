//go:build integration

package suite

// Group I — the enterprise profile's boot gates (§7 group I, F14).
// UC-156..159. Every case here deliberately REFUSES a node's boot, so they
// sort last and each one restores the node before the next runs.

import (
	"testing"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// enterpriseGate is one forbidden configuration and the phrase the refusal
// must carry.
//
// The phrase matters as much as the refusal. A node that fails to start for
// an unrelated reason — a bad binary, a full disk, a port already bound —
// also satisfies "did not start", and a matrix that only checked that would
// go green while proving nothing. Every row therefore asserts BOTH.
type enterpriseGate struct {
	name string
	env  map[string]string
	// want is a distinctive fragment of the message config.go (or daemon.go)
	// produces. Taken from the source, not invented.
	want string
}

// enterpriseGates mirrors internal/config/config.go's enterprise validation
// block and pkg/daemon/daemon.go's exporter check.
func enterpriseGates() []enterpriseGate {
	return []enterpriseGate{
		{
			name: "short PAT",
			env:  map[string]string{"SB_PAT_TOKEN": "short"},
			want: "SB_PAT_TOKEN must contain at least",
		},
		{
			name: "privileged containers",
			env:  map[string]string{"SB_CONTAINER_PRIVILEGED": "true"},
			want: "SB_CONTAINER_PRIVILEGED must be false",
		},
		{
			name: "resource limits disabled",
			env:  map[string]string{"SB_RESOURCE_LIMITS_DISABLED": "true"},
			want: "SB_RESOURCE_LIMITS_DISABLED must be false",
		},
		{
			name: "audit strict boot off",
			env:  map[string]string{"SB_SECRET_AUDIT_STRICT_BOOT": "false"},
			want: "SB_SECRET_AUDIT_STRICT_BOOT must be true",
		},
		{
			name: "awskms without strict boot",
			env: map[string]string{
				"SB_SECRET_PROVIDER":             "awskms",
				"SB_SECRET_PROVIDER_STRICT_BOOT": "false",
			},
			want: "SB_SECRET_PROVIDER_STRICT_BOOT must be true for awskms",
		},
		{
			name: "zero retention",
			env: map[string]string{
				"SB_SECRET_AUDIT_RETENTION_DAYS": "0",
				"SB_SECRET_TOMB_RETENTION_DAYS":  "0",
			},
			want: "retention must be non-zero",
		},
		{
			name: "unbounded per-sandbox evidence",
			env:  map[string]string{"SB_AUDIT_EGRESS_SANDBOX_RATE": "0"},
			want: "SB_AUDIT_EGRESS_SANDBOX_RATE must be > 0",
		},
		{
			name: "insecure gossip",
			env:  map[string]string{"SB_CLUSTER_INSECURE_GOSSIP": "true"},
			want: "insecure escape hatches are forbidden",
		},
		{
			name: "insecure credentials",
			env:  map[string]string{"SB_CLUSTER_INSECURE_CREDENTIALS": "true"},
			want: "insecure escape hatches are forbidden",
		},
		{
			name: "fewer than two secret backups",
			env:  map[string]string{"SB_SECRET_RECIPIENT_BACKUP_COUNT": "1"},
			want: "at least two backups is required",
		},
		{
			name: "isolate without a jail",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":   "true",
				"SB_ISOLATE_USE_JAIL": "false",
			},
			want: "SB_ISOLATE_USE_JAIL must be true",
		},
		{
			name: "isolate seccomp not enforcing",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":        "true",
				"SB_ISOLATE_USE_JAIL":      "true",
				"SB_ISOLATE_SECCOMP_MODE":  "permissive",
				"SB_ISOLATE_JAIL_PIDS_MAX": "64",
			},
			want: "SB_ISOLATE_SECCOMP_MODE must be enforce",
		},
		{
			name: "isolate jail with an unbounded pid cap",
			env: map[string]string{
				"SB_ENABLE_ISOLATE":        "true",
				"SB_ISOLATE_USE_JAIL":      "true",
				"SB_ISOLATE_SECCOMP_MODE":  "enforce",
				"SB_ISOLATE_JAIL_PIDS_MAX": "0",
			},
			want: "SB_ISOLATE_JAIL_PIDS_MAX must be > 0",
		},
	}
}

// UC-156 (with UC-158 and UC-159 folded in) — the enterprise boot-gate
// matrix. Every forbidden combination must refuse the node WITH the
// documented message, and the node must come back clean after each one.
//
// UC-159 is not a separate test function because it is not a separate
// experiment: "the matrix must not leave the fleet degraded" is a property of
// every row, and asserting it once at the end would not catch the row that
// broke it. harness.WithNodeEnv restores from a defer, so it holds even when
// a row fails its assertion.
func TestEnterpriseBootGateMatrix(t *testing.T) {
	harness.Require(t, sc, "UC-156", "UC-158", "UC-159")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deliberately refuses a node's boot, repeatedly")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	// Prefer a joiner: refusing the seed's boot on a cluster costs the
	// rendezvous every joiner needs, turning one red row into a split cluster.
	node, ok := pickNonSeedNode(targets)
	if !ok {
		var fallback bool
		node, fallback = harness.PickSSHNode(targets)
		if !fallback {
			t.Skip("no SSH-reachable node")
		}
	}
	c := client(t)

	gates := append(enterpriseGates(), enterpriseGate{
		// UC-158: an on-node-only exporter keeps the evidence on the machine
		// that produces it, which is the one an attacker who owns the node
		// can edit. daemon.go refuses it.
		name: "on-node-only audit exporter (UC-158)",
		env: map[string]string{
			"SB_AUDIT_EXPORT_ENABLED":   "true",
			"SB_AUDIT_EXPORT_BACKEND":   "file",
			"SB_AUDIT_EXPORT_FILE_PATH": "/var/log/aerol-uc158.jsonl",
		},
		want: "requires an off-node audit exporter",
	})

	for _, g := range gates {
		t.Run(g.name, func(t *testing.T) {
			harness.WithNodeEnv(t, node, g.env, func(res harness.NodeBootResult) {
				if res.Started {
					t.Fatalf("the enterprise node STARTED with %s (%v). This configuration is supposed to be refused; the gate is not enforced on a real node.",
						g.name, redactedKeys(g.env))
				}
				if !res.RefusedWith(g.want) {
					t.Fatalf("the node refused to start, but the journal does not contain %q — a boot-gate assertion must not be satisfied by an unrelated failure (a bad binary and a full disk also fail to start):\n%s",
						g.want, tailLines(res.Journal, 40))
				}
			})
			// UC-159, per row: the node must be back and serving before the
			// next row runs, or every later row asserts against a node that
			// was already down.
			assertNodeBackInService(t, c, targets, node)
		})
	}
}

// UC-157 — the CA signing key in the daemon's TLS directory refuses an
// enterprise boot.
//
// Separate from the matrix because its fault is a FILE, not an env var: the
// point is that an operator who copies ca.key onto a worker "just for a
// moment" cannot start that worker at all.
func TestCAKeyInTLSDirRefusesEnterpriseBoot(t *testing.T) {
	harness.Require(t, sc, "UC-157")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deliberately refuses a node's boot")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	node, ok := pickNonSeedNode(targets)
	if !ok {
		t.Skip("no SSH-reachable non-seed node")
	}
	target, _ := harness.SSHTarget(node)
	c := client(t)

	// Plant a decoy. It never has to be a real key: the gate is a stat().
	out, err := harness.SSHRun(t, target, plantDecoyCAKeyScript)
	if err != nil {
		t.Fatalf("plant a decoy ca.key on %s: %v\n%s", node.Name, err, out)
	}
	removed := false
	removeDecoy := func() {
		if removed {
			return
		}
		removed = true
		if rout, rerr := harness.SSHRun(t, target, removeDecoyCAKeyScript); rerr != nil {
			t.Errorf("RESTORE FAILED: the decoy ca.key is still on %s and that node can never boot again under enterprise: %v\n%s",
				node.Name, rerr, rout)
		}
	}
	defer removeDecoy()

	harness.WithNodeEnv(t, node, nil, func(res harness.NodeBootResult) {
		if res.Started {
			t.Fatalf("node %s started with a CA signing key in its TLS directory: an operator who copies ca.key onto a worker keeps a fleet-wide minting capability on a machine that only needs one identity",
				node.Name)
		}
		if !res.RefusedWith("CA signing key") && !res.RefusedWith("ca.key") {
			t.Fatalf("the node refused to start but not for the CA key:\n%s", tailLines(res.Journal, 40))
		}
	})

	removeDecoy()
	assertNodeBackInService(t, c, targets, node)
}
