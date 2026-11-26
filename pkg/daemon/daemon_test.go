package daemon

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestShouldStartSSHGateway is the regression guard for cluster-hetero
// UC-43/67: the SSH gateway was gated on IsWorker() only, so the ingress —
// which is where the public :2220 endpoint and wildcard DNS resolve — never
// bound a gateway and every `ssh sandbox.<domain>` got "connection refused".
// The gateway must run on workers AND ingress (and on mixed nodes, which are
// both), but not on a pure server.
func TestShouldStartSSHGateway(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{name: "worker_starts", cfg: config.Config{EnableSSHGateway: true, NodeRole: config.NodeRoleWorker}, want: true},
		{name: "ingress_starts", cfg: config.Config{EnableSSHGateway: true, NodeRole: config.NodeRoleIngress}, want: true},
		{name: "server_does_not_start", cfg: config.Config{EnableSSHGateway: true, NodeRole: config.NodeRoleServer}, want: false},
		{name: "mixed_starts", cfg: config.Config{EnableSSHGateway: true, NodeRole: config.NodeRoleMixed}, want: true},
		{name: "empty_role_is_mixed_starts", cfg: config.Config{EnableSSHGateway: true}, want: true},
		{name: "worker_ingress_hybrid_starts", cfg: config.Config{EnableSSHGateway: true, NodeRole: "worker,ingress"}, want: true},
		{name: "disabled_never_starts", cfg: config.Config{EnableSSHGateway: false, NodeRole: config.NodeRoleWorker}, want: false},
		{name: "disabled_ingress_never_starts", cfg: config.Config{EnableSSHGateway: false, NodeRole: config.NodeRoleIngress}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldStartSSHGateway(tt.cfg); got != tt.want {
				t.Fatalf("shouldStartSSHGateway(%+v) = %v, want %v", tt.cfg, got, tt.want)
			}
		})
	}
}

// TestReadBypassMarkerMissingReadsFalse: first boot has no marker file
// — the safer default is "previous run had bypass off", so no rollback
// force-reconcile fires.
func TestReadBypassMarkerMissingReadsFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass_last_enabled")
	if readBypassMarker(path) {
		t.Fatalf("missing marker read as true; want false")
	}
}

// TestWriteThenReadBypassMarkerRoundTrip: each boolean value written
// must round-trip exactly. The marker is the only source of truth for
// the rollback decision; a flip in storage would silently misfire the
// force-reconcile pass.
func TestWriteThenReadBypassMarkerRoundTrip(t *testing.T) {
	for _, want := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "bypass_last_enabled")
		if err := writeBypassMarker(path, want); err != nil {
			t.Fatalf("writeBypassMarker(%v): %v", want, err)
		}
		if got := readBypassMarker(path); got != want {
			t.Fatalf("readBypassMarker = %v, want %v", got, want)
		}
	}
}

// TestWriteBypassMarkerOverwritesPriorValue: a write must replace any
// existing content. Operator toggling true→false→true must not leave
// stale state behind.
func TestWriteBypassMarkerOverwritesPriorValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bypass_last_enabled")
	if err := writeBypassMarker(path, true); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := writeBypassMarker(path, false); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if readBypassMarker(path) {
		t.Fatalf("read after true→false write reports true; rollback would not fire on subsequent flip")
	}
}

// TestWriteBypassMarkerAtomicViaTmpRename: the tmp-then-rename pattern
// must not leak the .tmp file on success — otherwise the next boot's
// `cat ${dir}/bypass_last_enabled.tmp` could mislead an operator.
func TestWriteBypassMarkerAtomicViaTmpRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bypass_last_enabled")
	if err := writeBypassMarker(path, true); err != nil {
		t.Fatalf("writeBypassMarker: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("stat .tmp after success: err=%v (want IsNotExist)", err)
	}
}

// TestReadBypassMarkerTrimsTrailingNewline: writeBypassMarker appends
// a newline so an operator's `cat` is readable. readBypassMarker must
// tolerate that newline (and any incidental surrounding whitespace —
// e.g. if an operator hand-edits the marker for testing).
func TestReadBypassMarkerTrimsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bypass_last_enabled")
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"newline_terminated_true", "true\n", true},
		{"untrimmed_true_with_spaces", " true \n", true},
		{"tab_padded_true", "\ttrue\t\n", true},
		{"plain_false_no_newline", "false", false},
		{"empty_file_reads_false", "", false},
		{"junk_value_reads_false", "yes\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("seed marker: %v", err)
			}
			if got := readBypassMarker(path); got != tc.want {
				t.Fatalf("readBypassMarker(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

func TestAppendRuntimeIfMissing(t *testing.T) {
	got := appendRuntimeIfMissing([]string{models.RuntimeDocker}, models.RuntimeFirecracker)
	if len(got) != 2 || got[0] != models.RuntimeDocker || got[1] != models.RuntimeFirecracker {
		t.Fatalf("appendRuntimeIfMissing appended = %v, want [docker firecracker]", got)
	}

	got = appendRuntimeIfMissing([]string{" docker ", models.RuntimeFirecracker}, models.RuntimeFirecracker)
	if len(got) != 2 {
		t.Fatalf("appendRuntimeIfMissing duplicated existing runtime: %v", got)
	}

	got = appendRuntimeIfMissing([]string{models.RuntimeDocker}, " ")
	if len(got) != 1 || got[0] != models.RuntimeDocker {
		t.Fatalf("appendRuntimeIfMissing blank changed runtimes: %v", got)
	}
}

// TestSupportedRuntimesForConfig is the regression guard for the cluster
// placement bug: a wasm-enabled host that never advertised "wasm" in
// SupportedRuntimes made every wasm create fail with ErrNoPlacementTarget (the
// firecracker advertisement existed, the wasm one was missing). Each enable
// flag must surface its runtime; SB_HOST_RUNTIMES overrides the docker default.
func TestSupportedRuntimesForConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want []string
	}{
		{name: "docker_only_default", cfg: config.Config{}, want: []string{models.RuntimeDocker}},
		{name: "wasm_enabled_advertises_wasm", cfg: config.Config{EnableWasm: true}, want: []string{models.RuntimeDocker, models.RuntimeWasm}},
		{name: "wasm_enabled_worker_advertises_wasm", cfg: config.Config{EnableWasm: true, NodeRole: config.NodeRoleWorker}, want: []string{models.RuntimeDocker, models.RuntimeWasm}},
		{name: "wasm_enabled_ingress_does_not_advertise_wasm", cfg: config.Config{EnableWasm: true, NodeRole: config.NodeRoleIngress}, want: []string{models.RuntimeDocker}},
		{name: "wasm_enabled_server_does_not_advertise_wasm", cfg: config.Config{EnableWasm: true, NodeRole: config.NodeRoleServer}, want: []string{models.RuntimeDocker}},
		{name: "firecracker_enabled_advertises_fc", cfg: config.Config{EnableFirecracker: true}, want: []string{models.RuntimeDocker, models.RuntimeFirecracker}},
		{name: "firecracker_kvm_backend_advertises_fc", cfg: config.Config{EnableFirecracker: true, FirecrackerBackend: config.FirecrackerBackendKVM}, want: []string{models.RuntimeDocker, models.RuntimeFirecracker}},
		// A Nitro node offers only its own name: a create that asked for
		// KVM's snapshots and pause must never be placed on it.
		{name: "firecracker_nitro_backend_advertises_nitro_only", cfg: config.Config{EnableFirecracker: true, FirecrackerBackend: config.FirecrackerBackendNitro}, want: []string{models.RuntimeDocker, models.RuntimeFirecrackerNitro}},
		{name: "both_enabled", cfg: config.Config{EnableFirecracker: true, EnableWasm: true}, want: []string{models.RuntimeDocker, models.RuntimeFirecracker, models.RuntimeWasm}},
		// The isolate flag must advertise like wasm's — same placement-bug
		// class if omitted: cluster mode would reject every isolate create
		// with ErrNoPlacementTarget.
		{name: "isolate_enabled_advertises_isolate", cfg: config.Config{EnableIsolate: true}, want: []string{models.RuntimeDocker, models.RuntimeIsolate}},
		{name: "isolate_enabled_ingress_does_not_advertise", cfg: config.Config{EnableIsolate: true, NodeRole: config.NodeRoleIngress}, want: []string{models.RuntimeDocker}},
		{name: "all_optional_runtimes_enabled", cfg: config.Config{EnableFirecracker: true, EnableWasm: true, EnableIsolate: true}, want: []string{models.RuntimeDocker, models.RuntimeFirecracker, models.RuntimeWasm, models.RuntimeIsolate}},
		{name: "explicit_host_runtimes_override", cfg: config.Config{HostSupportedRuntimes: []string{models.RuntimeGvisor}, EnableWasm: true}, want: []string{models.RuntimeGvisor, models.RuntimeWasm}},
		// What install.sh --with-gvisor writes (SB_HOST_RUNTIMES=docker,gvisor):
		// gVisor has no enable flag, so the install script must advertise it
		// explicitly or placement rejects every gVisor create in cluster mode.
		{name: "gvisor_install_advertises_gvisor", cfg: config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeGvisor}, EnableWasm: true}, want: []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeWasm}},
		// gVisor has no enable flag, so a node whose default runtime is gvisor
		// (SB_RUNTIME=gvisor) but which never set SB_HOST_RUNTIMES must still
		// advertise gvisor or cluster placement rejects every gVisor create.
		{name: "default_runtime_gvisor_advertises_gvisor", cfg: config.Config{Runtime: models.RuntimeGvisor}, want: []string{models.RuntimeDocker, models.RuntimeGvisor}},
		{name: "default_runtime_gvisor_with_wasm", cfg: config.Config{Runtime: models.RuntimeGvisor, EnableWasm: true}, want: []string{models.RuntimeDocker, models.RuntimeGvisor, models.RuntimeWasm}},
		// Idempotent: explicit SB_HOST_RUNTIMES already containing gvisor must
		// not double-append when cfg.Runtime is also gvisor.
		{name: "default_runtime_gvisor_no_dup", cfg: config.Config{Runtime: models.RuntimeGvisor, HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeGvisor}}, want: []string{models.RuntimeDocker, models.RuntimeGvisor}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, off := supportedRuntimesForConfig(tt.cfg)
			if !slices.Equal(got, tt.want) || len(off) != 0 {
				t.Fatalf("supportedRuntimesForConfig = %v (switched off %v), want %v and none switched off", got, off, tt.want)
			}
		})
	}
}

// TestSupportedRuntimesDropsSwitchedOffRuntimes: SB_HOST_RUNTIMES cannot
// advertise a runtime whose own switch is off. Such a node used to tell
// GET /v1/runtimes the runtime was available and draw placement's creates
// for it, then refuse every one. The dropped names come back for the start
// warning, and the config's own slice is left as it was.
func TestSupportedRuntimesDropsSwitchedOffRuntimes(t *testing.T) {
	worker := config.NodeRoleWorker
	for _, tt := range []struct {
		name    string
		cfg     config.Config
		want    []string
		dropped []string
	}{
		{name: "firecracker listed, switch off",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecracker}},
			want: []string{models.RuntimeDocker}, dropped: []string{models.RuntimeFirecracker}},
		{name: "firecracker listed, switch on",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecracker}, EnableFirecracker: true},
			want: []string{models.RuntimeDocker, models.RuntimeFirecracker}},
		{name: "wasm and isolate listed, switches off",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeWasm, models.RuntimeIsolate}, NodeRole: worker},
			want: []string{models.RuntimeDocker}, dropped: []string{models.RuntimeWasm, models.RuntimeIsolate}},
		{name: "wasm listed and on, but not a worker",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeWasm}, EnableWasm: true, NodeRole: config.NodeRoleIngress},
			want: []string{models.RuntimeDocker}, dropped: []string{models.RuntimeWasm}},
		{name: "only a switched-off runtime listed: docker, as with none listed",
			cfg:  config.Config{HostSupportedRuntimes: []string{" firecracker ", ""}},
			want: []string{models.RuntimeDocker}, dropped: []string{models.RuntimeFirecracker}},
		{name: "nitro listed on a kvm node",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecrackerNitro}, EnableFirecracker: true},
			want: []string{models.RuntimeDocker, models.RuntimeFirecracker}, dropped: []string{models.RuntimeFirecrackerNitro}},
		{name: "firecracker listed on a nitro node",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecracker}, EnableFirecracker: true, FirecrackerBackend: config.FirecrackerBackendNitro},
			want: []string{models.RuntimeDocker, models.RuntimeFirecrackerNitro}, dropped: []string{models.RuntimeFirecracker}},
		{name: "nitro listed, switch off",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecrackerNitro}, FirecrackerBackend: config.FirecrackerBackendNitro},
			want: []string{models.RuntimeDocker}, dropped: []string{models.RuntimeFirecrackerNitro}},
		{name: "names with no switch stay",
			cfg:  config.Config{HostSupportedRuntimes: []string{models.RuntimeGvisor, models.RuntimeKata, "custom"}},
			want: []string{models.RuntimeGvisor, models.RuntimeKata, "custom"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listed := slices.Clone(tt.cfg.HostSupportedRuntimes)
			got, dropped := supportedRuntimesForConfig(tt.cfg)
			if !slices.Equal(got, tt.want) || !slices.Equal(dropped, tt.dropped) {
				t.Fatalf("supportedRuntimesForConfig = %v, dropped %v; want %v, dropped %v", got, dropped, tt.want, tt.dropped)
			}
			if !slices.Equal(tt.cfg.HostSupportedRuntimes, listed) {
				t.Fatalf("config's list changed to %v", tt.cfg.HostSupportedRuntimes)
			}
		})
	}
}

// TestWarnSwitchedOffRuntimes: one warning naming the dropped runtimes and
// the switches, and nothing when none were dropped.
func TestWarnSwitchedOffRuntimes(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	warnSwitchedOffRuntimes(logger, nil)
	warnSwitchedOffRuntimes(nil, []string{models.RuntimeFirecracker})
	if buf.Len() != 0 {
		t.Fatalf("logged with nothing dropped or no logger: %s", buf.String())
	}
	warnSwitchedOffRuntimes(logger, []string{models.RuntimeFirecracker, models.RuntimeWasm})
	out := buf.String()
	if strings.Count(out, "level=WARN") != 1 || !strings.Contains(out, "runtimes=firecracker,wasm") || !strings.Contains(out, "SB_ENABLE_FIRECRACKER") {
		t.Fatalf("warning = %q", out)
	}
}
