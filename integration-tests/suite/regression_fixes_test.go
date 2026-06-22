//go:build integration

package suite

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// This file holds the regression guards for the cluster-hetero fix pass
// (plans/cluster-hetero-failures-fix.md). Each test pins a specific bug that the
// full-suite UCs (UC-24/25/43) exercised only indirectly:
//
//   - UC-87 (B1): UC-25 proves a gVisor sandbox *runs*, but a create can succeed
//     by luck of placement even while a node mis-advertises its runtimes. UC-87
//     asserts the capability is actually published in gossip — the layer that
//     was broken (a --with-gvisor node advertised only [docker wasm]).
//   - UC-88 (B2): UC-24 creates with the default image, which may take the
//     template fast-path. UC-88 forces the cold-boot OCI->ext4 path that mkfs'd
//     into a not-yet-created jailer chroot.
//   - UC-89 (B4): UC-43 retries SSH through route/placement lag and can mask a
//     missing listener. UC-89 dials the raw TCP port on the ingress public host
//     and asserts a gateway is actually listening there.

// capacityView is the slice of /v1/cluster/members we need to assert on the
// advertised runtime set. It intentionally re-decodes (rather than sharing
// cluster_test.go's clusterMember) so the capacity shape lives next to the test
// that depends on it.
type capacityView struct {
	Members []struct {
		NodeID   string `json:"node_id"`
		Role     string `json:"role"`
		Capacity struct {
			SupportedRuntimes []string `json:"supported_runtimes"`
		} `json:"capacity"`
	} `json:"members"`
}

// UC-87 — every specialized runtime the scenario advertises a capability for
// must appear in at least one member's gossiped supported_runtimes. This is the
// direct guard for B1: the daemon ran gVisor locally but never told the cluster,
// so placement rejected every gVisor create with "no worker placement target
// available". Generalized to firecracker/wasm so the same advertise-or-be-
// invisible contract is enforced for each specialized runtime.
func TestClusterAdvertisesSpecializedRuntimes(t *testing.T) {
	harness.Require(t, sc, "UC-87")
	c := client(t)

	// Map the scenario's runtime capabilities to the runtime string each node
	// must advertise. Docker is always present and not interesting here.
	want := map[harness.Capability]string{
		harness.CapGvisor:      "gvisor",
		harness.CapFirecracker: "firecracker",
		harness.CapWasm:        "wasm",
	}
	var expect []string
	for cap, runtime := range want {
		if sc.Has(cap) {
			expect = append(expect, runtime)
		}
	}
	if len(expect) == 0 {
		t.Skip("scenario advertises no specialized runtime capability")
	}

	// Gossip capacity can lag node boot by a few heartbeats; poll until every
	// expected runtime is advertised somewhere, or fail with what was missing.
	deadline := time.Now().Add(90 * time.Second)
	var missing []string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		var cv capacityView
		err := c.GetJSON(ctx, "/v1/cluster/members", &cv)
		cancel()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}

		advertised := map[string]string{} // runtime -> node that advertises it
		for _, m := range cv.Members {
			for _, rt := range m.Capacity.SupportedRuntimes {
				if _, ok := advertised[rt]; !ok {
					advertised[rt] = m.NodeID
				}
			}
		}
		missing = missing[:0]
		for _, rt := range expect {
			if _, ok := advertised[rt]; !ok {
				missing = append(missing, rt)
			}
		}
		if len(missing) == 0 {
			for _, rt := range expect {
				t.Logf("runtime %q advertised by node %s", rt, advertised[rt])
			}
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("specialized runtimes never advertised in gossip capacity: %v (regression: a node runs the runtime but does not publish it, so placement rejects every create for it)", missing)
}

// UC-88 — create a firecracker sandbox from a plain OCI image (no template) and
// exec inside it. This forces the cold-boot OCI->ext4 pipeline: skopeo + umoci +
// `mkfs.ext4 -d <bundle> <runDir>/rootfs.ext4`. B2's bug was that <runDir> (the
// jailer chroot root) did not exist when mkfs ran, so the build failed with
// "mkfs.ext4: No such file or directory while trying to determine filesystem
// size". A successful exec proves the rootfs was built into the chroot and the
// VM booted.
func TestFirecrackerColdBootFromImage(t *testing.T) {
	harness.Require(t, sc, "UC-88")
	c := client(t)

	// DefaultImage is a small public image with no prebuilt firecracker
	// template, so Create takes the OCI cold-boot path rather than a snapshot
	// load. AEROL_FC_COLDBOOT_IMAGE can override it if the scenario stages a
	// different no-template image.
	image := os.Getenv("AEROL_FC_COLDBOOT_IMAGE")
	if image == "" {
		image = harness.DefaultImage
	}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:    harness.UniqueName(sc, t),
		Runtime: "firecracker",
		Image:   image,
	})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, "echo fc-coldboot-ok")
	if err != nil {
		t.Fatalf("exec in cold-booted firecracker sandbox: %v (regression: OCI rootfs build into the jailer chroot failed)", err)
	}
	if !strings.Contains(res.Stdout, "fc-coldboot-ok") {
		t.Fatalf("exec stdout = %q, want fc-coldboot-ok", res.Stdout)
	}
}

// UC-89 — the SSH gateway must be listening on the ingress public host. B4's bug
// gated the gateway on IsWorker(), so a pure-ingress node (where the public
// SB_SSH_LISTEN_ADDR and wildcard DNS resolve) bound nothing and every dial got
// "connection refused". We dial the raw TCP port and read the SSH identification
// banner ("SSH-2.0-...") — proving a gateway is up, independent of any sandbox
// existing or of per-sandbox routing.
func TestSSHGatewayListensOnPublicHost(t *testing.T) {
	harness.Require(t, sc, "UC-89")

	port := os.Getenv("AEROL_SSH_PORT")
	if port == "" {
		port = "2220" // matches SB_SSH_LISTEN_ADDR default
	}
	addr := net.JoinHostPort(sc.Domain, port)

	// Retry to absorb the gateway-startup window after the cluster forms; the
	// terminal state we assert is a real SSH banner, not a refused connection.
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(3 * time.Second)
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		banner, err := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if err != nil {
			lastErr = err
			time.Sleep(3 * time.Second)
			continue
		}
		if !strings.HasPrefix(banner, "SSH-") {
			t.Fatalf("port %s on ingress answered but not with an SSH banner: %q", addr, strings.TrimSpace(banner))
		}
		t.Logf("ingress SSH gateway banner: %s", strings.TrimSpace(banner))
		return
	}
	t.Fatalf("SSH gateway never reachable on ingress public host %s: %v (regression: gateway not bound on the ingress role)", addr, lastErr)
}
