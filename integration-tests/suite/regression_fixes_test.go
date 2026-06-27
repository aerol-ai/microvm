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
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
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
		NodeName string `json:"node_name"`
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

// UC-90..93 guard the cluster-hetero ROUTING fix pass. The offline counterpart
// is internal/cluster/placement_test.go (the SelectPlacement hetero matrix);
// these confirm the same invariants end to end on the live 8-node cluster,
// where the SDK only ever talks to the ingress URL.

// placementOwnerView is the slice of /v1/cluster/placements/{id} we assert on:
// which node currently owns the sandbox.
type placementOwnerView struct {
	Owner struct {
		NodeID string `json:"node_id"`
	} `json:"owner"`
}

// heteroRuntimeCaps maps a scenario runtime capability to the runtime string a
// create requests and a node must advertise to host it. Docker is always
// present and routed implicitly, so it is not listed here.
var heteroRuntimeCaps = []struct {
	cap     harness.Capability
	runtime string
}{
	{harness.CapWasm, "wasm"},
	{harness.CapFirecracker, "firecracker"},
	{harness.CapGvisor, "gvisor"},
}

// resolvePlacementOwner polls /v1/cluster/placements/{id} until an owner node is
// recorded (the FSM commit lands a moment after create returns).
func resolvePlacementOwner(t *testing.T, c *harness.Client, sandboxID string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var pv placementOwnerView
		err := c.GetJSON(ctx, "/v1/cluster/placements/"+sandboxID, &pv)
		cancel()
		if err == nil && pv.Owner.NodeID != "" {
			return pv.Owner.NodeID
		}
		time.Sleep(3 * time.Second)
	}
	return ""
}

// nodeAdvertisesRuntime reports whether nodeID's gossiped capacity lists runtime.
func nodeAdvertisesRuntime(members capacityView, nodeID, runtime string) bool {
	for _, m := range members.Members {
		if m.NodeID != nodeID {
			continue
		}
		for _, rt := range m.Capacity.SupportedRuntimes {
			if rt == runtime {
				return true
			}
		}
	}
	return false
}

// fetchMembers reads /v1/cluster/members with the capacity (supported_runtimes)
// projection.
func fetchMembers(t *testing.T, c *harness.Client) capacityView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var cv capacityView
	if err := c.GetJSON(ctx, "/v1/cluster/members", &cv); err != nil {
		t.Fatalf("get cluster members: %v", err)
	}
	return cv
}

// UC-90 — a create for a specialized runtime must be PLACED on a worker that
// advertises that runtime in gossip. This is the live confirmation of the
// offline SelectPlacement hetero matrix: the cluster-hetero failures were
// creates that landed on a node which could not run the requested runtime (the
// WASM create routed to a non-WASM worker; the create then failed instead of
// being forwarded). For each specialized runtime the scenario has, create a
// sandbox, resolve its owner node, and assert that node advertises the runtime.
func TestClusterPlacesRuntimeOnCapableWorker(t *testing.T) {
	harness.Require(t, sc, "UC-90")
	c := client(t)
	members := fetchMembers(t, c)

	ran := false
	for _, rc := range heteroRuntimeCaps {
		if !sc.Has(rc.cap) {
			continue
		}
		ran = true
		t.Run(rc.runtime, func(t *testing.T) {
			opts := sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Runtime: rc.runtime}
			if rc.runtime == "wasm" {
				// WASM resolves an image/module ref, not a container image.
				opts.ModuleRef = stagedWasmModuleRefOrDefault(t)
				opts.Image = opts.ModuleRef
			}
			sb := c.NewSandbox(t, opts)
			waitRunning(t, sb)

			owner := resolvePlacementOwner(t, c, sb.ID)
			if owner == "" {
				t.Fatalf("sandbox %s never got a placement owner", sb.ID)
			}
			if !nodeAdvertisesRuntime(members, owner, rc.runtime) {
				t.Fatalf("%s sandbox placed on %q, which does not advertise runtime %q (regression: create routed to a worker that cannot run it)",
					rc.runtime, owner, rc.runtime)
			}
			t.Logf("runtime %q placed on capable worker %s", rc.runtime, owner)
		})
	}
	if !ran {
		t.Skip("scenario advertises no specialized runtime capability")
	}
}

// UC-91 — a create that omits runtime must run under the placement worker's own
// configured default, never be silently forced to docker by the router. This is
// the gvisor-by-default isolation contract: the router leaves an omitted runtime
// empty so the selected worker applies its cfg.Runtime (e.g. gvisor). An omitted
// runtime is therefore placement-dependent in a heterogeneous cluster (it may
// run as docker on a docker worker or gvisor on a gvisor worker) — so this does
// NOT assert a single cluster-wide value. It asserts (a) the effective runtime
// is one the owner node actually runs, and (b) when the deployment pins a
// default via AEROL_DEFAULT_RUNTIME (e.g. a gvisor-by-default cluster), the
// omitted runtime equals it rather than being downgraded to docker.
func TestUnspecifiedRuntimeHonoredNotForced(t *testing.T) {
	harness.Require(t, sc, "UC-91")
	c := client(t)
	members := fetchMembers(t, c)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatalf("sandbox %s never got a placement owner", sb.ID)
	}
	effective := resolveEffectiveRuntime(t, c, sb.ID)
	if effective == "" {
		t.Fatalf("sandbox %s reported no effective runtime", sb.ID)
	}
	// The effective runtime must be one the owner node actually runs — an omitted
	// runtime resolves to the worker's own default, never to something the
	// placement node isn't configured for.
	if !nodeAdvertisesRuntime(members, owner, effective) {
		t.Fatalf("omitted-runtime sandbox runs %q on %q, which advertises no such runtime (regression: runtime not honored by the placement node)", effective, owner)
	}
	// When the deployment pins a cluster-wide default (a gvisor-by-default
	// cluster sets AEROL_DEFAULT_RUNTIME=gvisor), an omitted runtime MUST equal
	// it — the guard that the operator's isolation default is not silently
	// forced to docker by the router.
	if want := os.Getenv("AEROL_DEFAULT_RUNTIME"); want != "" && effective != want {
		t.Fatalf("omitted-runtime effective runtime = %q, want %q (regression: operator default-runtime silently overridden to docker)", effective, want)
	}
	t.Logf("omitted-runtime create ran as %q on %s (honored node default)", effective, owner)
}

// resolveEffectiveRuntime reads the runtime the sandbox actually runs under.
func resolveEffectiveRuntime(t *testing.T, c *harness.Client, sandboxID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var sb struct {
		Runtime string `json:"runtime"`
	}
	if err := c.GetJSON(ctx, "/v1/sandboxes/"+sandboxID, &sb); err != nil {
		t.Fatalf("get sandbox %s: %v", sandboxID, err)
	}
	return sb.Runtime
}

// UC-92 — CreateWithImage from a non-worker ingress. The SDK talks only to the
// ingress URL; CreateWithImage builds a local aerolvm-build/* image and then
// creates a sandbox from it. The cluster-hetero bug was the build landing on
// the ingress (which can't host the sandbox) and the create then failing with
// "no worker placement target available". This asserts the sandbox reaches
// running, the built artifact is present, and the placement owner is a worker
// that advertises docker.
func TestCreateWithImageThroughIngress(t *testing.T) {
	harness.Require(t, sc, "UC-92")
	c := client(t)

	img := microvm.BaseImage("alpine:3.20").
		RunCommands("echo created-with-image-92 > /uc92.txt")
	if err := img.Err(); err != nil {
		t.Fatalf("build image spec: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	sb, err := c.SDK().CreateWithImage(ctx, img, sdktypes.CreateSandboxOptions{
		Name: harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create with image through ingress: %v (regression: built image not reachable from the placement worker)", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().Destroy(cctx, sb.ID)
	})
	waitRunning(t, sb)

	res, err := sb.ExecCommand(ctx, "cat /uc92.txt")
	if err != nil {
		t.Fatalf("exec cat in built-image sandbox: %v", err)
	}
	if !strings.Contains(res.Stdout, "created-with-image-92") {
		t.Fatalf("built artifact missing: stdout = %q", res.Stdout)
	}

	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatalf("sandbox %s never got a placement owner", sb.ID)
	}
	if !nodeAdvertisesRuntime(fetchMembers(t, c), owner, "docker") {
		t.Fatalf("built-image sandbox placed on %q, which does not advertise docker (regression: built image created on a node that cannot host it)", owner)
	}
}

// UC-93 — the firecracker template lifecycle must work when the API entry node
// is not the firecracker worker. Templates are per-worker artifacts; the
// cluster-hetero bug was POST /v1/templates running on the ingress/server node
// (which has no firecracker) and rejecting with "requires SB_ENABLE_FIRECRACKER".
// The SDK talks only to the ingress URL, so create -> ready -> list -> get -> delete
// here exercises the template routing/fan-out path end to end.
func TestFirecrackerTemplateLifecycleThroughIngress(t *testing.T) {
	harness.Require(t, sc, "UC-93")
	c := client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	tmpl, err := c.SDK().CreateTemplate(ctx, sdktypes.CreateTemplateOptions{
		Image: "docker://alpine:3.20",
	})
	if err != nil {
		t.Fatalf("create template through ingress: %v (regression: template create evaluated on a non-firecracker node)", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteTemplate(cctx, tmpl.ID)
	})
	waitTemplateReady(t, c, tmpl.ID)

	// List is fanned out across firecracker workers; it must include the
	// template regardless of which worker built the rootfs.
	list, err := c.SDK().ListTemplates(ctx)
	if err != nil {
		t.Fatalf("list templates through ingress: %v", err)
	}
	found := false
	for _, tl := range list {
		if tl.ID == tmpl.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("template %s not in ingress-fanned list (regression: list not routed to the firecracker worker)", tmpl.ID)
	}
	if _, err := c.SDK().GetTemplate(ctx, tmpl.ID); err != nil {
		t.Fatalf("get template through ingress: %v (regression: per-id template read not routed to the owning worker)", err)
	}
}
