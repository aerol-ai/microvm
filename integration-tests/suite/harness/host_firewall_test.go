package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// localModeRefusal is the message sandboxd sent on the first local-mode run
// (main f34b607e) for a create with an allow list, word for word from that
// run's test.json. apihttp.WriteStoreAwareError sends it with status 501 and
// the code network_policy_unenforced.
const localModeRefusal = `network_allow_out refused: runtime "docker" enforces it with the host firewall, which is off on this node (SB_ENABLE_NETWORK_RULES=false, or not a Linux host). Turn on SB_ENABLE_NETWORK_RULES on a Linux host; for local development only, SB_ALLOW_UNENFORCED_NETWORK_POLICY=true accepts it unenforced`

// sdkErrorFor drives the real Go SDK against a server that answers every
// request with status and body, and returns the error the SDK hands back.
func sdkErrorFor(t *testing.T, status int, body models.ErrorResponse, call func(context.Context, *microvm.Client) error) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	c, err := microvm.NewClientWithConfig(&sdktypes.MicroVMConfig{APIUrl: srv.URL, PATToken: "p"})
	if err != nil {
		t.Fatal(err)
	}
	return call(context.Background(), c)
}

func createWithAllowList(ctx context.Context, c *microvm.Client) error {
	_, err := c.Create(ctx, sdktypes.CreateSandboxOptions{Image: DefaultImage, NetworkAllowOut: []string{"1.1.1.0/24"}})
	return err
}

func setByteCap(ctx context.Context, c *microvm.Client) error {
	limit := int64(1 << 20)
	_, err := c.SetNetworkLimits(ctx, "sb-0123456789abcdef", sdktypes.SetNetworkLimitsOptions{NetworkBytesInLimit: &limit})
	return err
}

// The refusal is recognised by the status and code the SDK keeps, through
// the same SDK calls the cases make, and nothing else passes for it: a 501
// without the code (Firecracker's "not supported" byte caps) or the code on
// another status is a different answer, and a case must say so.
func TestIsUnenforcedPolicyRefusal(t *testing.T) {
	unenforced := models.ErrorResponse{Error: localModeRefusal, Code: models.ErrorCodeNetworkPolicyUnenforced}
	for _, tc := range []struct {
		name   string
		status int
		body   models.ErrorResponse
		call   func(context.Context, *microvm.Client) error
		want   bool
	}{
		{name: "create refused as unenforced", status: http.StatusNotImplemented, body: unenforced, call: createWithAllowList, want: true},
		{name: "byte cap refused as unenforced", status: http.StatusNotImplemented, body: unenforced, call: setByteCap, want: true},
		{name: "501 without the code", status: http.StatusNotImplemented, body: models.ErrorResponse{Error: "network byte limits are not supported for firecracker sandboxes"}, call: setByteCap},
		{name: "the code on another status", status: http.StatusBadRequest, body: unenforced, call: createWithAllowList},
		{name: "another 501 code", status: http.StatusNotImplemented, body: models.ErrorResponse{Error: "nope", Code: "runtime_not_implemented"}, call: createWithAllowList},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sdkErrorFor(t, tc.status, tc.body, tc.call)
			if err == nil {
				t.Fatal("the SDK returned no error for a refusal")
			}
			if got := IsUnenforcedPolicyRefusal(err); got != tc.want {
				t.Fatalf("IsUnenforcedPolicyRefusal(%s) = %v, want %v", DescribeAPIError(err), got, tc.want)
			}
			if got := IsUnenforcedPolicyRefusal(fmt.Errorf("create: %w", err)); got != tc.want {
				t.Fatalf("a wrapped error read differently: %v, want %v", got, tc.want)
			}
		})
	}
	if IsUnenforcedPolicyRefusal(errors.New("dial tcp: connection refused")) || IsUnenforcedPolicyRefusal(nil) {
		t.Fatal("an error that is not an API answer was read as the refusal")
	}
}

// Why the predicate reads fields: the SDK's error text is the server's
// message alone. The old check looked for the code or "501" in that text and
// so failed every no-host-firewall case on a server that answered correctly.
// If the SDK ever starts printing them, this test says the text match would
// have worked, not that the field read is wrong.
func TestTheSDKErrorTextNamesNeitherStatusNorCode(t *testing.T) {
	err := sdkErrorFor(t, http.StatusNotImplemented,
		models.ErrorResponse{Error: localModeRefusal, Code: models.ErrorCodeNetworkPolicyUnenforced}, createWithAllowList)
	if msg := err.Error(); strings.Contains(msg, models.ErrorCodeNetworkPolicyUnenforced) || strings.Contains(msg, "501") {
		t.Fatalf("the SDK error text now carries the status or code (%q); the field read is still right, but this test's premise changed", msg)
	}
	if d := DescribeAPIError(err); !strings.Contains(d, "status 501") || !strings.Contains(d, models.ErrorCodeNetworkPolicyUnenforced) {
		t.Fatalf("DescribeAPIError does not name what the server sent: %s", d)
	}
	if d := DescribeAPIError(errors.New("boom")); !strings.Contains(d, "not an API error") {
		t.Fatalf("DescribeAPIError on a plain error = %q", d)
	}
}

// The create gate's refusal for a runtime whose egress deny floor is not
// installed is recognised by status and code, wrapped or not; the code on
// another status, or another 503, is a different answer.
func TestIsEgressFloorNotReady(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "503 egress_floor_not_ready", err: &microvm.APIError{StatusCode: http.StatusServiceUnavailable, Code: models.ErrorCodeEgressFloorNotReady}, want: true},
		{name: "wrapped", err: fmt.Errorf("create: %w", &microvm.APIError{StatusCode: http.StatusServiceUnavailable, Code: models.ErrorCodeEgressFloorNotReady}), want: true},
		{name: "another 503", err: &microvm.APIError{StatusCode: http.StatusServiceUnavailable, Code: models.ErrorCodeNodeGuardNotReady}},
		{name: "the code on another status", err: &microvm.APIError{StatusCode: http.StatusBadRequest, Code: models.ErrorCodeEgressFloorNotReady}},
		{name: "not an API error", err: errors.New("dial tcp: connection refused")},
		{name: "nil", err: nil},
	} {
		if got := IsEgressFloorNotReady(tc.err); got != tc.want {
			t.Errorf("%s: IsEgressFloorNotReady = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// floorDump is a node's rule dump in the shapes UC-363 reads: iptables-save
// (an exec-backend docker node), the same chain again in nft list ruleset
// (iptables-nft shows it in both), a legacy table with a jump that is not
// first, and the netlink backend's Firecracker floor in nft only, its jump
// below a per-guest rule.
const floorDump = `# Generated by iptables-nft-save
*filter
:DOCKER-USER - [0:0]
:AEROLVM-FLOOR-1a2b3c4d - [0:0]
:AEROLVM-FLOOR - [0:0]
-A DOCKER-USER -j AEROLVM-FLOOR-1a2b3c4d
-A DOCKER-USER -s 172.17.0.5/32 -j DROP
-A AEROLVM-FLOOR-1a2b3c4d -s 172.17.0.0/16 -d 172.16.0.0/16 -j DROP
-A AEROLVM-FLOOR-1a2b3c4d -s 172.17.0.0/16 -d 172.17.0.0/16 -j DROP
-A AEROLVM-FLOOR-1a2b3c4d -s 172.17.0.0/16 -d 169.254.169.254/32 -j DROP
-A AEROLVM-FLOOR -s 10.0.0.0/8 -d 169.254.169.254/32 -j DROP
COMMIT
# Generated by iptables-legacy-save
*filter
-A DOCKER-USER -j RETURN
-A DOCKER-USER -j AEROLVM-FLOOR-1a2b3c4d
COMMIT
table ip filter {
	chain DOCKER-USER {
		counter packets 0 bytes 0 jump AEROLVM-FLOOR-1a2b3c4d
		ip saddr 172.17.0.5 counter packets 0 bytes 0 drop
	}

	chain AEROLVM-FLOOR-1a2b3c4d {
		ip saddr 172.17.0.0/16 ip daddr 169.254.169.254 counter packets 3 bytes 180 drop
	}

	chain AEROLVM-FC {
		type filter hook forward priority filter; policy accept;
		ip saddr 172.16.0.2 drop
		jump AEROLVM-FLOOR-9f8e7d6c
	}

	chain AEROLVM-FLOOR-9f8e7d6c {
		ip saddr 172.16.0.0/16 ip daddr 172.16.0.0/16 drop
	}
}
`

func TestParseFloorChains(t *testing.T) {
	chains := ParseFloorChains(floorDump)
	if len(chains) != 2 {
		t.Fatalf("chains = %v, want the two hashed floor chains (the legacy shared one is not a floor)", chains)
	}
	docker, ok := FloorFor(chains, netip.MustParseAddr("172.17.0.9"))
	if !ok || docker.Name != "AEROLVM-FLOOR-1a2b3c4d" || docker.Src != netip.MustParsePrefix("172.17.0.0/16") {
		t.Fatalf("docker floor = %+v %v", docker, ok)
	}
	if !docker.Drops(netip.MustParseAddr("169.254.169.254")) || !docker.Drops(netip.MustParseAddr("172.16.0.7")) || docker.Drops(netip.MustParseAddr("1.1.1.1")) {
		t.Fatalf("docker floor drops %v", docker.Dsts)
	}
	if len(docker.Dsts) != 3 {
		t.Fatalf("the nft copy of an iptables rule must not count twice: %v", docker.Dsts)
	}
	// Jumped from the top of DOCKER-USER in the nft-backed listings; the
	// legacy dump is a section of its own, where a jump below another rule
	// counts for nothing.
	if !slices.Equal(docker.TopOf, []string{"DOCKER-USER"}) {
		t.Fatalf("docker floor is first in %v", docker.TopOf)
	}

	fc, ok := FloorFor(chains, netip.MustParseAddr("172.16.0.2"))
	if !ok || fc.Name != "AEROLVM-FLOOR-9f8e7d6c" {
		t.Fatalf("firecracker floor = %+v %v", fc, ok)
	}
	// Its jump is below a per-guest rule (and below the base chain's
	// declaration, which is not a rule), so it is first in nothing; and it
	// does not drop the metadata endpoint.
	if len(fc.TopOf) != 0 || fc.Drops(netip.MustParseAddr("169.254.169.254")) {
		t.Fatalf("firecracker floor = %+v", fc)
	}

	if _, ok := FloorFor(chains, netip.MustParseAddr("10.88.0.4")); ok {
		t.Fatal("an address in no floored subnet has a floor")
	}
	if got := ParseFloorChains("-A AEROLVM-FLOOR-1a2b3c4d -s bogus -d 169.254.169.254/32 -j DROP\n"); len(got) != 0 {
		t.Fatalf("an unparsable source made a chain: %v", got)
	}
}
