package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
