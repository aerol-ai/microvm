package harness

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// IsUnenforcedPolicyRefusal reports whether err is the documented refusal of
// network policy a node cannot enforce (#846): HTTP 501 with the code
// network_policy_unenforced, at create, start, a policy change or a byte cap.
//
// It reads the fields of the SDK's *microvm.APIError. The error's text is the
// server's message alone ("network_allow_out refused: runtime "docker"
// enforces it with the host firewall, which is off on this node ..."), which
// names neither the status nor the code. Matching on that text is why the
// first local-mode run (main f34b607e) failed every no-host-firewall case
// while the server answered exactly what the docs promise.
func IsUnenforcedPolicyRefusal(err error) bool {
	var apiErr *microvm.APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusNotImplemented &&
		apiErr.Code == models.ErrorCodeNetworkPolicyUnenforced
}

// DescribeAPIError is err with the HTTP status and error code the server
// sent, for a failure message that has to say what the server answered.
func DescribeAPIError(err error) string {
	var apiErr *microvm.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("status %d, code %q: %v", apiErr.StatusCode, apiErr.Code, err)
	}
	return fmt.Sprintf("not an API error: %v", err)
}
