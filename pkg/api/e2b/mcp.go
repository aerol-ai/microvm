package e2b

import (
	"context"
	"errors"
	"net/http"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// E2B's `mcp` create option, as E2B SDK 2.50.0 and e2b-dev/infra use it.
//
// The E2B API does not start anything for it: the create handler only keeps
// the server names for its analytics (buildCreationMetadata). The SDK starts
// the gateway itself once the create returns. It runs
// `mcp-gateway --config '<the mcp object as JSON>'` as root through envd,
// with GATEWAY_ACCESS_TOKEN set to a UUID it made, and getMcpUrl() is
// https://<getHost(50005)>/mcp. With no template named, the SDK asks for
// E2B's `mcp-gateway` template, whose image carries that program; any other
// template must carry it too, or the SDK's command fails and it kills the
// sandbox.
//
// So the facade's part is to accept the option, refuse up front what can
// never start (a wasm sandbox has no shell; E2B's mcp-gateway image is not
// something AerolVM ships), and give port 50005 an address. The gateway
// checks its own bearer token, as on E2B, so the port is exposed public, not
// behind an AerolVM sandbox token the E2B SDK could never send.
const (
	mcpGatewayTemplate = "mcp-gateway"
	mcpGatewayPort     = 50005
)

const (
	mcpOptionNotObject = "mcp must be an object that maps MCP server names to their settings"
	mcpWasmUnsupported = "mcp is not supported for wasm sandboxes: the E2B SDK starts the MCP gateway with a shell command, and a wasm sandbox has no shell"
	mcpTemplateMissing = "the E2B mcp-gateway template is not available on this server: AerolVM does not ship E2B's MCP gateway program. " +
		"Pass a template whose image has an mcp-gateway command, or ask your operator to map mcp-gateway in SB_E2B_TEMPLATE_MAP_JSON"
)

// parseMCPOption reports whether a create asks for E2B's MCP gateway. JSON
// null is the same as leaving the option out (E2B's schema allows it). An
// empty object still counts: both SDKs start the gateway for `mcp: {}`.
func parseMCPOption(raw any) (bool, error) {
	switch raw.(type) {
	case nil:
		return false, nil
	case map[string]any:
		return true, nil
	default:
		return false, badRequest(mcpOptionNotObject)
	}
}

// mcpTemplateError turns the "unsupported templateID" 400 for E2B's default
// MCP template into a 501 that names what is missing, so the caller learns
// the option itself is understood and only the gateway image is absent. A
// template the operator mapped, or a snapshot by that name, resolves before
// this and is used as is.
func mcpTemplateError(templateID string, err error) error {
	if templateID != mcpGatewayTemplate {
		return err
	}
	var reqErr requestError
	if errors.As(err, &reqErr) && reqErr.status == http.StatusBadRequest {
		return notImplemented(mcpTemplateMissing)
	}
	return err
}

// exposeMCPGateway gives the gateway's port an address once the sandbox
// exists. It runs before the compat row and the idempotency record are
// written, so a failure rolls the create back like any other step after it.
// Exposing is idempotent (a re-expose returns the URL it has), so a replayed
// create runs it again harmlessly. A caller that asked for
// allowPublicTraffic=false is left alone: exposing would make the sandbox
// public, and that choice is theirs to make with the AerolVM SDK.
func (h *handlers) exposeMCPGateway(ctx context.Context, sandboxID string, meta sandboxMeta) error {
	if !meta.MCP || h.deps.Service == nil {
		return nil
	}
	if meta.AllowPublicTraffic != nil && !*meta.AllowPublicTraffic {
		return nil
	}
	// The gateway is started by the E2B SDK after the create returns, so the
	// port is never listening yet: skip the expose's probe.
	_, err := h.deps.Service.ExposePort(service.WithoutPortProbe(ctx), sandboxID, mcpGatewayPort, models.ExposedPortProtocolHTTP)
	return err
}
