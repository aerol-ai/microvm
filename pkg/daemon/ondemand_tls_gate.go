package daemon

import "github.com/aerol-ai/microvm/internal/config"

// onDemandTLSOnThisNode reports whether this node should install Caddy's
// on-demand TLS policy for custom domains.
//
// Under SB_INGRESS_PROXY_ROUTING the ingress never terminates a tenant's
// custom domain. It splices TLS to the owner, which terminates it with its
// own on-demand cert (plans/ingress-proxy-routing.md §3.7, review T5). An
// ingress-only node (no worker role) that kept the policy would request and
// hold tenant certificates whenever a custom-domain connection fell back to
// its local listener. That is a Let's Encrypt quota drain and a tenant key
// off its owner. Flag off, or any node that can own sandboxes: unchanged.
func onDemandTLSOnThisNode(cfg config.Config) bool {
	if cfg.IngressProxyRouting && !cfg.IsWorker() {
		return false
	}
	return true
}
