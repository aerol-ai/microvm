package auditlog

import (
	"context"
	"net/url"
	"strings"
)

// SSH gateway attribution (UC-287 on a cluster). In cluster mode the SSH
// gateway on any node bridges a session for a sandbox another node owns
// through its own node's v1 sessions API, with the operator token: that is
// the credential the loopback hop has. Without more, every bridged call was
// recorded on the owner as caller=operator, and the session's ssh record
// was written on the gateway's node, which the sandbox's audit read never
// asks. An SSHGatewayCall says "this is the gateway acting for the holder
// of SandboxID's key", so the owner names that key as the caller and writes
// the ssh record where the sandbox's audit lives.
//
// It never supplies an identity on its own. The API edge attaches it only
// after checking where it came from (pkg/api sshGatewayCall): from this
// process's gateway (an attestation only this process can make), or from a
// live mTLS peer that forwarded the operator token. It lives here, beside
// the record it changes, because the API edge, the cluster forward helper
// and the service layer all read it and none may import the others.

// SSHGatewayCall is one call the SSH gateway bridged for a sandbox key
// holder.
type SSHGatewayCall struct {
	// SandboxID is the sandbox whose key opened the SSH session. It must be
	// the sandbox the call's path names.
	SandboxID string
	// Open marks the first call of an SSH session channel: the node that
	// runs it writes the session's one ssh record, naming Session.
	Open bool
	// Session is the toolbox session the SSH session attached to ("" for a
	// one-shot exec), as the ssh record's target. Only with Open.
	Session string
}

// Wire form keys. A url query keeps the value one header line whatever the
// session name holds.
const (
	sshGatewaySandboxKey = "sandbox"
	sshGatewayOpenKey    = "open"
)

// Encode is c's header value: "sandbox=<id>", plus "&open=<session>" on the
// call that opens the session.
func (c SSHGatewayCall) Encode() string {
	v := url.Values{sshGatewaySandboxKey: {strings.TrimSpace(c.SandboxID)}}
	if c.Open {
		v.Set(sshGatewayOpenKey, c.Session)
	}
	return v.Encode()
}

// ParseSSHGatewayCall reads a value Encode wrote. ok is false for anything
// else, including a value that names no sandbox or names it twice.
func ParseSSHGatewayCall(raw string) (SSHGatewayCall, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SSHGatewayCall{}, false
	}
	v, err := url.ParseQuery(raw)
	if err != nil || len(v[sshGatewaySandboxKey]) != 1 || len(v[sshGatewayOpenKey]) > 1 {
		return SSHGatewayCall{}, false
	}
	c := SSHGatewayCall{SandboxID: strings.TrimSpace(v.Get(sshGatewaySandboxKey))}
	if c.SandboxID == "" {
		return SSHGatewayCall{}, false
	}
	if v.Has(sshGatewayOpenKey) {
		c.Open, c.Session = true, v.Get(sshGatewayOpenKey)
	}
	return c, true
}

type sshGatewayKey struct{}

// ContextWithSSHGatewayCall marks ctx as a call the SSH gateway bridged.
// Only the API edge sets it, after checking the call's origin.
func ContextWithSSHGatewayCall(ctx context.Context, c SSHGatewayCall) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sshGatewayKey{}, c)
}

// SSHGatewayCallFromContext returns the call ContextWithSSHGatewayCall
// attached.
func SSHGatewayCallFromContext(ctx context.Context) (SSHGatewayCall, bool) {
	if ctx == nil {
		return SSHGatewayCall{}, false
	}
	c, ok := ctx.Value(sshGatewayKey{}).(SSHGatewayCall)
	return c, ok
}
