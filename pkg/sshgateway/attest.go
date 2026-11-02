package sshgateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// Attesting a bridged call (cluster mode, UC-287).
//
// The remote path calls this node's own v1 sessions API over loopback with
// the operator token (forward.go), so on the wire it looks like any operator
// call. The owner must record it as the sandbox key holder's, and only a
// call this gateway really made may say so: the operator token alone is not
// enough, since an operator could then pass their own calls off as a
// sandbox key's, and Caddy relays public callers over loopback too, so the
// source address proves nothing either.
//
// So each bridged call carries the auditlog.SSHGatewayCall it is plus an
// HMAC of that value under a key minted at random when this process first
// needs it. The key never leaves the process: not in config, not on disk,
// not on the wire. Only the API edge of this same process can check the
// MAC (TakeBridgedCall), and it removes both headers whatever they say, so
// they never reach a peer or a sandbox's toolbox. Across nodes the edge
// carries the call as X-Cluster-Ssh-Gateway instead, which a node honours
// only from a live mTLS peer (cluster.StampForward, pkg/api).
const (
	headerBridgedCall    = "X-Aerol-Ssh-Gateway"
	headerBridgedCallMAC = "X-Aerol-Ssh-Gateway-Mac"
)

// attestKey is the process-local MAC key. crypto/rand.Read does not fail
// (it aborts the process instead), so there is no unkeyed fallback.
var attestKey = sync.OnceValue(func() []byte {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return key
})

func bridgedCallMAC(value string) []byte {
	mac := hmac.New(sha256.New, attestKey())
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

// AttestBridgedCall puts call on h with this process's attestation. The
// gateway calls it on every request it bridges to its own node's API.
func AttestBridgedCall(h http.Header, call auditlog.SSHGatewayCall) {
	value := call.Encode()
	h.Set(headerBridgedCall, value)
	h.Set(headerBridgedCallMAC, hex.EncodeToString(bridgedCallMAC(value)))
}

// TakeBridgedCall removes the gateway's headers from h, whatever they hold,
// and returns the call they carry only when this process attested it and it
// names sandboxID, the sandbox the request's path targets. Anything else
// (no headers, a forged or copied MAC, another sandbox, a header sent twice)
// is ok=false: the request is then just the operator's call it looks like.
func TakeBridgedCall(h http.Header, sandboxID string) (auditlog.SSHGatewayCall, bool) {
	values, macs := h.Values(headerBridgedCall), h.Values(headerBridgedCallMAC)
	if len(values) == 0 && len(macs) == 0 {
		return auditlog.SSHGatewayCall{}, false
	}
	h.Del(headerBridgedCall)
	h.Del(headerBridgedCallMAC)
	if len(values) != 1 || len(macs) != 1 {
		return auditlog.SSHGatewayCall{}, false
	}
	got, err := hex.DecodeString(macs[0])
	if err != nil || !hmac.Equal(got, bridgedCallMAC(values[0])) {
		return auditlog.SSHGatewayCall{}, false
	}
	call, ok := auditlog.ParseSSHGatewayCall(values[0])
	sandboxID = strings.TrimSpace(sandboxID)
	if !ok || sandboxID == "" || call.SandboxID != sandboxID {
		return auditlog.SSHGatewayCall{}, false
	}
	return call, true
}
