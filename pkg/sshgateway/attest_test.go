package sshgateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditlog"
)

// TestTakeBridgedCall is the loopback half of the trust boundary: the API
// edge believes a bridged call only when this process's gateway attested it
// for the sandbox the path names. Whatever the headers hold, the edge takes
// them off, so neither a forgery nor a real attestation ever travels on to
// a peer or into the sandbox's toolbox.
func TestTakeBridgedCall(t *testing.T) {
	attested := func(call auditlog.SSHGatewayCall) http.Header {
		h := http.Header{}
		AttestBridgedCall(h, call)
		return h
	}
	open := auditlog.SSHGatewayCall{SandboxID: "sb-1", Open: true, Session: "default"}
	cases := []struct {
		name    string
		header  http.Header
		sandbox string
		want    *auditlog.SSHGatewayCall
	}{
		{name: "this gateway's call for the path's sandbox", header: attested(open), sandbox: "sb-1", want: &open},
		{name: "a later call of the session", header: attested(auditlog.SSHGatewayCall{SandboxID: "sb-1"}), sandbox: "sb-1", want: &auditlog.SSHGatewayCall{SandboxID: "sb-1"}},
		{name: "attested for another sandbox than the path names", header: attested(open), sandbox: "sb-2"},
		{name: "no path sandbox", header: attested(open), sandbox: " "},
		{name: "a MAC under another key (another node, a guess)", header: http.Header{
			headerBridgedCall: {open.Encode()}, headerBridgedCallMAC: {macUnder([]byte("not this process's key"), open.Encode())},
		}, sandbox: "sb-1"},
		{name: "a value changed after it was attested", header: func() http.Header {
			h := attested(auditlog.SSHGatewayCall{SandboxID: "sb-1"})
			h.Set(headerBridgedCall, open.Encode())
			return h
		}(), sandbox: "sb-1"},
		{name: "a MAC that is not hex", header: http.Header{headerBridgedCall: {open.Encode()}, headerBridgedCallMAC: {"zz"}}, sandbox: "sb-1"},
		{name: "a call with no MAC", header: http.Header{headerBridgedCall: {open.Encode()}}, sandbox: "sb-1"},
		{name: "a MAC with no call", header: http.Header{headerBridgedCallMAC: {"00"}}, sandbox: "sb-1"},
		{name: "the call sent twice", header: func() http.Header {
			h := attested(open)
			h.Add(headerBridgedCall, open.Encode())
			return h
		}(), sandbox: "sb-1"},
		{name: "an attested value that is not a call", header: http.Header{
			headerBridgedCall: {"%zz"}, headerBridgedCallMAC: {hex.EncodeToString(bridgedCallMAC("%zz"))},
		}, sandbox: "sb-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := TakeBridgedCall(tc.header, tc.sandbox)
			if tc.want == nil {
				if ok {
					t.Fatalf("accepted %+v, want refused", got)
				}
			} else if !ok || got != *tc.want {
				t.Fatalf("got %+v ok=%v, want %+v", got, ok, *tc.want)
			}
			if len(tc.header.Values(headerBridgedCall)) != 0 || len(tc.header.Values(headerBridgedCallMAC)) != 0 {
				t.Fatalf("headers left on the request: %v", tc.header)
			}
		})
	}

	t.Run("a request with no gateway headers is left alone", func(t *testing.T) {
		h := http.Header{"Authorization": {"Bearer pat"}}
		if _, ok := TakeBridgedCall(h, "sb-1"); ok || h.Get("Authorization") != "Bearer pat" {
			t.Fatalf("ok=%v headers=%v", ok, h)
		}
	})
}

func macUnder(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
