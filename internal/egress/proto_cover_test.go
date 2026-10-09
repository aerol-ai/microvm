package egress

import (
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
)

// TestTapPoolBridge: the Firecracker TAP pool binds the wildcard listeners
// and scopes the node-wide sets to the masked guest subnet; a real bridge
// binds its own gateway address.
func TestTapPoolBridge(t *testing.T) {
	b := TapPoolBridge(netip.MustParsePrefix("172.30.5.9/24"))
	if b.Name != "fctap" || !b.Wildcard() || b.Subnet != netip.MustParsePrefix("172.30.5.0/24") {
		t.Fatalf("tap pool bridge = %+v", b)
	}
	if (Bridge{Name: "aerolvm0", GatewayIP: netip.MustParseAddr("10.88.0.1")}).Wildcard() {
		t.Fatal("a bridge with a gateway address is not a wildcard")
	}
}

// protoCoverEndless is a peer that never ends its line.
type protoCoverEndless struct{}

func (protoCoverEndless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// TestFrameLimits: a peer that never sends a newline is cut off at maxFrame
// instead of growing the buffer without bound, and a value that can't be
// encoded never reaches the wire.
func TestFrameLimits(t *testing.T) {
	var v map[string]any
	if err := newFrameReader(protoCoverEndless{}).read(&v); err == nil || !strings.Contains(err.Error(), "frame exceeds") {
		t.Fatalf("endless frame err = %v", err)
	}
	if err := writeFrame(io.Discard, make(chan int)); err == nil {
		t.Fatal("an unencodable frame must fail")
	}
}

// TestErrorCodesRoundTrip: every sentinel the gateway returns survives the
// wire as the same sentinel, so sandboxd's errors.Is checks hold across the
// UDS; anything else arrives as a plain error.
func TestErrorCodesRoundTrip(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{nil, ""},
		{ErrNotAttached, codeNotAttached},
		{ErrLearnedCap, codeLearnedCap},
		{ErrUnavailable, codeUnavailable},
		{ErrVersionMismatch, codeVersion},
		{errors.New("bad spec"), codeInvalid},
	}
	for _, tc := range cases {
		code := codeFor(tc.err)
		if code != tc.code {
			t.Fatalf("codeFor(%v) = %q, want %q", tc.err, code, tc.code)
		}
		back := errFor(code, "msg")
		switch {
		case tc.err == nil:
			if back != nil {
				t.Fatalf("errFor(%q) = %v, want nil", code, back)
			}
		case tc.code == codeInvalid:
			if back == nil || back.Error() != "msg" {
				t.Fatalf("errFor(%q) = %v, want a plain error", code, back)
			}
		case !errors.Is(back, tc.err):
			t.Fatalf("errFor(%q) = %v, want %v", code, back, tc.err)
		}
	}
}
