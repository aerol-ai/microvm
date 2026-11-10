package egress

import (
	"context"
	"fmt"
	"net"
	"time"
)

// probeOfferCeiling is the highest version ProbeGatewayProtocol offers. The
// gateway answers with the highest offered version it accepts (negotiate),
// which is its own ProtocolVersion whenever that is offered, so the ceiling
// only has to stay above any version a gateway will ever speak.
const probeOfferCeiling = 64

// ProbeGatewayProtocol asks the gateway listening on socketPath which
// protocol version it speaks (its ProtocolVersion), with one hello and no
// other request. The node upgrader uses it to decide whether the egress
// gateway must restart with the new binary: a gateway keeps running across
// a sandboxd upgrade while the new sandboxd still speaks its version
// (plans/kubectl-style-cluster-ops.md §6.3). The running gateway may be
// older than the installed binary, since a compatible gateway is never
// restarted, so asking the process is the only answer that stays true.
//
// It offers every version from probeOfferCeiling down to 1; negotiate
// accepts only N and N-1 and picks the higher, so the answer is N.
func ProbeGatewayProtocol(ctx context.Context, socketPath string) (int, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return 0, fmt.Errorf("%w: dial %s: %v", ErrUnavailable, socketPath, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	offer := make([]int, 0, probeOfferCeiling)
	for v := probeOfferCeiling; v >= 1; v-- {
		offer = append(offer, v)
	}
	if err := writeFrame(conn, request{ID: 1, Op: opHello, Versions: offer}); err != nil {
		return 0, fmt.Errorf("%w: hello: %v", ErrUnavailable, err)
	}
	var resp response
	if err := newFrameReader(conn).read(&resp); err != nil {
		return 0, fmt.Errorf("%w: hello: %v", ErrUnavailable, err)
	}
	if resp.Error != "" {
		if err := errFor(resp.Code, resp.Error); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("egress: gateway refused hello: %s", resp.Error)
	}
	if resp.Version <= 0 {
		return 0, fmt.Errorf("%w: gateway answered hello with version %d", ErrVersionMismatch, resp.Version)
	}
	return resp.Version, nil
}
