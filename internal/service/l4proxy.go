package service

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PROXY protocol parsing for the L4 wake proxy. The splice and the
// connection limiter it pairs with live in internal/netsplice, shared with
// the egress FQDN proxy (plans/egress-domain-filtering.md D12, D17), so
// connection caps, half-close and PROXY parsing exist once, not once per
// proxy (eng review 3A).

// proxyHeader is a parsed PROXY protocol v1 line.
type proxyHeader struct {
	Family  string // TCP4 | TCP6
	SrcAddr string
	DstAddr string
	SrcPort int
	DstPort int
}

// readProxyV1Header reads one PROXY v1 line from br. br must be sized to the
// maximum header length, so a peer cannot make it buffer without bound. Bytes
// after the line stay in br and belong to the proxied stream.
func readProxyV1Header(br *bufio.Reader) (proxyHeader, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return proxyHeader{}, errors.New("proxy protocol header too large")
	}
	if err != nil {
		return proxyHeader{}, fmt.Errorf("read proxy protocol header: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(line)))
	if len(fields) != 6 || fields[0] != "PROXY" {
		return proxyHeader{}, fmt.Errorf("malformed proxy protocol header %q", strings.TrimSpace(string(line)))
	}
	if fields[1] != "TCP4" && fields[1] != "TCP6" {
		return proxyHeader{}, fmt.Errorf("unsupported proxy protocol family %q", fields[1])
	}
	// Only the destination port is load-bearing (the wake proxy keys
	// exposures by it) and strictly validated, as before the extraction.
	// The source is informational: an unparsable source port reads as 0
	// rather than refusing a header the old parser accepted.
	srcPort, err := strconv.Atoi(fields[4])
	if err != nil || srcPort < 0 || srcPort > 65535 {
		srcPort = 0
	}
	dstPort, err := strconv.Atoi(fields[5])
	if err != nil || dstPort <= 0 || dstPort > 65535 {
		return proxyHeader{}, fmt.Errorf("invalid proxy protocol destination port %q", fields[5])
	}
	return proxyHeader{Family: fields[1], SrcAddr: fields[2], DstAddr: fields[3], SrcPort: srcPort, DstPort: dstPort}, nil
}

// readProxyV1DestinationPort is the wake proxy's view of the header: it keys
// exposures by host port.
func readProxyV1DestinationPort(br *bufio.Reader) (int, error) {
	h, err := readProxyV1Header(br)
	if err != nil {
		return 0, err
	}
	return h.DstPort, nil
}
