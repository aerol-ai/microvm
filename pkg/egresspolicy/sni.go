package egresspolicy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// SNI peek for the egress proxy (§5.5) and the WASM mediator (§5.7).
//
// The parser is hand-rolled over cryptobyte instead of driving a crypto/tls
// server handshake: it never writes to the connection (so a refusal can
// still send its own access_denied alert), it allocates only the
// reassembled handshake bytes, and it keeps every byte for replay.

const (
	// MaxClientHelloBytes bounds the stream bytes (record headers included)
	// the peek will buffer. Real hellos are 0.5-2 KB even with GREASE ECH and
	// post-quantum key shares; 16 KB leaves room while capping what one
	// connection can make the proxy hold.
	MaxClientHelloBytes = 16 << 10
	// DefaultPeekTimeout is used when PeekClientHelloConn gets no timeout.
	DefaultPeekTimeout = 5 * time.Second

	recordHeaderLen          = 5
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	maxRecordPayload         = 1 << 14 // TLSPlaintext.length limit, RFC 8446 §5.1
	extServerName            = 0x0000
	extEncryptedClientHello  = 0xfe0d
	sniHostName              = 0x00
)

var (
	// ErrNotTLS means the stream does not start with a TLS handshake record
	// (for example plain HTTP sent to port 443).
	ErrNotTLS = errors.New("egresspolicy: not a TLS handshake")
	// ErrNotClientHello means the first handshake message is something else.
	ErrNotClientHello = errors.New("egresspolicy: first handshake message is not a ClientHello")
	// ErrHelloTooLarge means the hello would exceed MaxClientHelloBytes (or
	// the reader's buffer).
	ErrHelloTooLarge = errors.New("egresspolicy: ClientHello exceeds the peek limit")
	// ErrMalformedHello means the bytes are not a well-formed ClientHello.
	ErrMalformedHello = errors.New("egresspolicy: malformed ClientHello")
	// ErrIncomplete means ParseClientHello got a valid prefix that needs more
	// bytes.
	ErrIncomplete = errors.New("egresspolicy: incomplete ClientHello")
)

// ClientHello is what the policy needs from a TLS ClientHello.
type ClientHello struct {
	// ServerName is the outer SNI, lowercased; "" when the hello has none.
	// With ECH this is the provider's public name, which is exactly what the
	// policy must match (D6): real ECH then fails the allowlist, while GREASE
	// ECH carries the real name here and passes.
	ServerName string
	// HasECH reports whether the encrypted_client_hello extension is present.
	// It is informational only and must never be a reason to refuse (A2/D6):
	// Chrome and Firefox send a GREASE ECH extension on every hello.
	HasECH bool
	// Length is how many stream bytes (record headers included) carry the
	// hello.
	Length int
}

// ServerIP returns the SNI as an address when the client put an IP literal
// there (RFC 6066 forbids it, but clients do it); allowlist mode refuses it
// unless a CIDR allows the address.
func (h *ClientHello) ServerIP() (netip.Addr, bool) {
	if h == nil || h.ServerName == "" {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(strings.Trim(h.ServerName, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// NewHelloReader wraps r in a bufio.Reader big enough to Peek a maximal
// ClientHello. Pass the same reader to the splice afterwards: it writes the
// buffered prefix upstream first (internal/netsplice).
func NewHelloReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, MaxClientHelloBytes)
}

// PeekClientHello parses the ClientHello at the head of br using only Peek,
// so nothing is consumed: every byte of the hello stays buffered in br for
// the caller to replay upstream. It handles hellos split across TCP segments
// and across TLS records. The wait is bounded by a read deadline the caller
// sets on the underlying connection (PeekClientHelloConn does both); this
// function never times out on its own.
func PeekClientHello(br *bufio.Reader) (*ClientHello, error) {
	p := helloParser{limit: min(MaxClientHelloBytes, br.Size())}
	need := recordHeaderLen
	for {
		// Peek whatever is already buffered, not just the minimum, so a hello
		// that arrived in one segment parses in one pass.
		want := max(need, min(br.Buffered(), p.limit))
		data, err := br.Peek(want)
		if len(data) < need {
			if err == nil || errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("peek ClientHello: %w", err)
		}
		hello, n, perr := p.feed(data)
		if perr != nil {
			return nil, perr
		}
		if hello != nil {
			return hello, nil
		}
		need = n
	}
}

// PeekClientHelloConn peeks the hello on conn with a read deadline of timeout
// (DefaultPeekTimeout when <= 0), then clears the deadline. It returns the
// buffered reader holding the unconsumed bytes even on error, so the caller
// can splice it, or write its own alert, as policy decides.
func PeekClientHelloConn(conn net.Conn, timeout time.Duration) (*ClientHello, *bufio.Reader, error) {
	if timeout <= 0 {
		timeout = DefaultPeekTimeout
	}
	br := NewHelloReader(conn)
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, br, fmt.Errorf("peek ClientHello: set deadline: %w", err)
	}
	hello, err := PeekClientHello(br)
	if derr := conn.SetReadDeadline(time.Time{}); derr != nil && err == nil {
		err = fmt.Errorf("peek ClientHello: clear deadline: %w", derr)
	}
	return hello, br, err
}

// ParseClientHello parses a ClientHello from the start of data, a TLS byte
// stream with record framing. It returns ErrIncomplete when data is a valid
// prefix that needs more bytes, so a caller that accumulates writes (the
// WASM mediator) can call it again with a longer buffer.
func ParseClientHello(data []byte) (*ClientHello, error) {
	p := helloParser{limit: MaxClientHelloBytes}
	hello, need, err := p.feed(data)
	if err != nil {
		return nil, err
	}
	if hello == nil {
		return nil, fmt.Errorf("%w: need %d bytes, have %d", ErrIncomplete, need, len(data))
	}
	return hello, nil
}

// helloParser reassembles handshake bytes from TLS records. It keeps its
// position between calls, so re-feeding a longer prefix of the same stream
// costs only the new bytes: re-parsing from zero on every Peek would let a
// client sending 1-byte records make the proxy copy O(n²) bytes.
type helloParser struct {
	limit int
	off   int    // stream bytes already moved into hs
	hs    []byte // reassembled handshake message bytes
}

// feed consumes records from data (the stream prefix starting at byte 0).
// It returns the hello, or the prefix length needed to make progress.
func (p *helloParser) feed(data []byte) (*ClientHello, int, error) {
	for {
		if p.off+recordHeaderLen > len(data) {
			need := p.off + recordHeaderLen
			if need > p.limit {
				return nil, 0, ErrHelloTooLarge
			}
			return nil, need, nil
		}
		hdr := data[p.off : p.off+recordHeaderLen]
		if hdr[0] != recordTypeHandshake || hdr[1] != 0x03 {
			if p.off == 0 {
				return nil, 0, ErrNotTLS
			}
			// A ClientHello may span records but nothing may interleave
			// (RFC 8446 §5.1).
			return nil, 0, fmt.Errorf("%w: non-handshake record inside the hello", ErrMalformedHello)
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > maxRecordPayload {
			return nil, 0, fmt.Errorf("%w: record length %d", ErrMalformedHello, n)
		}
		end := p.off + recordHeaderLen + n
		if end > p.limit {
			return nil, 0, ErrHelloTooLarge
		}
		if end > len(data) {
			return nil, end, nil
		}
		p.hs = append(p.hs, data[p.off+recordHeaderLen:end]...)
		p.off = end
		if len(p.hs) < 4 {
			continue // the handshake header itself is split across records
		}
		if p.hs[0] != handshakeTypeClientHello {
			return nil, 0, ErrNotClientHello
		}
		msgLen := int(p.hs[1])<<16 | int(p.hs[2])<<8 | int(p.hs[3])
		if 4+msgLen > p.limit {
			// Fail now rather than wait for bytes that cannot fit anyway.
			return nil, 0, ErrHelloTooLarge
		}
		if len(p.hs) < 4+msgLen {
			continue
		}
		hello, err := parseClientHelloBody(p.hs[4 : 4+msgLen])
		if err != nil {
			return nil, 0, err
		}
		hello.Length = p.off
		return hello, 0, nil
	}
}

func malformed(reason string) error { return fmt.Errorf("%w: %s", ErrMalformedHello, reason) }

// parseClientHelloBody parses the ClientHello message body (RFC 8446 §4.1.2,
// which also covers the TLS 1.0-1.2 layout).
func parseClientHelloBody(body []byte) (*ClientHello, error) {
	s := cryptobyte.String(body)
	var (
		version      uint16
		random       []byte
		sessionID    cryptobyte.String
		cipherSuites cryptobyte.String
		compression  cryptobyte.String
	)
	if !s.ReadUint16(&version) || !s.ReadBytes(&random, 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) || len(sessionID) > 32 ||
		!s.ReadUint16LengthPrefixed(&cipherSuites) || len(cipherSuites) < 2 || len(cipherSuites)%2 != 0 ||
		!s.ReadUint8LengthPrefixed(&compression) || len(compression) < 1 {
		return nil, malformed("bad fixed fields")
	}
	hello := &ClientHello{}
	if s.Empty() {
		return hello, nil // no extensions at all: no SNI
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return nil, malformed("bad extensions block")
	}
	seen := make(map[uint16]struct{})
	for !exts.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, malformed("truncated extension")
		}
		// Duplicates are forbidden (RFC 8446 §4.2) and are a classic filter
		// bypass: the proxy reads one server_name, the origin another.
		if _, dup := seen[typ]; dup {
			return nil, malformed(fmt.Sprintf("duplicate extension %#04x", typ))
		}
		seen[typ] = struct{}{}
		switch typ {
		case extServerName:
			name, err := parseServerName(data)
			if err != nil {
				return nil, err
			}
			hello.ServerName = name
		case extEncryptedClientHello:
			hello.HasECH = true
		}
	}
	return hello, nil
}

// parseServerName reads the server_name extension (RFC 6066 §3).
func parseServerName(data cryptobyte.String) (string, error) {
	var list cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() || list.Empty() {
		return "", malformed("bad server_name list")
	}
	var name string
	for !list.Empty() {
		var typ uint8
		var host cryptobyte.String
		if !list.ReadUint8(&typ) || !list.ReadUint16LengthPrefixed(&host) || len(host) == 0 {
			return "", malformed("bad server_name entry")
		}
		if typ != sniHostName {
			continue
		}
		// Two host names would let the proxy and the origin disagree on the
		// destination; RFC 6066 forbids it, and so does crypto/tls.
		if name != "" {
			return "", malformed("more than one host_name")
		}
		name = string(host)
	}
	if name == "" {
		return "", nil
	}
	if len(name) > MaxHostnameLength || strings.HasSuffix(name, ".") {
		return "", malformed("invalid host_name")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		// ':' and brackets admit IP-literal SNIs so policy can refuse them by
		// name; anything else outside LDH+underscore is not a hostname.
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == ':' || c == '[' || c == ']') {
			return "", malformed("invalid host_name")
		}
	}
	return strings.ToLower(name), nil
}
