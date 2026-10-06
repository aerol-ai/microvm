package egresspolicy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

type helloExt struct {
	typ  uint16
	data []byte
}

// helloBody builds a ClientHello body. exts == nil omits the extensions
// block entirely (a legal pre-TLS-1.2 hello).
func helloBody(exts []helloExt) []byte {
	var b cryptobyte.Builder
	b.AddUint16(0x0303)
	b.AddBytes(make([]byte, 32))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 32)) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x1301); b.AddUint16(0x1302) })
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
	if exts != nil {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, e := range exts {
				b.AddUint16(e.typ)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.data) })
			}
		})
	}
	return b.BytesOrPanic()
}

// sniExt encodes a server_name extension with one host_name per name.
func sniExt(names ...string) helloExt {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, n := range names {
			b.AddUint8(sniHostName)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(n)) })
		}
	})
	return helloExt{extServerName, b.BytesOrPanic()}
}

// greaseECH mimics Chrome's decoy encrypted_client_hello extension.
var greaseECH = helloExt{extEncryptedClientHello, append([]byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x42}, make([]byte, 40)...)}

func handshakeMsg(typ byte, body []byte) []byte {
	n := len(body)
	return append([]byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}, body...)
}

// records frames hs into TLS records with the given payload sizes; the last
// record takes the remainder.
func records(hs []byte, sizes ...int) []byte {
	var out []byte
	for len(hs) > 0 {
		n := len(hs)
		if len(sizes) > 0 {
			n = min(sizes[0], len(hs))
			sizes = sizes[1:]
		}
		out = append(out, recordTypeHandshake, 0x03, 0x01, byte(n>>8), byte(n))
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}

func helloStream(exts []helloExt, sizes ...int) []byte {
	return records(handshakeMsg(handshakeTypeClientHello, helloBody(exts)), sizes...)
}

func TestParseClientHello(t *testing.T) {
	tests := []struct {
		name    string
		stream  []byte
		sni     string
		hasECH  bool
		trailer int // bytes after the hello that must not count in Length
	}{
		{"single_record", helloStream([]helloExt{sniExt("PyPI.org")}), "pypi.org", false, 0},
		{"handshake_header_split", helloStream([]helloExt{sniExt("pypi.org")}, 1, 2, 3, 10), "pypi.org", false, 0},
		{"one_byte_records", helloStream([]helloExt{sniExt("pypi.org")}, func() []int {
			s := make([]int, 400)
			for i := range s {
				s[i] = 1
			}
			return s
		}()...), "pypi.org", false, 0},
		// D6/A2: GREASE ECH carries the real name in the outer SNI and must pass.
		{"grease_ech", helloStream([]helloExt{{0x0a0a, nil}, sniExt("files.pythonhosted.org"), greaseECH}), "files.pythonhosted.org", true, 0},
		{"no_sni", helloStream([]helloExt{{0x000a, []byte{0, 2, 0, 0x1d}}}), "", false, 0},
		{"no_extensions", helloStream(nil), "", false, 0},
		{"only_non_host_name_entries", helloStream([]helloExt{{extServerName, []byte{0, 4, 1, 0, 1, 'x'}}}), "", false, 0},
		{"ip_literal_sni", helloStream([]helloExt{sniExt("203.0.113.7")}), "203.0.113.7", false, 0},
		{"trailing_app_data", append(helloStream([]helloExt{sniExt("pypi.org")}), 0x17, 0x03, 0x03, 0x00, 0x01, 0xff), "pypi.org", false, 6},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseClientHello(tc.stream)
			if err != nil {
				t.Fatal(err)
			}
			if h.ServerName != tc.sni || h.HasECH != tc.hasECH || h.Length != len(tc.stream)-tc.trailer {
				t.Fatalf("got %+v, want sni %q ech %v length %d", h, tc.sni, tc.hasECH, len(tc.stream)-tc.trailer)
			}
			// The same stream peeked through a reader that hands out one byte
			// per Read (worst-case TCP segmentation) parses identically and is
			// left fully buffered for replay.
			br := NewHelloReader(iotest.OneByteReader(bytes.NewReader(tc.stream)))
			ph, err := PeekClientHello(br)
			if err != nil {
				t.Fatalf("peek: %v", err)
			}
			if *ph != *h {
				t.Fatalf("peek = %+v, parse = %+v", ph, h)
			}
			replay, _ := io.ReadAll(br)
			if !bytes.Equal(replay, tc.stream) {
				t.Fatal("peek consumed bytes the caller must replay")
			}
		})
	}
}

// TestECHPolicyDecision is EF-07 at the matcher: the outer SNI decides.
func TestECHPolicyDecision(t *testing.T) {
	p := mustCompile(t, Spec{AllowOut: []string{"pypi.org"}})
	grease, _ := ParseClientHello(helloStream([]helloExt{sniExt("pypi.org"), greaseECH}))
	if ok, _ := p.MatchHostPort(grease.ServerName, 443); !ok || !grease.HasECH {
		t.Fatal("GREASE ECH hello with an allowed outer SNI must pass")
	}
	realECH, _ := ParseClientHello(helloStream([]helloExt{sniExt("cloudflare-ech.com"), greaseECH}))
	if ok, _ := p.MatchHostPort(realECH.ServerName, 443); ok {
		t.Fatal("real ECH whose outer (public) name is not allowlisted must be denied")
	}
	noSNI, _ := ParseClientHello(helloStream(nil))
	if ok, _ := p.MatchHostPort(noSNI.ServerName, 443); ok {
		t.Fatal("a hello with no SNI must be denied in allowlist mode")
	}
	ipSNI, _ := ParseClientHello(helloStream([]helloExt{sniExt("203.0.113.7")}))
	if ip, ok := ipSNI.ServerIP(); !ok || ip.String() != "203.0.113.7" {
		t.Fatalf("ServerIP = %v %v", ip, ok)
	}
	if ok, _ := p.MatchHostPort(ipSNI.ServerName, 443); ok {
		t.Fatal("an IP-literal SNI must be denied unless a CIDR allows it")
	}
	if _, ok := grease.ServerIP(); ok {
		t.Fatal("a hostname SNI is not an IP")
	}
	if _, ok := (*ClientHello)(nil).ServerIP(); ok {
		t.Fatal("nil hello has no IP")
	}
}

func TestParseClientHelloErrors(t *testing.T) {
	valid := handshakeMsg(handshakeTypeClientHello, helloBody([]helloExt{sniExt("pypi.org")}))
	bodyWith := func(mutate func([]byte) []byte) []byte {
		return records(handshakeMsg(handshakeTypeClientHello, mutate(helloBody([]helloExt{sniExt("pypi.org")}))))
	}
	tests := []struct {
		name   string
		stream []byte
		want   error
	}{
		{"plain_http", []byte("GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n"), ErrNotTLS},
		{"sslv2_style", []byte{0x80, 0x2e, 0x01, 0x03, 0x01, 0x00}, ErrNotTLS},
		{"bad_major_version", []byte{0x16, 0x02, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5}, ErrNotTLS},
		{"server_hello", records(handshakeMsg(0x02, helloBody(nil))), ErrNotClientHello},
		{"interleaved_record", func() []byte {
			s := records(valid, 10)
			s[15] = 0x17 // second record turns into application data
			return s
		}(), ErrMalformedHello},
		{"zero_length_record", []byte{0x16, 0x03, 0x01, 0x00, 0x00}, ErrMalformedHello},
		{"oversized_record", []byte{0x16, 0x03, 0x01, 0x40, 0x01}, ErrMalformedHello},
		{"hello_claims_16mb", records([]byte{0x01, 0xff, 0xff, 0xff, 0x00}), ErrHelloTooLarge},
		{"record_past_limit", append(records(valid[:4], 4), 0x16, 0x03, 0x01, 0x40, 0x00), ErrHelloTooLarge},
		{"duplicate_sni_extension", helloStream([]helloExt{sniExt("pypi.org"), sniExt("evil.com")}), ErrMalformedHello},
		{"two_host_names", helloStream([]helloExt{sniExt("pypi.org", "evil.com")}), ErrMalformedHello},
		{"empty_host_name", helloStream([]helloExt{sniExt("")}), ErrMalformedHello},
		{"trailing_dot_sni", helloStream([]helloExt{sniExt("pypi.org.")}), ErrMalformedHello},
		{"bad_char_sni", helloStream([]helloExt{sniExt("pypi.org/evil")}), ErrMalformedHello},
		{"nul_in_sni", helloStream([]helloExt{sniExt("evil.com\x00.pypi.org")}), ErrMalformedHello},
		{"overlong_sni", helloStream([]helloExt{sniExt(strings.Repeat("a", 254))}), ErrMalformedHello},
		{"empty_sni_list", helloStream([]helloExt{{extServerName, []byte{0, 0}}}), ErrMalformedHello},
		{"sni_list_trailing_bytes", helloStream([]helloExt{{extServerName, []byte{0, 0, 9}}}), ErrMalformedHello},
		{"truncated_extension", bodyWith(func(b []byte) []byte {
			// Extensions block claims 3 bytes: a type and half a length.
			return append(b[:len(b)-len(sniExt("pypi.org").data)-6], 0, 3, 0, 0, 0)
		}), ErrMalformedHello},
		{"extensions_trailing_garbage", bodyWith(func(b []byte) []byte { return append(b, 0xde, 0xad) }), ErrMalformedHello},
		{"truncated_fixed_fields", records(handshakeMsg(handshakeTypeClientHello, []byte{0x03, 0x03, 1, 2})), ErrMalformedHello},
		{"session_id_too_long", bodyWith(func(b []byte) []byte {
			var nb cryptobyte.Builder
			nb.AddUint16(0x0303)
			nb.AddBytes(make([]byte, 32))
			nb.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 33)) })
			nb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x1301) })
			nb.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
			return nb.BytesOrPanic()
		}), ErrMalformedHello},
		{"odd_cipher_suites", bodyWith(func(b []byte) []byte {
			var nb cryptobyte.Builder
			nb.AddUint16(0x0303)
			nb.AddBytes(make([]byte, 32))
			nb.AddUint8(0)
			nb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte{0x13, 0x01, 0x13}) })
			nb.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
			return nb.BytesOrPanic()
		}), ErrMalformedHello},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseClientHello(tc.stream)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseClientHelloIncompletePrefixes(t *testing.T) {
	stream := helloStream([]helloExt{sniExt("pypi.org"), greaseECH}, 7, 30)
	for n := 0; n < len(stream); n++ {
		if _, err := ParseClientHello(stream[:n]); !errors.Is(err, ErrIncomplete) {
			t.Fatalf("prefix %d/%d: err = %v, want ErrIncomplete", n, len(stream), err)
		}
	}
}

func TestPeekClientHelloEdges(t *testing.T) {
	stream := helloStream([]helloExt{sniExt("pypi.org")})

	t.Run("eof_mid_hello", func(t *testing.T) {
		_, err := PeekClientHello(NewHelloReader(bytes.NewReader(stream[:len(stream)-3])))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want ErrUnexpectedEOF", err)
		}
	})
	t.Run("eof_before_header", func(t *testing.T) {
		_, err := PeekClientHello(NewHelloReader(bytes.NewReader(nil)))
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("read_error_passes_through", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := PeekClientHello(NewHelloReader(iotest.ErrReader(boom)))
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("small_reader_buffer_caps_the_hello", func(t *testing.T) {
		_, err := PeekClientHello(bufio.NewReaderSize(bytes.NewReader(stream), 16))
		if !errors.Is(err, ErrHelloTooLarge) {
			t.Fatalf("err = %v, want ErrHelloTooLarge", err)
		}
	})
	t.Run("not_tls", func(t *testing.T) {
		_, err := PeekClientHello(NewHelloReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n")))
		if !errors.Is(err, ErrNotTLS) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestPeekClientHelloConn(t *testing.T) {
	t.Run("fragmented_over_a_pipe_then_deadline_cleared", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		stream := helloStream([]helloExt{sniExt("pypi.org")}, 3, 50)
		go func() {
			for i := 0; i < len(stream); i += 17 {
				_, _ = client.Write(stream[i:min(i+17, len(stream))])
			}
			time.Sleep(50 * time.Millisecond)
			_, _ = client.Write([]byte("after"))
		}()
		h, br, err := PeekClientHelloConn(server, 2*time.Second)
		if err != nil || h.ServerName != "pypi.org" {
			t.Fatalf("got %+v, %v", h, err)
		}
		got := make([]byte, len(stream)+5)
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("read after peek (deadline must be cleared): %v", err)
		}
		if !bytes.Equal(got[:len(stream)], stream) || string(got[len(stream):]) != "after" {
			t.Fatal("replayed bytes differ")
		}
	})
	t.Run("silent_client_times_out", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		start := time.Now()
		_, br, err := PeekClientHelloConn(server, 50*time.Millisecond)
		if !errors.Is(err, os.ErrDeadlineExceeded) || br == nil {
			t.Fatalf("err = %v, br = %v", err, br)
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("timeout not honored")
		}
	})
	t.Run("default_timeout", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() { _, _ = client.Write(helloStream([]helloExt{sniExt("pypi.org")})) }()
		if h, _, err := PeekClientHelloConn(server, 0); err != nil || h.ServerName != "pypi.org" {
			t.Fatalf("got %+v %v", h, err)
		}
	})
	t.Run("deadline_errors", func(t *testing.T) {
		boom := errors.New("no deadlines")
		_, br, err := PeekClientHelloConn(&deadlineConn{failAfter: 0, err: boom}, time.Second)
		if !errors.Is(err, boom) || br == nil {
			t.Fatalf("set deadline: err = %v", err)
		}
		c := &deadlineConn{Reader: bytes.NewReader(helloStream([]helloExt{sniExt("pypi.org")})), failAfter: 1, err: boom}
		if _, _, err := PeekClientHelloConn(c, time.Second); !errors.Is(err, boom) {
			t.Fatalf("clear deadline: err = %v", err)
		}
	})
	// A real crypto/tls client hello (Go's own, with key shares, ALPN etc.)
	// parses to the configured name.
	t.Run("crypto_tls_client", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() {
			_ = tls.Client(client, &tls.Config{ServerName: "Files.PythonHosted.org", NextProtos: []string{"h2", "http/1.1"}}).Handshake()
		}()
		h, br, err := PeekClientHelloConn(server, 2*time.Second)
		if err != nil || h.ServerName != "files.pythonhosted.org" {
			t.Fatalf("got %+v, %v", h, err)
		}
		if br.Buffered() < h.Length {
			t.Fatalf("buffered %d < hello length %d", br.Buffered(), h.Length)
		}
	})
}

// deadlineConn fails SetReadDeadline from call failAfter onward.
type deadlineConn struct {
	net.Conn
	io.Reader
	calls     int
	failAfter int
	err       error
}

func (c *deadlineConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (c *deadlineConn) SetReadDeadline(time.Time) error {
	c.calls++
	if c.calls > c.failAfter {
		return c.err
	}
	return nil
}
