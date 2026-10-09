package egresspolicy

import (
	"bytes"
	"testing"
	"testing/iotest"
)

// FuzzParseClientHello asserts the SNI peek's invariants (EF-71): no panics
// or hangs on arbitrary bytes; an accepted hello never claims more bytes than
// it was given; and peeking the same bytes through a one-byte-per-Read
// reader (worst-case segmentation) reaches the same answer without
// consuming anything.
func FuzzParseClientHello(f *testing.F) {
	seeds := [][]byte{
		helloStream([]helloExt{sniExt("pypi.org")}),
		helloStream([]helloExt{sniExt("pypi.org"), greaseECH}, 1, 2, 3, 40),
		helloStream([]helloExt{{0x0a0a, nil}, sniExt("files.pythonhosted.org"), greaseECH}),
		helloStream([]helloExt{sniExt("pypi.org", "evil.com")}),
		helloStream([]helloExt{sniExt("pypi.org"), sniExt("evil.com")}),
		helloStream([]helloExt{sniExt("203.0.113.7")}),
		helloStream(nil),
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x00},
		{0x16, 0x03, 0x01, 0x40, 0x00, 0x01, 0xff, 0xff, 0xff},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseClientHello(data)
		if err != nil {
			return
		}
		if h.Length <= 0 || h.Length > len(data) || h.Length > MaxClientHelloBytes {
			t.Fatalf("hello length %d out of range for %d input bytes", h.Length, len(data))
		}
		br := NewHelloReader(iotest.OneByteReader(bytes.NewReader(data)))
		ph, err := PeekClientHello(br)
		if err != nil || *ph != *h {
			t.Fatalf("peek = %+v, %v; parse = %+v", ph, err, h)
		}
		if br.Buffered() < h.Length {
			t.Fatalf("peek consumed bytes: buffered %d < length %d", br.Buffered(), h.Length)
		}
	})
}
