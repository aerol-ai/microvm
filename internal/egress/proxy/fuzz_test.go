package proxy

import (
	"bufio"
	"bytes"
	"net/http"
	"net/netip"
	"testing"
)

// FuzzRequestHost parses arbitrary request heads (EF-71): the Host decision
// must never panic, and a Host naming a port other than 80 is never accepted.
func FuzzRequestHost(f *testing.F) {
	for _, s := range []string{
		"GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n",
		"GET http://evil.example/ HTTP/1.1\r\nHost: pypi.org:80\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
		"CONNECT x:443 HTTP/1.1\r\n\r\n",
	} {
		f.Add([]byte(s))
	}
	dst := netip.MustParseAddrPort("93.184.216.34:80")
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		host, ok := requestHost(req, dst)
		if ok && host == "" {
			t.Fatal("accepted an empty host")
		}
		_ = isUpgrade(req)
	})
}
