package service

import (
	"bufio"
	"strings"
	"testing"
)

// The splice and connection-limiter tests moved with the code to
// internal/netsplice.

func TestReadProxyV1Header(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    proxyHeader
		wantErr string
	}{
		{name: "tcp4", line: "PROXY TCP4 1.2.3.4 5.6.7.8 40000 443\r\n",
			want: proxyHeader{Family: "TCP4", SrcAddr: "1.2.3.4", DstAddr: "5.6.7.8", SrcPort: 40000, DstPort: 443}},
		{name: "tcp6", line: "PROXY TCP6 ::1 ::2 1 30001\r\n",
			want: proxyHeader{Family: "TCP6", SrcAddr: "::1", DstAddr: "::2", SrcPort: 1, DstPort: 30001}},
		{name: "junk source port is informational", line: "PROXY TCP4 a b x 443\n",
			want: proxyHeader{Family: "TCP4", SrcAddr: "a", DstAddr: "b", SrcPort: 0, DstPort: 443}},
		{name: "bad dest port", line: "PROXY TCP4 a b 1 0\n", wantErr: "destination port"},
		{name: "unknown family", line: "PROXY UNKNOWN a b 1 2\n", wantErr: "family"},
		{name: "not proxy", line: "GET / HTTP/1.1\r\n", wantErr: "malformed"},
		{name: "too large", line: strings.Repeat("P", 300) + "\n", wantErr: "too large"},
		{name: "no newline", line: "PROXY TCP4 a b 1 2", wantErr: "read proxy protocol header"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReaderSize(strings.NewReader(tc.line), l4WakeProxyHeaderMaxBytes)
			got, err := readProxyV1Header(br)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got (%+v, %v), want %+v", got, err, tc.want)
			}
		})
	}
}
