package nodejoin

import (
	"errors"
	"strings"
	"testing"
)

// --advertise takes an IP or a DNS name: a server pod on Kubernetes
// advertises its headless-Service name (C4), which used to be refused.
func TestPickAdvertise(t *testing.T) {
	cases := []struct {
		name, asked, hostIP string
		hostErr             error
		want, wantErr       string
	}{
		{name: "an IP", asked: " 10.0.0.7 ", want: "10.0.0.7"},
		{name: "an IPv6 address", asked: "fd00::7", want: "fd00::7"},
		{name: "a server pod's DNS name", asked: "aerolvm-server-0.aerolvm-servers.aerolvm-system.svc",
			want: "aerolvm-server-0.aerolvm-servers.aerolvm-system.svc"},
		{name: "not a name", asked: "server_0.svc", wantErr: "not an IP address or a DNS name"},
		{name: "upper case", asked: "Server-0.svc", wantErr: "not an IP address or a DNS name"},
		{name: "a label ending in a dash", asked: "server-.svc", wantErr: "not an IP address or a DNS name"},
		{name: "an empty label", asked: "server..svc", wantErr: "not an IP address or a DNS name"},
		{name: "a port is not an address", asked: "10.0.0.7:7000", wantErr: "not an IP address or a DNS name"},
		{name: "a label too long", asked: strings.Repeat("a", 64) + ".svc", wantErr: "not an IP address or a DNS name"},
		{name: "a name too long", asked: strings.Repeat("a.", 127) + "ab", wantErr: "not an IP address or a DNS name"},
		{name: "none asked: the machine's address", hostIP: "10.0.0.9", want: "10.0.0.9"},
		{name: "none asked, none found", wantErr: "pass --advertise"},
		{name: "none asked, lookup failed", hostErr: errors.New("no route"), wantErr: "no route"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pickAdvertise(&fakeHost{ip: tc.hostIP, ipErr: tc.hostErr}, tc.asked)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
