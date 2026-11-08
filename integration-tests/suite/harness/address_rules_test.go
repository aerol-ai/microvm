package harness

import (
	"reflect"
	"strings"
	"testing"
)

// blockSet renders the aerolvm_block table the way `nft list ruleset`
// prints it on a node (2026-11-08, single-node-containerd-pool): two
// addresses to a line.
func blockSet(addrs ...string) string {
	var b strings.Builder
	b.WriteString("table ip aerolvm_block {\n\tset blocked {\n\t\ttype ipv4_addr\n\t\telements = { ")
	for i, a := range addrs {
		switch {
		case i == len(addrs)-1:
			b.WriteString(a + " }\n")
		case i%2 == 1:
			b.WriteString(a + ",\n\t\t\t     ")
		default:
			b.WriteString(a + ", ")
		}
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func TestAddressRuleLines(t *testing.T) {
	const ip = "10.88.2.6"
	tests := []struct {
		name   string
		before string
		after  string
		same   bool
		want   []string // AddressRuleLines(before, ip), when set
	}{
		{
			// The UC-345 failure: a park's address left the set, so the
			// line that held ip ("10.88.0.39, 10.88.2.6,") re-wrapped.
			name:   "a neighbour leaving a wrapped set re-wraps it",
			before: blockSet("10.88.0.20", "10.88.0.31", "10.88.0.39", "10.88.2.6", "10.88.2.9"),
			after:  blockSet("10.88.0.20", "10.88.0.31", "10.88.2.6", "10.88.2.9"),
			same:   true,
			want:   []string{"set element 10.88.2.6"},
		},
		{
			name:   "a neighbour joining a wrapped set re-wraps it",
			before: blockSet("10.88.2.6", "10.88.2.9"),
			after:  blockSet("10.88.0.5", "10.88.2.6", "10.88.2.9"),
			same:   true,
		},
		{
			name:   "ip leaving the set is a change",
			before: blockSet("10.88.0.39", "10.88.2.6", "10.88.2.9"),
			after:  blockSet("10.88.0.39", "10.88.2.9"),
			same:   false,
		},
		{
			name:   "a one-line set",
			before: "\t\telements = { 10.88.2.6 }\n",
			want:   []string{"set element 10.88.2.6"},
		},
		{
			name:   "a longer address is not ip",
			before: blockSet("10.88.2.60", "110.88.2.6", "10.88.2.61"),
			want:   nil,
		},
		{
			name: "concatenated elements, one per port",
			before: "\t\telements = { 172.17.0.0/16 . 10.88.2.6 . 22,\n" +
				"\t\t\t     172.17.0.0/16 . 10.88.2.6 . 111,\n" +
				"\t\t\t     172.17.0.0/16 . 10.42.1.221 . 22 }\n",
			want: []string{"set element 172.17.0.0/16 . 10.88.2.6 . 111", "set element 172.17.0.0/16 . 10.88.2.6 . 22"},
		},
		{
			name:   "an element's countdown is not a change",
			before: "\t\telements = { 10.88.2.6 timeout 1h expires 59m58s, 10.88.2.9 }\n",
			after:  "\t\telements = { 10.88.2.6 timeout 1h expires 51m2s, 10.88.2.9 }\n",
			same:   true,
			want:   []string{"set element 10.88.2.6 timeout 1h"},
		},
		{
			name: "rule lines keep their text without counters",
			before: "-A AEROLVM-BLOCK -s 10.88.2.6/32 -j DROP\n" +
				"\t\tip saddr 10.88.2.6 counter packets 12 bytes 720 drop\n" +
				"-A AEROLVM-BLOCK -s 10.88.2.60/32 -j DROP\n",
			after: "-A AEROLVM-BLOCK -s 10.88.2.6/32 -j DROP\n" +
				"\t\tip saddr 10.88.2.6 counter packets 99 bytes 5940 drop\n",
			same: true,
			want: []string{"-A AEROLVM-BLOCK -s 10.88.2.6/32 -j DROP", "ip saddr 10.88.2.6 drop"},
		},
		{
			name:   "a rule line for ip going away is a change",
			before: "-A AEROLVM-BLOCK -s 10.88.2.6/32 -j DROP\n" + blockSet("10.88.2.6"),
			after:  blockSet("10.88.2.6"),
			same:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AddressRuleLines(tt.before, ip)
			if tt.want != nil || tt.after == "" {
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("AddressRuleLines(before) = %q, want %q", got, tt.want)
				}
			}
			if tt.after == "" {
				return
			}
			after := AddressRuleLines(tt.after, ip)
			if same := reflect.DeepEqual(got, after); same != tt.same {
				t.Errorf("before %q vs after %q: same = %v, want %v", got, after, same, tt.same)
			}
		})
	}
}
