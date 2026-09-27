package harness

import "testing"

func TestParseLeaderJSON(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"leader", `{"leader":"aerolvm-itest-x-node2"}`, "aerolvm-itest-x-node2"},
		{"election in flight", `{"leader":""}`, ""},
		{"curl error text is not a leader", `curl: (7) Failed to connect to 127.0.0.1 port 21212`, ""},
		{"empty capture", "", ""},
		{"whitespace around", "  {\"leader\":\" n1 \"}\n", "n1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseLeaderJSON(tc.body); got != tc.want {
				t.Fatalf("ParseLeaderJSON(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}
