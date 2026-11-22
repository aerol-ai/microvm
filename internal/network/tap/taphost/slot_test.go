package taphost

import "testing"

func TestSlotAt(t *testing.T) {
	s, err := SlotAt("172.16.0.9/20", 256, 255)
	want := Slot{TapName: "fctap255", CIDR: "172.16.3.252/30", HostIP: "172.16.3.253", GuestIP: "172.16.3.254", VsockCID: 258}
	if err != nil || s != want {
		t.Fatalf("SlotAt = %+v, %v; want %+v", s, err, want)
	}
	for _, tc := range []struct {
		base        string
		size, index int
	}{
		{"fd00::/64", 4, 0},         // not IPv4
		{"172.16.0.0", 4, 0},        // not a CIDR
		{"172.16.0.0/24", 0, 0},     // no pool
		{"172.16.0.0/16", 10001, 0}, // past the pool's cap
		{"172.16.0.0/24", 65, 0},    // more slots than the base holds
		{"172.16.0.0/24", 64, 64},   // past the pool
		{"172.16.0.0/24", 64, -1},   // before it
	} {
		if s, err := SlotAt(tc.base, tc.size, tc.index); err == nil {
			t.Errorf("SlotAt(%q, %d, %d) = %+v, want an error", tc.base, tc.size, tc.index, s)
		}
	}
}

func TestIndexOf(t *testing.T) {
	for name, want := range map[string]int{"fctap0": 0, "fctap7": 7, "fctap255": 255, "fctap9999": 9999} {
		if got, ok := IndexOf(name, MaxPoolSize); !ok || got != want {
			t.Errorf("IndexOf(%q) = %d %v, want %d", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "fctap", "fctap01", "fctap-1", "fctap+1", "fctap1a", "fctap 1", "eth0", "lo",
		"xfctap1", "fctap10000", "fctap99999", "fctap100000", "FCTAP1"} {
		if got, ok := IndexOf(name, MaxPoolSize); ok {
			t.Errorf("IndexOf(%q) = %d, want none", name, got)
		}
	}
	if _, ok := IndexOf("fctap4", 4); ok {
		t.Error("an index past a pool of 4")
	}
	if _, ok := IndexOf("fctap1", MaxPoolSize+1); ok {
		t.Error("a pool past the cap")
	}
}
