package firecracker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestClearBits(t *testing.T) {
	for _, tc := range []struct {
		bits []uint
		want string
	}{
		{nil, "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{[]uint{0}, "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0"},
		{[]uint{2}, "0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx"},
		{[]uint{5}, "0bxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxx"},
		{[]uint{31}, "0b0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"},
		{[]uint{5, 2}, "0bxxxxxxxxxxxxxxxxxxxxxxxxxx0xx0xx"},
	} {
		got := ClearBits(tc.bits...)
		if got != tc.want {
			t.Errorf("ClearBits(%v) = %s, want %s", tc.bits, got, tc.want)
		}
		if len(got) != 34 {
			t.Errorf("ClearBits(%v) is %d characters, Firecracker wants 34", tc.bits, len(got))
		}
	}
}

func TestClearBitsRefusesABitPast31(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("ClearBits(32) did not panic; a skipped bit would stay set")
		}
	}()
	ClearBits(32)
}

func TestNestedVirtMatches(t *testing.T) {
	for _, tc := range []struct {
		saved       NestedVirt
		nodeAllowed bool
		want        bool
	}{
		{NestedVirtOff, false, true},
		{NestedVirtOn, false, false},
		{NestedVirtUnknown, false, false},
		{NestedVirtOff, true, false},
		{NestedVirtOn, true, true},
		{NestedVirtUnknown, true, true},
	} {
		if got := tc.saved.Matches(tc.nodeAllowed); got != tc.want {
			t.Errorf("NestedVirt(%q).Matches(%v) = %v, want %v", tc.saved, tc.nodeAllowed, got, tc.want)
		}
	}
	if NestedVirtSetting(false) != NestedVirtOff || NestedVirtSetting(true) != NestedVirtOn {
		t.Fatalf("NestedVirtSetting: false=%q true=%q", NestedVirtSetting(false), NestedVirtSetting(true))
	}
	for _, allowed := range []bool{false, true} {
		if !NestedVirtSetting(allowed).Matches(allowed) {
			t.Errorf("a VM booted with nested virt allowed=%v does not match its own node", allowed)
		}
	}
}

// The body is compared byte for byte with the shape Firecracker v1.15's
// custom CPU template takes (docs/cpu_templates/cpu-templates.md and the
// swagger's CpuConfig): a wrong key is a 400 at every boot, and a wrong
// bit would hide the wrong CPU feature without any error.
func TestPutCPUConfigSendsHideNestedVirt(t *testing.T) {
	const want = `{"cpuid_modifiers":[` +
		`{"leaf":"0x1","subleaf":"0x0","flags":0,"modifiers":[{"register":"ecx","bitmap":"0bxxxxxxxxxxxxxxxxxxxxxxxxxx0xxxxx"}]},` +
		`{"leaf":"0x80000001","subleaf":"0x0","flags":0,"modifiers":[{"register":"ecx","bitmap":"0bxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx"}]}]}`
	var body string
	sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cpu-config" || r.Method != http.MethodPut {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusNoContent)
	}))
	if err := New(sock).PutCPUConfig(context.Background(), HideNestedVirt()); err != nil {
		t.Fatalf("PutCPUConfig: %v", err)
	}
	if body != want {
		t.Fatalf("body:\n got %s\nwant %s", body, want)
	}
	var back CPUConfig
	if err := json.Unmarshal([]byte(body), &back); err != nil || len(back.CPUIDModifiers) != 2 {
		t.Fatalf("body does not round-trip: %v %+v", err, back)
	}
}

func TestPutCPUConfigSurfacesARefusal(t *testing.T) {
	sock := startUDSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"fault_message":"Template changes a CPUID entry not supported by KVM"}`))
	}))
	if err := New(sock).PutCPUConfig(context.Background(), HideNestedVirt()); err == nil {
		t.Fatal("a 400 from /cpu-config returned no error")
	}
}
