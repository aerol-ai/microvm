package rootpolicy

import (
	"strings"
	"testing"
)

func TestCheckReclaimSource(t *testing.T) {
	e := NFSExport{Server: "10.0.0.9", Export: "/exports/vols/"}
	for _, ok := range []string{"10.0.0.9:/exports/vols/t-0123abcd/data", "10.0.0.9:/exports/vols/op-main/my.vol_1-x"} {
		if err := CheckReclaimSource(e, ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"10.0.0.9:/exports/vols",               // the export itself
		"10.0.0.9:/exports/vols/t-1",           // a scope, every volume of a tenant
		"10.0.0.9:/exports/vols/t-1/a/b",       // inside a volume
		"10.0.0.9:/exports/vols/t-1/../../etc", // out of the export
		"10.0.0.9:/exports/vols/../vols/t-1/a", // not clean
		"10.0.0.9:/exports/volsx/t-1/a",        // a sibling export
		"10.0.0.9:/exports/vols/T-1/a",         // not a sanitized name
		"10.0.0.9:/exports/vols/t-1/..",        // a climb as the name
		"10.0.0.9:/exports/vols/t-1/a b",
		"10.0.0.8:/exports/vols/t-1/a", // another server
		":/exports/vols/t-1/a", "/exports/vols/t-1/a", "",
		"10.0.0.9:/exports/vols/t-1/" + strings.Repeat("a", 129),
	} {
		if err := CheckReclaimSource(e, bad); RuleOf(err) != RuleReclaim {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if err := CheckReclaimSource(NFSExport{Server: "h", Export: "/"}, "h://t/a"); RuleOf(err) != RuleReclaim {
		t.Errorf("an export of /: %v", err)
	}
}

// FuzzCheckReclaimSource: a source the rule lets through is exactly two
// plain names below the export, on the export's server.
func FuzzCheckReclaimSource(f *testing.F) {
	f.Add("10.0.0.9:/exports/vols/t-1/data")
	f.Add("10.0.0.9:/exports/vols/t-1/../x")
	f.Add("10.0.0.9:/exports/vols//t/a")
	e := NFSExport{Server: "10.0.0.9", Export: "exports/vols"}
	f.Fuzz(func(t *testing.T, source string) {
		if err := CheckReclaimSource(e, source); err != nil {
			if RuleOf(err) != RuleReclaim {
				t.Fatalf("refusal names no rule: %v", err)
			}
			return
		}
		rest, ok := strings.CutPrefix(source, "10.0.0.9:/exports/vols/")
		parts := strings.Split(rest, "/")
		if !ok || len(parts) != 2 || !plainVolumeName(parts[0]) || !plainVolumeName(parts[1]) {
			t.Fatalf("%q passed", source)
		}
	})
}
