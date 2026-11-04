package tap

import (
	"errors"
	"strings"
	"testing"
)

type fakeNAT struct {
	rules     []string
	existsErr error
	appendErr error
}

func (f *fakeNAT) Exists(table, chain string, spec ...string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	want := table + "/" + chain + " " + strings.Join(spec, " ")
	for _, r := range f.rules {
		if r == want {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeNAT) Append(table, chain string, spec ...string) error {
	if f.appendErr != nil {
		return f.appendErr
	}
	f.rules = append(f.rules, table+"/"+chain+" "+strings.Join(spec, " "))
	return nil
}

func TestEnsureNAT(t *testing.T) {
	f := &fakeNAT{}
	for i := 0; i < 2; i++ {
		if err := EnsureNAT(f, "172.16.5.9/16"); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.rules) != 1 || f.rules[0] != "nat/POSTROUTING -s 172.16.0.0/16 ! -d 172.16.0.0/16 -m comment --comment aerolvm-fc-masq -j MASQUERADE" {
		t.Fatalf("rules = %v", f.rules)
	}
	for _, bad := range []string{"", "nope", "fd00::/64"} {
		if err := EnsureNAT(f, bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	if err := EnsureNAT(&fakeNAT{existsErr: errors.New("x")}, "10.0.0.0/8"); err == nil {
		t.Fatal("exists error")
	}
	if err := EnsureNAT(&fakeNAT{appendErr: errors.New("x")}, "10.0.0.0/8"); err == nil {
		t.Fatal("append error")
	}
}
