package sandboxenv

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/cmd/toolboxd/loginshell"
)

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"nil", nil, true},
		{"plain", map[string]string{"A": "1", "B_2": "x=y"}, true},
		{"empty value", map[string]string{"A": ""}, true},
		{"empty key", map[string]string{"": "v"}, false},
		{"key with equals", map[string]string{"A=B": "v"}, false},
		{"key with NUL", map[string]string{"A\x00": "v"}, false},
		{"value with NUL", map[string]string{"A": "v\x00w"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.env)
			if (err == nil) != tc.ok {
				t.Fatalf("Validate = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate error %v is not ErrInvalid", err)
			}
		})
	}
}

// The error must not carry the offending key or value: a secret pasted into
// the key field ("TOKEN=s3cr3t") would otherwise reach the host's logs.
func TestValidateErrorNamesNoKeyOrValue(t *testing.T) {
	const canary = "canary-7f3a"
	for _, env := range []map[string]string{
		{"TOKEN=" + canary: "v"},
		{"K": canary + "\x00"},
	} {
		err := Validate(env)
		if err == nil || strings.Contains(err.Error(), canary) {
			t.Fatalf("Validate(%q) = %v; want an error that does not quote the input", env, err)
		}
	}
}

func TestReplaceConvergesAndReplaces(t *testing.T) {
	var s Store
	if s.Len() != 0 {
		t.Fatalf("zero store Len = %d", s.Len())
	}
	env := map[string]string{"A": "1", "B": "2"}
	for i, want := range []bool{true, false, false} {
		changed, err := s.Replace(env)
		if err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
		if changed != want {
			t.Fatalf("push %d changed = %v, want %v (a re-push of the same env must be a no-op)", i, changed, want)
		}
	}
	if got := s.Environ(nil); !slices.Equal(got, []string{"A=1", "B=2"}) {
		t.Fatalf("after re-push Environ = %v, want each key once", got)
	}

	// The caller's map is copied: mutating it later does not leak in.
	env["A"] = "mutated"
	if got := s.Environ(nil); !slices.Equal(got, []string{"A=1", "B=2"}) {
		t.Fatalf("store aliased the caller's map: %v", got)
	}

	// A different push replaces, it does not merge: B is gone.
	if changed, err := s.Replace(map[string]string{"A": "9"}); err != nil || !changed {
		t.Fatalf("replace = %v, %v", changed, err)
	}
	if got := s.Environ(nil); !slices.Equal(got, []string{"A=9"}) {
		t.Fatalf("Environ after replace = %v, want [A=9]", got)
	}

	// An invalid push is refused whole and leaves the store as it was.
	if _, err := s.Replace(map[string]string{"A": "1", "": "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid push err = %v", err)
	}
	if got := s.Environ(nil); !slices.Equal(got, []string{"A=9"}) {
		t.Fatalf("invalid push changed the store: %v", got)
	}

	// An empty push clears.
	if changed, err := s.Replace(map[string]string{}); err != nil || !changed {
		t.Fatalf("clear = %v, %v", changed, err)
	}
	if s.Len() != 0 {
		t.Fatalf("Len after clear = %d", s.Len())
	}
	if changed, _ := s.Replace(nil); changed {
		t.Fatal("clearing an empty store reported a change")
	}
}

func TestEnvironPrecedence(t *testing.T) {
	base := []string{"HOME=/root", "SECRET=image-default", "PATH=/usr/bin", loginshell.Env + "=/usr/bin", "NOEQUALS"}
	baseCopy := slices.Clone(base)

	var empty Store
	got := empty.Environ(base)
	if !slices.Equal(got, base) {
		t.Fatalf("empty store Environ = %v, want base unchanged", got)
	}
	got[0] = "x"
	if base[0] != "HOME=/root" {
		t.Fatal("empty store Environ returned base itself, not a copy")
	}

	for _, tc := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			name: "sandbox env overrides the image's and adds its own, each key once",
			env:  map[string]string{"SECRET": "from-create", "BANK": "x"},
			want: []string{"HOME=/root", "PATH=/usr/bin", loginshell.Env + "=/usr/bin", "NOEQUALS", "BANK=x", "SECRET=from-create"},
		},
		{
			name: "a sandbox PATH is also the PATH login shells put back",
			env:  map[string]string{"PATH": "/opt/bin:/usr/bin"},
			want: []string{"HOME=/root", "SECRET=image-default", "NOEQUALS", "PATH=/opt/bin:/usr/bin", loginshell.Env + "=/opt/bin:/usr/bin"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s Store
			if _, err := s.Replace(tc.env); err != nil {
				t.Fatal(err)
			}
			got := s.Environ(base)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("Environ =\n  %v\nwant\n  %v", got, tc.want)
			}
			if !slices.Equal(base, baseCopy) {
				t.Fatalf("Environ modified base: %v", base)
			}
		})
	}
}

// A reader racing a replace sees the old env or the new one, never a mix:
// the store swaps whole maps. Run under -race.
func TestReplaceIsAtomicForReaders(t *testing.T) {
	var s Store
	a := map[string]string{"K1": "a", "K2": "a"}
	b := map[string]string{"K1": "b", "K2": "b"}
	if _, err := s.Replace(a); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			env := a
			if i%2 == 0 {
				env = b
			}
			if _, err := s.Replace(env); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		got := s.Environ(nil)
		if len(got) != 2 || got[0][len(got[0])-1] != got[1][len(got[1])-1] {
			close(stop)
			wg.Wait()
			t.Fatalf("reader saw a half-applied env: %v", got)
		}
	}
	close(stop)
	wg.Wait()
}
