package egresspolicy

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestUnion(t *testing.T) {
	got, err := Union([]string{"pypi.org", "10.0.0.0/8"}, []string{"PyPI.org", "*.github.com"}, []string{"github.com:22"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"pypi.org", "10.0.0.0/8", "*.github.com", "github.com:22"}; !slices.Equal(got, want) {
		t.Fatalf("Union = %v, want %v", got, want)
	}
	if got, err := Union(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty Union = %v, %v", got, err)
	}
	var big []string
	for i := 0; i <= MaxUnionHostnames; i++ {
		big = append(big, fmt.Sprintf("h%d.example.com", i))
	}
	if _, err := Union(nil, big[:MaxProfileHostnames], big[MaxProfileHostnames:]); !errors.Is(err, ErrInvalid) {
		t.Fatalf("over the union cap: err = %v", err)
	}
	if _, err := Union([]string{"bad host!"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad entry: err = %v", err)
	}
}

func TestValidateProfileRefs(t *testing.T) {
	for _, ok := range [][]string{nil, {"python-deps"}, {"org:bank-mirrors", "builtin:npm", "builtin:pypi@20261006", "a.b_c-1"}} {
		if err := ValidateProfileRefs(ok); err != nil {
			t.Fatalf("%v: %v", ok, err)
		}
	}
	tooMany := make([]string, MaxProfileRefs+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("p%d", i)
	}
	for _, bad := range [][]string{{"Upper"}, {"-lead"}, {"org:"}, {"builtin:@1"}, {"a", "a"}, {"builtin:pypi", "builtin:pypi@20261006"}, {"x:y"}, tooMany} {
		if err := ValidateProfileRefs(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%v: err = %v", bad, err)
		}
	}
	if err := ValidateProfileName("ok-name"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfileName("builtin:x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reserved prefix: %v", err)
	}
}
