package toolhost

import (
	"reflect"
	"testing"
)

func TestSplitShellWords(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "", want: nil},
		{in: "   \t\n ", want: nil},
		{in: "python -c 'print(1 + 2)'", want: []string{"python", "-c", "print(1 + 2)"}},
		{in: `echo "a b" c`, want: []string{"echo", "a b", "c"}},
		{in: `a"b c"d`, want: []string{"ab cd"}},
		{in: `x '' ""`, want: []string{"x", "", ""}},
		{in: `say "\$HOME \"q\" \\ \x"`, want: []string{"say", `$HOME "q" \ \x`}},
		{in: "say \"one\\\ntwo\"", want: []string{"say", "onetwo"}},
		{in: `a\ b c\'d`, want: []string{"a b", "c'd"}},
		{in: "a\\\nb", want: []string{"ab"}},
		{in: `'it''s'`, want: []string{"its"}},
		{in: `'no \escape'`, want: []string{`no \escape`}},
		// No shell: operators are plain words.
		{in: "ls | grep x > out", want: []string{"ls", "|", "grep", "x", ">", "out"}},
		{in: "naïve 'ünïcode'", want: []string{"naïve", "ünïcode"}},
		{in: `'open`, wantErr: true},
		{in: `"open`, wantErr: true},
		{in: `"ends with \"`, wantErr: true},
		{in: `trailing\`, wantErr: true},
	}
	for _, tc := range cases {
		got, err := splitShellWords(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q: no error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%q = %q %v, want %q", tc.in, got, err, tc.want)
		}
	}
}
