package models

import "testing"

func TestValidRuntime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// Empty input is *not* an error — the caller (service layer) is
		// expected to substitute the host default. The function's job is to
		// reject *unknown* values, not to enforce that one was supplied.
		{name: "empty_passes_through", input: "", want: ""},
		{name: "runc_accepted", input: "runc", want: "runc"},
		{name: "runsc_accepted", input: "runsc", want: "runsc"},
		{name: "kata_rejected", input: "kata", wantErr: true},
		{name: "case_sensitive", input: "RunC", wantErr: true},
		{name: "whitespace_rejected", input: " runsc ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidRuntime(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got nil (got=%q)", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
