package ingressproxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBufferBodyCases(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		max     int64
		wantErr error
		wantLen int
	}{
		{name: "empty_body_under_cap", body: "", max: 16, wantLen: 0},
		{name: "exact_fit", body: "abcdefghij", max: 10, wantLen: 10},
		{name: "below_cap", body: "abc", max: 1024, wantLen: 3},
		{name: "over_cap_rejected", body: strings.Repeat("a", 17), max: 16, wantErr: errBodyTooLarge},
		{name: "zero_cap_rejected", body: "", max: 0, wantErr: errBodyTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := bufferBody(bytes.NewReader([]byte(tc.body)), tc.max)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(buf) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(buf), tc.wantLen)
			}
		})
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestBufferBodyPropagatesReadError(t *testing.T) {
	_, err := bufferBody(errorReader{}, 1024)
	if err == nil || errors.Is(err, errBodyTooLarge) {
		t.Fatalf("expected raw read error, got %v", err)
	}
}
