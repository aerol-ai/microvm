package readyproto

import (
	"strings"
	"testing"
)

func TestDecodeParkedRejectsBadEvents(t *testing.T) {
	cases := []string{
		`{"event":"ready","token":"t","nonce":"n"}`,
		`{"event":"parked","token":"","nonce":"n"}`,
		`{"event":"parked","token":"t","nonce":""}`,
	}
	for _, line := range cases {
		if _, err := DecodeParked(strings.NewReader(line + "\n")); err == nil {
			t.Fatalf("expected error for %q", line)
		}
	}
}

func TestDecodeAdoptRejectsBadEvents(t *testing.T) {
	cases := []string{
		`{"event":"parked","sandbox_id":"sb","token":"t","nonce":"n"}`,
		`{"event":"adopt","sandbox_id":"","token":"t","nonce":"n"}`,
		`{"event":"adopt","sandbox_id":"sb","token":"","nonce":"n"}`,
		`{"event":"adopt","sandbox_id":"sb","token":"t","nonce":""}`,
	}
	for _, line := range cases {
		if _, err := DecodeAdopt(strings.NewReader(line + "\n")); err == nil {
			t.Fatalf("expected error for %q", line)
		}
	}
}

func TestDecodeParkedOversizeLine(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes+1)
	_, err := DecodeParked(strings.NewReader(line))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize error, got %v", err)
	}
}

func TestEncodeParkedDefaultEvent(t *testing.T) {
	var buf strings.Builder
	if err := EncodeParked(&buf, ParkedSignal{Token: "t", Nonce: "n"}); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeParked(strings.NewReader(buf.String()))
	if err != nil || got.Event != EventParked {
		t.Fatalf("got = %+v err = %v", got, err)
	}
}

func TestEncodeAdoptDefaultEvent(t *testing.T) {
	var buf strings.Builder
	if err := EncodeAdopt(&buf, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n"}); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAdopt(strings.NewReader(buf.String()))
	if err != nil || got.Event != EventAdopt {
		t.Fatalf("got = %+v err = %v", got, err)
	}
}
