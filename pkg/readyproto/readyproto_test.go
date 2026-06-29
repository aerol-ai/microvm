package readyproto

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	want := ReadySignal{
		Event:        EventReady,
		SandboxID:    "sb-abc123",
		Token:        "tok-secret",
		Nonce:        "nonce-1",
		AgentVersion: "1.2.3",
	}
	var buf bytes.Buffer
	if err := Encode(&buf, want); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}
}

func TestDecodeOversizeLine(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes+1)
	_, err := Decode(strings.NewReader(line))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize error, got %v", err)
	}
}

func TestDecodeMalformedJSON(t *testing.T) {
	_, err := Decode(strings.NewReader("{not json}\n"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDecodeUnknownFieldsTolerated(t *testing.T) {
	line := `{"event":"ready","sandbox_id":"sb","token":"t","nonce":"n","extra":1}` + "\n"
	got, err := Decode(strings.NewReader(line))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SandboxID != "sb" || got.Nonce != "n" {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeRejectsEmptyValues(t *testing.T) {
	cases := []string{
		`{"event":"ready","sandbox_id":"","token":"t","nonce":"n"}`,
		`{"event":"ready","sandbox_id":"sb","token":"","nonce":"n"}`,
		`{"event":"ready","sandbox_id":"sb","token":"t","nonce":""}`,
		`{"event":"ping","sandbox_id":"sb","token":"t","nonce":"n"}`,
	}
	for _, line := range cases {
		if _, err := Decode(strings.NewReader(line + "\n")); err == nil {
			t.Fatalf("expected error for %q", line)
		}
	}
}
