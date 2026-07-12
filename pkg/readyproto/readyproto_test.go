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

func TestEncodeDefaultReadyEvent(t *testing.T) {
	want := ReadySignal{
		SandboxID: "sb-abc-default",
		Token:     "tok-default",
		Nonce:     "nonce-default",
	}
	var buf bytes.Buffer
	if err := Encode(&buf, want); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(&buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want.Event = EventReady
	if got != want {
		t.Fatalf("round-trip = %+v, want %+v", got, want)
	}
}

func TestEncodeOversizeJSON(t *testing.T) {
	longToken := strings.Repeat("x", MaxLineBytes)
	err := Encode(&bytes.Buffer{}, ReadySignal{
		SandboxID: "sb",
		Token:     longToken,
		Nonce:     "n",
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize encode error, got %v", err)
	}
}

func TestDecodeOversizeLine(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes+1)
	_, err := Decode(strings.NewReader(line))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversize error, got %v", err)
	}
}

func TestDecodeNoTrailingNewline(t *testing.T) {
	line := `{"event":"ready","sandbox_id":"sb","token":"t","nonce":"n"}`
	got, err := Decode(strings.NewReader(line))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SandboxID != "sb" || got.Token != "t" || got.Nonce != "n" {
		t.Fatalf("got = %+v", got)
	}
}

func TestReadLineEmptyLine(t *testing.T) {
	_, err := readLine(strings.NewReader("\n"))
	if err == nil || !strings.Contains(err.Error(), "empty line") {
		t.Fatalf("expected empty line error, got %v", err)
	}
}

func TestReadLineOversizeRawNoNewline(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes+2)
	_, err := readLine(strings.NewReader(line))
	if err == nil || !strings.Contains(err.Error(), "line exceeds") {
		t.Fatalf("expected oversize raw line error, got %v", err)
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

func TestParkedAdoptRoundTrip(t *testing.T) {
	parked := ParkedSignal{
		Event:        EventParked,
		Token:        "park-tok",
		Nonce:        "park-nonce",
		AgentVersion: "1.0.0",
	}
	var buf bytes.Buffer
	if err := EncodeParked(&buf, parked); err != nil {
		t.Fatalf("encode parked: %v", err)
	}
	gotParked, err := DecodeParked(&buf)
	if err != nil {
		t.Fatalf("decode parked: %v", err)
	}
	if gotParked != parked {
		t.Fatalf("parked round-trip = %+v, want %+v", gotParked, parked)
	}

	adopt := AdoptFrame{
		Event:     EventAdopt,
		SandboxID: "sb-123",
		Token:     "adopt-tok",
		Nonce:     "adopt-nonce",
	}
	buf.Reset()
	if err := EncodeAdopt(&buf, adopt); err != nil {
		t.Fatalf("encode adopt: %v", err)
	}
	gotAdopt, err := DecodeAdopt(&buf)
	if err != nil {
		t.Fatalf("decode adopt: %v", err)
	}
	if gotAdopt != adopt {
		t.Fatalf("adopt round-trip = %+v, want %+v", gotAdopt, adopt)
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
