package readyproto

import (
	"net"
	"strings"
	"testing"
)

func TestDecodeParkedFromOpenConn(t *testing.T) {
	// Regression: readLine must stop at '\n', not EOF. Persistent park sockets
	// stay open for the adopt frame after the parked hello.
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	done := make(chan error, 1)
	go func() {
		if err := EncodeParked(client, ParkedSignal{Token: "t", Nonce: "n"}); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	got, err := DecodeParked(server)
	if err != nil {
		t.Fatalf("decode parked: %v", err)
	}
	if got.Token != "t" || got.Nonce != "n" {
		t.Fatalf("got = %+v", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("encode parked: %v", err)
	}
}

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
