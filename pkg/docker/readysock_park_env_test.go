package docker

import (
	"bufio"
	"context"
	"maps"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// AdoptWithEnv hands the toolbox the env in the frame and accepts the ack
// only when its digest proves the toolbox applied exactly that env. An
// older agent drops the unknown field and acks without a digest; that must
// fail the adopt (the caller then destroys the slot and goes cold), or the
// sandbox would be served without its env.
func TestParkedListenerAdoptWithEnvChecksTheDigest(t *testing.T) {
	const canary = "canary-env-5e1f"
	env := map[string]string{"API_KEY": canary, "MODE": "prod"}
	for _, tc := range []struct {
		name    string
		env     map[string]string
		digest  func(frame readyproto.AdoptFrame) string // what the guest acks with
		wantErr bool
	}{
		{"agent applied the env", env, func(f readyproto.AdoptFrame) string { return readyproto.EnvDigest(f.Nonce, f.Env) }, false},
		{"older agent: no digest", env, func(readyproto.AdoptFrame) string { return "" }, true},
		{"digest over another env", env, func(f readyproto.AdoptFrame) string {
			return readyproto.EnvDigest(f.Nonce, map[string]string{"MODE": "prod"})
		}, true},
		{"digest under another nonce", env, func(f readyproto.AdoptFrame) string { return readyproto.EnvDigest("other", f.Env) }, true},
		{"garbage digest", env, func(readyproto.AdoptFrame) string { return "zz" }, true},
		{"env-less adopt, older agent", nil, func(readyproto.AdoptFrame) string { return "" }, false},
		{"env-less adopt, current agent", nil, func(f readyproto.AdoptFrame) string { return readyproto.EnvDigest(f.Nonce, nil) }, false},
		{"env-less adopt, wrong digest", nil, func(readyproto.AdoptFrame) string { return "zz" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pl, err := NewParkedListener(shortParkTestDir(t), "park-env", "boot", "park-n")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pl.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			got := make(chan readyproto.AdoptFrame, 1)
			go func() {
				conn, err := net.Dial("unix", pl.HostSocketPath())
				if err != nil {
					t.Errorf("dial: %v", err)
					return
				}
				defer conn.Close()
				if err := readyproto.EncodeParked(conn, readyproto.ParkedSignal{Token: "boot", Nonce: "park-n"}); err != nil {
					t.Errorf("parked: %v", err)
					return
				}
				frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
				if err != nil {
					t.Errorf("adopt read: %v", err)
					return
				}
				got <- frame
				_ = readyproto.Encode(conn, readyproto.ReadySignal{
					SandboxID: frame.SandboxID, Token: frame.Token, Nonce: frame.Nonce, EnvDigest: tc.digest(frame),
				})
			}()
			if err := pl.WaitParked(ctx); err != nil {
				t.Fatalf("WaitParked: %v", err)
			}
			err = pl.AdoptWithEnv(ctx, "sb-env", "sandbox-tok", "adopt-n", tc.env)
			if (err != nil) != tc.wantErr {
				t.Fatalf("AdoptWithEnv = %v, want error %v", err, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), canary) {
				t.Fatalf("the error quotes the env: %v", err)
			}
			frame := <-got
			if !maps.Equal(frame.Env, tc.env) || frame.SandboxID != "sb-env" || frame.Nonce != "adopt-n" {
				t.Fatalf("the toolbox was sent %+v", frame)
			}
		})
	}
}

// An env the frame cannot carry is refused before anything is written, and
// the refusal names no value.
func TestParkedListenerAdoptWithEnvRefusesBadEnv(t *testing.T) {
	pl, err := NewParkedListener(shortParkTestDir(t), "park-bad-env", "boot", "park-n")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sent := make(chan int, 1)
	go func() {
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{Token: "boot", Nonce: "park-n"})
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		sent <- n
	}()
	if err := pl.WaitParked(ctx); err != nil {
		t.Fatal(err)
	}
	err = pl.AdoptWithEnv(ctx, "sb", "tok", "n", map[string]string{"K": "canary-x\x00"})
	if err == nil || strings.Contains(err.Error(), "canary-x") {
		t.Fatalf("AdoptWithEnv = %v", err)
	}
	if n := <-sent; n != 0 {
		t.Fatalf("the guest received %d bytes of a frame that should not have been sent", n)
	}
}
