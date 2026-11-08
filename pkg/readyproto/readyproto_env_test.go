package readyproto

import (
	"bytes"
	"errors"
	"maps"
	"strings"
	"testing"
)

// The canary stands in for a secret: no error the protocol returns may
// carry it, since callers on both ends log these errors.
const envCanary = "canary-s3cr3t-9b1d"

func TestAdoptFrameEnvRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"nil", nil},
		{"plain", map[string]string{"A": "1", "B_2": "two"}},
		{"empty value", map[string]string{"EMPTY": ""}},
		{"value with separators", map[string]string{"DSN": "postgres://u:p@h/db?x=1&y=2", "MULTI": "line1\nline2\r\n\ttab"}},
		{"json and html metacharacters", map[string]string{"Q": `"quoted" \back\slash <tag> & amp`}},
		{"unicode", map[string]string{"GREETING": "héllo wörld ✓", "LS": "a b"}},
		{"many keys", func() map[string]string {
			m := map[string]string{}
			for i := range 500 {
				m["K_"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('A'+i/26))] = strings.Repeat("v", i)
			}
			return m
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			want := AdoptFrame{SandboxID: "sb-env", Token: "tok", Nonce: "n-1", Env: tc.env}
			if err := EncodeAdopt(&buf, want); err != nil {
				t.Fatalf("EncodeAdopt: %v", err)
			}
			got, err := DecodeAdopt(&buf)
			if err != nil {
				t.Fatalf("DecodeAdopt: %v", err)
			}
			if got.SandboxID != want.SandboxID || got.Token != want.Token || got.Nonce != want.Nonce || got.Event != EventAdopt {
				t.Fatalf("identity = %+v", got)
			}
			if !maps.Equal(got.Env, tc.env) {
				t.Fatalf("env did not round-trip: got %d keys, want %d", len(got.Env), len(tc.env))
			}
		})
	}
}

// An env-less adopt must be the bytes an older agent has always read, and
// a frame from an older host (no env field) must decode to an empty env.
func TestAdoptFrameWithoutEnvIsUnchangedOnTheWire(t *testing.T) {
	var buf bytes.Buffer
	if err := EncodeAdopt(&buf, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n"}`+"\n"; got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
	frame, err := DecodeAdopt(strings.NewReader(`{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n"}` + "\n"))
	if err != nil || len(frame.Env) != 0 {
		t.Fatalf("old frame = %+v, %v", frame, err)
	}
	// And an ack from an older agent decodes with no digest.
	sig, err := Decode(strings.NewReader(`{"event":"ready","sandbox_id":"sb","token":"t","nonce":"n"}` + "\n"))
	if err != nil || sig.EnvDigest != "" {
		t.Fatalf("old ack = %+v, %v", sig, err)
	}
}

func TestReadyAckCarriesEnvDigest(t *testing.T) {
	var buf bytes.Buffer
	digest := EnvDigest("n", map[string]string{"A": "1"})
	if err := Encode(&buf, ReadySignal{SandboxID: "sb", Token: "t", Nonce: "n", EnvDigest: digest}); err != nil {
		t.Fatal(err)
	}
	sig, err := Decode(&buf)
	if err != nil || sig.EnvDigest != digest {
		t.Fatalf("ack = %+v, %v", sig, err)
	}
}

// The larger cap is the adopt frame's alone: the host reads the parked
// hello and the ready ack, which a guest controls, under the 4 KiB cap.
func TestLargerLimitAppliesToAdoptFramesOnly(t *testing.T) {
	big := strings.Repeat("v", 100<<10)
	t.Run("adopt frame well over 4 KiB round-trips", func(t *testing.T) {
		var buf bytes.Buffer
		if err := EncodeAdopt(&buf, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: map[string]string{"BIG": big}}); err != nil {
			t.Fatalf("EncodeAdopt: %v", err)
		}
		if buf.Len() <= MaxLineBytes {
			t.Fatalf("setup: frame is only %d bytes", buf.Len())
		}
		got, err := DecodeAdopt(&buf)
		if err != nil || got.Env["BIG"] != big {
			t.Fatalf("DecodeAdopt: %v", err)
		}
	})
	t.Run("ready line of the same size is refused", func(t *testing.T) {
		line := `{"event":"ready","sandbox_id":"sb","token":"t","nonce":"n","agent_version":"` + big + `"}` + "\n"
		if _, err := Decode(strings.NewReader(line)); err == nil || !strings.Contains(err.Error(), "exceeds 4096") {
			t.Fatalf("Decode = %v, want the 4 KiB cap", err)
		}
		if err := Encode(&bytes.Buffer{}, ReadySignal{SandboxID: "sb", Token: "t", Nonce: "n", AgentVersion: big}); err == nil {
			t.Fatal("Encode of an oversize ready line succeeded")
		}
	})
	t.Run("parked line of the same size is refused", func(t *testing.T) {
		line := `{"event":"parked","token":"t","nonce":"n","agent_version":"` + big + `"}` + "\n"
		if _, err := DecodeParked(strings.NewReader(line)); err == nil || !strings.Contains(err.Error(), "exceeds 4096") {
			t.Fatalf("DecodeParked = %v, want the 4 KiB cap", err)
		}
	})
	t.Run("adopt frame over its own cap is refused both ways", func(t *testing.T) {
		huge := map[string]string{"HUGE": strings.Repeat("v", MaxAdoptLineBytes)}
		if err := EncodeAdopt(&bytes.Buffer{}, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: huge}); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("EncodeAdopt = %v", err)
		}
		line := `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":{"HUGE":"` + huge["HUGE"] + `"}}` + "\n"
		if _, err := DecodeAdopt(strings.NewReader(line)); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("DecodeAdopt = %v", err)
		}
	})
}

func TestAdoptEnvEntriesRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		wire string // the env object as a peer could send it
	}{
		{"empty key", map[string]string{"": "v"}, `{"":"v"}`},
		{"key with equals", map[string]string{"A=B": "v"}, `{"A=B":"v"}`},
		{"NUL in key", map[string]string{"A\x00": "v"}, `{"A\u0000":"v"}`},
		{"NUL in value", map[string]string{"A": "v\x00w"}, `{"A":"v\u0000w"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := EncodeAdopt(&bytes.Buffer{}, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: tc.env})
			if !errors.Is(err, ErrEnvInvalid) {
				t.Fatalf("EncodeAdopt = %v, want ErrEnvInvalid", err)
			}
			if err := ValidateAdoptEnv(tc.env); !errors.Is(err, ErrEnvInvalid) {
				t.Fatalf("ValidateAdoptEnv = %v, want ErrEnvInvalid", err)
			}
			line := `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":` + tc.wire + "}\n"
			if _, err := DecodeAdopt(strings.NewReader(line)); !errors.Is(err, ErrEnvInvalid) {
				t.Fatalf("DecodeAdopt = %v, want ErrEnvInvalid", err)
			}
		})
	}
	// Bytes JSON cannot carry unchanged never leave the host.
	if err := ValidateAdoptEnv(map[string]string{"A": "\xff\xfe"}); !errors.Is(err, ErrEnvInvalid) {
		t.Fatalf("invalid UTF-8 value: %v", err)
	}
	if err := ValidateAdoptEnv(map[string]string{"\xff": "v"}); !errors.Is(err, ErrEnvInvalid) {
		t.Fatalf("invalid UTF-8 key: %v", err)
	}
}

func TestValidateAdoptEnvSize(t *testing.T) {
	// {"K":"<n bytes>"} is n+8 bytes encoded.
	fits := map[string]string{"K": strings.Repeat("v", MaxAdoptEnvBytes-8)}
	over := map[string]string{"K": strings.Repeat("v", MaxAdoptEnvBytes-7)}
	if err := ValidateAdoptEnv(nil); err != nil {
		t.Fatalf("nil env: %v", err)
	}
	if err := ValidateAdoptEnv(fits); err != nil {
		t.Fatalf("env at the limit: %v", err)
	}
	if err := ValidateAdoptEnv(over); !errors.Is(err, ErrEnvTooLarge) {
		t.Fatalf("env one byte over: %v", err)
	}
	// An env at the limit still leaves room for the identity fields.
	if err := EncodeAdopt(&bytes.Buffer{}, AdoptFrame{SandboxID: strings.Repeat("s", 64), Token: strings.Repeat("t", 64), Nonce: strings.Repeat("n", 32), Env: fits}); err != nil {
		t.Fatalf("frame with an env at the limit: %v", err)
	}
	// The encoded size counts, not the raw one: encoding/json writes '<'
	// as six bytes, so a value whose raw size fits can still be too big.
	escaped := map[string]string{"K": strings.Repeat("<", MaxAdoptEnvBytes/2)}
	if err := ValidateAdoptEnv(escaped); !errors.Is(err, ErrEnvTooLarge) {
		t.Fatalf("escape-expanded env: %v", err)
	}
}

func TestEnvDigest(t *testing.T) {
	env := map[string]string{"A": "1", "B": "2", "C": ""}
	d := EnvDigest("nonce-1", env)
	if len(d) != 64 {
		t.Fatalf("digest %q is not hex SHA-256", d)
	}
	same := map[string]string{"C": "", "B": "2", "A": "1"}
	if EnvDigest("nonce-1", same) != d {
		t.Fatal("digest depends on map order")
	}
	for _, tc := range []struct {
		name  string
		nonce string
		env   map[string]string
	}{
		{"other nonce", "nonce-2", env},
		{"value changed", "nonce-1", map[string]string{"A": "1", "B": "3", "C": ""}},
		{"key dropped", "nonce-1", map[string]string{"A": "1", "B": "2"}},
		{"key added", "nonce-1", map[string]string{"A": "1", "B": "2", "C": "", "D": ""}},
		{"boundary moved", "nonce-1", map[string]string{"A": "1B=2", "C": ""}},
		{"empty env", "nonce-1", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if EnvDigest(tc.nonce, tc.env) == d {
				t.Fatal("different input, same digest")
			}
			if EnvDigestMatches("nonce-1", env, EnvDigest(tc.nonce, tc.env)) {
				t.Fatal("EnvDigestMatches accepted another input's digest")
			}
		})
	}
	if !EnvDigestMatches("nonce-1", env, d) {
		t.Fatal("EnvDigestMatches refused the right digest")
	}
	if EnvDigestMatches("nonce-1", nil, "") || EnvDigestMatches("nonce-1", env, "") {
		t.Fatal("an empty digest matched")
	}
	if strings.Contains(EnvDigest("n", map[string]string{"K": envCanary}), envCanary) {
		t.Fatal("digest carries the value")
	}
}

// No error either end returns names a key or a value: toolboxd logs a
// failed handshake, and sandboxd logs a failed adopt before it goes cold.
func TestEnvErrorsNeverQuoteKeysOrValues(t *testing.T) {
	frame := func(env string) string {
		return `{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":` + env + "}\n"
	}
	errs := map[string]error{}
	errs["encode: NUL in value"] = EncodeAdopt(&bytes.Buffer{}, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: map[string]string{"K": envCanary + "\x00"}})
	errs["encode: secret in key"] = EncodeAdopt(&bytes.Buffer{}, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: map[string]string{"TOKEN=" + envCanary: "v"}})
	errs["encode: too big"] = EncodeAdopt(&bytes.Buffer{}, AdoptFrame{SandboxID: "sb", Token: "t", Nonce: "n", Env: map[string]string{"K": envCanary + strings.Repeat("v", MaxAdoptLineBytes)}})
	errs["validate: too big"] = ValidateAdoptEnv(map[string]string{"K": envCanary + strings.Repeat("v", MaxAdoptEnvBytes)})
	errs["validate: bad UTF-8"] = ValidateAdoptEnv(map[string]string{"K": envCanary + "\xff"})
	_, errs["decode: NUL in value"] = DecodeAdopt(strings.NewReader(frame(`{"K":"` + envCanary + `\u0000"}`)))
	_, errs["decode: secret in key"] = DecodeAdopt(strings.NewReader(frame(`{"TOKEN=` + envCanary + `":"v"}`)))
	_, errs["decode: syntax error inside a value"] = DecodeAdopt(strings.NewReader(frame(`{"K":"` + envCanary + "\x01" + `"}`)))
	_, errs["decode: truncated"] = DecodeAdopt(strings.NewReader(`{"event":"adopt","sandbox_id":"sb","token":"t","nonce":"n","env":{"K":"` + envCanary))
	_, errs["decode: wrong type"] = DecodeAdopt(strings.NewReader(frame(`{"K":["` + envCanary + `"]}`)))
	_, errs["decode: too big"] = DecodeAdopt(strings.NewReader(frame(`{"K":"` + envCanary + strings.Repeat("v", MaxAdoptLineBytes) + `"}`)))
	for name, err := range errs {
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if strings.Contains(err.Error(), envCanary) || strings.Contains(err.Error(), "TOKEN") {
			t.Errorf("%s: error quotes the input: %v", name, err)
		}
	}
}

// infiniteReader never sends a newline and counts what it hands out.
type infiniteReader struct{ n int }

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	r.n += len(p)
	return len(p), nil
}

// The cap bounds what is read, not only what is accepted: a peer that never
// sends a newline must not grow the buffer past the limit.
func TestReadLineStopsAtTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		read  func(*infiniteReader) error
		limit int
	}{
		{"host-side line", func(r *infiniteReader) error { _, err := DecodeParked(r); return err }, MaxLineBytes},
		{"adopt frame", func(r *infiniteReader) error { _, err := DecodeAdopt(r); return err }, MaxAdoptLineBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &infiniteReader{}
			if err := tc.read(r); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("err = %v", err)
			}
			if r.n > tc.limit+2*4096 {
				t.Fatalf("read %d bytes for a %d-byte limit", r.n, tc.limit)
			}
		})
	}
}
