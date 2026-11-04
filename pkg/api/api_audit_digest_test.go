package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// newExecDigestKey is a one-key server key ring whose key is 32 bytes of b.
func newExecDigestKey(t *testing.T, b byte) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipherRing([]secrets.RingKey{{ID: 0, Key: bytes.Repeat([]byte{b}, 32), Current: true}})
	if err != nil {
		t.Fatalf("NewCipherRing: %v", err)
	}
	return c
}

// cipherDigester is RequestDigests over a bare Cipher: one node's server
// key without the rest of the service.
type cipherDigester struct{ c *secrets.Cipher }

func (d cipherDigester) RequestDigests(purpose string, data []byte) ([]secrets.KeyedDigest, error) {
	return d.c.Digests(purpose, data)
}

// fixedDigester answers RequestDigests with fixed values.
type fixedDigester struct {
	digests []secrets.KeyedDigest
	err     error
}

func (d fixedDigester) RequestDigests(string, []byte) ([]secrets.KeyedDigest, error) {
	return d.digests, d.err
}

// streamedDigest is what an exec record says about body, hashed as a
// handler would read it, under k.
func streamedDigest(t *testing.T, k bodyDigester, body string) string {
	t.Helper()
	d := newDigestBody(io.NopCloser(strings.NewReader(body)), nil, false)
	if _, err := io.Copy(io.Discard, d); err != nil {
		t.Fatal(err)
	}
	return d.digest(k)
}

func mustExecDigest(t *testing.T, c *secrets.Cipher, body string) string {
	t.Helper()
	got := streamedDigest(t, cipherDigester{c}, body)
	if got == "" {
		t.Fatal("no digest")
	}
	return got
}

var keyedDigestShape = regexp.MustCompile(`^hmac:[0-9]+:[0-9a-f]{64}$`)

// The exec digest is keyed: the same body gives the same digest on every
// node holding the server key, so identical calls still correlate (and
// coalesce), while any other body or key gives another digest, and nothing
// in it lets a reader of the audit log test a guessed env value offline.
func TestExecDigestIsKeyed(t *testing.T) {
	body := `{"command":"deploy","env":{"DB_PASSWORD":"hunter2"}}`
	base := mustExecDigest(t, newExecDigestKey(t, 1), body)
	if !keyedDigestShape.MatchString(base) || !strings.HasPrefix(base, "hmac:0:") {
		t.Fatalf("digest = %q, want hmac:0:<64 hex>", base)
	}
	plain := sha256.Sum256([]byte(body))
	if strings.Contains(base, hex.EncodeToString(plain[:])) || strings.Contains(base, "hunter2") {
		t.Fatalf("digest %q holds the plain hash or the input", base)
	}

	for _, tc := range []struct {
		name string
		key  byte
		body string
		same bool
	}{
		{"the same body on another node or after a restart", 1, body, true},
		{"another env value", 1, strings.Replace(body, "hunter2", "hunter3", 1), false},
		{"another command", 1, strings.Replace(body, "deploy", "rollback", 1), false},
		{"another server key", 2, body, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustExecDigest(t, newExecDigestKey(t, tc.key), tc.body)
			if (got == base) != tc.same {
				t.Fatalf("digest = %s, base %s: same = %v, want %v", got, base, got == base, tc.same)
			}
		})
	}
}

// A rotation changes the digest only when the new key is promoted, and the
// record names the key, so a reader can tell two epochs of one command
// apart from two commands.
func TestExecDigestFollowsTheCurrentKey(t *testing.T) {
	const body = `{"command":"deploy"}`
	c := newExecDigestKey(t, 1)
	before := mustExecDigest(t, c, body)
	for _, step := range []struct {
		name       string
		ring       []secrets.RingKey
		wantPrefix string
		wantSame   bool
	}{
		{"staged: key 0 stays current", []secrets.RingKey{{ID: 0, Current: true}, {ID: 1, Key: bytes.Repeat([]byte{2}, 32)}}, "hmac:0:", true},
		{"promoted: key 1", []secrets.RingKey{{ID: 0}, {ID: 1, Current: true}}, "hmac:1:", false},
		{"key 0 retired", []secrets.RingKey{{ID: 1, Current: true}}, "hmac:1:", false},
	} {
		if err := c.SetRing(step.ring); err != nil {
			t.Fatalf("%s: SetRing: %v", step.name, err)
		}
		got := mustExecDigest(t, c, body)
		if !strings.HasPrefix(got, step.wantPrefix) || (got == before) != step.wantSame {
			t.Fatalf("%s: digest = %s (before %s), want prefix %s and same=%v", step.name, got, before, step.wantPrefix, step.wantSame)
		}
	}
}

// With no usable key the digest is absent, never an unkeyed one.
func TestExecDigestWithoutAKeyIsEmpty(t *testing.T) {
	revoked := newExecDigestKey(t, 1)
	revoked.Revoke()
	for _, tc := range []struct {
		name string
		k    bodyDigester
	}{
		{"no digester", nil},
		{"a service without a server key", (*service.Service)(nil)},
		{"a revoked key", cipherDigester{revoked}},
		{"an empty ring", fixedDigester{}},
		{"a failing digest", fixedDigester{err: errors.New("boom")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamedDigest(t, tc.k, `{"command":"deploy"}`); got != "" {
				t.Fatalf("digest = %q, want none", got)
			}
		})
	}
}

// Records written before keyed digests keep the plain SHA-256 they were
// written with: nothing rewrites them, and a chain that holds both kinds
// verifies; editing either digest breaks it.
func TestAChainWithOldAndKeyedExecDigestsVerifies(t *testing.T) {
	plain := sha256.Sum256([]byte(`{"command":"deploy"}`))
	keyed := mustExecDigest(t, newExecDigestKey(t, 1), `{"command":"deploy"}`)
	chain := func() []auditlog.Event {
		var evs []auditlog.Event
		prev := auditlog.GenesisPrevHash
		for i, digest := range []string{hex.EncodeToString(plain[:]), keyed} {
			ev := auditlog.Event{EventID: string(rune('a' + i)), Kind: auditlog.KindAPI, Ref: "POST /v1/sandboxes/{id}/exec", Result: auditlog.APIResultOK,
				Request: &auditlog.Request{Method: "POST", Route: "/v1/sandboxes/{id}/exec", Status: 200, Digest: digest}}
			auditlog.LinkEvent(prev, &ev)
			prev = ev.EventHash
			evs = append(evs, ev)
		}
		return evs
	}
	verify := func(evs []auditlog.Event) error {
		v := auditlog.NewChainVerifier()
		for _, ev := range evs {
			if err := v.Add(ev); err != nil {
				return err
			}
		}
		return nil
	}
	if err := verify(chain()); err != nil {
		t.Fatalf("a chain with an old and a keyed digest: %v", err)
	}
	for i := range 2 {
		evs := chain()
		edited := *evs[i].Request
		edited.Digest += "0"
		evs[i].Request = &edited
		if verify(evs) == nil {
			t.Fatalf("an edited digest in record %d still verifies", i)
		}
	}
}
