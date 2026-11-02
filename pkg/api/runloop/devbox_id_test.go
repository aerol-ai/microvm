package runloop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// ringDigester is RequestDigests over a bare Cipher: the server key of a
// node, without the rest of the service.
type ringDigester struct{ c *secrets.Cipher }

func (d ringDigester) RequestDigests(purpose string, data []byte) ([]secrets.KeyedDigest, error) {
	return d.c.Digests(purpose, data)
}

// stubDigester answers RequestDigests with fixed values.
type stubDigester struct {
	digests []secrets.KeyedDigest
	err     error
}

func (d stubDigester) RequestDigests(string, []byte) ([]secrets.KeyedDigest, error) {
	return d.digests, d.err
}

func idKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func idRing(t *testing.T, keys ...secrets.RingKey) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipherRing(keys)
	if err != nil {
		t.Fatalf("NewCipherRing: %v", err)
	}
	return c
}

func mustDevboxIDs(t *testing.T, d requestDigester, owner, requestID, body string, withLegacy bool) devboxIDs {
	t.Helper()
	ids, err := devboxIDsForRequest(d, owner, requestID, []byte(body), withLegacy)
	if err != nil {
		t.Fatalf("devboxIDsForRequest: %v", err)
	}
	return ids
}

// legacyDevboxID is the id servers before keyed ids derived: "sb-" and the
// first 64 bits of a plain SHA-256. Kept here, verbatim, to prove the
// upgrade lookup finds what they made.
func legacyDevboxID(ownerRef, requestID, body string) string {
	h := sha256.New()
	h.Write([]byte("runloop.create\x00"))
	h.Write([]byte(ownerRef))
	h.Write([]byte{0})
	h.Write([]byte(requestID))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return "sb-" + hex.EncodeToString(h.Sum(nil)[:8])
}

// devboxID is the id a create with this owner, x-request-id and body gets
// on env's server.
func (e *testEnv) devboxID(t *testing.T, owner, requestID, body string) string {
	t.Helper()
	return mustDevboxIDs(t, e.svc, owner, requestID, body, false).current
}

var devboxIDShape = regexp.MustCompile(`^sb-[0-9a-f]{16}$`)

// The devbox id is public and the body it is derived from carries env
// values, so it must be keyed: the same on every node holding the server
// key, different for any other input, and not the plain hash older servers
// used, which anyone knowing the request id could test guesses against.
func TestDevboxIDsAreKeyedAndStable(t *testing.T) {
	const owner, requestID = "acme", "req-1"
	body := `{"name":"box","environment_variables":{"DB_PASSWORD":"hunter2"}}`
	key1 := secrets.RingKey{ID: 0, Key: idKey(1), Current: true}
	base := mustDevboxIDs(t, ringDigester{idRing(t, key1)}, owner, requestID, body, false)
	if !devboxIDShape.MatchString(base.current) || len(base.earlier) != 0 {
		t.Fatalf("ids = %+v, want one sb-<16 hex> id and nothing earlier", base)
	}
	if base.current == legacyDevboxID(owner, requestID, body) {
		t.Fatal("the id is the plain SHA-256 one")
	}
	if strings.Contains(base.current, "hunter2") {
		t.Fatal("the id holds its input")
	}

	for _, tc := range []struct {
		name      string
		key       []byte
		owner     string
		requestID string
		body      string
		same      bool
	}{
		{"the same create on another node or after a restart", idKey(1), owner, requestID, body, true},
		{"another env value", idKey(1), owner, requestID, strings.Replace(body, "hunter2", "hunter3", 1), false},
		{"another owner", idKey(1), "globex", requestID, body, false},
		{"another request id", idKey(1), owner, "req-2", body, false},
		{"another server key", idKey(2), owner, requestID, body, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustDevboxIDs(t, ringDigester{idRing(t, secrets.RingKey{ID: 0, Key: tc.key, Current: true})}, tc.owner, tc.requestID, tc.body, false)
			if (got.current == base.current) != tc.same {
				t.Fatalf("id = %s, base %s: same = %v, want %v", got.current, base.current, got.current == base.current, tc.same)
			}
		})
	}
}

// A rotation in progress holds two keys: the current key's id is the one a
// create makes, the other's is looked up, so a retry across the promote
// still finds the devbox the first attempt made.
func TestDevboxIDsAcrossAKeyRotation(t *testing.T) {
	const owner, requestID, body = "acme", "req-1", `{"name":"box"}`
	c := idRing(t, secrets.RingKey{ID: 0, Key: idKey(1), Current: true})
	d := ringDigester{c}
	before := mustDevboxIDs(t, d, owner, requestID, body, false)

	steps := []struct {
		name string
		ring []secrets.RingKey
		want func(staged devboxIDs) devboxIDs
	}{
		{"stage key 1: key 0 stays current", []secrets.RingKey{{ID: 0, Current: true}, {ID: 1, Key: idKey(2)}},
			func(devboxIDs) devboxIDs { return before }},
		{"promote key 1: key 0's id is looked up", []secrets.RingKey{{ID: 0}, {ID: 1, Current: true}},
			func(staged devboxIDs) devboxIDs {
				return devboxIDs{current: staged.earlier[0], earlier: []string{before.current}}
			}},
		{"retire key 0: nothing earlier", []secrets.RingKey{{ID: 1, Current: true}},
			func(staged devboxIDs) devboxIDs { return devboxIDs{current: staged.earlier[0]} }},
	}
	var staged devboxIDs
	for i, step := range steps {
		if err := c.SetRing(step.ring); err != nil {
			t.Fatalf("%s: SetRing: %v", step.name, err)
		}
		got := mustDevboxIDs(t, d, owner, requestID, body, false)
		if i == 0 {
			staged = got
			if len(got.earlier) != 1 || got.current != before.current || got.earlier[0] == before.current {
				t.Fatalf("%s: ids = %+v", step.name, got)
			}
			continue
		}
		want := step.want(staged)
		if got.current != want.current || strings.Join(got.earlier, ",") != strings.Join(want.earlier, ",") {
			t.Fatalf("%s: ids = %+v, want %+v", step.name, got, want)
		}
	}
}

// For a while after start a create also looks for the id older servers
// derived, which must be exactly theirs; after that it is not computed.
func TestDevboxIDsLegacyOnlyInTheWindow(t *testing.T) {
	const owner, requestID, body = "acme", "req-1", `{"environment_variables":{"K":"v"}}`
	d := ringDigester{idRing(t, secrets.RingKey{ID: 0, Key: idKey(1), Current: true})}
	legacy := legacyDevboxID(owner, requestID, body)
	for _, tc := range []struct {
		name       string
		withLegacy bool
		want       []string
	}{
		{"inside the window", true, []string{legacy}},
		{"after the window", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mustDevboxIDs(t, d, owner, requestID, body, tc.withLegacy)
			if strings.Join(got.earlier, ",") != strings.Join(tc.want, ",") || got.current == legacy {
				t.Fatalf("ids = %+v, want earlier %v", got, tc.want)
			}
		})
	}
}

// Without a usable server key there is no id to derive: the create is
// refused, never given a plain-hash id.
func TestDevboxIDsNeedTheServerKey(t *testing.T) {
	revoked := idRing(t, secrets.RingKey{ID: 0, Key: idKey(1), Current: true})
	revoked.Revoke()
	for _, tc := range []struct {
		name    string
		d       requestDigester
		wantErr error
	}{
		{"no digester", nil, nil},
		{"a service without a server key", (*service.Service)(nil), nil},
		{"a revoked key", ringDigester{revoked}, secrets.ErrKeyRevoked},
		{"an empty ring", stubDigester{}, nil},
		{"a failing digest", stubDigester{err: errors.New("boom")}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ids, err := devboxIDsForRequest(tc.d, "acme", "req-1", []byte(`{}`), true)
			if err == nil || ids.current != "" || len(ids.earlier) != 0 {
				t.Fatalf("ids = %+v, err = %v, want an error and no id", ids, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func createWithRequestID(t *testing.T, env *testEnv, body, requestID string) devboxView {
	t.Helper()
	var view devboxView
	expectStatus(t, env.do(t, http.MethodPost, "", body, &view, "X-Request-Id", requestID), http.StatusOK)
	return view
}

// The same x-request-id and body is one devbox; another env value under a
// pinned x-request-id is another devbox, and neither id is the plain hash.
func TestCreateIDIsKeyedPerRequest(t *testing.T) {
	env := newTestEnv(t)
	first := `{"name":"a","environment_variables":{"API_KEY":"sk-1"}}`
	second := `{"name":"a","environment_variables":{"API_KEY":"sk-2"}}`
	a := createWithRequestID(t, env, first, "req-pinned")
	again := createWithRequestID(t, env, first, "req-pinned")
	b := createWithRequestID(t, env, second, "req-pinned")
	if a.ID != again.ID || a.ID == b.ID || env.runtime.creates != 2 {
		t.Fatalf("ids %s, %s, %s with %d runtime creates; want the retry on the first and a new devbox for the new env", a.ID, again.ID, b.ID, env.runtime.creates)
	}
	if a.ID != env.devboxID(t, "", "req-pinned", first) || a.ID == legacyDevboxID("", "req-pinned", first) {
		t.Fatalf("id %s is not the keyed id", a.ID)
	}
}

// An upgrade restarts the server between a create and its retry: the
// devbox the old server made under the unkeyed id is the answer for as long
// as the window lasts, and only then does a retry make a new one.
func TestCreateFindsTheUnkeyedIDAfterUpgrade(t *testing.T) {
	const requestID = "req-upgrade"
	body := `{"name":"legacy","environment_variables":{"API_KEY":"sk-1"}}`
	for _, tc := range []struct {
		name        string
		windowOpen  bool
		wantLegacy  bool
		wantCreates int
	}{
		{"inside the window the retry gets the old devbox", true, true, 1},
		{"after the window the retry makes a new one", false, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			legacy := legacyDevboxID("", requestID, body)
			if _, err := env.h.runCreate(context.Background(), models.CreateSandboxRequest{Image: defaultImage}, "", legacy, devboxBlob{Name: "legacy"}); err != nil {
				t.Fatalf("make the old server's devbox: %v", err)
			}
			if !tc.windowOpen {
				env.h.legacyDevboxIDsUntil = time.Now().Add(-time.Second)
			}
			got := createWithRequestID(t, env, body, requestID)
			if (got.ID == legacy) != tc.wantLegacy || env.runtime.creates != tc.wantCreates {
				t.Fatalf("retry = %s (legacy %s) with %d runtime creates, want legacy=%v and %d", got.ID, legacy, env.runtime.creates, tc.wantLegacy, tc.wantCreates)
			}
			if !tc.wantLegacy && got.ID != env.devboxID(t, "", requestID, body) {
				t.Fatalf("new devbox %s is not under the keyed id", got.ID)
			}
		})
	}
}

// A retry that arrives while the old server's create is still in flight on
// this node joins it rather than start a second one.
func TestCreateJoinsAnInFlightCreateUnderAnEarlierID(t *testing.T) {
	env := newTestEnv(t)
	old := createHold
	createHold = 20 * time.Millisecond
	t.Cleanup(func() { createHold = old })

	const requestID, body = "req-inflight", `{"name":"slow"}`
	legacy := legacyDevboxID("", requestID, body)
	f, sandbox := stopCreateBetweenWrites(t, env, legacy, devboxBlob{Name: "slow"}, nil)
	got := createWithRequestID(t, env, body, requestID)
	if got.ID != legacy || got.Status != statusProvisioning || env.runtime.creates != 1 {
		t.Fatalf("retry = %+v with %d runtime creates, want the in-flight create %s", got, env.runtime.creates, legacy)
	}
	env.h.creates.finish(f, sandbox, nil)
}

// A key rotation between a create and its retry: while the ring holds the
// old key the retry finds the devbox made under it; once the old key is
// retired the id is free and a retry makes a new devbox.
func TestCreateAcrossAServerKeyRotation(t *testing.T) {
	env := newTestEnv(t)
	const requestID, body = "req-rotate", `{"name":"rot","environment_variables":{"API_KEY":"sk-1"}}`
	first := createWithRequestID(t, env, body, requestID)

	for _, step := range []struct {
		name        string
		ring        []secrets.RingKey
		wantFirst   bool
		wantCreates int
	}{
		{"staged", []secrets.RingKey{{ID: 0, Current: true}, {ID: 1, Key: idKey(7)}}, true, 1},
		{"promoted", []secrets.RingKey{{ID: 0}, {ID: 1, Current: true}}, true, 1},
		{"old key retired", []secrets.RingKey{{ID: 1, Current: true}}, false, 2},
	} {
		if err := env.cipher.SetRing(step.ring); err != nil {
			t.Fatalf("%s: SetRing: %v", step.name, err)
		}
		got := createWithRequestID(t, env, body, requestID)
		if (got.ID == first.ID) != step.wantFirst || env.runtime.creates != step.wantCreates {
			t.Fatalf("%s: retry = %s (first %s) with %d runtime creates, want first=%v and %d", step.name, got.ID, first.ID, env.runtime.creates, step.wantFirst, step.wantCreates)
		}
	}
}

// With the server key revoked a create that would need a keyed id is
// refused (503, retryable once the key is back) and nothing is created.
func TestCreateIsRefusedWithoutTheServerKey(t *testing.T) {
	env := newTestEnv(t)
	env.cipher.Revoke()
	rr := env.do(t, http.MethodPost, "", `{"name":"x","environment_variables":{"API_KEY":"sk-1"}}`, nil, "X-Request-Id", "req-revoked")
	expectStatus(t, rr, http.StatusServiceUnavailable)
	if env.runtime.creates != 0 {
		t.Fatalf("the runtime was asked to create %d devboxes", env.runtime.creates)
	}
}
