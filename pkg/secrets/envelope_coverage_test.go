package secrets

import (
	"errors"
	"testing"
)

func TestEnvelopeBindingAndInvalidSeals(t *testing.T) {
	if _, err := EnvelopeBinding(nil); err == nil {
		t.Fatal("empty payload must fail")
	}
	if _, err := EnvelopeBinding([]byte("{")); err == nil {
		t.Fatal("invalid json must fail")
	}
	if _, err := EnvelopeBinding([]byte(`{"version":4}`)); err == nil {
		t.Fatal("missing payload must fail")
	}
	if _, err := EnvelopeBinding([]byte(`{"version":3,"payload":"YQ=="}`)); err == nil {
		t.Fatal("unsupported version must fail")
	}
	if _, err := EnvelopeBinding([]byte(`{"version":4,"payload":"YQ=="}`)); err == nil {
		t.Fatal("incomplete binding must fail")
	}

	c := testCipher(t)
	binding := testBinding()
	sealed, err := SealEnvelopeBound(c, Secrets{Env: map[string]string{"K": "V"}}, []string{"node-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := EnvelopeBinding(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if fields.SandboxID != "sb-1" || fields.IncarnationID != "inc-1" || fields.Version != EnvelopeVersion || fields.Generation != 1 {
		t.Fatalf("binding = %+v", fields)
	}

	if _, err := SealEnvelopeBound(nil, Secrets{Env: map[string]string{"K": "V"}}, []string{"node-a"}, binding); err == nil {
		t.Fatal("nil cipher must fail")
	}
	if _, err := SealRawEnvelopeBound(nil, []byte("x"), []string{"node-a"}, binding); err == nil {
		t.Fatal("nil cipher raw seal must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"node-a"}, binding, nil); err == nil {
		t.Fatal("nil wrap must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), nil, binding, func([]byte) ([]byte, error) { return []byte("w"), nil }); err == nil {
		t.Fatal("empty recipients must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"*"}, binding, func([]byte) ([]byte, error) { return []byte("w"), nil }); err == nil {
		t.Fatal("wildcard recipient must fail")
	}
	badBind := binding
	badBind.Generation = 0
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"node-a"}, badBind, func([]byte) ([]byte, error) { return []byte("w"), nil }); err == nil {
		t.Fatal("invalid generation must fail")
	}
	if _, err := SealRawEnvelopeWrappedBound([]byte("x"), []string{"node-a"}, binding, func([]byte) ([]byte, error) {
		return nil, errors.New("wrap failed")
	}); err == nil {
		t.Fatal("wrap failure must surface")
	}

	if got, err := OpenEnvelopeBound(c, nil, "node-a", binding); err != nil || got.Env != nil {
		t.Fatalf("empty open = %+v %v", got, err)
	}
	if _, err := OpenEnvelopeBound(c, []byte("not-json"), "node-a", binding); err == nil {
		t.Fatal("bad open must fail")
	}
}
