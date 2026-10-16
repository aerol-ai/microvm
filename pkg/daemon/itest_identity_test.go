package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/controlplane"
)

func TestITestStaticValidator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity")
	if err := os.WriteFile(path, []byte("# map\ntok-a acct-a\ntok-b  acct-b\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := loadITestIdentityFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	v := itestStaticValidator{tokens: tokens}
	for tok, want := range map[string]string{"tok-a": "acct-a", "tok-b": "acct-b"} {
		id, err := v.Validate(context.Background(), tok)
		if err != nil || id.OwnerRef != want {
			t.Fatalf("Validate(%q) = %+v, %v; want owner %q", tok, id, err, want)
		}
	}
	if _, err := v.Validate(context.Background(), "unknown"); !errors.Is(err, controlplane.ErrTokenRejected) {
		t.Fatalf("unknown token = %v, want ErrTokenRejected", err)
	}
	if _, err := v.Validate(context.Background(), ""); !errors.Is(err, controlplane.ErrTokenRejected) {
		t.Fatalf("empty token = %v, want ErrTokenRejected", err)
	}
	if _, err := loadITestIdentityFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file should error")
	}
}
