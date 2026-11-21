package privmode

import (
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestParse(t *testing.T) {
	for raw, want := range map[string]Mode{"": Single, "single": Single, " Split ": Split, "SINGLE": Single, "split": Split} {
		if got, err := Parse(raw); err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"splt", "both", "root", "0", "true"} {
		if _, err := Parse(raw); err == nil || !strings.Contains(err.Error(), "SB_PRIVILEGE_MODE") {
			t.Errorf("Parse(%q) = %v, want an error naming the setting", raw, err)
		}
	}
}

func TestGap(t *testing.T) {
	if NotYet("create a sandbox") != nil {
		t.Fatal("no step, no gap")
	}
	err := NotYet("create a sandbox", StepImageUser, StepDiskQuota, Step("later"))
	if !errors.Is(err, ErrGap) || !errors.Is(err, models.ErrRuntimeNotImplemented) || errors.Is(err, errors.New("x")) {
		t.Fatalf("%v matches the wrong things", err)
	}
	msg := err.Error()
	for _, want := range []string{"create a sandbox", "image's users", "disk quota", "later", "SB_PRIVILEGE_MODE=single"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q lacks %q", msg, want)
		}
	}
	for s := range steps {
		if !strings.Contains(NotYet("x", s).Error(), steps[s]) {
			t.Errorf("step %s is not described", s)
		}
	}
}
