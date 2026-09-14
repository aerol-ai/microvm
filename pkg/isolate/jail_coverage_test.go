package isolate

import (
	"os"
	"runtime"
	"testing"
)

func TestJailRealizable(t *testing.T) {
	got := JailRealizable()
	if runtime.GOOS != "linux" {
		if got {
			t.Fatal("non-linux host reported the jail as realizable")
		}
		return
	}
	// Linux is not enough: applyJail needs root. A non-root daemon must
	// not boot with jail_realizable=true and then fail every create.
	want := os.Geteuid() == 0
	if got != want {
		t.Fatalf("JailRealizable() = %v, want %v (euid=%d)", got, want, os.Geteuid())
	}
}
