package containerd

import (
	"os"
	"testing"
)

// afterTests run once every test is done (removing the copy of this binary
// prepareUnpackChild makes, for one).
var afterTests []func()

// unpackTestHelperEnv starts this test binary as a helper process for the
// unpacker tests (runUnpackTestHelper): a neighbour, or a descriptor holder.
const unpackTestHelperEnv = "AEROL_UNPACK_TEST_HELPER"

// TestMain lets this test binary stand in for sandboxd as the build-context
// unpacker. unpackContextInChild re-execs os.Executable() with
// ContextUnpackFlag, which under go test is this binary, so it dispatches the
// flag the way cmd/sandboxd's main does, before the testing flags are parsed.
func TestMain(m *testing.M) {
	if len(os.Args) >= 2 && os.Args[1] == ContextUnpackFlag {
		if err := RunContextUnpack(os.Args[2:]); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	if mode := os.Getenv(unpackTestHelperEnv); mode != "" {
		os.Exit(runUnpackTestHelper(mode))
	}
	if err := prepareUnpackChild(); err != nil {
		os.Stderr.WriteString("prepare the build-context unpacker: " + err.Error() + "\n")
		os.Exit(1)
	}
	code := m.Run()
	for _, f := range afterTests {
		f()
	}
	os.Exit(code)
}
