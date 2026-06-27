package harness

import "os"

// DisruptiveAllowed reports whether fault-injection tests (node kill, etc.) may
// run. cluster-hetero enables this by default via integration-tests/run.sh;
// pass --no-disruptive or use make integration-cluster-hetero-safe to opt out.
func DisruptiveAllowed() bool {
	switch os.Getenv("AEROL_ALLOW_DISRUPTIVE") {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
