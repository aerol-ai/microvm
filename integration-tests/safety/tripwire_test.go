// Package safety holds OFFLINE tests of the prod-safety tripwires in
// provision.sh. They shell out to the script's `check-safety` mode (no AWS) and
// assert that prod-targeting inputs abort non-zero. An unverified guard is not a
// guard — this is the test that proves the harness cannot nuke production.
//
// Runs in the normal `go test ./...` / `make test` flow (no build tag).
package safety

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func provisionScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	// .../integration-tests/safety/tripwire_test.go -> .../integration-tests/lib/provision.sh
	return filepath.Join(filepath.Dir(thisFile), "..", "lib", "provision.sh")
}

// runCheck invokes `bash provision.sh check-safety ...` and returns the exit code.
func runCheck(t *testing.T, stateKey, leased, prod, cluster string) int {
	t.Helper()
	cmd := exec.Command("bash", provisionScript(t), "check-safety", stateKey, leased, prod, cluster)
	out, err := cmd.CombinedOutput()
	t.Logf("check-safety(%q,%q,%q,%q) -> %s", stateKey, leased, prod, cluster, out)
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatalf("running provision.sh: %v", err)
	return -1
}

func TestSafePassesAllTripwires(t *testing.T) {
	if code := runCheck(t, "integration/single-node/terraform.tfstate",
		"abc.itest.example.com", "sandbox.example.com", "aerolvm-itest-single-node"); code != 0 {
		t.Fatalf("safe inputs rejected (exit %d)", code)
	}
}

func TestProdStateKeyAborts(t *testing.T) {
	if code := runCheck(t, "prod/terraform.tfstate",
		"abc.itest.example.com", "sandbox.example.com", "aerolvm-itest-x"); code == 0 {
		t.Fatal("prod/ state key was NOT rejected — tripwire failed")
	}
}

func TestStateKeyOutsideIntegrationAborts(t *testing.T) {
	if code := runCheck(t, "staging/terraform.tfstate",
		"abc.itest.example.com", "sandbox.example.com", "aerolvm-itest-x"); code == 0 {
		t.Fatal("non-integration state key was NOT rejected")
	}
}

func TestProdDomainCollisionAborts(t *testing.T) {
	// leased == prod
	if code := runCheck(t, "integration/x/terraform.tfstate",
		"sandbox.example.com", "sandbox.example.com", "aerolvm-itest-x"); code == 0 {
		t.Fatal("leased domain equal to prod was NOT rejected")
	}
	// leased is a subdomain of prod
	if code := runCheck(t, "integration/x/terraform.tfstate",
		"abc.sandbox.example.com", "sandbox.example.com", "aerolvm-itest-x"); code == 0 {
		t.Fatal("leased domain under prod was NOT rejected")
	}
}

func TestClusterNameWithoutItestMarkerAborts(t *testing.T) {
	if code := runCheck(t, "integration/x/terraform.tfstate",
		"abc.itest.example.com", "sandbox.example.com", "aerolvm-prod"); code == 0 {
		t.Fatal("cluster_name without 'itest' marker was NOT rejected")
	}
}
