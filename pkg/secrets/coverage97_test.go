package secrets

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage97EnvelopeMismatch(t *testing.T) {
	c := testCipher(t)
	binding := testBinding()
	sealed, err := SealEnvelopeBound(c, Secrets{
		Registry: &models.RegistryAuth{Server: "r", Username: "u", Password: "pw"},
	}, []string{"node-a"}, binding)
	if err != nil {
		t.Fatal(err)
	}
	wrongGen := binding
	wrongGen.Generation = binding.Generation + 1
	if _, err := OpenEnvelopeBound(c, sealed, "node-a", wrongGen); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("generation mismatch = %v", err)
	}
	wrongSandbox := binding
	wrongSandbox.SandboxID = "sb-other"
	wrongSandbox.Ref = FormatRef(wrongSandbox.SandboxID, binding.IncarnationID, binding.Version)
	if _, err := OpenEnvelopeBound(c, sealed, "node-a", wrongSandbox); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("binding mismatch = %v", err)
	}
	incomplete := []byte(`{"version":4,"recipients":["node-a"],"sandbox_id":"sb-1","incarnation_id":"inc-1","ref":"cluster-secret://sandbox/sb-1/i/inc-1/v1","ref_version":1,"generation":1}`)
	if _, err := OpenEnvelopeBound(c, incomplete, "node-a", binding); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete envelope = %v", err)
	}
}
