package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

// witnessFake starts an S3 fake with a compliant witness bucket and an
// export bucket, and points the witness settings at it. The AWS settings
// are pinned so a developer's own profile cannot reach a real account.
// It serves https because enterprise mode refuses a plain-http endpoint.
func witnessFake(t *testing.T) *s3fake.Server {
	t.Helper()
	fake := s3fake.NewTLS()
	t.Cleanup(fake.Close)
	fake.CreateBucket("witness", s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Days: 30}})
	fake.CreateBucket("export", s3fake.BucketOptions{Versioning: true})
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, fake.CertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", ca)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "no-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "no-credentials"))
	t.Setenv("SB_AUDIT_WITNESS_S3_BUCKET", "witness")
	t.Setenv("SB_AUDIT_WITNESS_S3_ENDPOINT", fake.URL)
	t.Setenv("SB_AUDIT_WITNESS_S3_REGION", "us-east-1")
	t.Setenv("SB_AUDIT_WITNESS_S3_PATH_STYLE", "true")
	t.Setenv("SB_NODE_ID", "node-1")
	return fake
}

// Regression contract item 1 (D14): witness settings without a backend are
// inert. The free build keeps its placeholder witness, makes no S3 request,
// and the external-witness gate still fails closed with today's message.
func TestAuditWitnessSettingsWithoutBackendAreInert(t *testing.T) {
	_ = setBaseRunEnv(t)
	fake := witnessFake(t)
	t.Setenv("SB_AUDIT_WITNESS_BACKEND", "")
	t.Setenv("SB_SECRET_AUDIT_EXTERNAL_WITNESS", "true")
	err := runWithAutoCancel(t, 800*time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "requires a non-noop controlplane.Witness") {
		t.Fatalf("err = %v, want the existing external-witness refusal", err)
	}
	if n := fake.Requests(); n != 0 {
		t.Fatalf("an unset backend made %d S3 requests", n)
	}
}

// countingWitness records that the daemon used it.
type countingWitness struct{ reads atomic.Int64 }

func (w *countingWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "r1"}, nil
}

func (w *countingWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	w.reads.Add(1)
	return "", false, nil
}

// Regression contract item 2 (D14): a provider-supplied witness wins over
// SB_AUDIT_WITNESS_BACKEND, and the setting then never reaches S3.
func TestProviderWitnessWinsOverAuditWitnessBackend(t *testing.T) {
	_ = setBaseRunEnv(t)
	fake := witnessFake(t)
	t.Setenv("SB_AUDIT_WITNESS_BACKEND", "s3")
	t.Setenv("SB_SECRET_AUDIT_EXTERNAL_WITNESS", "true")
	w := &countingWitness{}
	err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{Witness: w}.WithDefaults(), nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := fake.Requests(); n != 0 {
		t.Fatalf("the S3 witness opened over a provider witness: %d requests", n)
	}
	if w.reads.Load() == 0 {
		t.Fatal("the provider witness was not the one installed")
	}
}

// The setting fills the placeholder witness: enterprise mode boots on the
// open-source provider with only an Object Lock bucket and an off-node
// exporter, and the boot checks ran against the bucket.
func TestAuditWitnessBackendLetsEnterpriseBoot(t *testing.T) {
	_ = setBaseRunEnv(t)
	fake := witnessFake(t)
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_PAT_TOKEN", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	t.Setenv("SB_SECRET_AUDIT_STRICT_BOOT", "true")
	t.Setenv("SB_AUDIT_WITNESS_BACKEND", "s3")
	t.Setenv("SB_AUDIT_EXPORT_BACKEND", "s3")
	t.Setenv("SB_AUDIT_EXPORT_S3_BUCKET", "export")
	t.Setenv("SB_AUDIT_EXPORT_S3_ENDPOINT", fake.URL)
	t.Setenv("SB_AUDIT_EXPORT_S3_REGION", "us-east-1")
	t.Setenv("SB_AUDIT_EXPORT_S3_PATH_STYLE", "true")
	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
		t.Fatalf("enterprise boot with the S3 witness: %v", err)
	}
	ops := fake.Ops()
	want := map[string]int{"GetBucketVersioning": 1, "GetObjectLockConfiguration": 1, "DeleteObject": 2}
	for op, n := range want {
		if ops[op] != n {
			t.Fatalf("boot check %s ran %d times, want %d; ops %v", op, ops[op], n, ops)
		}
	}
}

// A bucket that would not protect a head stops boot with the fix named.
func TestAuditWitnessBackendRefusesUnlockedBucket(t *testing.T) {
	_ = setBaseRunEnv(t)
	fake := witnessFake(t)
	fake.CreateBucket("plain", s3fake.BucketOptions{Versioning: true})
	t.Setenv("SB_AUDIT_WITNESS_BACKEND", "s3")
	t.Setenv("SB_AUDIT_WITNESS_S3_BUCKET", "plain")
	err := runWithAutoCancel(t, 800*time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "open audit witness") || !strings.Contains(err.Error(), "does not have Object Lock") {
		t.Fatalf("err = %v", err)
	}
}
