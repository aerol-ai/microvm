package harness

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditwitness"
	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
)

const (
	testWitnessBucket = "aerolvm-itest-x-witness-abc123"
	testWitnessNode   = "aerolvm-itest-x-node2"
	testHeadA         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testHeadB         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// newWitnessFake is the integration scenarios' bucket in miniature: Object
// Lock in GOVERNANCE mode for one day (D13), driven through the real SDK. The
// fake refuses an upload to a locked bucket without a checksum, exactly as S3
// does, so a plant that passes here carries one.
func newWitnessFake(t *testing.T) (*s3fake.Server, WitnessBucket) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	// An operator's own AWS_PROFILE must not leak into an offline test: the
	// SDK would go looking for that profile's config instead of the keys above.
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	fake := s3fake.New()
	t.Cleanup(fake.Close)
	fake.CreateBucket(testWitnessBucket, s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeGovernance, Days: 1}})
	return fake, WitnessBucket{
		Bucket: testWitnessBucket, Prefix: "witness/", Region: "us-east-1",
		Endpoint: fake.URL, PathStyle: true,
	}
}

func TestLoadWitnessBucket(t *testing.T) {
	t.Setenv(EnvAuditWitnessBucket, "")
	t.Setenv(EnvAuditWitnessPrefix, "")
	t.Setenv(EnvAuditWitnessRegion, "")
	if _, ok := LoadWitnessBucket(); ok {
		t.Fatal("no bucket in the environment must read as no witness")
	}

	t.Setenv(EnvAuditWitnessBucket, " "+testWitnessBucket+" ")
	t.Setenv(EnvAuditWitnessPrefix, "witness/")
	t.Setenv(EnvAuditWitnessRegion, "us-east-2")
	w, ok := LoadWitnessBucket()
	if !ok || w.Bucket != testWitnessBucket || w.Prefix != "witness/" || w.Region != "us-east-2" {
		t.Fatalf("LoadWitnessBucket = %+v, %v", w, ok)
	}
	if got := RequireWitnessBucket(t); got != w {
		t.Fatalf("RequireWitnessBucket = %+v, want %+v", got, w)
	}
	// An empty prefix output means the daemon default, which is also what
	// the nodes write under when SB_AUDIT_WITNESS_S3_PREFIX is unset.
	if got := (WitnessBucket{}).s3Config().Prefix; got != auditwitness.DefaultPrefix {
		t.Fatalf("default prefix = %q, want %q", got, auditwitness.DefaultPrefix)
	}
}

// "Never recorded" and "could not read" are different facts, and UC-143 polls
// on the first while failing on the second.
func TestWitnessedHeadForNeverRecorded(t *testing.T) {
	_, w := newWitnessFake(t)
	head, ok, err := WitnessedHeadFor(t, w, testWitnessNode)
	if err != nil || ok || head != "" {
		t.Fatalf("empty bucket = %q %v %v, want no head and no error", head, ok, err)
	}
}

// UC-144 depends on two properties of a plant: it lands as the newest head,
// so the victim's boot reads it, and a later plant buries it, which is the
// only way to restore a locked witness.
func TestPlantWitnessHeadBecomesTheNewestHead(t *testing.T) {
	fake, w := newWitnessFake(t)
	start := time.Now()
	for _, head := range []string{testHeadA, testHeadB} {
		if err := PlantWitnessHead(t, w, testWitnessNode, head); err != nil {
			t.Fatalf("plant %s: %v", head[:4], err)
		}
		got, ok, err := WitnessedHeadFor(t, w, testWitnessNode)
		if err != nil || !ok || got != head {
			t.Fatalf("after planting %s the witness answers %q %v %v", head[:4], got, ok, err)
		}
	}

	// Both versions stay, locked: the plant added to the history, as a node's
	// own ship does, and replaced nothing. Two day keys only when the test
	// straddled UTC midnight.
	var versions []s3fake.Version
	for _, key := range slices.Compact([]string{
		auditwitness.HeadKey("witness/", testWitnessNode, start),
		auditwitness.HeadKey("witness/", testWitnessNode, time.Now()),
	}) {
		versions = append(versions, fake.Versions(testWitnessBucket, key)...)
	}
	if len(versions) != 2 {
		t.Fatalf("today's key holds %d versions, want 2", len(versions))
	}
	for _, v := range versions {
		if v.Mode != s3fake.ModeGovernance || v.RetainUntil.IsZero() {
			t.Fatalf("version %s is not locked: %+v", v.VersionID, v)
		}
		// The body must be the record the node's own reader accepts, or the
		// victim's boot fails for a parse error instead of a disagreement.
		if _, err := auditwitness.ParseHeadRecord(v.Body, testWitnessNode); err != nil {
			t.Fatalf("planted body is not a head record: %v", err)
		}
	}
}

func TestPlantWitnessHeadNamesTheKeyOnFailure(t *testing.T) {
	_, w := newWitnessFake(t)
	w.Bucket = "no-such-bucket"
	err := PlantWitnessHead(t, w, testWitnessNode, testHeadA)
	if err == nil || !strings.Contains(err.Error(), "s3://no-such-bucket/witness/node="+testWitnessNode+"/day=") {
		t.Fatalf("err = %v, want one that names the bucket and key", err)
	}
}

// A delete marker on the newest head is the tamper the witness exists to
// expose, so the harness must surface it as an error, never as "no head".
func TestWitnessedHeadForReportsAHiddenHead(t *testing.T) {
	fake, w := newWitnessFake(t)
	if err := PlantWitnessHead(t, w, testWitnessNode, testHeadA); err != nil {
		t.Fatal(err)
	}
	fake.PutDeleteMarker(testWitnessBucket, auditwitness.HeadKey("witness/", testWitnessNode, time.Now()))
	if _, _, err := WitnessedHeadFor(t, w, testWitnessNode); err == nil || !strings.Contains(err.Error(), "delete marker") {
		t.Fatalf("a hidden head must be an error, got %v", err)
	}
}

// The canary count must page past S3's 1000-entry listing and must not count
// a neighbouring node whose id merely starts with this one.
func TestWitnessCanaryCountsOnlyItsOwnKey(t *testing.T) {
	fake, w := newWitnessFake(t)
	own := auditwitness.CanaryKey("witness/", testWitnessNode)
	for i := 0; i < 1005; i++ {
		fake.Put(testWitnessBucket, own, []byte(`{"canary":true}`))
	}
	neighbour := auditwitness.CanaryKey("witness/", testWitnessNode+"0")
	fake.Put(testWitnessBucket, neighbour, []byte(`{"canary":true}`))
	fake.PutDeleteMarker(testWitnessBucket, neighbour)

	versions, markers, err := WitnessCanary(t, w, testWitnessNode)
	if err != nil || versions != 1005 || markers != 0 {
		t.Fatalf("canary = %d versions, %d markers, %v; want 1005, 0", versions, markers, err)
	}

	fake.PutDeleteMarker(testWitnessBucket, own)
	if _, markers, err := WitnessCanary(t, w, testWitnessNode); err != nil || markers != 1 {
		t.Fatalf("a delete marker on the canary was not counted: %d %v", markers, err)
	}

	w.Bucket = "no-such-bucket"
	if _, _, err := WitnessCanary(t, w, testWitnessNode); err == nil || !strings.Contains(err.Error(), own) {
		t.Fatalf("err = %v, want one that names the canary key", err)
	}
}
