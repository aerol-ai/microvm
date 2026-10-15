package auditwitness

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const (
	testBucket = "witness-bkt"
	testNode   = "node-a"
	headA      = "aaaa000000000000000000000000000000000000000000000000000000000001"
	headB      = "bbbb000000000000000000000000000000000000000000000000000000000002"
)

var lockedCompliance = s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Days: 30}}

// testClient is the production client builder pointed at a fake endpoint:
// every test in this package goes through the real SDK, so headers, XML and
// error codes are exercised as S3 would see them (D12).
func testClient(t *testing.T, endpoint string) *s3.Client {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	c, err := auditexport.NewS3Client(context.Background(), auditexport.S3Config{Endpoint: endpoint, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testConfig(endpoint string) Config {
	return Config{
		Backend:       BackendS3,
		NodeID:        testNode,
		RetentionDays: 30,
		S3:            auditexport.S3Config{Bucket: testBucket, Prefix: "witness/", Endpoint: endpoint, Region: "us-east-1", PathStyle: true},
	}
}

// fixture is a fake with one bucket and a witness on it, its clock held so
// tests choose which day is "today".
type fixture struct {
	fake *s3fake.Server
	w    *s3Witness
	day  time.Time
}

func newFixture(t *testing.T, opts s3fake.BucketOptions) *fixture {
	t.Helper()
	fake := s3fake.New()
	t.Cleanup(fake.Close)
	fake.CreateBucket(testBucket, opts)
	f := &fixture{fake: fake, day: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	f.w = newS3Witness(testClient(t, fake.URL), testConfig(fake.URL))
	f.w.now = func() time.Time { return f.day }
	fake.SetClock(func() time.Time { return f.day })
	return f
}

func (f *fixture) ship(t *testing.T, head string) controlplane.WitnessReceipt {
	t.Helper()
	rec, err := f.w.WitnessHeads(context.Background(), []controlplane.AuditHead{{NodeID: testNode, HeadHex: head, EventID: "ev-1"}})
	if err != nil {
		t.Fatalf("WitnessHeads(%s): %v", head, err)
	}
	return rec
}

func (f *fixture) latest(t *testing.T) (string, bool, error) {
	t.Helper()
	return f.w.LastWitnessedHead(context.Background(), testNode)
}

func TestHeadKeyLayout(t *testing.T) {
	day := time.Date(2026, 10, 11, 23, 59, 0, 0, time.FixedZone("x", -5*3600))
	cases := []struct {
		prefix, key, node, canary string
	}{
		{"witness/", "witness/node=n1/day=2026-10-12/head.json", "witness/node=n1/", "witness/canary/node=n1"},
		{"witness", "witness/node=n1/day=2026-10-12/head.json", "witness/node=n1/", "witness/canary/node=n1"},
		{"/a/b/", "a/b/node=n1/day=2026-10-12/head.json", "a/b/node=n1/", "a/b/canary/node=n1"},
		{"", "node=n1/day=2026-10-12/head.json", "node=n1/", "canary/node=n1"},
	}
	for _, c := range cases {
		if got := HeadKey(c.prefix, "n1", day); got != c.key {
			t.Errorf("HeadKey(%q) = %q, want %q (the day is UTC)", c.prefix, got, c.key)
		}
		if got := NodePrefix(c.prefix, "n1"); got != c.node {
			t.Errorf("NodePrefix(%q) = %q, want %q", c.prefix, got, c.node)
		}
		if got := CanaryKey(c.prefix, "n1"); got != c.canary {
			t.Errorf("CanaryKey(%q) = %q, want %q", c.prefix, got, c.canary)
		}
	}
}

func TestParseHeadRecord(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"valid", `{"node_id":"n1","head_hex":"` + headA + `"}`, ""},
		{"malformed", `{`, "malformed"},
		{"other node", `{"node_id":"n2","head_hex":"` + headA + `"}`, `names node "n2"`},
		{"empty head", `{"node_id":"n1","head_hex":""}`, "no valid head_hex"},
		{"not hex", `{"node_id":"n1","head_hex":"zz"}`, "no valid head_hex"},
		{"too long", `{"node_id":"n1","head_hex":"` + strings.Repeat("a", 129) + `"}`, "no valid head_hex"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, err := ParseHeadRecord([]byte(c.body), "n1")
			if c.want == "" {
				if err != nil || rec.HeadHex != headA {
					t.Fatalf("got %+v, %v", rec, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestWitnessHeadsWritesOneLockedVersionPerShip(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	before := f.fake.Ops()
	rec := f.ship(t, headA)
	after := f.fake.Ops()
	if got := after["PutObject"] - before["PutObject"]; got != 1 || len(after) != 1 {
		t.Fatalf("a ship must be exactly one PutObject, got ops %v", after)
	}
	key := HeadKey("witness/", testNode, f.day)
	versions := f.fake.Versions(testBucket, key)
	if len(versions) != 1 || rec.ReceiptID != versions[0].VersionID {
		t.Fatalf("receipt %q, versions %+v", rec.ReceiptID, versions)
	}
	if !rec.RecordedAt.IsZero() {
		t.Fatal("RecordedAt must stay zero so the service stores its ship time (D10)")
	}
	if versions[0].Mode != s3fake.ModeCompliance {
		t.Fatalf("version not locked: %+v", versions[0])
	}
	got, err := ParseHeadRecord(versions[0].Body, testNode)
	if err != nil || got.HeadHex != headA || got.EventID != "ev-1" || got.Observed.IsZero() {
		t.Fatalf("stored record %+v, %v", got, err)
	}
	head, ok, err := f.latest(t)
	if err != nil || !ok || head != headA {
		t.Fatalf("latest = %q %v %v", head, ok, err)
	}
	// A second ship the same day adds a version to the same key.
	f.ship(t, headB)
	if n := len(f.fake.Versions(testBucket, key)); n != 2 {
		t.Fatalf("versions = %d, want 2", n)
	}
	if head, _, _ := f.latest(t); head != headB {
		t.Fatalf("latest = %q, want %q", head, headB)
	}
}

func TestWitnessHeadsRejectsBadInput(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	cases := []struct {
		name  string
		heads []controlplane.AuditHead
		want  string
	}{
		{"no heads", nil, "exactly one head per call, got 0"},
		{"two heads", []controlplane.AuditHead{{NodeID: testNode, HeadHex: headA}, {NodeID: testNode, HeadHex: headB}}, "exactly one head per call, got 2"},
		{"no node id", []controlplane.AuditHead{{HeadHex: headA}}, "SB_NODE_ID is required"},
		{"standalone", []controlplane.AuditHead{{NodeID: "standalone", HeadHex: headA}}, `must not be "standalone"`},
		{"not hex", []controlplane.AuditHead{{NodeID: testNode, HeadHex: "nope"}}, "not a hex digest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.w.WitnessHeads(context.Background(), c.heads)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	if n := f.fake.Requests(); n != 0 {
		t.Fatalf("rejected input reached S3: %d requests", n)
	}
}

// S3 refuses an upload to a bucket with default retention unless it carries
// a checksum; the shared client only adds one when an API requires it. The
// fake enforces the same rule, so this proves the witness sets the
// algorithm and the SDK puts the headers on the wire.
func TestLockedBucketRequiresChecksumHeaders(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	_, err := f.w.api.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(testBucket), Key: aws.String("witness/raw"), Body: bytes.NewReader([]byte("x")),
	})
	if apiCode(err) != "InvalidRequest" || !strings.Contains(err.Error(), "x-amz-checksum") {
		t.Fatalf("a PUT without a checksum must be refused like S3 does, got %v", err)
	}
	if _, err := f.w.WitnessHeads(context.Background(), []controlplane.AuditHead{{NodeID: testNode, HeadHex: headA}}); err != nil {
		t.Fatalf("the witness's own PUT must carry the checksum: %v", err)
	}
}

func TestWitnessHeadsRefusesUnversionedWrite(t *testing.T) {
	f := newFixture(t, s3fake.BucketOptions{})
	_, err := f.w.WitnessHeads(context.Background(), []controlplane.AuditHead{{NodeID: testNode, HeadHex: headA}})
	if err == nil || !strings.Contains(err.Error(), "no version id") {
		t.Fatalf("err = %v", err)
	}
}

func TestLastWitnessedHead(t *testing.T) {
	day1 := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		setup func(t *testing.T, f *fixture)
		head  string
		ok    bool
		err   string
		ops   []string
	}{
		{
			name: "never recorded",
			ok:   false,
		},
		{
			name: "today's key",
			setup: func(t *testing.T, f *fixture) {
				f.ship(t, headA)
			},
			head: headA, ok: true, ops: []string{"GetObject"},
		},
		{
			// A node down across midnight finds its newest day by listing.
			name: "idle since an earlier day",
			setup: func(t *testing.T, f *fixture) {
				f.day = day1
				f.ship(t, headA)
				f.day = day1.AddDate(0, 0, 1)
				f.ship(t, headB)
				f.day = day1.AddDate(0, 0, 4)
			},
			head: headB, ok: true, ops: []string{"GetObject", "ListObjectVersions"},
		},
		{
			// A clock running behind still finds the newest head.
			name: "newest day is after today",
			setup: func(t *testing.T, f *fixture) {
				f.ship(t, headA)
				f.day = f.day.AddDate(0, 0, -1)
			},
			head: headA, ok: true,
		},
		{
			name: "delete marker on today's key never falls back to yesterday",
			setup: func(t *testing.T, f *fixture) {
				f.day = day1
				f.ship(t, headA)
				f.day = day1.AddDate(0, 0, 1)
				f.ship(t, headB)
				f.fake.PutDeleteMarker(testBucket, HeadKey("witness/", testNode, f.day))
			},
			err: "hidden by a delete marker",
		},
		{
			name: "delete marker on the newest day of an idle node",
			setup: func(t *testing.T, f *fixture) {
				f.day = day1
				f.ship(t, headA)
				f.day = day1.AddDate(0, 0, 1)
				f.ship(t, headB)
				f.fake.PutDeleteMarker(testBucket, HeadKey("witness/", testNode, f.day))
				f.day = day1.AddDate(0, 0, 3)
			},
			err: "hidden by a delete marker",
		},
		{
			name: "malformed current version",
			setup: func(t *testing.T, f *fixture) {
				f.fake.Put(testBucket, HeadKey("witness/", testNode, f.day), []byte("not json"))
			},
			err: "malformed head record",
		},
		{
			name: "current version names another node",
			setup: func(t *testing.T, f *fixture) {
				f.fake.Put(testBucket, HeadKey("witness/", testNode, f.day), []byte(`{"node_id":"node-b","head_hex":"`+headA+`"}`))
			},
			err: `names node "node-b"`,
		},
		{
			name: "oversized body",
			setup: func(t *testing.T, f *fixture) {
				f.fake.Put(testBucket, HeadKey("witness/", testNode, f.day), bytes.Repeat([]byte("a"), maxHeadBody+10))
			},
			err: "larger than any head record",
		},
		{
			name: "role without s3:ListBucket",
			setup: func(t *testing.T, f *fixture) {
				f.fake.SetPolicy(s3fake.Policy{NoListBucket: true})
			},
			err: "needs s3:ListBucket",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, lockedCompliance)
			if c.setup != nil {
				c.setup(t, f)
			}
			before := f.fake.Ops()
			head, ok, err := f.latest(t)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || ok != c.ok || head != c.head {
				t.Fatalf("got %q %v %v, want %q %v", head, ok, err, c.head, c.ok)
			}
			after := f.fake.Ops()
			for _, op := range c.ops {
				if after[op] == before[op] {
					t.Errorf("expected a %s call, ops %v -> %v", op, before, after)
				}
			}
			if c.name == "today's key" && after["ListObjectVersions"] != before["ListObjectVersions"] {
				t.Errorf("a node that shipped today must read with one GET, ops %v", after)
			}
		})
	}
}

func TestLastWitnessedHeadStandaloneNeverReadsTheBucket(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	for _, id := range []string{"standalone", "", "  "} {
		head, ok, err := f.w.LastWitnessedHead(context.Background(), id)
		if head != "" || ok || err != nil {
			t.Fatalf("LastWitnessedHead(%q) = %q %v %v", id, head, ok, err)
		}
	}
	if n := f.fake.Requests(); n != 0 {
		t.Fatalf("the standalone id reached S3: %d requests (D24)", n)
	}
}

// The newest-day listing must follow pagination: years of locked history
// pass the 1,000-entry page.
func TestLastWitnessedHeadPagesThroughDays(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	start := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	var last time.Time
	for i := 0; i < 1105; i++ {
		last = start.AddDate(0, 0, i)
		body := fmt.Sprintf(`{"node_id":%q,"head_hex":"%04x"}`, testNode, i)
		f.fake.Put(testBucket, HeadKey("witness/", testNode, last), []byte(body))
	}
	f.day = last.AddDate(0, 0, 2)
	head, ok, err := f.latest(t)
	if err != nil || !ok || head != fmt.Sprintf("%04x", 1104) {
		t.Fatalf("latest = %q %v %v", head, ok, err)
	}
}

func TestOpen(t *testing.T) {
	cases := []struct {
		name   string
		bucket *s3fake.BucketOptions
		policy s3fake.Policy
		mutate func(*Config)
		err    string
		// offline errors must be raised before any request
		offline bool
	}{
		{name: "compliance bucket", bucket: &lockedCompliance},
		{name: "governance bucket, role without bypass", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeGovernance, Days: 30}}},
		{name: "lock alone refuses the version delete", bucket: &lockedCompliance, policy: s3fake.Policy{AllowDeleteVersion: true}},
		{name: "governance lock refuses a role without bypass", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeGovernance, Days: 30}}, policy: s3fake.Policy{AllowDeleteVersion: true}},
		{name: "rule in years", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Years: 1}}},
		{name: "retention 0 needs any lock", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Days: 1}}, mutate: func(c *Config) { c.RetentionDays = 0 }},
		{name: "unknown backend", mutate: func(c *Config) { c.Backend = "gcs" }, err: `unknown backend "gcs"`, offline: true},
		{name: "no backend", mutate: func(c *Config) { c.Backend = "" }, err: "no backend configured", offline: true},
		{name: "no bucket", mutate: func(c *Config) { c.S3.Bucket = "" }, err: "SB_AUDIT_WITNESS_S3_BUCKET is required", offline: true},
		{name: "no node id", mutate: func(c *Config) { c.NodeID = "" }, err: "SB_NODE_ID is required", offline: true},
		{name: "standalone node id", mutate: func(c *Config) { c.NodeID = "standalone" }, err: `must not be "standalone"`, offline: true},
		{name: "versioning off", bucket: &s3fake.BucketOptions{}, err: `has versioning "off"`},
		{name: "object lock off", bucket: &s3fake.BucketOptions{Versioning: true}, err: "does not have Object Lock"},
		{name: "no default rule", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{}}, err: "no default retention rule"},
		{name: "retention too short", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Days: 7}}, err: "shorter than SB_SECRET_AUDIT_RETENTION_DAYS=30"},
		{name: "years still too short", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeCompliance, Years: 1}}, mutate: func(c *Config) { c.RetentionDays = 400 }, err: "locks heads for 365 days"},
		{name: "role without s3:ListBucket", bucket: &lockedCompliance, policy: s3fake.Policy{NoListBucket: true}, err: "grant the node role s3:ListBucket"},
		{name: "role holds governance bypass", bucket: &s3fake.BucketOptions{Lock: &s3fake.Lock{Mode: s3fake.ModeGovernance, Days: 30}}, policy: s3fake.Policy{BypassGovernance: true, AllowDeleteVersion: true}, err: "s3:BypassGovernanceRetention"},
		{name: "role can place delete markers", bucket: &lockedCompliance, policy: s3fake.Policy{AllowDeleteMarker: true}, err: "deny s3:DeleteObject"},
		{name: "missing bucket", err: "read versioning of bucket"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := s3fake.New()
			defer fake.Close()
			if c.bucket != nil {
				fake.CreateBucket(testBucket, *c.bucket)
			}
			fake.SetPolicy(c.policy)
			testClient(t, fake.URL) // sets the static test credentials
			cfg := testConfig(fake.URL)
			if c.mutate != nil {
				c.mutate(&cfg)
			}
			w, err := Open(context.Background(), cfg)
			if c.offline && fake.Requests() != 0 {
				t.Fatalf("config error reached S3: %d requests", fake.Requests())
			}
			if c.err == "" {
				if err != nil || w == nil {
					t.Fatalf("Open: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("err = %v, want %q", err, c.err)
			}
		})
	}
}

// The canary must leave its locked version behind: a delete that worked
// would have refused boot instead.
func TestOpenCanaryLeavesLockedVersion(t *testing.T) {
	fake := s3fake.New()
	defer fake.Close()
	fake.CreateBucket(testBucket, lockedCompliance)
	testClient(t, fake.URL)
	if _, err := Open(context.Background(), testConfig(fake.URL)); err != nil {
		t.Fatal(err)
	}
	if ops := fake.Ops(); ops["DeleteObject"] != 2 || ops["GetObject"] != 1 {
		t.Fatalf("boot ops = %v (two canary deletes, one missing-key probe)", ops)
	}
	if v := fake.Versions(testBucket, "witness/canary/node="+testNode); len(v) != 1 || v[0].Mode != s3fake.ModeCompliance {
		t.Fatalf("canary versions = %+v", v)
	}
}

// Any canary answer other than AccessDenied is not proof the evidence is
// safe, for the version delete and for the delete marker alike.
func TestCanaryUnexpectedDeleteErrorRefusesBoot(t *testing.T) {
	cases := []struct {
		name string
		// versioned picks which of the two canary deletes fails oddly.
		versioned bool
		want      string
	}{
		{"version delete", true, "not proof that the lock holds"},
		{"delete marker", false, "not proof that a head cannot be hidden"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := s3fake.New()
			defer fake.Close()
			fake.CreateBucket(testBucket, lockedCompliance)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete && r.URL.Query().Has("versionId") == c.versioned {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`<Error><Code>InvalidArgument</Code><Message>no</Message></Error>`))
					return
				}
				fake.Config.Handler.ServeHTTP(w, r)
			}))
			defer front.Close()
			testClient(t, front.URL)
			_, err := Open(context.Background(), testConfig(front.URL))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestProbeErrorsRefuseBoot(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"key exists", http.StatusOK, `{}`, "unexpectedly exists"},
		{"other error", http.StatusBadRequest, `<Error><Code>InvalidArgument</Code><Message>no</Message></Error>`, "probe a missing key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := s3fake.New()
			defer fake.Close()
			fake.CreateBucket(testBucket, lockedCompliance)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/probe/") {
					w.WriteHeader(c.status)
					_, _ = w.Write([]byte(c.body))
					return
				}
				fake.Config.Handler.ServeHTTP(w, r)
			}))
			defer front.Close()
			testClient(t, front.URL)
			_, err := Open(context.Background(), testConfig(front.URL))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// An endpoint that never answers must fail boot within the deadline, naming
// the check and the bucket rather than a bare dial error (D9).
func TestBootChecksDeadline(t *testing.T) {
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hang.Close()
	w := newS3Witness(testClient(t, hang.URL), testConfig(hang.URL))
	const deadline = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	start := time.Now()
	err := w.bootChecks(ctx, deadline)
	if err == nil || !strings.Contains(err.Error(), `the versioning check on bucket "witness-bkt" timed out after 300ms`) {
		t.Fatalf("err = %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("boot checks took %s past a %s deadline", took, deadline)
	}
}

func TestWitnessReadErrorsAreWrapped(t *testing.T) {
	fake := s3fake.New()
	defer fake.Close()
	// No bucket: every call fails with NoSuchBucket.
	w := newS3Witness(testClient(t, fake.URL), testConfig(fake.URL))
	if _, _, err := w.LastWitnessedHead(context.Background(), testNode); err == nil || !strings.Contains(err.Error(), "audit witness s3: read") {
		t.Fatalf("read err = %v", err)
	}
	if _, err := w.WitnessHeads(context.Background(), []controlplane.AuditHead{{NodeID: testNode, HeadHex: headA}}); err == nil || !strings.Contains(err.Error(), "audit witness s3: write") {
		t.Fatalf("write err = %v", err)
	}
	if _, _, err := w.newestDay(context.Background(), testNode); err == nil {
		t.Fatal("list against a missing bucket must fail")
	}
	if _, err := w.latestIsDeleteMarker(context.Background(), "k"); err == nil {
		t.Fatal("version list against a missing bucket must fail")
	}
}

// Production reaches S3 over https, where the SDK sends the checksum as an
// aws-chunked trailer rather than a header. The whole witness path must work
// there too, not only over the plain-http fake.
func TestWitnessOverTLS(t *testing.T) {
	fake := s3fake.NewTLS()
	defer fake.Close()
	fake.CreateBucket(testBucket, lockedCompliance)
	ca := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(ca, fake.CertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CA_BUNDLE", ca)
	testClient(t, fake.URL)
	w, err := Open(context.Background(), testConfig(fake.URL))
	if err != nil {
		t.Fatalf("Open over TLS: %v", err)
	}
	if _, err := w.WitnessHeads(context.Background(), []controlplane.AuditHead{{NodeID: testNode, HeadHex: headA}}); err != nil {
		t.Fatalf("ship over TLS: %v", err)
	}
	if head, ok, err := w.LastWitnessedHead(context.Background(), testNode); err != nil || !ok || head != headA {
		t.Fatalf("latest over TLS = %q %v %v", head, ok, err)
	}
}
