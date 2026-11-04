package auditwitness

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/auditexport"
	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
)

func TestReaderLatestHead(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	f.ship(t, headA)
	r, err := NewReader(context.Background(), testConfig(f.fake.URL).S3)
	if err != nil {
		t.Fatal(err)
	}
	r.w.now = f.w.now
	if head, ok, err := r.LatestHead(context.Background(), testNode); err != nil || !ok || head != headA {
		t.Fatalf("LatestHead = %q %v %v", head, ok, err)
	}
	if _, ok, err := r.LatestHead(context.Background(), "node-z"); err != nil || ok {
		t.Fatalf("unknown node = %v %v", ok, err)
	}
	f.fake.PutDeleteMarker(testBucket, HeadKey("witness/", testNode, f.day))
	if _, _, err := r.LatestHead(context.Background(), testNode); err == nil || !strings.Contains(err.Error(), "delete marker") {
		t.Fatalf("a hidden head must be an error, got %v", err)
	}
}

func TestNewReaderNeedsBucket(t *testing.T) {
	if _, err := NewReader(context.Background(), auditexport.S3Config{}); err == nil || !strings.Contains(err.Error(), "bucket is required") {
		t.Fatalf("err = %v", err)
	}
	// The default prefix applies when none is given.
	fake := s3fake.New()
	defer fake.Close()
	r, err := NewReader(context.Background(), auditexport.S3Config{Bucket: "b", Endpoint: fake.URL, Region: "us-east-1", PathStyle: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.w.prefix != DefaultPrefix {
		t.Fatalf("prefix = %q", r.w.prefix)
	}
}
