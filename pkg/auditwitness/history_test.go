package auditwitness

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/auditwitness/s3fake"
)

func headHex(i int) string { return fmt.Sprintf("%064x", i) }

func TestReaderHistoryOrderAndWindow(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	r := newReader(f.w.api, testConfig(f.fake.URL).S3)
	put := func(node string, day time.Time, i int) {
		f.fake.Put(testBucket, HeadKey("witness/", node, day), []byte(fmt.Sprintf(`{"node_id":%q,"head_hex":%q}`, node, headHex(i))))
	}
	clock := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	f.fake.SetClock(func() time.Time { return clock })
	// An old day the window skips without reading.
	put(testNode, clock, 1)
	// Three versions in one second on one key: only S3's version order can
	// tell them apart.
	clock = time.Date(2026, 10, 10, 23, 59, 59, 0, time.UTC)
	put(testNode, clock, 2)
	put(testNode, clock, 3)
	put(testNode, clock, 4)
	// The next day, written with a node clock that ran behind: the key says
	// the 10th, but S3 saw it after the 11th's first head.
	clock = time.Date(2026, 10, 11, 0, 0, 5, 0, time.UTC)
	put(testNode, clock, 5)
	clock = clock.Add(time.Second)
	put(testNode, time.Date(2026, 10, 10, 23, 59, 59, 0, time.UTC), 6)
	// An unchanged re-ship: same body, read once.
	clock = clock.Add(time.Second)
	put(testNode, clock, 5)
	put("node-b", clock, 9)
	f.fake.PutDeleteMarker(testBucket, HeadKey("witness/", "node-b", clock))

	before := f.fake.Ops()["GetObject"]
	h, err := r.History(context.Background(), testNode, time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, w := range h.Heads {
		got = append(got, w.HeadHex[len(w.HeadHex)-1:]+"@"+w.Day)
	}
	want := "2@2026-10-10,3@2026-10-10,4@2026-10-10,5@2026-10-11,6@2026-10-10,5@2026-10-11"
	if strings.Join(got, ",") != want {
		t.Fatalf("order = %v, want %s", got, want)
	}
	if h.NewestDay != "2026-10-11" || len(h.HiddenKeys) != 0 {
		t.Fatalf("history = %+v", h)
	}
	if h.Prior == nil || h.Prior.HeadHex != headHex(1) || h.Prior.Day != "2026-10-01" {
		t.Fatalf("prior = %+v, want the Oct 1 head", h.Prior)
	}
	if reads := f.fake.Ops()["GetObject"] - before; reads != 6 {
		t.Fatalf("reads = %d, want 6: five distinct bodies (the re-shipped one is read once) and the prior head", reads)
	}

	hb, err := r.History(context.Background(), "node-b", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(hb.HiddenKeys) != 1 || len(hb.Heads) != 1 {
		t.Fatalf("node-b = %+v", hb)
	}
	nodes, err := r.Nodes(context.Background())
	if err != nil || strings.Join(nodes, ",") != "node-a,node-b" {
		t.Fatalf("nodes = %v %v", nodes, err)
	}
	empty, err := r.History(context.Background(), "node-z", time.Time{})
	if err != nil || len(empty.Heads) != 0 || empty.NewestDay != "" {
		t.Fatalf("unknown node = %+v %v", empty, err)
	}
}

func TestReaderHistoryErrors(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	r := newReader(f.w.api, testConfig(f.fake.URL).S3)
	f.fake.Put(testBucket, HeadKey("witness/", testNode, f.day), []byte(`{"node_id":"other","head_hex":"aa"}`))
	if _, err := r.History(context.Background(), testNode, time.Time{}); err == nil || !strings.Contains(err.Error(), `names node "other"`) {
		t.Fatalf("err = %v", err)
	}
	f.fake.Put(testBucket, HeadKey("witness/", testNode, f.day), make([]byte, maxHeadBody+1))
	if _, err := r.History(context.Background(), testNode, time.Time{}); err == nil {
		t.Fatal("an oversized version must fail")
	}
	missing := newReader(f.w.api, testConfig(f.fake.URL).S3)
	missing.w.bucket = "nope"
	if _, err := missing.Nodes(context.Background()); err == nil {
		t.Fatal("listing a missing bucket must fail")
	}
	if _, err := missing.History(context.Background(), testNode, time.Time{}); err == nil {
		t.Fatal("history of a missing bucket must fail")
	}
}

// Nodes pages through more node prefixes than one listing returns, and an
// empty prefix lists from the bucket root.
func TestReaderNodesPagesAndRootPrefix(t *testing.T) {
	fake := s3fake.New()
	t.Cleanup(fake.Close)
	fake.CreateBucket(testBucket, lockedCompliance)
	day := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 1003; i++ {
		id := fmt.Sprintf("n%04d", i)
		fake.Put(testBucket, HeadKey("", id, day), []byte(fmt.Sprintf(`{"node_id":%q,"head_hex":"aa"}`, id)))
	}
	cfg := testConfig(fake.URL).S3
	cfg.Prefix = "/"
	r := newReader(testClient(t, fake.URL), cfg)
	nodes, err := r.Nodes(context.Background())
	if err != nil || len(nodes) != 1003 || nodes[0] != "n0000" || nodes[1002] != "n1002" {
		t.Fatalf("nodes = %d %v", len(nodes), err)
	}
}

// A prior day whose newest version is hidden yields no prior head; the
// window's own listing is where hidden keys are reported.
func TestReaderHistoryHiddenPriorDay(t *testing.T) {
	f := newFixture(t, lockedCompliance)
	r := newReader(f.w.api, testConfig(f.fake.URL).S3)
	old := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f.fake.Put(testBucket, HeadKey("witness/", testNode, old), []byte(fmt.Sprintf(`{"node_id":%q,"head_hex":"aa"}`, testNode)))
	f.fake.PutDeleteMarker(testBucket, HeadKey("witness/", testNode, old))
	f.ship(t, headA)
	h, err := r.History(context.Background(), testNode, f.day)
	if err != nil || h.Prior != nil || len(h.Heads) != 1 {
		t.Fatalf("history = %+v %v", h, err)
	}
	f.fake.Put(testBucket, HeadKey("witness/", testNode, old), []byte(`{"node_id":"other","head_hex":"aa"}`))
	if _, err := r.History(context.Background(), testNode, f.day); err == nil {
		t.Fatal("a prior head naming another node must fail")
	}
}
