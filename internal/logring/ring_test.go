package logring

import (
	"bytes"
	"math/rand"
	"testing"
)

// The ring keeps the newest max bytes of everything written, whatever the
// write sizes, and Total and Base keep counting the whole stream.
func TestRingKeepsTheNewestBytes(t *testing.T) {
	tests := []struct {
		name   string
		max    int
		writes []string
		want   string
	}{
		{name: "under the limit", max: 10, writes: []string{"ab", "cd"}, want: "abcd"},
		{name: "exactly the limit", max: 4, writes: []string{"ab", "cd"}, want: "abcd"},
		{name: "wraps", max: 4, writes: []string{"abc", "def"}, want: "cdef"},
		{name: "one write past the limit", max: 3, writes: []string{"abcdefg"}, want: "efg"},
		{name: "a write as long as the ring", max: 3, writes: []string{"ab", "xyz"}, want: "xyz"},
		{name: "many small writes", max: 5, writes: []string{"a", "b", "c", "d", "e", "f", "g"}, want: "cdefg"},
		{name: "empty writes", max: 5, writes: []string{"", "ab", ""}, want: "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r Ring
			total := 0
			for _, w := range tt.writes {
				r.Write([]byte(w), tt.max, nil)
				total += len(w)
			}
			if got := string(r.Bytes()); got != tt.want {
				t.Fatalf("kept %q, want %q", got, tt.want)
			}
			if r.Total() != int64(total) || r.Base() != int64(total-len(tt.want)) || r.Len() != len(tt.want) {
				t.Fatalf("total %d base %d len %d", r.Total(), r.Base(), r.Len())
			}
		})
	}
}

// Random write sizes against a plain slice: the kept tail and every slice
// of it must match.
func TestRingMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, limit := range []int{1, 7, 4096, 10000} {
		var r Ring
		var all []byte
		for i := 0; i < 400; i++ {
			p := make([]byte, rng.Intn(3*limit/2+2))
			rng.Read(p)
			r.Write(p, limit, nil)
			all = append(all, p...)
			want := all[max0(len(all)-limit):]
			if !bytes.Equal(r.Bytes(), want) {
				t.Fatalf("limit %d write %d: kept bytes differ", limit, i)
			}
			lo, hi := rng.Intn(len(want)+2)-1, rng.Intn(len(want)+2)
			if got := r.Slice(lo, hi); !bytes.Equal(got, want[min(max0(lo), len(want)):max(min(max0(lo), len(want)), min(hi, len(want)))]) {
				t.Fatalf("limit %d write %d: Slice(%d, %d) differs", limit, i, lo, hi)
			}
			if r.Size() > limit {
				t.Fatalf("ring grew to %d past its limit %d", r.Size(), limit)
			}
		}
	}
}

func max0(n int) int { return max(n, 0) }

// grow decides how far the ring may grow: a partial grant caps it there,
// and no grant keeps nothing while still counting the bytes.
func TestRingGrowth(t *testing.T) {
	var asked []int
	var r Ring
	r.Write([]byte("abc"), 100, func(want int) int {
		asked = append(asked, want)
		return 2
	})
	if len(asked) != 1 || asked[0] != 100 {
		t.Fatalf("asked %v, want one request for the limit", asked)
	}
	if r.Size() != 2 || string(r.Bytes()) != "bc" || r.Total() != 3 {
		t.Fatalf("size %d kept %q total %d", r.Size(), r.Bytes(), r.Total())
	}
	// A grant larger than asked is ignored.
	var r2 Ring
	r2.Write([]byte("abc"), 5, func(want int) int { return want * 10 })
	if r2.Size() != 5 {
		t.Fatalf("size %d, want the limit", r2.Size())
	}

	var none Ring
	none.Write([]byte("lost"), 10, func(int) int { return 0 })
	if none.Len() != 0 || none.Total() != 4 || none.Base() != 4 || none.Bytes() != nil {
		t.Fatalf("no room: len %d total %d base %d", none.Len(), none.Total(), none.Base())
	}

	// Growth starts at a few KiB and doubles, so small writes do not
	// reallocate each time.
	var small Ring
	small.Write([]byte("x"), 1<<20, nil)
	if small.Size() != minGrowth {
		t.Fatalf("first allocation %d, want %d", small.Size(), minGrowth)
	}
	small.Write(make([]byte, minGrowth), 1<<20, nil)
	if small.Size() != 2*minGrowth {
		t.Fatalf("second allocation %d, want %d", small.Size(), 2*minGrowth)
	}
}

func TestRingRelease(t *testing.T) {
	var r Ring
	r.Write([]byte("hello"), 3, nil)
	if freed := r.Release(); freed != 3 {
		t.Fatalf("freed %d", freed)
	}
	if r.Len() != 0 || r.Size() != 0 || r.Total() != 5 || r.Base() != 5 {
		t.Fatalf("after release: len %d size %d total %d base %d", r.Len(), r.Size(), r.Total(), r.Base())
	}
	// It can be written again.
	r.Write([]byte("yo"), 3, nil)
	if string(r.Bytes()) != "yo" || r.Total() != 7 {
		t.Fatalf("after reuse: %q total %d", r.Bytes(), r.Total())
	}
}
