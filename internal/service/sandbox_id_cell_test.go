package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

var (
	testCellKey  = bytes.Repeat([]byte{7}, 32)
	otherCellKey = bytes.Repeat([]byte{9}, 32)
)

// C12 and C16 (plans/kubernetes-v2-architecture.md §12.3-12.4): with the
// federation's key, a new ID carries its cell in a byte only the cells can
// read, and keeps the shape clients route by.
func TestNewSandboxIDCarriesTheCell(t *testing.T) {
	for _, tc := range []struct {
		cell, want int
	}{
		{0, 1}, // a Config not built by config.Load: the default cell
		{1, 1},
		{7, 7},
		{255, 255},
	} {
		s := &Service{cfg: config.Config{CellID: tc.cell, CellIDKey: testCellKey}}
		seen := map[string]bool{}
		plain := 0
		for i := 0; i < 200; i++ {
			id, err := s.NewSandboxID()
			if err != nil {
				t.Fatal(err)
			}
			if !models.IsGeneratedSandboxID(id) {
				t.Fatalf("cell %d: id %q, want the sb-<16 hex> shape", tc.cell, id)
			}
			if seen[id] {
				t.Fatalf("cell %d: id %q minted twice", tc.cell, id)
			}
			seen[id] = true
			if got, ok := sandboxIDCell(id, testCellKey); !ok || got != tc.want {
				t.Fatalf("cell %d: id %q reads as cell %d (%v), want %d", tc.cell, id, got, ok, tc.want)
			}
			if id[3:5] == hex.EncodeToString([]byte{byte(tc.want)}) {
				plain++
			}
		}
		// The cell must not show: its plain byte leads about 1 ID in 256.
		if plain > 20 {
			t.Fatalf("cell %d: %d of 200 ids start with the plain cell byte", tc.cell, plain)
		}
	}
	for _, cell := range []int{-1, 256} {
		if id, err := newSandboxIDInCell(cell, testCellKey); err == nil {
			t.Fatalf("cell %d: minted %q, want an error", cell, id)
		}
	}
}

// Without a key there is one cell: the first byte is random, so IDs do not
// show a cell scheme either, and none reads as any cell.
func TestNewSandboxIDWithoutAKeyShowsNoCell(t *testing.T) {
	s := &Service{cfg: config.Config{CellID: 3}}
	first := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := s.NewSandboxID()
		if err != nil {
			t.Fatal(err)
		}
		if !models.IsGeneratedSandboxID(id) {
			t.Fatalf("id %q, want the sb-<16 hex> shape", id)
		}
		if _, ok := sandboxIDCell(id, nil); ok {
			t.Fatalf("id %q reads as a cell without a key", id)
		}
		first[id[3:5]] = true
	}
	if len(first) < 50 {
		t.Fatalf("200 ids share only %d first bytes, want random ones", len(first))
	}
}

func TestSandboxIDCell(t *testing.T) {
	rest := []byte{1, 2, 3, 4, 5, 6, 7}
	idFor := func(first byte) string { return "sb-" + hex.EncodeToString(append([]byte{first}, rest...)) }
	mask := cellIDMask(testCellKey, rest)
	for _, tc := range []struct {
		name string
		id   string
		key  []byte
		want int
		ok   bool
	}{
		{name: "masked cell", id: idFor(5 ^ mask), key: testCellKey, want: 5, ok: true},
		{name: "another key reads another cell", id: idFor(5 ^ mask), key: otherCellKey, want: int(5 ^ mask ^ cellIDMask(otherCellKey, rest)), ok: 5^mask^cellIDMask(otherCellKey, rest) != 0},
		{name: "no key", id: idFor(5 ^ mask), key: nil},
		{name: "unmasks to no cell", id: idFor(mask), key: testCellKey},
		{name: "a name", id: "my-sandbox", key: testCellKey},
		{name: "upper-case hex is not a generated id", id: "SB-0102030405060708", key: testCellKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := sandboxIDCell(tc.id, tc.key)
			if ok != tc.ok || (ok && got != tc.want) {
				t.Fatalf("sandboxIDCell(%q) = %d, %v; want %d, %v", tc.id, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// A request for another cell's sandbox is that cell's, unless this node
// holds the sandbox (an ID minted before the key can read as any cell).
func TestOtherCellEndpoint(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.CellID = 1
	svc.cfg.CellIDKey = testCellKey
	svc.cfg.CellEndpoints = map[int]string{2: "https://cell2.example.com"}
	mint := func(cell int) string {
		t.Helper()
		id, err := newSandboxIDInCell(cell, testCellKey)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	here := mint(2) // lives on this node although it reads as cell 2
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID: here, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		CPU: 1, MemoryMB: 256, DiskGB: 1, OSUser: "root",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		id   string
		want string
	}{
		{name: "another known cell", id: mint(2), want: "https://cell2.example.com"},
		{name: "this cell", id: mint(1)},
		{name: "a cell with no address", id: mint(3)},
		{name: "held here", id: here},
		{name: "a name", id: "my-sandbox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := svc.OtherCellEndpoint(context.Background(), tc.id)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("OtherCellEndpoint(%q) = %q, %v; want %q", tc.id, got, ok, tc.want)
			}
		})
	}
	svc.cfg.CellIDKey = nil
	if got, ok := svc.OtherCellEndpoint(context.Background(), mint(2)); ok {
		t.Fatalf("without a key: %q, want none", got)
	}
}

// An Idempotency-Key create's ID (a digest of owner and key) gets the
// cell's byte too, and stays the same for the same digest, so a retry
// finds the first call's sandbox and the ID routes to its cell.
func TestIDInCell(t *testing.T) {
	digest := "sb-0123456789abcdef"
	for _, cell := range []int{1, 2, 200} {
		s := &Service{cfg: config.Config{CellID: cell, CellIDKey: testCellKey}}
		id := s.IDInCell(digest)
		if id != s.IDInCell(digest) || id[5:] != digest[5:] || !models.IsGeneratedSandboxID(id) {
			t.Fatalf("cell %d: IDInCell(%q) = %q, want a stable id that differs only in its first byte", cell, digest, id)
		}
		if got, ok := sandboxIDCell(id, testCellKey); !ok || got != cell {
			t.Fatalf("cell %d: %q reads as cell %d (%v)", cell, id, got, ok)
		}
	}
	for _, tc := range []struct {
		name string
		s    *Service
		id   string
	}{
		{name: "no service", s: nil, id: digest},
		{name: "no key", s: &Service{cfg: config.Config{CellID: 2}}, id: digest},
		{name: "a name", s: &Service{cfg: config.Config{CellID: 2, CellIDKey: testCellKey}}, id: "my-sandbox"},
	} {
		if got := tc.s.IDInCell(tc.id); got != tc.id {
			t.Fatalf("%s: IDInCell(%q) = %q, want it unchanged", tc.name, tc.id, got)
		}
	}
}

// The router counts each 421 it sends with another cell's address.
func TestRecordCellRedirect(t *testing.T) {
	before := cellRedirectsTotal.Value()
	RecordCellRedirect()
	if got := cellRedirectsTotal.Value() - before; got != 1 {
		t.Fatalf("aerolvm_cell_redirects_total rose by %d, want 1", got)
	}
}
