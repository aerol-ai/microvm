package netrules

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSets is a kernel with the block table, and a filter table holding
// per-address rules as strings. Transactions are all or nothing; deleting
// an absent element fails the transaction as the kernel does (ENOENT).
type fakeSets struct {
	mu      sync.Mutex
	missing bool // the table is gone (a flush)
	sets    map[string]map[string]bool
	rules   []string
	legacy  map[string][]string // chain -> addresses with a legacy block rule
	ensures int
	txs     [][]blockSetOp
	// injected failures
	ensureErr, elementsErr, applyErr, listErr error
	applyHook                                 func(ops []blockSetOp) error
}

func newFakeSets() *fakeSets {
	return &fakeSets{sets: map[string]map[string]bool{BlockedSet: {}, ReleasedSet: {}}}
}

func (f *fakeSets) Exists(_, chain string, spec ...string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.rules, chain+" "+strings.Join(spec, " ")), nil
}
func (f *fakeSets) Insert(_, chain string, _ int, spec ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, chain+" "+strings.Join(spec, " "))
	return nil
}
func (f *fakeSets) Delete(_, chain string, spec ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := chain + " " + strings.Join(spec, " ")
	if i := slices.Index(f.rules, k); i >= 0 {
		f.rules = slices.Delete(f.rules, i, i+1)
		return nil
	}
	return errors.New("rule does not exist")
}
func (f *fakeSets) EnsureInputChain(string) error { return nil }

func (f *fakeSets) EnsureBlockTable() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensures++
	if f.ensureErr != nil {
		return f.ensureErr
	}
	if f.missing {
		f.missing = false
		f.sets = map[string]map[string]bool{BlockedSet: {}, ReleasedSet: {}}
	}
	return nil
}

func (f *fakeSets) BlockSetElements() (blocked, released []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.elementsErr != nil {
		return nil, nil, f.elementsErr
	}
	if f.missing {
		return nil, nil, fmt.Errorf("%w: gone", errBlockTableMissing)
	}
	return slices.Sorted(maps.Keys(f.sets[BlockedSet])), slices.Sorted(maps.Keys(f.sets[ReleasedSet])), nil
}

func (f *fakeSets) ApplyBlockSetOps(ops []blockSetOp) error {
	if f.applyHook != nil {
		if err := f.applyHook(ops); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return f.applyErr
	}
	if f.missing {
		return fmt.Errorf("%w: gone", errBlockTableMissing)
	}
	// Check first: the transaction applies nothing if one op fails.
	next := map[string]map[string]bool{BlockedSet: maps.Clone(f.sets[BlockedSet]), ReleasedSet: maps.Clone(f.sets[ReleasedSet])}
	for _, op := range ops {
		if op.Add {
			next[op.Set][op.IP] = true
			continue
		}
		if !next[op.Set][op.IP] {
			return fmt.Errorf("%w: no element %s in %s", errBlockTableMissing, op.IP, op.Set)
		}
		delete(next[op.Set], op.IP)
	}
	f.sets = next
	f.txs = append(f.txs, slices.Clone(ops))
	return nil
}

func (f *fakeSets) LegacyBlockIPs(chain string, _ func(string) []string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.legacy[chain]), nil
}

func (f *fakeSets) has(set, ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sets[set][ip]
}

func (f *fakeSets) lastTx() []blockSetOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.txs) == 0 {
		return nil
	}
	return f.txs[len(f.txs)-1]
}

func (f *fakeSets) txCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.txs)
}

// open reports whether the kernel lets ip's traffic through: not in
// @blocked, or in @released.
func (f *fakeSets) open(ip string) bool {
	return !f.has(BlockedSet, ip) || f.has(ReleasedSet, ip)
}

func setsManager(t *testing.T, f *fakeSets) *Manager {
	t.Helper()
	ResetBlockSetsForTest()
	t.Cleanup(ResetBlockSetsForTest)
	m := &Manager{enabled: true, ipt: f, userChain: ChainAerolvmUser}
	if err := m.PrepareBlockSets(); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestBlockSetsLifecycle: a block is one add, a lift one add, a re-block
// deletes the release in the same transaction, and a let-go deletes the
// release first and the block second, in one transaction.
func TestBlockSetsLifecycle(t *testing.T) {
	f := newFakeSets()
	m := setsManager(t, f)
	const ip = "10.88.0.5"
	inserted, err := m.BlockAllEgressReport(ip)
	if err != nil || !inserted || f.open(ip) {
		t.Fatalf("block: inserted=%v err=%v open=%v", inserted, err, f.open(ip))
	}
	if got := f.lastTx(); !slices.Equal(got, []blockSetOp{{Set: BlockedSet, Add: true, IP: ip}}) {
		t.Fatalf("block tx %v, want one add to @blocked", got)
	}
	if inserted, _ = m.BlockAllEgressReport(ip); inserted {
		t.Fatal("a block already in place reported as drift")
	}
	if err := m.LiftBlockAllEgress(ip); err != nil || !f.open(ip) {
		t.Fatalf("lift: err=%v open=%v", err, f.open(ip))
	}
	if got := f.lastTx(); !slices.Equal(got, []blockSetOp{{Set: ReleasedSet, Add: true, IP: ip}}) {
		t.Fatalf("lift tx %v, want one add to @released", got)
	}
	n := f.txCount()
	if err := m.LiftBlockAllEgress(ip); err != nil || f.txCount() != n {
		t.Fatalf("a second lift wrote (err=%v)", err)
	}
	if inserted, _ = m.BlockAllEgressReport(ip); !inserted || f.open(ip) {
		t.Fatalf("re-block: inserted=%v open=%v", inserted, f.open(ip))
	}
	if got := f.lastTx(); !slices.Equal(got, []blockSetOp{{Set: ReleasedSet, IP: ip}, {Set: BlockedSet, Add: true, IP: ip}}) {
		t.Fatalf("re-block tx %v, want the release deleted, then the add", got)
	}
	if err := m.LiftBlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	if err := m.ClearBlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	if got := f.lastTx(); !slices.Equal(got, []blockSetOp{{Set: ReleasedSet, IP: ip}, {Set: BlockedSet, IP: ip}}) {
		t.Fatalf("let-go tx %v, want @released then @blocked deleted", got)
	}
	if b, r := BlockedInSets(ip); b || r || f.has(BlockedSet, ip) || f.has(ReleasedSet, ip) {
		t.Fatalf("let-go left mirror %v/%v", b, r)
	}
	n = f.txCount()
	if err := m.ClearBlockAllEgress(ip); err != nil || f.txCount() != n {
		t.Fatalf("a let-go of nothing wrote (err=%v)", err)
	}
	if err := m.LiftBlockAllEgress(ip); err != nil || f.txCount() != n {
		t.Fatalf("a lift of nothing wrote (err=%v)", err)
	}
}

// TestBlockSetsStaleReleaseNeverOpensTheNextOwner: a sandboxd that died
// after a release leaves it in the kernel; the next process reads it, and
// the address's next block deletes it.
func TestBlockSetsStaleReleaseNeverOpensTheNextOwner(t *testing.T) {
	f := newFakeSets()
	const ip = "10.88.0.6"
	f.sets[BlockedSet][ip], f.sets[ReleasedSet][ip] = true, true
	m := setsManager(t, f)
	if b, r := BlockedInSets(ip); !b || !r {
		t.Fatal("prepare didn't read the kernel's sets")
	}
	if err := m.BlockAllEgress(ip); err != nil || f.open(ip) {
		t.Fatalf("next owner open (err=%v)", err)
	}
}

// TestBlockSetsUnsureAddressReadsTheKernel: an operation that failed may
// have applied; the next one on the address reads the kernel instead of
// trusting the mirror.
func TestBlockSetsUnsureAddressReadsTheKernel(t *testing.T) {
	f := newFakeSets()
	m := setsManager(t, f)
	const ip = "10.88.0.7"
	if err := m.BlockAllEgress(ip); err != nil {
		t.Fatal(err)
	}
	// The lift's add lands, but its answer is lost.
	f.applyHook = func(ops []blockSetOp) error {
		f.applyHook = nil
		f.mu.Lock()
		f.sets[ReleasedSet][ip] = true
		f.mu.Unlock()
		return errors.New("netlink receive: no buffer space")
	}
	if err := m.LiftBlockAllEgress(ip); err == nil {
		t.Fatal("lift succeeded")
	}
	// The mirror says blocked only; the kernel holds a release. A block
	// must still delete it.
	if err := m.BlockAllEgress(ip); err != nil || f.open(ip) {
		t.Fatalf("block after an unsure lift left it open (err=%v)", err)
	}
	// A read failure of an unsure address fails the operation.
	f.applyErr = errors.New("boom")
	if err := m.ClearBlockAllEgress(ip); err == nil {
		t.Fatal("let-go succeeded")
	}
	f.applyErr = nil
	f.elementsErr = errors.New("dump boom")
	if err := m.BlockAllEgress(ip); err == nil || !strings.Contains(err.Error(), "read block sets") {
		t.Fatalf("err = %v", err)
	}
	f.elementsErr = nil
	if err := m.ClearBlockAllEgress(ip); err != nil || f.has(BlockedSet, ip) {
		t.Fatalf("let-go after recovery: err=%v", err)
	}
}

// TestBlockSetsTableLostIsPutBack: after a flush of the table, the next
// operation recreates it, puts back every element this process knows of,
// and reports the drift.
func TestBlockSetsTableLostIsPutBack(t *testing.T) {
	f := newFakeSets()
	m := setsManager(t, f)
	for _, ip := range []string{"10.88.0.8", "10.88.0.9"} {
		if err := m.BlockAllEgress(ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.LiftBlockAllEgress("10.88.0.9"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.missing = true
	f.mu.Unlock()
	inserted, err := m.BlockAllEgressReport("10.88.0.10")
	if err != nil || !inserted {
		t.Fatalf("inserted=%v err=%v", inserted, err)
	}
	if f.open("10.88.0.8") || !f.open("10.88.0.9") || f.open("10.88.0.10") {
		t.Fatal("the recreated sets don't hold what this process put in them")
	}
	// A flush seen by a read is put back too.
	f.mu.Lock()
	f.missing = true
	f.mu.Unlock()
	blockSets.markUnsure("10.88.0.8")
	if err := m.LiftBlockAllEgress("10.88.0.8"); err != nil || !f.open("10.88.0.8") || f.open("10.88.0.10") {
		t.Fatalf("lift after a flush: err=%v", err)
	}
	// Recreating can fail; so can the refill.
	f.mu.Lock()
	f.missing = true
	f.ensureErr = errors.New("ensure boom")
	f.mu.Unlock()
	if err := m.BlockAllEgress("10.88.0.11"); err == nil || !strings.Contains(err.Error(), "recreate") {
		t.Fatalf("err = %v", err)
	}
	blockSets.markUnsure("10.88.0.12")
	if err := m.BlockAllEgress("10.88.0.12"); err == nil {
		t.Fatal("block of an unsure address with the table gone and not recreatable succeeded")
	}
	f.ensureErr = nil
	calls := 0
	f.applyHook = func([]blockSetOp) error {
		calls++
		if calls == 2 {
			return errors.New("refill boom")
		}
		return nil
	}
	if err := m.BlockAllEgress("10.88.0.13"); err == nil || !strings.Contains(err.Error(), "refill") {
		t.Fatalf("err = %v", err)
	}
}

// TestReassertBlockSets: a lost element is put back, a release nothing
// here made is deleted, an unknown block is kept and learned; runs are
// spaced.
func TestReassertBlockSets(t *testing.T) {
	f := newFakeSets()
	m := setsManager(t, f)
	blockReassertMinGap = 0
	defer func() { blockReassertMinGap = 10 * time.Second }()
	if repaired, err := m.ReassertBlockSets(); err != nil || repaired {
		t.Fatalf("clean: repaired=%v err=%v", repaired, err)
	}
	if err := m.BlockAllEgress("10.88.1.2"); err != nil {
		t.Fatal(err)
	}
	if err := m.BlockAllEgress("10.88.1.3"); err != nil {
		t.Fatal(err)
	}
	if err := m.LiftBlockAllEgress("10.88.1.3"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	delete(f.sets[BlockedSet], "10.88.1.2")  // lost
	delete(f.sets[ReleasedSet], "10.88.1.3") // lost
	f.sets[ReleasedSet]["10.88.1.4"] = true  // nobody here made it
	f.sets[BlockedSet]["10.88.1.5"] = true   // nobody here made it: closed, kept
	f.mu.Unlock()
	if repaired, err := m.ReassertBlockSets(); err != nil || !repaired {
		t.Fatalf("repaired=%v err=%v", repaired, err)
	}
	if f.open("10.88.1.2") || !f.open("10.88.1.3") || f.has(ReleasedSet, "10.88.1.4") || !f.has(BlockedSet, "10.88.1.5") {
		t.Fatalf("after reassert: %v", f.sets)
	}
	if b, _ := BlockedInSets("10.88.1.5"); !b {
		t.Fatal("the unknown block wasn't learned (a let-go couldn't remove it)")
	}
	blockReassertMinGap = time.Hour
	f.mu.Lock()
	delete(f.sets[BlockedSet], "10.88.1.2")
	f.mu.Unlock()
	if repaired, _ := m.ReassertBlockSets(); repaired {
		t.Fatal("ran again within the gap")
	}
	blockReassertMinGap = 0
	f.ensureErr = errors.New("ensure boom")
	if _, err := m.ReassertBlockSets(); err == nil {
		t.Fatal("ensure failure hidden")
	}
	f.ensureErr = nil
	f.elementsErr = errors.New("dump boom")
	if _, err := m.ReassertBlockSets(); err == nil {
		t.Fatal("read failure hidden")
	}
	f.elementsErr = nil
	f.applyErr = errors.New("apply boom")
	if _, err := m.ReassertBlockSets(); err == nil {
		t.Fatal("repair failure hidden")
	}
	f.applyErr = nil
	if _, err := (&Manager{}).ReassertBlockSets(); err != nil {
		t.Fatal("no sets: no-op")
	}
}

// TestPrepareBlockSets: what decides whether a manager serves from the
// sets, and the conversion of an older daemon's rules.
func TestPrepareBlockSets(t *testing.T) {
	ResetBlockSetsForTest()
	t.Cleanup(ResetBlockSetsForTest)
	// Disabled, or a backend without sets: nothing to do, per-address rules.
	if err := (&Manager{}).PrepareBlockSets(); err != nil {
		t.Fatal(err)
	}
	plain := NewWithBackend(&memBackend{})
	if err := plain.PrepareBlockSets(); err != nil || plain.blockSetsOf() != nil {
		t.Fatalf("no-sets backend: err=%v", err)
	}
	if err := plain.LiftBlockAllEgress("10.88.2.2"); err != nil {
		t.Fatal(err)
	}

	f := newFakeSets()
	f.ensureErr = errors.New("ensure boom")
	m := &Manager{enabled: true, ipt: f, userChain: ChainAerolvmUser}
	if err := m.PrepareBlockSets(); err == nil || m.blockSetsOf() != nil {
		t.Fatalf("ensure failure: err=%v ready=%v", err, m.blockSetsOf() != nil)
	}
	f.ensureErr = nil
	f.elementsErr = errors.New("dump boom")
	if err := m.PrepareBlockSets(); err == nil || m.blockSetsOf() != nil {
		t.Fatalf("read failure: err=%v", err)
	}
	f.elementsErr = nil

	// An older daemon left block pairs: they become elements, the rules go.
	f.legacy = map[string][]string{ChainAerolvmUser: {"10.88.2.3"}, ChainAerolvmInput: {"10.88.2.3", "10.88.2.4"}}
	for _, ip := range []string{"10.88.2.3", "10.88.2.4"} {
		_ = f.Insert("filter", ChainAerolvmUser, 1, egressDropSpec(ip)...)
		_ = f.Insert("filter", ChainAerolvmInput, 2, inputBlockSpec(ip)...)
	}
	if err := m.PrepareBlockSets(); err != nil || !m.legacyConverted.Load() {
		t.Fatalf("convert: err=%v converted=%v", err, m.legacyConverted.Load())
	}
	if f.open("10.88.2.3") || f.open("10.88.2.4") || len(f.rules) != 0 {
		t.Fatalf("after conversion: sets %v rules %v", f.sets, f.rules)
	}

	// A conversion that fails leaves the sets serving and the rules for
	// Lift and Forget to clear.
	ResetBlockSetsForTest()
	f2 := newFakeSets()
	f2.listErr = errors.New("list boom")
	m2 := &Manager{enabled: true, ipt: f2, userChain: ChainAerolvmUser}
	if err := m2.PrepareBlockSets(); err == nil || m2.blockSetsOf() == nil || m2.legacyConverted.Load() {
		t.Fatalf("failed conversion: err=%v ready=%v converted=%v", err, m2.blockSetsOf() != nil, m2.legacyConverted.Load())
	}
	_ = f2.Insert("filter", ChainAerolvmUser, 1, egressDropSpec("10.88.2.5")...)
	if err := m2.LiftBlockAllEgress("10.88.2.5"); err != nil || len(f2.rules) != 0 {
		t.Fatalf("lift kept the old rule: err=%v rules=%v", err, f2.rules)
	}
	_ = f2.Insert("filter", ChainAerolvmUser, 1, egressDropSpec("10.88.2.6")...)
	if err := m2.ClearBlockAllEgress("10.88.2.6"); err != nil || len(f2.rules) != 0 {
		t.Fatalf("let-go kept the old rule: err=%v rules=%v", err, f2.rules)
	}
	f2.listErr = nil
	f2.legacy = map[string][]string{ChainAerolvmInput: {"10.88.2.7"}}
	f2.applyErr = errors.New("apply boom")
	if err := m2.PrepareBlockSets(); err == nil {
		t.Fatal("a conversion whose block fails succeeded")
	}
	f2.applyErr = nil
}

// TestBlockSetsKeepIPv6OnTheRules: an address the ip-family sets can't
// hold stays on the per-address path.
func TestBlockSetsKeepIPv6OnTheRules(t *testing.T) {
	f := newFakeSets()
	m := setsManager(t, f)
	if err := m.BlockAllEgress("fd00::5"); err != nil {
		t.Fatal(err)
	}
	if f.txCount() != 0 || !slices.Contains(f.rules, ChainAerolvmUser+" -s fd00::5 -j DROP") {
		t.Fatalf("txs %v rules %v", f.txs, f.rules)
	}
	if err := m.LiftBlockAllEgress("fd00::5"); err != nil || len(f.rules) != 0 {
		t.Fatalf("lift: err=%v rules=%v", err, f.rules)
	}
	for _, fn := range []func() error{
		func() error { return m.LiftBlockAllEgress("") },
		func() error { return (&Manager{}).LiftBlockAllEgress("10.0.0.1") },
	} {
		if err := fn(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestBlockSetsConcurrentAddressesAndReassert: creates, lifts and
// let-goes on many addresses at once, with reasserts running, end with the
// kernel and the mirror agreeing and nothing left.
func TestBlockSetsConcurrentAddressesAndReassert(t *testing.T) {
	f := newFakeSets()
	m := setsManager(t, f)
	blockReassertMinGap = 0
	defer func() { blockReassertMinGap = 10 * time.Second }()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				ip := fmt.Sprintf("10.88.%d.%d", 10+g, i+2)
				if err := m.BlockAllEgress(ip); err != nil {
					t.Error(err)
				}
				if f.open(ip) {
					t.Errorf("%s open after its block", ip)
				}
				if err := m.LiftBlockAllEgress(ip); err != nil {
					t.Error(err)
				}
				if err := m.ClearBlockAllEgress(ip); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				if _, err := m.ReassertBlockSets(); err != nil {
					t.Error(err)
				}
			}
		}
	}()
	wg.Wait()
	close(stop)
	<-done
	if b, r, _ := f.BlockSetElements(); len(b)+len(r) != 0 {
		t.Fatalf("left in the kernel: %v %v", b, r)
	}
}
