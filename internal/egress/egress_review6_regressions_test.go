package egress

// Regression test from the sixth review of PR #622: under -race, it reports
// the Sync merge writing a live entry under the read lock on the reviewed
// head (87e02279), and passes with the fix.

import (
	"sync"
	"testing"
)

func TestSyncPreservedEntryIsNotSharedWithReaders(t *testing.T) {
	g, _, _ := newTestGateway(t)
	tok := g.SyncToken()
	if err := g.Attach(allowSpec("sb", ipA, "pypi.org")); err != nil {
		t.Fatal(err)
	}
	if err := g.SetBlocked("sb", BlockHold, true); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				g.Source(ipA)
			}
		}
	}()
	defer func() { close(done); wg.Wait() }()
	for i := 0; i < 200; i++ {
		if err := g.SyncFrom(tok, nil); err != nil {
			t.Fatal(err)
		}
	}
}
