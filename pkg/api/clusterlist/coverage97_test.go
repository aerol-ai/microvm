package clusterlist

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
)

func TestPlacementWantIDsNilMeansNoFilter(t *testing.T) {
	if got := PlacementWantIDs(nil); got != nil {
		t.Fatalf("nil placements = %#v", got)
	}
}

type coverage97BlockTransport struct {
	release context.Context
}

func (t coverage97BlockTransport) RoundTrip(*http.Request) (*http.Response, error) {
	<-t.release.Done()
	return nil, errors.New("released")
}

func TestCoverage97MergeStopsWhenCancelled(t *testing.T) {
	peers := make([]cluster.Member, MaxConcurrentPeerReads+1)
	for i := range peers {
		peers[i] = cluster.Member{NodeID: "peer", InternalURL: "https://peer.invalid", Alive: true}
	}
	run := func(t *testing.T, merge func(context.Context, *http.Client)) {
		t.Helper()
		releaseCtx, release := context.WithCancel(context.Background())
		client := &http.Client{Transport: coverage97BlockTransport{release: releaseCtx}}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			merge(ctx, client)
		}()
		time.Sleep(40 * time.Millisecond)
		cancel()
		time.Sleep(20 * time.Millisecond)
		release()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("cancelled merge did not return")
		}
	}
	run(t, func(ctx context.Context, client *http.Client) {
		Merge(ctx, peers, Options{Transport: Transport{InternalClient: client}})
	})
	run(t, func(ctx context.Context, client *http.Client) {
		MergeJSON[string](ctx, peers, nil, nil, Options{Transport: Transport{InternalClient: client}})
	})
}

func TestCoverage97MergeRequiresInternalClient(t *testing.T) {
	peers := []cluster.Member{{NodeID: "peer", InternalURL: "https://peer.invalid", Alive: true}}
	res := Merge(context.Background(), peers, Options{})
	if !res.Coverage.Partial || len(res.Coverage.Missing) != 1 {
		t.Fatalf("coverage = %+v", res.Coverage)
	}
}
