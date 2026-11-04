package cluster

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

type coverage97BlockTransport struct {
	release context.Context
}

func (t coverage97BlockTransport) RoundTrip(*http.Request) (*http.Response, error) {
	<-t.release.Done()
	return nil, errors.New("released")
}

func TestCoverage97SecretFanoutBranches(t *testing.T) {
	lookup := func(id string) (Member, bool) {
		switch id {
		case "dead":
			return Member{NodeID: id, Alive: false, InternalURL: "http://dead"}, true
		case "nourl":
			return Member{NodeID: id, Alive: true}, true
		case "dial", "noclient", "peer":
			return Member{NodeID: id, Alive: true, InternalURL: "http://" + id}, true
		default:
			return Member{}, false
		}
	}
	dial := func(m Member) (*http.Client, string, error) {
		switch m.NodeID {
		case "dial":
			return nil, "", errors.New("dial down")
		case "noclient":
			return nil, "http://noclient", nil
		default:
			return &http.Client{Timeout: time.Second}, "http://" + m.NodeID, nil
		}
	}
	if _, err := pushSecretBlobToPeersLookupDialUntil(
		context.Background(), lookup, nil, dial, "", "self",
		secrets.SecretBlob{SandboxID: "sb"},
		[]string{"missing", "missing", "dead", "nourl", "dial", "noclient", "self", ""},
		false,
	); err == nil {
		t.Fatal("fan-out of unreachable peers succeeded")
	}

	releaseCtx, release := context.WithCancel(context.Background())
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := pushSecretBlobToPeersLookupDialUntil(ctx, lookup, nil, func(Member) (*http.Client, string, error) {
			return &http.Client{Transport: coverage97BlockTransport{release: releaseCtx}}, "http://peer", nil
		}, "pat", "self", secrets.SecretBlob{SandboxID: "sb"}, []string{"peer"}, false)
		errCh <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled fan-out = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fan-out did not return after cancel")
	}

	if _, err := deleteSecretOnPeersLookupDial(
		ctx, lookup, nil, dial, "pat", "self", "sb", "inc", []string{"peer"}, 1,
	); err == nil {
		t.Fatal("cancelled delete succeeded")
	}
	if _, err := probeSecretOnPeersLookupDial(
		ctx, lookup, nil, dial, "pat", "self", "sb", "inc", []string{"peer"}, 1,
	); err == nil {
		t.Fatal("cancelled probe succeeded")
	}
}
