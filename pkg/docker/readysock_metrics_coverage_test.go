package docker

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestCoverage95ClientReadySocketSweepAndMetrics(t *testing.T) {
	dir := coverageReadyDir(t)
	keep := filepath.Join(dir, "keep.sock")
	orphan := filepath.Join(dir, "orphan.sock")
	for _, path := range []string{keep, orphan} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &Client{
		readyDir: dir,
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			switch r.URL.Path {
			case "/containers/json":
				return jsonResponse(http.StatusOK, []containerSummary{
					{ID: "managed", Labels: map[string]string{managedLabelKey: "true"}},
					{ID: "unmanaged", Labels: map[string]string{}},
				}), nil
			case "/containers/managed/json":
				return textResponse(http.StatusOK, `{"HostConfig":{"Binds":["`+keep+`:`+GuestReadySocketPath+`"]}}`), nil
			}
			return textResponse(http.StatusNotFound, "missing"), nil
		})},
	}
	if err := c.SweepOrphanReadySockets(context.Background()); err != nil {
		t.Fatalf("SweepOrphanReadySockets: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("kept socket removed: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan socket remained: %v", err)
	}
	if c.readySocketPathOwnedByDir(filepath.Join(dir, "..", "outside.sock")) {
		t.Fatal("path outside ready directory was accepted")
	}
	if err := (&Client{}).SweepOrphanReadySockets(context.Background()); err != nil {
		t.Fatalf("empty ready dir: %v", err)
	}

	recordReadySocketHit(17)
	recordReadySocketFallback(23)
	recordReadySocketTimeout()
	recordReadySocketInvalid()
	if got := ReadyWaitMS(); got != 23 {
		t.Fatalf("ReadyWaitMS() = %d, want 23", got)
	}
}
