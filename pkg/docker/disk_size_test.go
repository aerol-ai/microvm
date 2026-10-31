package docker

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestWritableLayerBytes: the size is SizeRw from a size=true inspect; an
// absent SizeRw is 0 and an engine error surfaces.
func TestWritableLayerBytes(t *testing.T) {
	var query string
	body := `{"SizeRw": 3221225472}`
	status := http.StatusOK
	c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		query = r.URL.RawQuery
		return textResponse(status, body), nil
	})}}
	got, err := c.WritableLayerBytes(context.Background(), "abc")
	if err != nil || got != 3<<30 || !strings.Contains(query, "size=true") {
		t.Fatalf("size = %d %v (query %q)", got, err, query)
	}
	body = `{}`
	if got, err := c.WritableLayerBytes(context.Background(), "abc"); err != nil || got != 0 {
		t.Fatalf("no SizeRw = %d %v", got, err)
	}
	status, body = http.StatusNotFound, `{"message":"no such container"}`
	if _, err := c.WritableLayerBytes(context.Background(), "abc"); err == nil {
		t.Fatal("an engine error must surface")
	}
}
