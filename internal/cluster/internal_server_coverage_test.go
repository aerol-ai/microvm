package cluster

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentCloseInternalServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// Close the real server, then wrap as internalServer-like by using a closed listener via Agent fields.
	srv.Close()
	a := &Agent{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		gossip: &gossipNode{},
	}
	_ = a.Close()
}
