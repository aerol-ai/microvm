package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAPIListenerServesH2CAndHTTP1 pins the protocol set of the public API
// listener: an HTTP/2 prior-knowledge client (the Runloop TS SDK on an
// http:// base URL) and a plain HTTP/1.1 client both get served.
func TestAPIListenerServesH2CAndHTTP1(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	srv.Config.Protocols = apiListenerProtocols()
	srv.Start()
	t.Cleanup(srv.Close)

	var priorKnowledge http.Protocols
	priorKnowledge.SetUnencryptedHTTP2(true)
	h2c := &http.Client{Transport: &http.Transport{Protocols: &priorKnowledge}}
	for name, client := range map[string]*http.Client{"h2c": h2c, "http1": http.DefaultClient} {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		want := "HTTP/1.1"
		if name == "h2c" {
			want = "HTTP/2.0"
		}
		if string(body) != want {
			t.Fatalf("%s: served %q, want %q", name, body, want)
		}
	}
}
