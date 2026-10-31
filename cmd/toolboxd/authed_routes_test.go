package main

import "net/http"

// testToolboxToken is the token authedRoutes gives a server that has none.
const testToolboxToken = "test-toolbox-token"

// authedRoutes is s.routes() for a test about what a route does rather than
// who may call it. toolboxd serves nothing without a token (see
// servingRequests), so a token-less test server gets one, and a request that
// carries no Authorization header gets that server's token. The auth tests
// drive s.routes() directly.
func authedRoutes(s *server) http.Handler {
	s.mu.Lock()
	if s.authToken == "" {
		s.authToken = testToolboxToken
	}
	token := s.authToken
	s.mu.Unlock()
	h := s.routes()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		h.ServeHTTP(w, r)
	})
}
