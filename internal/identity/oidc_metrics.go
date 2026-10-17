package identity

import (
	"expvar"
	"sync"
	"time"
)

// Identity metrics (plans/identity-and-access.md §5.15), exported through
// /v1/metrics like every aerolvm_ expvar. Nested maps become the key/key2
// labels. Every label value is an issuer name from the identity file or a
// fixed word, never anything a caller sent, so a caller cannot grow the
// series count.
//
//	aerolvm_identity_file_info{key=<sha256 of the file>}           1 for the file in force
//	aerolvm_identity_file_load_errors_total                        invalid loads (boot or reload)
//	aerolvm_identity_jwks_fetch_total{key=<issuer>,key2=<result>}  ok | error | too_large
//	aerolvm_identity_jwks_last_success_timestamp{key=<issuer>}     unix seconds
//	aerolvm_identity_oversize_total{key=<input>}                   jwt | identity_file | discovery | jwks
var (
	identityFileInfo       = expvar.NewMap("aerolvm_identity_file_info")
	identityFileLoadErrors = expvar.NewInt("aerolvm_identity_file_load_errors_total")
	jwksFetchTotal         = expvar.NewMap("aerolvm_identity_jwks_fetch_total")
	jwksLastSuccess        = expvar.NewMap("aerolvm_identity_jwks_last_success_timestamp")
	oversizeTotal          = expvar.NewMap("aerolvm_identity_oversize_total")
	metricMu               sync.Mutex
)

// JWKS fetch results.
const (
	fetchOK       = "ok"
	fetchError    = "error"
	fetchTooLarge = "too_large"
)

// Inputs with a size cap (CEO review finding 5.5).
const (
	oversizeJWT          = "jwt"
	oversizeIdentityFile = "identity_file"
	oversizeDiscovery    = "discovery"
	oversizeJWKS         = "jwks"
)

// publishFileHash makes hash the only aerolvm_identity_file_info series, so
// distinct values across nodes show identity-file drift.
func publishFileHash(hash string) {
	metricMu.Lock()
	defer metricMu.Unlock()
	identityFileInfo.Init()
	v := new(expvar.Int)
	v.Set(1)
	identityFileInfo.Set(hash, v)
}

func observeJWKSFetch(issuer, result string, at time.Time) {
	metricMu.Lock()
	inner, ok := jwksFetchTotal.Get(issuer).(*expvar.Map)
	if !ok {
		inner = new(expvar.Map)
		jwksFetchTotal.Set(issuer, inner)
	}
	metricMu.Unlock()
	inner.Add(result, 1)
	if result == fetchOK {
		v := new(expvar.Int)
		v.Set(at.Unix())
		jwksLastSuccess.Set(issuer, v)
	}
}

func observeOversize(input string) { oversizeTotal.Add(input, 1) }
