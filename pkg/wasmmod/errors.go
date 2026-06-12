package wasmmod

import "errors"

// Module-resolution error taxonomy. The service layer maps these to HTTP
// status via apihttp.WriteStoreAwareError so the SDK can tell a terminal
// failure (fix your ref / token) from a transient one (retry the pull).
//
// ErrComponentModelUnsupported (validate.go) is the sixth member of this set;
// it is mapped to 422 the same way.
var (
	// ErrModuleNotFound: the ref named no reserved keyword, catalogue id, or
	// local file. The service surfaces the valid reserved keywords alongside.
	ErrModuleNotFound = errors.New("wasm module not found")
	// ErrRegistryNotAllowed: an oci:// ref named a host outside
	// SB_WASM_REGISTRY_ALLOWLIST. This is the SSRF guard — never relax it to
	// a warning.
	ErrRegistryNotAllowed = errors.New("wasm module registry not allowed")
	// ErrRegistryAuth: the registry rejected our credentials (bad/expired PAT).
	// Terminal — retrying without fixing the token will not help.
	ErrRegistryAuth = errors.New("wasm module registry authentication failed")
	// ErrRegistryUnavailable: network/registry transient failure. Retryable.
	ErrRegistryUnavailable = errors.New("wasm module registry unavailable")
	// ErrModuleTooLarge: the artifact exceeded the size cap mid-stream. We
	// abort the pull rather than buffer an unbounded body.
	ErrModuleTooLarge = errors.New("wasm module exceeds size cap")
	// ErrModuleDigestMismatch: a sandbox pinned digest X at create, but the
	// alias/tag it referenced now resolves to different bytes and the frozen
	// copy is gone. We fail loudly rather than silently boot different code on
	// restart/failover (codex C2).
	ErrModuleDigestMismatch = errors.New("wasm module digest drift")
)
