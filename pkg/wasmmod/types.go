package wasmmod

// ResolvedModule is a validated local .wasm artifact ready for the engine.
type ResolvedModule struct {
	Ref       string
	Path      string
	Digest    string // sha256 hex
	SizeBytes int64
}
