package wasmmod

// ResolvedModule is a validated local .wasm artifact ready for the engine.
type ResolvedModule struct {
	Ref       string
	Path      string
	Digest    string // sha256 hex
	SizeBytes int64
	// Operator is set when the module is the operator's own: a reserved
	// keyword, or a file the operator staged in the modules dir. It is
	// decided from where the resolver found the module, never from the
	// request, and is what lets a trusted step compile it into the
	// compile cache every owner's workers read (pkg/wasm.PrecompileModule).
	// Pulled (oci://) and catalogue modules are not the operator's.
	Operator bool
}
