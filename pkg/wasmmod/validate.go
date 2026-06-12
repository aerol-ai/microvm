package wasmmod

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

var wasmMagic = []byte{0x00, 0x61, 0x73, 0x6d} // \0asm

// maxModuleBytes caps a .wasm artifact (256MiB). Enforced both post-download
// (ValidateFile) and as the pre-download manifest-size bound on oci:// pulls.
const maxModuleBytes = 256 << 20

// ErrComponentModelUnsupported flags a WASI Component Model artifact. Neither
// engine in this repo (wazero, nor wasmtime-go which has no component API) can
// instantiate a component — both run core wasip1 modules only. Detecting it here
// turns a cryptic deep parse failure into a directed, actionable error.
var ErrComponentModelUnsupported = errors.New("wasm component model not supported")

// ValidateFile checks the WASM magic header, the core-vs-component layer, and
// the size bounds. A WASM binary's 8-byte preamble is 4 magic bytes + a 4-byte
// version/layer field: core modules carry layer 0x0000 (version u32 = 1),
// components carry layer 0x0001 (bytes 6–7 == 0x01 0x00). We reject the latter.
func ValidateFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return fmt.Errorf("wasm module %q is empty", path)
	}
	if st.Size() > maxModuleBytes {
		return fmt.Errorf("wasm module %q exceeds 256MiB cap", path)
	}
	head := make([]byte, 8)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	head = head[:n]
	if len(head) < 4 || !bytes.Equal(head[:4], wasmMagic) {
		return fmt.Errorf("wasm module %q: bad magic header", path)
	}
	// Layer field (bytes 6–7) distinguishes a component (0x0001) from a core
	// module (0x0000). Components fail deep inside the engine with an opaque
	// error otherwise, so signpost the fix here.
	if len(head) >= 8 && head[6] == 0x01 && head[7] == 0x00 {
		return fmt.Errorf("wasm module %q is a WASI component, but this runtime executes core wasip1 modules only — "+
			"recompile to a core module (e.g. GOOS=wasip1 / wasm32-wasip1) or lower it with `wasm-tools component`: %w",
			path, ErrComponentModelUnsupported)
	}
	return nil
}
