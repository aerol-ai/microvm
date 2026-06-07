package wasmmod

import (
	"bytes"
	"fmt"
	"os"
)

var wasmMagic = []byte{0x00, 0x61, 0x73, 0x6d} // \0asm

// ValidateFile checks the WASM magic header and non-zero size.
func ValidateFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return fmt.Errorf("wasm module %q is empty", path)
	}
	if st.Size() > 256<<20 {
		return fmt.Errorf("wasm module %q exceeds 256MiB cap", path)
	}
	head := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Read(head); err != nil {
		return err
	}
	if !bytes.Equal(head, wasmMagic) {
		return fmt.Errorf("wasm module %q: bad magic header", path)
	}
	return nil
}
