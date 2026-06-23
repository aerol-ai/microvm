package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/pkg/oci"
)

func ociHappyConfig(t *testing.T) (oci.Config, string) {
	t.Helper()
	dir := t.TempDir()
	bins := filepath.Join(dir, "bins")
	work := filepath.Join(dir, "work")
	if err := os.MkdirAll(bins, 0o755); err != nil {
		t.Fatalf("mkdir bins: %v", err)
	}

	skopeo := writeOCIFake(t, bins, "skopeo", `
last="$1"
while [ $# -gt 1 ]; do shift; last="$1"; done
case "$last" in
  oci:*) path="${last#oci:}"; path="${path%:*}"; mkdir -p "$path/blobs" "$path"; echo '{}' > "$path/index.json" ;;
esac
`)
	umoci := writeOCIFake(t, bins, "umoci", `
last="$1"
while [ $# -gt 0 ]; do last="$1"; shift; done
mkdir -p "$last/rootfs/bin"
echo fake > "$last/rootfs/bin/sh"
`)
	mkfs := writeOCIFake(t, bins, "mkfs.ext4", `
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) shift 2 ;;
    -F) shift ;;
    *) if [ -z "$out" ]; then out="$1"; fi; shift ;;
  esac
done
printf 'fake-ext4\n' > "$out"
`)

	return oci.Config{
		SkopeoBin: skopeo,
		UmociBin:  umoci,
		Mkfs4Bin:  mkfs,
		WorkDir:   work,
	}, work
}

func writeOCIFake(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return p
}
